"""lab downgrade, and the viewer reading every kit result file (issue #589, LAB-16 Task 12).

    uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/modules/kit/tests -v

The downgrade tests run the real example Guardian in a subprocess on a port it picks itself, never 8787, which the
conformance suite and the lab bind.
"""
from __future__ import annotations

import contextlib
import copy
import http.server
import importlib.util
import json
import os
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")

import fixtures  # noqa: E402
from fixtures import HMAC_KEY_ID, SESSION_A, SESSION_B, LabState  # noqa: E402
from kit_sessions import kit, write_session  # noqa: E402

from acs.testing.harness import launch_guardian  # noqa: E402

downgrade, forge, verify = kit("downgrade"), kit("forge"), kit("verify")
VIEWER_DIR = Path(__file__).resolve().parents[3] / "viewer"


@pytest.fixture
def lab(tmp_path) -> LabState:
    lab = LabState(tmp_path / "bundle")
    lab.write_hmac_secret()
    return lab


def pinned_key(lab: LabState) -> fixtures.DecisionKey:
    """The Guardian's decision key where lab init puts it, with its fingerprint in .env, written once per lab."""
    if not (lab.state / "keys" / "guardian-keys.json").exists():
        key = fixtures.decision_key(lab.state / "keys")
        lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
        lab.decision_key = key  # type: ignore[attr-defined]
    return lab.decision_key  # type: ignore[attr-defined]


@contextlib.contextmanager
def guardian(lab: LabState, tmp_path: Path, *, mldsa: bool) -> Iterator[str]:
    """The example Guardian on the lab's HMAC secret, signing responses with the lab's pinned ML-DSA-65 key when
    mldsa is set, as compose.yaml runs it."""
    pinned_key(lab)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
    env.update({"ACS_HMAC_SECRET_FILE": str(lab.state / "secrets" / "hmac.key"), "ACS_HMAC_KEY_ID": HMAC_KEY_ID,
                "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "guardian-state")})
    if mldsa:
        env.update({"ACS_RESPONSE_SIGNING": "ML-DSA-65",
                    "ACS_GUARDIAN_SIGNING_KEY_FILE": str(lab.state / "keys" / "guardian.key"),
                    "ACS_GUARDIAN_KEY_ID": fixtures.KEY_ID,
                    "ACS_GUARDIAN_KEYS": str(lab.state / "keys" / "guardian-keys.json")})
    process, port = launch_guardian(env=env, timeout=20.0)
    try:
        assert port != 8787
        yield f"http://127.0.0.1:{port}/"
    finally:
        process.terminate()
        process.wait(timeout=10)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


Answer = Callable[[dict[str, Any]], tuple[int, Any]]


@contextlib.contextmanager
def responder(answer: Answer) -> Iterator[str]:
    """A fake Guardian on a free port: answer(ClientHello) gives the HTTP status and the JSON body sent back."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802  (the name http.server calls)
            hello = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            status, body = answer(hello)
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


def refusal(hello: dict[str, Any], key: fixtures.DecisionKey | None, **change: Any) -> dict[str, Any]:
    """The Guardian's -32000 refusal of hello, signed with key the way the Guardian signs an error: the request hash
    goes into error.data first. change edits the envelope before it is signed."""
    from acs.core import REQUEST_DIGEST_FIELD, request_sha256, sign_with_signing_key
    envelope: dict[str, Any] = {"jsonrpc": "2.0", "id": hello["id"], "error": {
        "code": -32000, "message": "SESSION_REFUSED: unsupported_signature_algorithm",
        "data": {"reason": "unsupported_signature_algorithm"}}}
    envelope.update(copy.deepcopy(change))
    if key is None:
        return envelope
    envelope["error"]["data"][REQUEST_DIGEST_FIELD] = request_sha256(hello)
    return sign_with_signing_key(envelope, key.signing_key)


def one_line(capsys) -> str:
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1, out
    return out[0]


def results(lab: LabState, kind: str) -> list[Path]:
    return sorted((lab.state / "verify").glob(f"{kind}-*.json"))


def test_downgrade_refused_by_mldsa_guardian(lab, capsys, tmp_path):
    with guardian(lab, tmp_path, mldsa=True) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 0
    line = one_line(capsys)
    assert line.startswith("DONE: ") and "unsupported_signature_algorithm" in line
    [path] = results(lab, "downgrade")
    record = json.loads(path.read_text(encoding="utf-8"))
    assert (record["kind"], record["algorithm"], record["result"], record["entry"]) == (
        "downgrade", "ML-DSA-65", "refused", None)
    # The pin the refusal verified under, so check 7 can tell a refusal from before a re-init (Task 13 review C1).
    assert record["fingerprint"] == lab.decision_key.fingerprint
    assert path.name.startswith("downgrade-ML-DSA-65-")


def test_downgrade_on_hmac_guardian_is_not_yet(lab, capsys, tmp_path):
    with guardian(lab, tmp_path, mldsa=False) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 1
    assert one_line(capsys) == "NOT YET: run ./lab.sh sign mldsa first"
    assert results(lab, "downgrade") == []
    # Nothing listening is a broken lab, not a refusal, and paints nothing.
    assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID, timeout=2) == 2
    assert one_line(capsys).startswith("NOT YET: ")
    assert results(lab, "downgrade") == []


def test_downgrade_needs_a_signed_bound_refusal(lab, capsys, tmp_path):
    """Review I2: DONE needs HTTP 200, a JSON-RPC error with no result, the ClientHello's id, -32000 with
    unsupported_signature_algorithm, and a signature that verifies under the pinned key. Each fake below breaks one."""
    key = pinned_key(lab)
    attacker = fixtures.decision_key(tmp_path / "attacker")
    fakes: dict[str, Answer] = {
        "unsigned": lambda h: (200, refusal(h, None)),
        "http 500": lambda h: (500, refusal(h, key)),
        "wrong id": lambda h: (200, refusal(h, key, id="not-the-client-hello")),
        "result too": lambda h: (200, refusal(h, key, result={"negotiated_version": "0.1.0"})),
        "other key": lambda h: (200, refusal(h, attacker)),
        "other reason": lambda h: (200, refusal(h, key, error={"code": -32000, "message": "SESSION_REFUSED: x",
                                                                "data": {"reason": "x"}})),
    }
    for name, answer in fakes.items():
        with responder(answer) as url:
            code = downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID)
        line = one_line(capsys)
        assert code == 2 and line.startswith("NOT YET: "), (name, code, line)
        assert results(lab, "downgrade") == [], name
    # The same fake, signed and bound as the Guardian signs it, is accepted, so each refusal above is its one flaw.
    with responder(lambda h: (200, refusal(h, key))) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 0
    assert one_line(capsys).startswith("DONE: ")
    assert len(results(lab, "downgrade")) == 1


def test_downgrade_without_a_pin_exits_2(lab, capsys):
    pinned_key(lab)
    lab.write_env()
    posted: list[dict[str, Any]] = []

    def answer(hello: dict[str, Any]) -> tuple[int, Any]:
        posted.append(hello)
        return 200, refusal(hello, None)

    with responder(answer) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 2
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "LAB_GUARDIAN_FINGERPRINT" in line
    # Without a pin there is no verdict to check, so nothing is sent.
    assert posted == [] and results(lab, "downgrade") == []


def test_downgrade_names_a_guardian_that_falls_back(lab, capsys):
    """Review M4: an ML-DSA-65 Guardian that opens an HMAC only session is falling back, not still on HMAC."""
    pinned_key(lab)

    def fallback(hello: dict[str, Any]) -> tuple[int, Any]:
        return 200, {"jsonrpc": "2.0", "id": hello["id"], "result": {
            "negotiated_version": "0.1.0", "x_acs_lab_response_algorithm": "ML-DSA-65"}}

    with responder(fallback) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 1
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "fell back" in line and "sign mldsa" not in line
    assert results(lab, "downgrade") == []


def _beats():
    """LAB-13's beats.py loaded by path, as the viewer runs it, with its directory on sys.path for model."""
    if str(VIEWER_DIR) not in sys.path:
        sys.path.append(str(VIEWER_DIR))
    spec = importlib.util.spec_from_file_location("lab_viewer_beats", VIEWER_DIR / "beats.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab_viewer_beats"] = module
    spec.loader.exec_module(module)
    return module


def test_result_files_read_by_the_viewer(lab, capsys, tmp_path):
    key = pinned_key(lab)
    write_session(lab, session_id=SESSION_A)
    write_session(lab, key=key, session_id=SESSION_B)
    assert forge.main(["--session", SESSION_A], root=lab.root) == 0
    assert forge.main(["--session", SESSION_B], root=lab.root) == 0
    assert verify.main(["--keys-only"], root=lab.root) == 0
    with guardian(lab, tmp_path, mldsa=True) as url:
        assert downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID) == 0
    capsys.readouterr()

    beats = _beats()
    painted = {}
    for path in sorted((lab.state / "verify").iterdir()):
        record = beats.read_result(path)
        assert record is not None, path.name
        row = beats.result_row(record, path.stat().st_mtime_ns)
        painted[path.name.split("-")[0] + "/" + record["algorithm"]] = beats.classify(row, beats.BeatHistory())
    assert painted == {
        "forge/HMAC-SHA256": "forge_passes_hmac",
        "forge/ML-DSA-65": "forge_fails_mldsa",
        "keys_only/ML-DSA-65": "keys_only_verify",
        "downgrade/ML-DSA-65": "downgrade_refused",
    }
    # The viewer's own directory reader takes every file too.
    assert len(beats.result_files(lab.state / "verify")) == 4


def test_result_refuses_a_malformed_fingerprint(lab):
    results = kit("results")
    with pytest.raises(ValueError, match="fingerprint"):
        results.write(lab.state, kind="downgrade", algorithm="ML-DSA-65", session_id=SESSION_A, result="refused",
                      entry=None, detail="x", fingerprint="sha256:short")
