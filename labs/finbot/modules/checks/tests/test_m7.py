"""Module 7's check, Forge a decision (issue #589, LAB-16 Task 13).

Version 1.0.0. Owner: Rock Lambros.

Each session is written by the code the lab writes it with (fixtures.py, the kit's kit_sessions.py), each forged copy
by the real lab forge, and every forgery verdict comes from the real acs-verify. The downgrade result comes from the
real lab downgrade against the real example Guardian in a subprocess on a port it picks itself, never 8787. The check
itself opens no socket. So the tests need the pqc extra:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m7.py -v
"""
from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")

KIT_TESTS = Path(__file__).resolve().parents[2] / "kit" / "tests"
if str(KIT_TESTS) not in sys.path:
    sys.path.insert(0, str(KIT_TESTS))

import fixtures  # noqa: E402
from fixtures import HMAC_KEY_ID, SESSION_A, SESSION_B, LabState, answer  # noqa: E402
from kit_sessions import HMAC, MLDSA, kit, write_session  # noqa: E402

import m7  # noqa: E402
from evidence import Evidence  # noqa: E402

from acs.testing.harness import launch_guardian  # noqa: E402

downgrade, forge, results = kit("downgrade"), kit("forge"), kit("results")
HMAC_RUN, MLDSA_RUN = "20261125T100000Z-s2", "20261125T101500Z-s2"


@pytest.fixture
def lab(tmp_path) -> LabState:
    """A bundle as lab init leaves it, with one completed s2 run under each signing mode and a deny in each."""
    lab = LabState(tmp_path / "bundle")
    lab.write_hmac_secret()
    lab.key = fixtures.decision_key(lab.state / "keys")  # type: ignore[attr-defined]
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=lab.key.fingerprint)  # type: ignore[attr-defined]
    lab.hmac = write_session(lab, session_id=SESSION_A)  # type: ignore[attr-defined]
    lab.mldsa = write_session(lab, key=lab.key, session_id=SESSION_B)  # type: ignore[attr-defined]
    lab.run_record(HMAC_RUN, scenario="s2", signing=HMAC, sessions=[SESSION_A], started="2026-11-25T10:00:00Z")
    lab.run_record(MLDSA_RUN, scenario="s2", signing=MLDSA, sessions=[SESSION_B], started="2026-11-25T10:15:00Z")
    return lab


def forge_both(lab: LabState, capsys) -> None:
    assert forge.main(["--session", SESSION_A], root=lab.root) == 0
    assert forge.main(["--session", SESSION_B], root=lab.root) == 0
    capsys.readouterr()


@contextlib.contextmanager
def guardian(lab: LabState, tmp_path: Path, *, mldsa: bool) -> Iterator[str]:
    """The example Guardian on the lab's HMAC secret, signing answers with the lab's pinned key when mldsa is set, as
    compose.yaml runs it."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
    env.update({"ACS_HMAC_SECRET_FILE": str(lab.state / "secrets" / "hmac.key"), "ACS_HMAC_KEY_ID": HMAC_KEY_ID,
                "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "guardian-state")})
    if mldsa:
        env.update({"ACS_RESPONSE_SIGNING": MLDSA,
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


def probe(lab: LabState, tmp_path: Path, capsys, *, mldsa: bool) -> int:
    """lab downgrade against the real example Guardian, as the attendee runs it before check 7."""
    with guardian(lab, tmp_path, mldsa=mldsa) as url:
        code = downgrade.main([], root=lab.root, guardian_url=url, key_id=HMAC_KEY_ID)
    capsys.readouterr()
    return code


def check(lab: LabState, capsys) -> tuple[int, str]:
    code = m7.check(Evidence(lab.root))
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1, out
    return code, out[0]


def test_all_four_hold(lab, capsys, tmp_path):
    forge_both(lab, capsys)
    assert probe(lab, tmp_path, capsys, mldsa=True) == 0
    code, line = check(lab, capsys)
    assert code == 0, line
    assert line.startswith("DONE: module 7.")
    assert f"line {lab.hmac.deny_line}" in line and SESSION_A in line and SESSION_B in line
    assert "signed refusal" in line and "downgrade-ML-DSA-65-" in line


def test_result_file_without_forged_copy_is_not_yet(lab, capsys):
    # Result files say all four held, but the check recomputes and finds no forged copy behind them.
    for kind, algorithm, session_id, result, entry in (("forge", HMAC, SESSION_A, "verified", lab.hmac.deny_line),
                                                       ("forge", MLDSA, SESSION_B, "broken", lab.mldsa.deny_line),
                                                       ("keys_only", MLDSA, SESSION_B, "verified", None),
                                                       ("downgrade", MLDSA, SESSION_B, "refused", None)):
        results.write(lab.state, kind=kind, algorithm=algorithm, session_id=session_id, result=result, entry=entry,
                      detail="written by hand")
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and f"./lab.sh forge --session {SESSION_A}" in line


def test_unchanged_hmac_copy_is_not_yet(lab, capsys):
    # The genuine transcript copied whole verifies under HMAC too, but it forges nothing.
    forge_both(lab, capsys)
    (lab.state / "forged" / f"{SESSION_A}.jsonl").write_bytes(lab.hmac.path.read_bytes())
    code, line = check(lab, capsys)
    assert code == 1
    assert "isn't lab forge's copy" in line and f"./lab.sh forge --session {SESSION_A}" in line


def test_forged_mldsa_copy_that_passes_is_not_yet(lab, capsys):
    forge_both(lab, capsys)
    # The deny line rewritten to allow and signed with the Guardian's own key: only the Guardian could write this,
    # so acs-verify passes it, and it shows nothing about a forger.
    path = lab.state / "forged" / f"{SESSION_B}.jsonl"
    lines = lab.mldsa.path.read_bytes().splitlines()
    req = json.loads(lines[lab.mldsa.deny_line - 2])["envelope"]
    record = json.loads(lines[lab.mldsa.deny_line - 1])
    result = {k: v for k, v in record["envelope"]["result"].items()
              if k not in ("reason_codes", "signature", "x_acs_lab_request_sha256")}
    result.pop("decision")
    record["envelope"] = lab.key.sign(answer(req, "allow", **result), req)
    lines[lab.mldsa.deny_line - 1] = json.dumps(record, separators=(",", ":")).encode()
    path.write_bytes(b"".join(line + b"\n" for line in lines))
    code, line = check(lab, capsys)
    assert code == 1
    assert "verifies under ML-DSA-65" in line and SESSION_B in line


def test_guardian_on_hmac_is_not_yet(lab, capsys, tmp_path):
    # A genuine refusal is on disk, but the Guardian signs with HMAC now, so it would open an HMAC only session.
    forge_both(lab, capsys)
    assert probe(lab, tmp_path, capsys, mldsa=True) == 0
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=lab.key.fingerprint, ACS_RESPONSE_SIGNING=HMAC)
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and "./lab.sh sign mldsa" in line


def test_no_refusal_is_not_yet(lab, capsys, tmp_path):
    # A Guardian on HMAC opens the session, so lab downgrade writes no refusal and the check names the step.
    forge_both(lab, capsys)
    assert probe(lab, tmp_path, capsys, mldsa=False) == 1
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and line.endswith("./lab.sh downgrade")


def test_refusal_under_an_old_pin_is_not_yet(lab, capsys, tmp_path):
    """Review probe P1: a genuine refusal under the first key, then a fresh lab init with a new key and a new
    ML-DSA-65 session forged again. The old refusal says nothing about the Guardian's current key."""
    forge_both(lab, capsys)
    assert probe(lab, tmp_path, capsys, mldsa=True) == 0
    # Read before the rotation: DecisionKey.fingerprint reads the key document, which the new key overwrites.
    old = lab.key.fingerprint
    for name in ("guardian.key", "guardian-keys.json"):
        (lab.state / "keys" / name).unlink()
    key = fixtures.decision_key(lab.state / "keys")
    assert key.fingerprint != old
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    session_c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    write_session(lab, key=key, session_id=session_c)
    lab.run_record("20261125T103000Z-s2", scenario="s2", signing=MLDSA, sessions=[session_c],
                   started="2026-11-25T10:30:00Z")
    assert forge.main(["--session", session_c], root=lab.root) == 0
    capsys.readouterr()
    code, line = check(lab, capsys)
    assert code == 1
    assert key.fingerprint in line and line.endswith("./lab.sh downgrade again")


def test_refusal_without_a_fingerprint_is_not_yet(lab, capsys):
    forge_both(lab, capsys)
    results.write(lab.state, kind="downgrade", algorithm=MLDSA, session_id=SESSION_A, result="refused", entry=None,
                  detail="written before lab downgrade recorded the key")
    code, line = check(lab, capsys)
    assert code == 1
    assert "fingerprint" in line and line.endswith("./lab.sh downgrade")


def test_downgrade_result_that_isnt_a_refusal_is_not_yet(lab, capsys):
    forge_both(lab, capsys)
    results.write(lab.state, kind="downgrade", algorithm=MLDSA, session_id=SESSION_A, result="verified", entry=None,
                  detail="not a refusal")
    code, line = check(lab, capsys)
    assert code == 1
    assert line.endswith("./lab.sh downgrade")


def test_check_opens_no_socket(lab, capsys, monkeypatch):
    """A check reads files only. acs-verify runs as a subprocess, which needs no socket in the check's process."""
    forge_both(lab, capsys)
    results.write(lab.state, kind="downgrade", algorithm=MLDSA, session_id=SESSION_A, result="refused", entry=None,
                  detail="the Guardian refused a ClientHello offering only HMAC", fingerprint=lab.key.fingerprint)

    def no_socket(*args, **kwargs):
        raise AssertionError("check 7 opened a socket")

    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)
    before = sorted(p.name for p in (lab.state / "verify").iterdir())
    code, line = check(lab, capsys)
    assert code == 0, line
    assert sorted(p.name for p in (lab.state / "verify").iterdir()) == before, "check 7 wrote a result"


def test_missing_fingerprint_exits_2(lab, capsys):
    forge_both(lab, capsys)
    lab.write_env()
    code, line = check(lab, capsys)
    assert code == 2
    assert "LAB_GUARDIAN_FINGERPRINT" in line and "./lab.sh init" in line


def test_incomplete_run_is_not_yet(lab, capsys):
    forge_both(lab, capsys)
    lab.run_record(MLDSA_RUN, scenario="s2", signing=MLDSA, sessions=[SESSION_B], started="2026-11-25T10:15:00Z",
                   result="timed_out")
    code, line = check(lab, capsys)
    assert code == 1
    assert "timed_out" in line and "./lab.sh run s2" in line
