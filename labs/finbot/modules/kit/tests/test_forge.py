"""lab forge: a denied tool call rewritten to allow in a copy of the transcript (issue #589, LAB-16 Task 12).

    uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/modules/kit/tests -v

Every verdict here comes from the real acs-verify, run once by the kit and once more by the test on the files the kit
left behind, so a test never trusts the kit's own account of what it wrote.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")

import fixtures  # noqa: E402
from fixtures import SESSION_A, SESSION_B, LabState  # noqa: E402
from kit_sessions import DENY_REASON, HMAC, MLDSA, kit, write_session  # noqa: E402

forge = kit("forge")


@pytest.fixture
def lab(tmp_path) -> LabState:
    lab = LabState(tmp_path / "bundle")
    lab.write_hmac_secret()
    return lab


def one_line(capsys) -> str:
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1, out
    return out[0]


def acs_verify(path: Path, *args: str) -> tuple[int, dict]:
    done = subprocess.run([sys.executable, "-m", "acs.testing.verify", "--json", str(path), *args],
                          capture_output=True, text=True, check=False)
    return done.returncode, json.loads(done.stdout)


def mldsa_lab(lab: LabState, session_id: str = SESSION_A):
    key = fixtures.decision_key(lab.state / "keys")
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    return key, write_session(lab, key=key, session_id=session_id)


def lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines()


def test_forge_hmac_verifies(lab, capsys):
    session = write_session(lab)
    assert forge.main([], root=lab.root) == 0
    assert one_line(capsys) == (f"DONE: the forged allow at line {session.deny_line} verifies under HMAC. Anyone "
                                "holding the shared key could have written it")
    copy = lab.state / "forged" / f"{SESSION_A}.jsonl"
    code, report = acs_verify(copy, "--hmac-secret", str(lab.state / "secrets" / "hmac.key"))
    assert code == 0, report
    assert json.loads(lines(copy)[session.deny_line - 1])["envelope"]["result"]["decision"] == "allow"
    result = json.loads((lab.state / "verify" / f"forge-{HMAC}-{SESSION_A}.json").read_text(encoding="utf-8"))
    assert {k: result[k] for k in ("kind", "algorithm", "result", "entry")} == {
        "kind": "forge", "algorithm": HMAC, "result": "verified", "entry": session.deny_line}
    assert isinstance(result["detail"], str) and result["detail"]


def test_forge_mldsa_fails_at_the_forged_line(lab, capsys):
    key, session = mldsa_lab(lab)
    assert forge.main([], root=lab.root) == 0
    assert one_line(capsys) == f"DONE: the forged allow fails at line {session.deny_line} under ML-DSA-65"
    pin = ("--keys", str(lab.state / "keys" / "guardian-keys.json"), "--expect-fingerprint", key.fingerprint)
    # The genuine session passes in full, so the failure is the forgery's and nothing else's.
    assert acs_verify(session.path, *pin)[0] == 0
    code, report = acs_verify(lab.state / "forged" / f"{SESSION_A}.jsonl", *pin)
    assert code == 1 and report["failure"]["line"] == session.deny_line, report
    result = json.loads((lab.state / "verify" / f"forge-{MLDSA}-{SESSION_A}.json").read_text(encoding="utf-8"))
    assert (result["kind"], result["algorithm"], result["result"], result["entry"]) == (
        "forge", MLDSA, "broken", session.deny_line)


def test_forge_keeps_chain_head_and_binding(lab, capsys):
    hmac_session = write_session(lab, session_id=SESSION_A)
    _, mldsa_session = mldsa_lab(lab, SESSION_B)
    for session in (hmac_session, mldsa_session):
        assert forge.main(["--session", session.session_id], root=lab.root) == 0, capsys.readouterr().out
        before = lines(session.path)
        after = lines(lab.state / "forged" / f"{session.session_id}.jsonl")
        n = session.deny_line - 1
        # Every other line is the gateway's, byte for byte.
        assert len(after) == len(before)
        assert [line for i, line in enumerate(after) if i != n] == [line for i, line in enumerate(before) if i != n]
        old, new = json.loads(before[n]), json.loads(after[n])
        assert old["dir"] == new["dir"] == "resp"
        old_result, new_result = old["envelope"]["result"], new["envelope"]["result"]
        assert old_result["decision"] == "deny" and old_result["reason_codes"] == [DENY_REASON]
        assert new_result["decision"] == "allow" and "reason_codes" not in new_result
        # The chain hashes requests only, so the head the Guardian signed still holds. The binding stays too.
        for name in ("chain_hash", "request_id", "x_acs_lab_request_sha256"):
            assert new_result.get(name) == old_result.get(name), name
        assert new["envelope"]["id"] == old["envelope"]["id"]
        # Signed the only way the forger can: HMAC under the session key, labelled as the request's own key.
        request = json.loads(before[n - 1])["envelope"]
        assert new_result["signature"]["algorithm"] == HMAC
        assert new_result["signature"]["key_id"] == request["params"]["signature"]["key_id"]
        capsys.readouterr()
    assert "x_acs_lab_request_sha256" in json.loads(lines(mldsa_session.path)[mldsa_session.deny_line - 1])[
        "envelope"]["result"]


def _snapshot(directory: Path) -> dict[str, tuple[bytes, int]]:
    return {str(p.relative_to(directory)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in directory.rglob("*") if p.is_file()}


def test_forge_never_writes_transcripts(lab, capsys):
    write_session(lab, session_id=SESSION_A)
    mldsa_lab(lab, SESSION_B)
    before = _snapshot(lab.state)
    assert forge.main([], root=lab.root) == 0
    assert forge.main(["--session", SESSION_A], root=lab.root) == 0
    after = _snapshot(lab.state)
    changed = {name for name in after if before.get(name) != after[name]}
    assert changed and all(name.startswith(("forged/", "verify/")) for name in changed), changed
    assert set(before) <= set(after)
    # The copy holds signed envelopes, so it is the owner's alone, as the gateway's transcripts are.
    for copy in (lab.state / "forged").iterdir():
        assert os.stat(copy).st_mode & 0o077 == 0
    capsys.readouterr()


def test_forge_without_a_deny_is_not_yet(lab, capsys):
    write_session(lab, deny=False)
    assert forge.main([], root=lab.root) == 1
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "module 3" in line and "./lab.sh run s2" in line
    assert forge.main(["--session", SESSION_A], root=lab.root) == 1
    assert one_line(capsys).startswith("NOT YET: ")
    # Nothing to forge means nothing written: no copy and no result for the viewer to paint.
    assert not (lab.state / "forged").exists()
    assert not any((lab.state / "verify").glob("*"))


def test_forge_hmac_reports_on_the_forged_copy(lab, capsys, monkeypatch):
    """Review M1: the HMAC DONE line is about the copy. If acs-verify were ever pointed at the genuine transcript,
    which passes under HMAC too, forge must not claim the forgery verified."""
    write_session(lab)
    real_verify = forge.sessions.evidence.Evidence.verify

    def genuine_only(self, session_id, **kwargs):
        kwargs.pop("directory", None)
        return real_verify(self, session_id, **kwargs)

    monkeypatch.setattr(forge.sessions.evidence.Evidence, "verify", genuine_only)
    assert forge.main([], root=lab.root) == 2
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "forged copy" in line
    assert not any((lab.state / "verify").glob("*"))


def test_forge_names_a_swapped_key_document(lab, capsys, tmp_path):
    """Review M2: a key document that fails the pin is reported as that, never as a failure at line None."""
    key, _ = mldsa_lab(lab)
    attacker = fixtures.decision_key(tmp_path / "attacker")
    # Compared first: a DecisionKey reads its fingerprint from the document, which the swap overwrites.
    assert key.fingerprint != attacker.fingerprint
    document = lab.state / "keys" / "guardian-keys.json"
    document.write_bytes(attacker.document_path.read_bytes())
    assert forge.main([], root=lab.root) == 1
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "None" not in line
    assert "fingerprint" in line and "./lab.sh verify" in line
    assert not any((lab.state / "verify").glob("*"))
