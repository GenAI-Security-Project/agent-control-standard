"""lab verify: acs-verify over the newest ML-DSA-65 session, always pinned to .env's fingerprint (issue #589).

    uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/modules/kit/tests -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")

import fixtures  # noqa: E402
from fixtures import SESSION_A, SESSION_B, LabState  # noqa: E402
from kit_sessions import MLDSA, kit, write_session  # noqa: E402

verify = kit("verify")
FINGERPRINT = "sha256:" + "ab" * 32


@pytest.fixture
def lab(tmp_path) -> LabState:
    lab = LabState(tmp_path / "bundle")
    lab.write_hmac_secret()
    return lab


def one_line(capsys) -> str:
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1, out
    return out[0]


def recording_runner(calls: list[list[str]]):
    def run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, json.dumps({"result": "pass"}), "")
    return run


def age(path, seconds: int) -> None:
    """Sets path's mtime seconds into the past, so which session is newest never rests on clock resolution."""
    stamp = path.stat().st_mtime_ns - seconds * 1_000_000_000
    os.utime(path, ns=(stamp, stamp))


def test_verify_always_pins_the_fingerprint(lab, capsys, monkeypatch):
    key = fixtures.decision_key(lab.state / "keys")
    write_session(lab, session_id=SESSION_B)
    write_session(lab, key=key, session_id=SESSION_A)
    age(lab.transcript_path(SESSION_B), 60)
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=FINGERPRINT)
    # A pin anywhere but .env is the forger's to choose, so it never counts.
    monkeypatch.setenv("LAB_GUARDIAN_FINGERPRINT", key.fingerprint)
    (lab.state / "fingerprint").write_text(key.fingerprint, encoding="utf-8")
    calls: list[list[str]] = []
    for argv in ([], ["--keys-only"], ["--session", SESSION_A], ["--keys-only", "--session", SESSION_A],
                 ["--session", SESSION_B]):
        assert verify.main(argv, root=lab.root, runner=recording_runner(calls)) == 0
        assert one_line(capsys).startswith("DONE: ")
    assert len(calls) == 5
    for argv in calls:
        assert argv[argv.index("--keys") + 1] == str(lab.state / "keys" / "guardian-keys.json")
        assert argv[argv.index("--expect-fingerprint") + 1] == FINGERPRINT
        assert argv.count("--expect-fingerprint") == 1 and "--hmac-secret" not in argv
        assert argv[-1] == "--keys-only" or "--keys-only" not in argv
    # The newest session by default, and a named HMAC session is judged under the pinned key like any other.
    assert [str(lab.transcript_path(SESSION_A)) in argv for argv in calls] == [True, True, True, True, False]
    assert str(lab.transcript_path(SESSION_B)) in calls[-1]


def test_verify_never_skips_a_relabeled_newest_session(lab, capsys):
    """Review I1: the forger strips the ML-DSA-65 field from the newest session's ServerHello, after writing an HMAC
    allow into it. lab verify must judge that session, never fall back to the older genuine one."""
    key = fixtures.decision_key(lab.state / "keys")
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    write_session(lab, key=key, session_id=SESSION_A)
    newer = write_session(lab, key=key, session_id=SESSION_B)
    forge = kit("forge")
    transcript = forge.sessions.read(forge.sessions.evidence.Evidence(lab.root), SESSION_B)
    lines = list(transcript.lines)
    lines[newer.deny_line - 1] = json.dumps(forge.forged_record(transcript, newer.deny_line, fixtures.HMAC_SECRET),
                                            separators=(",", ":")).encode()
    hello = json.loads(lines[newer.lines["hello"] - 1])
    del hello["envelope"]["result"]["x_acs_lab_response_algorithm"]
    lines[newer.lines["hello"] - 1] = json.dumps(hello, separators=(",", ":")).encode()
    newer.path.write_bytes(b"".join(line + b"\n" for line in lines))
    age(lab.transcript_path(SESSION_A), 60)

    for argv in ([], ["--keys-only"], ["--session", SESSION_B]):
        assert verify.main(argv, root=lab.root) == 1, argv
        line = one_line(capsys)
        assert line.startswith("NOT YET: ") and SESSION_B in line and SESSION_A not in line, line
        assert "doesn't verify" in line
    result = json.loads((lab.state / "verify" / f"keys_only-{MLDSA}-{SESSION_B}.json").read_text(encoding="utf-8"))
    assert result["result"] == "broken"
    assert not (lab.state / "verify" / f"keys_only-{MLDSA}-{SESSION_A}.json").exists()
    # The older genuine session still verifies when named, so nothing but the forgery fails.
    assert verify.main(["--session", SESSION_A], root=lab.root) == 0
    assert one_line(capsys).startswith("DONE: ")


def test_verify_without_fingerprint_exits_2(lab, capsys):
    key = fixtures.decision_key(lab.state / "keys")
    write_session(lab, key=key)
    calls: list[list[str]] = []
    for env in ({}, {"LAB_CLIENT_TOKEN": "x" * 64}, {"LAB_GUARDIAN_FINGERPRINT": "sha256:" + "ab" * 31}):
        lab.write_env(**env)
        for argv in ([], ["--keys-only"]):
            assert verify.main(argv, root=lab.root, runner=recording_runner(calls)) == 2
            line = one_line(capsys)
            assert line.startswith("NOT YET: ") and "LAB_GUARDIAN_FINGERPRINT" in line
    assert calls == []
    assert not any((lab.state / "verify").glob("*"))


def test_verify_keys_only_writes_result(lab, capsys):
    key = fixtures.decision_key(lab.state / "keys")
    write_session(lab, key=key)
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    assert verify.main(["--keys-only"], root=lab.root) == 0
    assert one_line(capsys).startswith("DONE: ")
    result = json.loads((lab.state / "verify" / f"keys_only-{MLDSA}-{SESSION_A}.json").read_text(encoding="utf-8"))
    assert (result["kind"], result["algorithm"], result["result"], result["entry"]) == (
        "keys_only", MLDSA, "verified", None)
    # A full verify writes no keys_only result of its own.
    (lab.state / "verify" / f"keys_only-{MLDSA}-{SESSION_A}.json").unlink()
    assert verify.main([], root=lab.root) == 0
    assert one_line(capsys).startswith("DONE: ")
    assert not any((lab.state / "verify").glob("*"))


def test_swapped_key_document_fails_on_the_pin(lab, capsys, tmp_path):
    genuine = fixtures.decision_key(lab.state / "keys")
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=genuine.fingerprint)
    # The forger holds state/, so it writes its own key under the Guardian's key id, signs a whole session with it,
    # and puts its key document where the Guardian's was.
    attacker = fixtures.decision_key(tmp_path / "attacker")
    assert attacker.fingerprint != genuine.fingerprint
    write_session(lab, key=attacker)
    document = lab.state / "keys" / "guardian-keys.json"
    shutil.copyfile(attacker.document_path, document)
    os.chmod(document, 0o644)
    assert json.loads(document.read_text(encoding="utf-8"))["keys"][0]["key_id"] == fixtures.KEY_ID
    # Without the pin the swap would pass, which is why lab verify never runs without it.
    unpinned = subprocess.run([sys.executable, "-m", "acs.testing.verify", "--json", "--keys", str(document),
                               str(lab.transcript_path())], capture_output=True, text=True, check=False)
    assert unpinned.returncode == 0, unpinned.stdout
    assert verify.main(["--keys-only"], root=lab.root) == 1
    line = one_line(capsys)
    assert line.startswith("NOT YET: ") and "fingerprint" in line
    result = json.loads((lab.state / "verify" / f"keys_only-{MLDSA}-{SESSION_A}.json").read_text(encoding="utf-8"))
    # acs-verify refuses the document before reading any entry, so the failure names no line.
    assert result["result"] == "broken" and result["entry"] is None
    assert "fingerprint_mismatch" in result["detail"]
