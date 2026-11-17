"""The acs-verify command line: exit codes, text and JSON output (issue #584).

These run on today's HMAC path, so they need no pqc extra and run in every adapter job. The ML-DSA-65 cases are in
test_acs_verify.py.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from acs_verify_helpers import record_session, start_guardian, stop_guardian
from acs.testing.verify import EXIT_FAIL, EXIT_PASS, EXIT_USAGE, main


@pytest.fixture
def hmac_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=False)
    yield run
    stop_guardian(run)


@pytest.fixture
def secret_file(tmp_path, hmac_run):
    path = tmp_path / "hmac.key"
    path.write_bytes(hmac_run.hmac_secret + b"\n")
    os.chmod(path, 0o600)
    return path


def write(tmp_path, lines, name="session.jsonl"):
    path = tmp_path / name
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def test_a_clean_transcript_exits_0(tmp_path, hmac_run, secret_file, capsys):
    path = write(tmp_path, record_session(hmac_run))
    assert main([str(path), "--hmac-secret", str(secret_file)]) == EXIT_PASS
    out = capsys.readouterr().out
    assert out.startswith("acs-verify: PASS\n")
    assert "The whole transcript verified." in out
    assert "8.6" in out


def test_a_tampered_transcript_exits_1_and_names_the_line(tmp_path, hmac_run, secret_file, capsys):
    lines = record_session(hmac_run)
    records = [json.loads(line) for line in lines]
    number = next(i for i, r in enumerate(records, start=1)
                  if r["dir"] == "resp" and (r["envelope"].get("result") or {}).get("decision") == "deny")
    records[number - 1]["envelope"]["result"]["decision"] = "allow"
    path = write(tmp_path, [json.dumps(r, separators=(",", ":")) for r in records])
    assert main([str(path), "--hmac-secret", str(secret_file)]) == EXIT_FAIL
    out = capsys.readouterr().out
    assert f"acs-verify: FAIL at line {number} (signature_invalid)" in out


def test_json_output_is_one_object(tmp_path, hmac_run, secret_file, capsys):
    path = write(tmp_path, record_session(hmac_run, end=False))
    assert main([str(path), "--hmac-secret", str(secret_file), "--json"]) == EXIT_PASS
    report = json.loads(capsys.readouterr().out)
    assert report["result"] == "pass"
    assert report["complete"] is False
    assert report["response_algorithm"] == "HMAC-SHA256"
    assert report["session_id"] == hmac_run.session_id


def test_a_bad_line_is_a_verification_failure_at_that_line(tmp_path, hmac_run, secret_file, capsys):
    lines = record_session(hmac_run)
    path = tmp_path / "session.jsonl"
    path.write_bytes(b"".join(line.encode() + b"\n" for line in lines[:2]) + b"\xff\xfe\n")
    assert main([str(path), "--hmac-secret", str(secret_file)]) == EXIT_FAIL
    assert "FAIL at line 3 (line_invalid)" in capsys.readouterr().out


def test_an_empty_transcript_fails(tmp_path, secret_file, capsys):
    path = write(tmp_path, [])
    assert main([str(path), "--hmac-secret", str(secret_file)]) == EXIT_FAIL
    assert "(empty)" in capsys.readouterr().out


@pytest.mark.parametrize("argv_tail", [
    [],                                                     # neither --keys nor --hmac-secret
    ["--keys", "{missing}"],                                # unreadable key document
    ["--hmac-secret", "{missing}"],                         # unreadable secret
    ["--hmac-secret", "{secret}", "--expect-fingerprint", "sha256:00"],
    ["--hmac-secret", "{secret}", "--key-id", "lab-guardian-1"],
    ["--hmac-secret", "{secret}", "--no-such-flag"],
])
def test_usage_errors_exit_2(tmp_path, hmac_run, secret_file, argv_tail, capsys):
    path = write(tmp_path, record_session(hmac_run))
    missing = str(tmp_path / "missing")
    argv = [str(path)] + [a.format(missing=missing, secret=str(secret_file)) for a in argv_tail]
    assert main(argv) == EXIT_USAGE


def test_a_missing_transcript_exits_2(tmp_path, secret_file, capsys):
    assert main([str(tmp_path / "nope.jsonl"), "--hmac-secret", str(secret_file)]) == EXIT_USAGE
    assert "can't be read" in capsys.readouterr().err


def test_a_short_or_shared_secret_file_exits_2(tmp_path, hmac_run, capsys):
    path = write(tmp_path, record_session(hmac_run))
    short = tmp_path / "short.key"
    short.write_bytes(b"too short")
    os.chmod(short, 0o600)
    assert main([str(path), "--hmac-secret", str(short)]) == EXIT_USAGE
    readable = tmp_path / "readable.key"
    readable.write_bytes(hmac_run.hmac_secret)
    os.chmod(readable, 0o644)
    assert main([str(path), "--hmac-secret", str(readable)]) == EXIT_USAGE


def test_the_module_runs_as_a_command():
    done = subprocess.run([sys.executable, "-m", "acs.testing.verify", "--help"], capture_output=True, text=True,
                          timeout=30)
    assert done.returncode == 0
    assert "usage: acs-verify" in done.stdout
