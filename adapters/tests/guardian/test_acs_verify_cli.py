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


def test_a_short_shared_or_linked_secret_file_exits_2(tmp_path, hmac_run, capsys):
    path = write(tmp_path, record_session(hmac_run))
    short = tmp_path / "short.key"
    short.write_bytes(b"too short")
    os.chmod(short, 0o600)
    assert main([str(path), "--hmac-secret", str(short)]) == EXIT_USAGE
    readable = tmp_path / "readable.key"
    readable.write_bytes(hmac_run.hmac_secret)
    os.chmod(readable, 0o644)
    assert main([str(path), "--hmac-secret", str(readable)]) == EXIT_USAGE
    os.chmod(readable, 0o600)
    link = tmp_path / "link.key"
    link.symlink_to(readable)
    assert main([str(path), "--hmac-secret", str(link)]) == EXIT_USAGE
    assert main([str(path), "--hmac-secret", str(readable)]) == EXIT_PASS


def test_the_module_runs_as_a_command():
    done = subprocess.run([sys.executable, "-m", "acs.testing.verify", "--help"], capture_output=True, text=True,
                          timeout=30)
    assert done.returncode == 0
    assert "usage: acs-verify" in done.stdout


# Fix round 2.


def test_a_transcript_over_the_byte_cap_exits_2(tmp_path, hmac_run, secret_file, capsys):
    path = write(tmp_path, record_session(hmac_run))
    assert main([str(path), "--hmac-secret", str(secret_file), "--max-bytes", "100"]) == EXIT_USAGE
    assert "100 bytes" in capsys.readouterr().err
    assert main([str(path), "--hmac-secret", str(secret_file), "--max-bytes", "0"]) == EXIT_USAGE


@pytest.mark.parametrize("prepare", ["group_writable", "symlink"])
def test_the_key_document_goes_through_the_trusted_file_reader(tmp_path, hmac_run, secret_file, prepare, capsys):
    path = write(tmp_path, record_session(hmac_run))
    document = tmp_path / "keys.json"
    document.write_text("{}", encoding="utf-8")
    os.chmod(document, 0o644)
    if prepare == "group_writable":
        os.chmod(document, 0o664)
        target = document
    else:
        target = tmp_path / "link.json"
        target.symlink_to(document)
    assert main([str(path), "--keys", str(target)]) == EXIT_USAGE
    assert "--keys" in capsys.readouterr().err


def test_json_reports_a_missing_pqc_extra(tmp_path, hmac_run, secret_file, monkeypatch, capsys):
    from acs.testing import verify

    def no_extra(*args, **kwargs):
        raise ImportError("ML-DSA-65 signing needs the pqc extra")

    monkeypatch.setattr(verify, "verify_transcript", no_extra)
    path = write(tmp_path, record_session(hmac_run))
    assert main([str(path), "--hmac-secret", str(secret_file), "--json"]) == EXIT_USAGE
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "error" and "pqc" in out["error"]


def test_a_request_jcs_cannot_encode_still_prints_a_json_report(tmp_path, hmac_run, secret_file, capsys):
    lines = record_session(hmac_run)
    number = next(i for i, line in enumerate(lines, start=1) if '"steps/toolCallRequest"' in line
                  and '"dir":"req"' in line)
    lines[number - 1] = lines[number - 1].replace('"payload":{', '"payload":{"far":1e400,', 1)
    path = write(tmp_path, lines)
    assert main([str(path), "--hmac-secret", str(secret_file), "--json"]) == EXIT_FAIL
    report = json.loads(capsys.readouterr().out)
    assert report["failure"]["line"] == number and report["failure"]["code"] == "not_canonical"


# A signed ServerHello must also be one the client would accept: negotiated_version present and
# acs.core.server_hello_problem clean against the ClientHello it answers (LAB-03 round 4). Re-signed here with the
# HMAC session key, so only the content check can catch it.


@pytest.mark.parametrize("change,expected", [
    (lambda hello: hello.pop("negotiated_version"), "negotiated_version"),
    (lambda hello: hello.update({"negotiated_version": "9.0.0"}), "9.0.0"),
    (lambda hello: hello.update({"selected_transport": "carrier-pigeon"}), "selected_transport"),
])
def test_a_signed_server_hello_the_client_would_refuse_fails(hmac_run, change, expected):
    from acs.core import derive_session_key, sign_with_key
    from acs.testing.harness import TEST_KEY_ID
    from acs.testing.verify import verify_transcript
    lines = record_session(hmac_run)
    records = [json.loads(line) for line in lines]
    number = next(i for i, r in enumerate(records, start=1)
                  if r["dir"] == "resp" and "negotiated_version" in ((r["envelope"] or {}).get("result") or {}))
    hello = records[number - 1]["envelope"]
    del hello["result"]["signature"]
    change(hello["result"])
    sign_with_key(hello, derive_session_key(hmac_run.hmac_secret, hmac_run.session_id), key_id=TEST_KEY_ID)
    lines[number - 1] = json.dumps(records[number - 1], separators=(",", ":"))
    report = verify_transcript(lines, key_document=None, hmac_secret=hmac_run.hmac_secret)
    assert (report.failure.line, report.failure.code) == (number, "server_hello_invalid"), report.to_text()
    assert expected in report.failure.reason
