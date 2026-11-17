"""acs-verify against sessions the real example Guardian signed (issue #584).

Every transcript here comes from the example Guardian over HTTP, in ML-DSA-65 response mode or today's HMAC mode,
recorded through acs.client's on_wire the way the lab gateway records it. Tampered copies are made from those
lines. The key document, the request hash, and the response algorithm offer are lab conventions (issues #460, #13,
#316).
"""
from __future__ import annotations

import json

import pytest

from decision_signing_helpers import require_pqc

require_pqc()

from acs_verify_helpers import record_session, start_guardian, stop_guardian  # noqa: E402
from acs.core import iso8601_now  # noqa: E402
from acs.testing.verify import verify_transcript  # noqa: E402


@pytest.fixture
def mldsa_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=True)
    yield run
    stop_guardian(run)


@pytest.fixture
def hmac_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=False)
    yield run
    stop_guardian(run)


def records(lines):
    return [json.loads(line) for line in lines]


def line_of(lines, predicate) -> int:
    """The 1-based line number of the first record the predicate accepts."""
    for number, record in enumerate(records(lines), start=1):
        if predicate(record):
            return number
    raise AssertionError("no such line")


def test_clean_mldsa_session_passes(mldsa_run):
    lines = record_session(mldsa_run)
    report = verify_transcript(lines, key_document=mldsa_run.key_document(), hmac_secret=None)
    assert report.ok, report.to_text()
    assert report.complete
    assert report.chain_checked
    assert report.response_algorithm == "ML-DSA-65"
    assert report.lines == len(lines)
    assert report.session_id == mldsa_run.session_id


def test_clean_hmac_session_passes_with_the_secret(hmac_run):
    lines = record_session(hmac_run)
    report = verify_transcript(lines, key_document=None, hmac_secret=hmac_run.hmac_secret)
    assert report.ok, report.to_text()
    assert report.complete
    assert report.response_algorithm == "HMAC-SHA256"


def test_the_recomputed_chain_matches_the_guardians_chain_hash(mldsa_run):
    lines = record_session(mldsa_run)
    report = verify_transcript(lines, key_document=mldsa_run.key_document(), hmac_secret=None)
    guardian_heads = [r["envelope"]["result"]["chain_hash"] for r in records(lines)
                      if r["dir"] == "resp" and "chain_hash" in (r["envelope"].get("result") or {})]
    assert len(guardian_heads) == 4  # sessionStart, allow, deny, sessionEnd
    assert report.chain_heads == guardian_heads


# Tampering. Each copy is made from a session the Guardian signed, and each must fail at the entry that was changed.


def rewrite(lines, number, change):
    """A copy of the transcript with line `number` (1-based) parsed, changed in place, and written back."""
    out = list(lines)
    record = json.loads(out[number - 1])
    change(record)
    out[number - 1] = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    return out


def tool_request_line(lines, command):
    return line_of(lines, lambda r: r["dir"] == "req" and r["envelope"].get("method") == "steps/toolCallRequest"
                   and r["envelope"]["params"]["payload"]["arguments"]["command"]["value"] == command)


def mldsa_verify(run, lines, **kwargs):
    return verify_transcript(lines, key_document=kwargs.pop("key_document", None) or run.key_document(),
                             hmac_secret=None, **kwargs)


def hmac_forgery(run, response, *, key_id):
    """The deny answer rewritten as an allow and signed with the session's shared HMAC key, as lab forge does."""
    from acs.core import derive_session_key, sign_with_key
    forged = json.loads(json.dumps(response))
    result = forged["result"]
    result.pop("signature", None)
    result.update({"decision": "allow"})
    result.pop("reasoning", None)
    result.pop("reason_codes", None)
    return sign_with_key(forged, derive_session_key(run.hmac_secret, run.session_id), key_id=key_id)


def test_an_edited_request_fails_at_that_request(mldsa_run):
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "ls -la")
    edited = rewrite(lines, number, lambda r: r["envelope"]["params"]["payload"]["arguments"]["command"]
                     .update({"value": "ls -l"}))
    report = mldsa_verify(mldsa_run, edited)
    assert not report.ok
    assert (report.failure.line, report.failure.code) == (number, "request_digest_mismatch")


def test_an_edited_request_fails_at_that_request_under_hmac(hmac_run):
    lines = record_session(hmac_run)
    number = tool_request_line(lines, "ls -la")
    edited = rewrite(lines, number, lambda r: r["envelope"]["params"]["payload"]["arguments"]["command"]
                     .update({"value": "ls -l"}))
    report = verify_transcript(edited, key_document=None, hmac_secret=hmac_run.hmac_secret)
    assert (report.failure.line, report.failure.code) == (number, "request_signature_invalid")


def test_a_reordered_entry_fails_at_the_moved_entry(mldsa_run):
    lines = record_session(mldsa_run)
    allow_req = tool_request_line(lines, "ls -la")
    deny_req = tool_request_line(lines, "rm -rf /")
    assert deny_req == allow_req + 2
    reordered = list(lines)
    reordered[allow_req - 1:allow_req + 3] = lines[deny_req - 1:deny_req + 1] + lines[allow_req - 1:allow_req + 1]
    report = mldsa_verify(mldsa_run, reordered)
    assert (report.failure.line, report.failure.code) == (allow_req, "chain_mismatch")


def test_a_deny_flipped_to_allow_with_its_signature_kept_fails_at_that_response(mldsa_run):
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "rm -rf /") + 1
    flipped = rewrite(lines, number, lambda r: r["envelope"]["result"].update({"decision": "allow"}))
    report = mldsa_verify(mldsa_run, flipped)
    assert (report.failure.line, report.failure.code) == (number, "signature_invalid")


@pytest.mark.parametrize("key_id,code", [("test-key-id", "key_unknown"), ("lab-guardian-1", "signature_invalid")])
def test_a_correctly_hmac_signed_allow_inside_an_mldsa_session_fails(mldsa_run, key_id, code):
    from acs.core import derive_session_key, verify_with_key
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "rm -rf /") + 1
    forged = hmac_forgery(mldsa_run, json.loads(lines[number - 1])["envelope"], key_id=key_id)
    # The forgery is a correct HMAC under the session key the agent side holds.
    assert verify_with_key(forged, derive_session_key(mldsa_run.hmac_secret, mldsa_run.session_id))
    tampered = rewrite(lines, number, lambda r: r.update({"envelope": forged}))
    report = mldsa_verify(mldsa_run, tampered)
    assert (report.failure.line, report.failure.code) == (number, code)
    # Giving the secret too checks requests, and still never accepts an HMAC response beside a key document.
    both = verify_transcript(tampered, key_document=mldsa_run.key_document(), hmac_secret=mldsa_run.hmac_secret)
    assert (both.failure.line, both.failure.code) == (number, code)


def test_an_hmac_forged_decision_verifies_under_hmac_with_the_flag(hmac_run):
    from acs.testing.harness import TEST_KEY_ID
    lines = record_session(hmac_run)
    number = tool_request_line(lines, "rm -rf /") + 1
    forged = hmac_forgery(hmac_run, json.loads(lines[number - 1])["envelope"], key_id=TEST_KEY_ID)
    tampered = rewrite(lines, number, lambda r: r.update({"envelope": forged}))
    report = verify_transcript(tampered, key_document=None, hmac_secret=hmac_run.hmac_secret)
    # HMAC proves only that someone holding the secret wrote the entry (specification section 8.6).
    assert report.ok, report.to_text()
    assert "8.6" in report.to_text()


def test_a_response_for_another_request_fails_the_binding(mldsa_run):
    lines = record_session(mldsa_run)
    req = tool_request_line(lines, "rm -rf /")
    tampered = rewrite(lines, req + 1, lambda r: r["envelope"].update({"id": "another-id"}))
    report = mldsa_verify(mldsa_run, tampered)
    assert (report.failure.line, report.failure.code) == (req, "binding")


def test_a_key_outside_its_validity_window_fails(mldsa_run):
    lines = record_session(mldsa_run)
    document = mldsa_run.key_document()
    document["keys"][0].update({"not_before": "2020-01-01T00:00:00Z", "not_after": "2020-04-01T00:00:00Z"})
    report = mldsa_verify(mldsa_run, lines, key_document=document)
    assert (report.failure.line, report.failure.code) == (2, "key_not_valid")


def test_a_key_revoked_before_the_session_fails(mldsa_run):
    document = mldsa_run.key_document()
    document["revoked"] = [{"key_id": "lab-guardian-1", "revoked_at": document["keys"][0]["not_before"]}]
    lines = record_session(mldsa_run)
    report = mldsa_verify(mldsa_run, lines, key_document=document)
    assert (report.failure.line, report.failure.code) == (2, "key_not_valid")


def test_a_key_revoked_after_the_session_still_verifies_the_session(mldsa_run):
    # Validity is judged at each request's own timestamp, not at the time acs-verify runs (PREMORTEM P25).
    lines = record_session(mldsa_run)
    document = mldsa_run.key_document()
    document["revoked"] = [{"key_id": "lab-guardian-1", "revoked_at": iso8601_now()}]
    report = mldsa_verify(mldsa_run, lines, key_document=document)
    assert report.ok and report.complete, report.to_text()


def test_a_request_without_a_timestamp_fails(mldsa_run):
    lines = record_session(mldsa_run)
    tampered = rewrite(lines, 1, lambda r: r["envelope"]["params"].pop("timestamp"))
    report = mldsa_verify(mldsa_run, tampered)
    assert (report.failure.line, report.failure.code) == (1, "no_timestamp")


def test_a_request_from_another_session_fails(mldsa_run):
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "rm -rf /")
    tampered = rewrite(lines, number, lambda r: r["envelope"]["params"]["metadata"]
                       .update({"session_id": "77777777-7777-4777-8777-777777777777"}))
    report = mldsa_verify(mldsa_run, tampered)
    assert (report.failure.line, report.failure.code) == (number, "session_mismatch")


def test_a_line_with_a_repeated_key_fails_at_that_line(mldsa_run):
    lines = record_session(mldsa_run)
    tampered = list(lines)
    tampered[3] = tampered[3].replace('{"dir":"resp",', '{"dir":"resp","dir":"resp",', 1)
    report = mldsa_verify(mldsa_run, tampered)
    assert (report.failure.line, report.failure.code) == (4, "line_invalid")


def test_a_response_with_no_request_before_it_fails(mldsa_run):
    lines = record_session(mldsa_run)
    report = mldsa_verify(mldsa_run, lines[1:])
    assert (report.failure.line, report.failure.code) == (1, "order")
