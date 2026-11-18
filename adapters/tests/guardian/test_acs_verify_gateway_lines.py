"""acs-verify reads every line the lab gateway writes (fix round 4, issue #584, gateway lines from issue #577).

The gateway (LAB-04F) writes three kinds of line beyond signed pairs: a discards line marking an answer it withheld,
a gap line or a verbatim non-answer body with the cause acs.client gave, and an unsigned error recorded verbatim.
The synthetic cases start from sessions the real example Guardian signed under HMAC, so they need no pqc extra.
The files under gateway_transcripts/ were written by LAB-04F's own gateway suite at e5a6d52 (its evicted-session,
late-answer and in-flight sessionEnd tests), under that suite's public test secret.
"""
from __future__ import annotations

import json
import urllib.request
import uuid
from pathlib import Path

import pytest

from acs_verify_helpers import (
    ALLOWED,
    record_custom,
    record_session,
    start_guardian,
    stop_guardian,
    transcript_line,
)
from acs.core import derive_session_key, sign_with_key
from acs.guardian.example_guardian import internal_error_envelope
from acs.testing.verify import verify_transcript

FIXTURES = Path(__file__).parent / "gateway_transcripts"
# The gateway suite's test secret (adapters/gateway/tests/conftest.py), public by design.
GATEWAY_SECRET = ("lab-test-secret-" + "0123456789abcdef" * 2).encode("utf-8")
# A secret the Guardian doesn't hold, under a label it doesn't know, as a misconfigured gateway would sign with.
OTHER_SECRET = b"another-deployment-secret-" + b"fedcba9876543210" * 2


@pytest.fixture
def hmac_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=False)
    yield run
    stop_guardian(run)


def records(lines):
    return [json.loads(line) for line in lines]


def verify(lines, run):
    return verify_transcript(lines, key_document=None, hmac_secret=run.hmac_secret)


def answer_line(lines, decision):
    """The 1-based line of the answer with this decision, and its request's line and request_id."""
    recs = records(lines)
    for number, record in enumerate(recs, start=1):
        result = (record.get("envelope") or {}).get("result") or {}
        if record["dir"] == "resp" and result.get("decision") == decision:
            request = recs[number - 2]["envelope"]
            return number, number - 1, request["params"]["request_id"]
    raise AssertionError(f"no {decision} answer")


def discards(request_id):
    return json.dumps({"dir": "resp", "envelope": None, "cause": "decision_timeout", "discards": request_id},
                      separators=(",", ":"))


def body_line(body, cause):
    return json.dumps({"dir": "resp", "envelope": body, "cause": cause}, separators=(",", ":"))


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


# F1: the discards line.


def test_a_discards_line_marks_the_answer_before_it_as_discarded(hmac_run):
    lines = record_session(hmac_run)
    resp, req, request_id = answer_line(lines, "allow")
    lines.insert(resp, discards(request_id))
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.discarded_lines == [req]
    assert report.complete
    assert f"withheld by the gateway: request line {req}" in report.to_text()
    assert report.to_json()["discarded_lines"] == [req]


def test_a_verbatim_answer_written_with_a_cause_is_discarded(hmac_run):
    lines = record_session(hmac_run)
    resp, req, _ = answer_line(lines, "allow")
    record = json.loads(lines[resp - 1])
    lines[resp - 1] = body_line(record["envelope"], "decision_timeout")
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.discarded_lines == [req]


def test_a_discards_line_naming_a_request_it_has_not_seen_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "allow")
    lines.insert(resp, discards(str(uuid.uuid4())))
    report = verify(lines, hmac_run)
    assert not report.ok
    assert (report.failure.line, report.failure.code) == (resp + 1, "discards_invalid")
    assert "not seen" in report.failure.reason


def test_a_discards_line_naming_an_earlier_request_fails(hmac_run):
    lines = record_session(hmac_run)
    _, _, allowed_id = answer_line(lines, "allow")
    resp, _, _ = answer_line(lines, "deny")
    lines.insert(resp, discards(allowed_id))
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp + 1, "discards_invalid")


def test_a_discards_line_after_a_request_with_no_answer_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, request_id = answer_line(lines, "allow")
    del lines[resp - 1]
    lines.insert(resp - 1, discards(request_id))
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "discards_invalid")


def test_a_discards_line_after_a_gap_line_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, request_id = answer_line(lines, "allow")
    lines[resp - 1] = transcript_line("resp", None, "transport_failure")
    lines.insert(resp, discards(request_id))
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp + 1, "discards_invalid")


def test_a_second_discards_line_for_one_answer_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, request_id = answer_line(lines, "allow")
    lines[resp:resp] = [discards(request_id), discards(request_id)]
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp + 2, "discards_invalid")


def test_a_discards_line_that_carries_an_envelope_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, request_id = answer_line(lines, "allow")
    record = json.loads(lines[resp - 1])
    lines.insert(resp, json.dumps({"dir": "resp", "envelope": record["envelope"], "cause": "decision_timeout",
                                   "discards": request_id}))
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp + 1, "line_invalid")


def test_the_gateways_own_discards_transcript_verifies():
    lines = fixture("discards.jsonl")
    report = verify_transcript(lines, key_document=None, hmac_secret=GATEWAY_SECRET)
    assert report.ok, report.to_text()
    assert report.discarded_lines == [5]
    assert report.recorded_failures == [{"line": 8, "cause": "transport_failure"}]
    assert not report.complete


# F2: gap lines and verbatim non-answer bodies are recorded failures.


def test_a_gap_line_is_reported_as_a_recorded_failure(hmac_run):
    lines = record_session(hmac_run)
    resp, req, _ = answer_line(lines, "deny")
    lines[resp - 1] = transcript_line("resp", None, "http_503_error")
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.recorded_failures == [{"line": req, "cause": "http_503_error"}]
    assert req in report.unsigned_lines
    assert not report.complete
    assert f"recorded failures: request line {req} (http_503_error)" in report.to_text()


@pytest.mark.parametrize("body,cause", [({"detail": "Too Many Requests"}, "http_429_error"),
                                        ({"detail": "not an answer"}, "malformed_response")])
def test_a_verbatim_non_answer_body_with_a_cause_is_a_recorded_failure(hmac_run, body, cause):
    lines = record_session(hmac_run)
    resp, req, _ = answer_line(lines, "deny")
    lines[resp - 1] = body_line(body, cause)
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.recorded_failures == [{"line": req, "cause": cause}]
    assert req in report.unsigned_lines
    assert not report.complete


def test_a_failed_hello_is_a_recorded_failure(hmac_run):
    hello = record_session(hmac_run)[0]
    lines = [hello, body_line({"detail": "Service Unavailable"}, "http_503_error")]
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.recorded_failures == [{"line": 1, "cause": "http_503_error"}]
    assert not report.complete


def test_a_non_answer_body_without_a_cause_still_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "deny")
    lines[resp - 1] = transcript_line("resp", {"detail": "Too Many Requests"})
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "unsigned_response")


def test_a_tampered_answer_with_a_cause_still_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "deny")
    record = json.loads(lines[resp - 1])
    record["envelope"]["result"]["decision"] = "allow"
    lines[resp - 1] = body_line(record["envelope"], "decision_timeout")
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "signature_invalid")


# F3: only the -32004 for an unknown key_id may be unsigned (specification section 10, D-039).


def post(url, envelope):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, data=json.dumps(envelope).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    with opener.open(request, timeout=5) as answer:
        return json.loads(answer.read())


def foreign_key_step(session):
    """A request signed under a secret and label the Guardian doesn't hold, and the Guardian's verbatim answer."""
    envelope = session.envelope("steps/toolCallRequest", ALLOWED)
    key = derive_session_key(OTHER_SECRET, session.run.session_id)
    signed = sign_with_key(envelope, key, key_id="other-deployment")
    answer = post(session.run.url, signed)
    session.recorder.lines.extend([transcript_line("req", signed), transcript_line("resp", answer)])


def test_the_guardians_unsigned_minus_32004_for_an_unknown_key_id_is_an_unsigned_error(hmac_run):
    lines = record_custom(hmac_run, [foreign_key_step])
    req = len(lines) - 3
    answer = records(lines)[req]["envelope"]
    assert answer["error"]["code"] == -32004 and "signature" not in answer["error"], answer
    report = verify(lines, hmac_run)
    assert report.ok, report.to_text()
    assert report.unsigned_errors == [{"line": req, "code": -32004}]
    assert req in report.unsigned_lines
    assert not report.complete
    assert f"unsigned -32004 for an unknown key_id: request line {req}" in report.to_text()


def test_an_unsigned_minus_32004_for_a_key_id_the_guardian_accepted_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "deny")
    answer = records(lines)[resp - 1]["envelope"]
    lines[resp - 1] = transcript_line("resp", {"jsonrpc": "2.0", "id": answer["id"],
                                               "error": {"code": -32004, "message": "SIGNATURE_INVALID"}})
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "unsigned_response")
    assert "accepted" in report.failure.reason


def test_an_unsigned_minus_32004_before_the_key_id_is_accepted_fails_at_the_later_answer(hmac_run):
    lines = record_session(hmac_run)
    # The ServerHello is the first signed answer, so the sessionStart answer at line 4 is the first to accept the key.
    hello = records(lines)[1]["envelope"]
    lines[1] = transcript_line("resp", {"jsonrpc": "2.0", "id": hello["id"],
                                        "error": {"code": -32004, "message": "SIGNATURE_INVALID"}})
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (4, "unsigned_response")
    assert "line 2" in report.failure.reason


def test_the_unsigned_minus_32603_floor_still_fails_and_cites_the_spec(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "deny")
    answer = records(lines)[resp - 1]["envelope"]
    lines[resp - 1] = transcript_line("resp", internal_error_envelope(answer["id"]))
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "unsigned_response")
    assert "section 10" in report.failure.reason


def test_another_unsigned_error_code_still_fails(hmac_run):
    lines = record_session(hmac_run)
    resp, _, _ = answer_line(lines, "deny")
    answer = records(lines)[resp - 1]["envelope"]
    lines[resp - 1] = transcript_line("resp", {"jsonrpc": "2.0", "id": answer["id"],
                                               "error": {"code": -32005, "message": "REPLAY_DETECTED"}})
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (resp, "unsigned_response")


def test_a_request_under_an_unknown_key_with_no_answer_still_fails_its_signature(hmac_run):
    lines = record_custom(hmac_run, [foreign_key_step])
    req = len(lines) - 3
    lines[req] = transcript_line("resp", None, "transport_failure")
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (req, "request_signature_invalid")


def test_a_request_under_an_unknown_key_answered_by_a_signed_allow_still_fails(hmac_run):
    lines = record_custom(hmac_run, [foreign_key_step])
    req = len(lines) - 3
    resp, _, _ = answer_line(lines, "allow")
    lines[req] = lines[resp - 1]
    report = verify(lines, hmac_run)
    assert (report.failure.line, report.failure.code) == (req, "request_signature_invalid")


# F4: a transcript ending in sessionEnd verifies complete, the in_flight case stays tail unverified.


def test_the_gateways_transcript_ending_in_session_end_verifies_complete():
    lines = fixture("session_end.jsonl")
    report = verify_transcript(lines, key_document=None, hmac_secret=GATEWAY_SECRET)
    assert report.ok, report.to_text()
    assert report.complete, report.to_text()
    assert report.checkpoint_method == "steps/sessionEnd"
    assert report.to_text().startswith("acs-verify: PASS\n")


def test_the_gateways_in_flight_transcript_stays_tail_unverified():
    lines = fixture("in_flight.jsonl")
    assert json.loads(lines[-1])["envelope"]["method"] == "steps/toolCallRequest"
    report = verify_transcript(lines, key_document=None, hmac_secret=GATEWAY_SECRET)
    assert report.ok, report.to_text()
    assert not report.complete
    assert report.unverified_lines == [5]
    assert report.to_text().startswith("acs-verify: PASS, tail unverified")
