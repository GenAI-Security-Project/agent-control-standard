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


# The key document sits beside the transcript in the attendee's state tree, so swapping both must be caught by the
# fingerprint the Guardian printed at startup (PREMORTEM P5).


def resign(lines, signing_key):
    """Every response re-signed with another key, as an attacker who swapped the key document would do."""
    from acs.core import sign_with_signing_key
    out = []
    for line in lines:
        record = json.loads(line)
        if record["dir"] == "resp" and record["envelope"] is not None:
            sign_with_signing_key(record["envelope"], signing_key)
        out.append(json.dumps(record, separators=(",", ":"), ensure_ascii=True))
    return out


def attacker_document(run, key_id):
    import datetime
    from acs.core import MLDSA65SigningKey
    from acs.guardian.decision_keys import key_document
    signing_key = MLDSA65SigningKey.generate(key_id)
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    document = key_document(signing_key, guardian_id="lab-guardian", not_before=start,
                            not_after=start + datetime.timedelta(days=3650))
    return signing_key, document


def test_the_guardian_prints_the_fingerprint_of_its_key_document_at_startup(mldsa_run):
    assert mldsa_run.startup_fingerprint() == mldsa_run.key_document()["keys"][0]["fingerprint"]


def test_the_startup_fingerprint_passes_the_guardians_own_document(mldsa_run):
    fingerprint = mldsa_run.startup_fingerprint()
    report = mldsa_verify(mldsa_run, record_session(mldsa_run), expect_fingerprints=[fingerprint])
    assert report.ok and report.complete, report.to_text()
    assert report.keys_used == {"lab-guardian-1": fingerprint}


def test_a_swapped_key_document_fails_with_the_expected_fingerprint(mldsa_run):
    fingerprint = mldsa_run.startup_fingerprint()
    lines = record_session(mldsa_run)
    signing_key, swapped = attacker_document(mldsa_run, "lab-guardian-1")
    forged = resign(rewrite(lines, tool_request_line(lines, "rm -rf /") + 1,
                            lambda r: r["envelope"]["result"].update({"decision": "allow"})), signing_key)
    # Without the pin, a swapped document and re-signed responses pass. That is why the pin exists.
    assert mldsa_verify(mldsa_run, forged, key_document=swapped).ok
    report = mldsa_verify(mldsa_run, forged, key_document=swapped, expect_fingerprints=[fingerprint])
    assert (report.failure.line, report.failure.code) == (0, "fingerprint_mismatch")
    assert "FAIL at the key document" in report.to_text()


def test_an_extra_key_added_to_the_real_document_fails_at_the_first_response_it_signed(mldsa_run):
    fingerprint = mldsa_run.startup_fingerprint()
    lines = record_session(mldsa_run)
    signing_key, extra = attacker_document(mldsa_run, "lab-guardian-2")
    document = mldsa_run.key_document()
    document["keys"].append(extra["keys"][0])
    number = tool_request_line(lines, "rm -rf /") + 1
    flipped = rewrite(lines, number, lambda r: r["envelope"]["result"].update({"decision": "allow"}))
    forged = flipped[:number - 1] + resign(flipped[number - 1:number], signing_key) + flipped[number:]
    report = mldsa_verify(mldsa_run, forged, key_document=document, expect_fingerprints=[fingerprint])
    assert (report.failure.line, report.failure.code) == (number, "fingerprint_mismatch")


# The tail. Entries cut from the end of a transcript leave no trace, so without a verified sessionEnd acs-verify
# passes only up to its last checkpoint and says so (PREMORTEM P31).


def test_no_session_end_prints_tail_unverified(mldsa_run):
    lines = record_session(mldsa_run, end=False)
    report = mldsa_verify(mldsa_run, lines)
    assert report.ok
    assert not report.complete
    assert report.checkpoint_line == len(lines)
    text = report.to_text()
    assert "tail unverified" in text
    assert "whole transcript verified" not in text
    assert report.to_json()["complete"] is False


def test_a_truncated_transcript_does_not_claim_the_whole_log(mldsa_run):
    lines = record_session(mldsa_run)
    report = mldsa_verify(mldsa_run, lines[:-2])
    assert report.ok and not report.complete
    assert "tail unverified" in report.to_text()


def test_a_request_with_no_answer_after_the_last_checkpoint_is_unverified(mldsa_run):
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run, end=False)
    unanswered = json.loads(lines[-2])
    unanswered["envelope"]["id"] = "no-answer"
    unanswered["envelope"]["params"]["request_id"] = "no-answer-request"
    tail = [json.dumps(unanswered), transcript_line("resp", None, "decision_timeout")]
    report = mldsa_verify(mldsa_run, lines + tail)
    assert report.ok and not report.complete
    assert report.unverified_lines == [len(lines) + 1, len(lines) + 2]
    assert report.unsigned_lines == [len(lines) + 1]
    assert f"Lines {len(lines) + 1} to {len(lines) + 2}" in report.to_text()


def test_a_replayed_request_fails_at_the_second_copy(mldsa_run):
    # The Guardian refuses the copy with a signed -32005, but a request_id seen twice is itself the anomaly.
    lines = record_session(mldsa_run, replay=True)
    assert any((r["envelope"].get("error") or {}).get("code") == -32005 for r in records(lines) if r["dir"] == "resp")
    request_ids = [r["envelope"]["params"].get("request_id") for r in records(lines) if r["dir"] == "req"]
    repeated = next(rid for rid in request_ids if request_ids.count(rid) > 1)
    copies = [n for n, r in enumerate(records(lines), start=1)
              if r["dir"] == "req" and r["envelope"]["params"].get("request_id") == repeated]
    report = mldsa_verify(mldsa_run, lines)
    assert (report.failure.line, report.failure.code) == (copies[1], "duplicate_request_id")


def test_keys_only_checks_signatures_without_the_chain(mldsa_run):
    lines = record_session(mldsa_run)
    allow_req = tool_request_line(lines, "ls -la")
    deny_req = tool_request_line(lines, "rm -rf /")
    reordered = list(lines)
    reordered[allow_req - 1:allow_req + 3] = lines[deny_req - 1:deny_req + 1] + lines[allow_req - 1:allow_req + 1]
    report = mldsa_verify(mldsa_run, reordered, keys_only=True)
    assert report.ok and not report.complete and not report.chain_checked
    assert "chain: not checked (--keys-only)" in report.to_text()
    flipped = rewrite(lines, deny_req + 1, lambda r: r["envelope"]["result"].update({"decision": "allow"}))
    assert mldsa_verify(mldsa_run, flipped, keys_only=True).failure.code == "signature_invalid"


def test_a_chained_request_whose_answer_was_lost_settles_but_is_listed(mldsa_run):
    # The Guardian chained the allow, but the answer never reached the gateway (a timeout). The deny's signed
    # chain_hash settles that the entry is in the chain (PREMORTEM P6).
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "ls -la") + 1
    lost = list(lines)
    lost[number - 1] = transcript_line("resp", None, "decision_timeout")
    report = mldsa_verify(mldsa_run, lost)
    # The chain settles, but no signature covers what was decided for that request, so the log is not complete.
    assert report.ok and not report.complete, report.to_text()
    assert report.unsigned_lines == [number - 1]
    # Dropping the request line too leaves an entry the chain needs, so the next checkpoint fails.
    dropped = lines[:number - 2] + lines[number:]
    report = mldsa_verify(mldsa_run, dropped)
    assert (report.failure.line, report.failure.code) == (number - 1, "chain_mismatch")


# Fix round 2. A pass claims only what a signature covers: every request line no signed decision covers is listed,
# and then the transcript is never called complete.


def assert_partial(report, listed):
    assert report.ok, report.to_text()
    assert not report.complete
    assert set(listed) <= set(report.unsigned_lines), (listed, report.unsigned_lines)
    text = report.to_text()
    assert "whole transcript verified" not in text
    assert "no signed decision" in text


def test_a_deleted_deny_response_is_listed_and_the_log_is_not_complete(mldsa_run):
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    report = mldsa_verify(mldsa_run, lines[:deny_req] + lines[deny_req + 1:])
    assert_partial(report, [deny_req])


def test_a_nulled_deny_response_is_listed_and_the_log_is_not_complete(mldsa_run):
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    nulled = list(lines)
    nulled[deny_req] = transcript_line("resp", None, "decision_timeout")
    assert_partial(mldsa_verify(mldsa_run, nulled), [deny_req])


def test_an_inserted_request_with_a_null_response_is_listed(mldsa_run):
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    inserted = json.loads(lines[deny_req - 1])
    inserted["envelope"]["id"] = "inserted"
    inserted["envelope"]["params"]["request_id"] = "inserted-request"
    out = lines[:deny_req + 1] + [json.dumps(inserted), transcript_line("resp", None, "decision_timeout")] \
        + lines[deny_req + 1:]
    assert_partial(mldsa_verify(mldsa_run, out), [deny_req + 2])


def test_an_inserted_ping_pair_is_listed(mldsa_run):
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    ping = {"jsonrpc": "2.0", "id": "ping-1", "method": "system/ping",
            "params": {"acs_version": "0.1.0", "request_id": "ping-1", "timestamp": iso8601_now(),
                       "payload": {"echo": "x"}}}
    pong = {"jsonrpc": "2.0", "id": "ping-1", "result": {"type": "final", "acs_version": "0.1.0",
                                                         "request_id": "ping-1", "decision": "allow"}}
    at = len(lines) - 2
    out = lines[:at] + [transcript_line("req", ping), transcript_line("resp", pong)] + lines[at:]
    assert_partial(mldsa_verify(mldsa_run, out), [at + 1])


def test_a_duplicated_request_line_fails_at_the_copy(mldsa_run):
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    out = lines[:deny_req] + [lines[deny_req - 1]] + lines[deny_req:]
    report = mldsa_verify(mldsa_run, out)
    assert (report.failure.line, report.failure.code) == (deny_req + 1, "duplicate_request_id")


def test_a_wrapped_mcp_call_is_chained_as_the_guardian_chains_it(mldsa_run):
    from acs_verify_helpers import MCP_CALL, record_custom
    lines = record_custom(mldsa_run, [lambda session: session.step(*MCP_CALL)])
    mcp = [r for r in records(lines) if r["dir"] == "resp" and "chain_hash" in (r["envelope"].get("result") or {})]
    assert len(mcp) == 3  # sessionStart, the MCP call, sessionEnd
    report = mldsa_verify(mldsa_run, lines)
    assert report.ok and report.complete, report.to_text()


def test_the_guardians_predicate_matches_what_it_chained(mldsa_run):
    # The Guardian's own predicate decides which methods acs-verify chains, so no second copy of the rule exists.
    from acs.guardian._chain import chains_method
    from acs_verify_helpers import MCP_CALL, record_custom
    lines = record_custom(mldsa_run, [lambda session: session.step(*MCP_CALL),
                                      lambda session: session.step("steps/toolCallRequest",
                                                                   {"tool": {"name": "Bash"},
                                                                    "arguments": {"command": {"value": "ls"}}})])
    rows = records(lines)
    for request, response in zip(rows[0::2], rows[1::2]):
        chained = "chain_hash" in (response["envelope"].get("result") or {})
        assert chained == chains_method(request["envelope"]["method"]), request["envelope"]["method"]


def refused_session(run, count):
    from acs_verify_helpers import ALLOWED, record_custom, unreachable_url
    dead = unreachable_url()

    def refused(session):
        for _ in range(count):
            session.step("steps/toolCallRequest", ALLOWED, url=dead)

    lines = record_custom(run, [refused])
    causes = [r.get("cause") for r in records(lines) if r["dir"] == "resp" and r["envelope"] is None]
    assert causes == ["transport_failure"] * count
    return lines


def test_refused_connections_up_to_the_cap_pass_as_not_complete(mldsa_run):
    # transport_failure can also follow a send whose reply was lost, so each is held, not dropped (fix round 3).
    report = mldsa_verify(mldsa_run, refused_session(mldsa_run, 20))
    assert report.ok, report.to_text()
    assert len(report.unsigned_lines) == 20
    assert not report.complete


def test_more_unanswered_requests_than_the_cap_fail_as_unsettled(mldsa_run):
    report = mldsa_verify(mldsa_run, refused_session(mldsa_run, 21))
    assert report.failure.code == "chain_unsettled", report.to_text()


def dropping_relay(guardian_url: str) -> str:
    """A one-shot relay that forwards the request to the Guardian, reads its signed answer, and closes the client
    connection without replying, so the Guardian chained a step whose reply never arrived."""
    import socket
    import threading
    import urllib.request

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(65536)
        head, body = data.split(b"\r\n\r\n", 1)
        length = next(int(line.split(b":")[1]) for line in head.split(b"\r\n")
                      if line.lower().startswith(b"content-length"))
        while len(body) < length:
            body += conn.recv(65536)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        forwarded = urllib.request.Request(guardian_url, data=body, headers={"Content-Type": "application/json"})
        with opener.open(forwarded, timeout=5) as answer:
            answer.read()
        conn.close()
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{port}/acs"


def lost_reply_session(run):
    from acs_verify_helpers import ALLOWED, record_custom
    lines = record_custom(run, [lambda session: session.step("steps/toolCallRequest", ALLOWED,
                                                             url=dropping_relay(run.url))])
    lost = [n for n, r in enumerate(records(lines), start=1) if r["dir"] == "resp" and r["envelope"] is None]
    assert len(lost) == 1 and json.loads(lines[lost[0] - 1])["cause"] == "transport_failure"
    return lines, lost[0] - 1


def test_a_reply_lost_after_the_guardian_chained_the_step_passes_as_not_complete(mldsa_run):
    # The re-reviewer's probe (fix round 3, F1): a genuine transcript must not fail as chain_mismatch.
    lines, request_line = lost_reply_session(mldsa_run)
    report = mldsa_verify(mldsa_run, lines)
    assert report.ok, report.to_text()
    assert not report.complete
    assert report.unsigned_lines == [request_line]


def test_deleting_the_lost_reply_step_still_fails(mldsa_run):
    lines, request_line = lost_reply_session(mldsa_run)
    deleted = lines[:request_line - 1] + lines[request_line + 1:]
    report = mldsa_verify(mldsa_run, deleted)
    assert report.failure.code == "chain_mismatch", report.to_text()


def test_an_on_wire_failure_is_held_not_dropped(mldsa_run):
    # on_wire_failed names a callback failure on either side of the send, so it proves nothing about the Guardian.
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    nulled = list(lines)
    nulled[deny_req] = transcript_line("resp", None, "on_wire_failed")
    report = mldsa_verify(mldsa_run, nulled)
    assert report.ok and not report.complete, report.to_text()
    assert deny_req in report.unsigned_lines


def test_a_chain_mismatch_names_the_lines_left_out_as_never_sent(mldsa_run):
    from acs_verify_helpers import transcript_line
    lines = record_session(mldsa_run)
    deny_req = tool_request_line(lines, "rm -rf /")
    # The deny is relabelled as never sent, so it is left out, and the next chain_hash can't be reached.
    out = list(lines)
    out[deny_req] = transcript_line("resp", None, "envelope_not_signable")
    report = mldsa_verify(mldsa_run, out)
    assert report.failure.code == "chain_mismatch", report.to_text()
    assert f"line {deny_req}" in report.failure.reason
    assert "never sent" in report.failure.reason


def test_a_revoked_key_that_signed_an_entry_warns_about_backdating(mldsa_run):
    lines = record_session(mldsa_run)
    document = mldsa_run.key_document()
    document["revoked"] = [{"key_id": "lab-guardian-1", "revoked_at": iso8601_now()}]
    report = mldsa_verify(mldsa_run, lines, key_document=document)
    assert report.ok
    assert report.warnings and "backdate" in report.warnings[0]
    assert "warning:" in report.to_text()
    assert not mldsa_verify(mldsa_run, lines).warnings


@pytest.mark.parametrize("raw", ['"big":9007199254740993,', '"far":1e400,'])
def test_a_request_jcs_cannot_encode_fails_at_its_line(mldsa_run, raw):
    lines = record_session(mldsa_run)
    number = tool_request_line(lines, "ls -la")
    out = list(lines)
    out[number - 1] = out[number - 1].replace('"payload":{', '"payload":{' + raw, 1)
    report = mldsa_verify(mldsa_run, out)
    assert (report.failure.line, report.failure.code) == (number, "not_canonical"), report.to_text()


@pytest.mark.parametrize("change,expected", [
    (lambda d: d.update({"revoked": "nobody"}), "revoked"),
    (lambda d: d.update({"revoked": [{"key_id": "lab-guardian-1", "revoked_at": "yesterday"}]}), "revoked_at"),
])
def test_a_malformed_revoked_list_is_a_usage_error(mldsa_run, change, expected):
    from acs.testing.verify import UsageError
    document = mldsa_run.key_document()
    change(document)
    with pytest.raises(UsageError, match=expected):
        mldsa_verify(mldsa_run, record_session(mldsa_run), key_document=document)


def test_an_unknown_key_id_pin_is_a_usage_error(mldsa_run):
    from acs.testing.verify import UsageError
    with pytest.raises(UsageError, match="lab-guardian-9"):
        mldsa_verify(mldsa_run, record_session(mldsa_run), key_id="lab-guardian-9")


def test_keys_are_parsed_once_per_key_not_per_response(mldsa_run, monkeypatch):
    from acs.testing import verify
    calls = []
    real = verify.parse_key_document

    def counting(*args, **kwargs):
        calls.append(kwargs.get("key_id"))
        return real(*args, **kwargs)

    monkeypatch.setattr(verify, "parse_key_document", counting)
    lines = record_session(mldsa_run)
    assert mldsa_verify(mldsa_run, lines).ok
    assert len(calls) <= 2  # the load check and the key itself, whatever the transcript's length


@pytest.mark.parametrize("field,value,words,absent", [
    ("id", "another-id", "JSON-RPC id", "request_id"),
    ("request_id", "another-request", "request_id", "JSON-RPC id"),
])
def test_the_binding_failure_names_what_differs(mldsa_run, field, value, words, absent):
    lines = record_session(mldsa_run)
    req = tool_request_line(lines, "rm -rf /")
    if field == "id":
        out = rewrite(lines, req + 1, lambda r: r["envelope"].update({"id": value}))
    else:
        out = rewrite(lines, req + 1, lambda r: r["envelope"]["result"].update({"request_id": value}))
    report = mldsa_verify(mldsa_run, out)
    assert report.failure.code == "binding"
    assert words in report.failure.reason
    assert absent not in report.failure.reason
