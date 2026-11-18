"""A withheld late answer leaves a cause line, so a verifier can tell the allow was discarded (issue #577).

Ledger ruling 2026-11-17 12:55: an answer that was on time but became late behind its own response line is withheld,
and the transcript must say so after the line that carries it.
"""
import json
import time
import uuid

import pytest

from conftest import call_item, finbot_request, message_item, response_body, transcript_lines


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


class SlowLine:
    """Wraps the real transcript and stalls on every envelope line in one direction. Swapped in after the session
    opened, so only the step under test meets it."""

    def __init__(self, inner, delay, direction):
        self.inner, self.delay, self.direction = inner, delay, direction

    def append(self, session_id, direction, envelope, **kwargs):
        if direction == self.direction and envelope is not None:
            time.sleep(self.delay)
        self.inner.append(session_id, direction, envelope, **kwargs)


def started(gateway, guardian, upstream, mode, timeout_ms):
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian, ACS_DECISION_TIMEOUT_MS=timeout_ms)
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request())
    return client


def test_transcript_writes_a_discards_line(tmp_path):
    from acs_gateway.transcript import Transcript

    session_id, request_id = str(uuid.uuid4()), str(uuid.uuid4())
    Transcript(tmp_path).append(session_id, "resp", None, cause="decision_timeout", discards=request_id)
    line = json.loads((tmp_path / f"{session_id}.jsonl").read_text())
    assert line == {"dir": "resp", "envelope": None, "cause": "decision_timeout", "discards": request_id}


def test_only_a_gap_line_may_discard(tmp_path):
    from acs_gateway.transcript import Transcript

    with pytest.raises(ValueError):
        Transcript(tmp_path).append(str(uuid.uuid4()), "resp", {"id": 1}, discards=str(uuid.uuid4()))


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_an_answer_made_late_by_its_own_line_is_marked_discarded(gateway, guardian, upstream, audit, tmp_path, mode):
    client = started(gateway, guardian, upstream, mode, "300")
    gw = client.app.state.gateway
    gw.guardian.transcript = SlowLine(gw.guardian.transcript, 0.5, "resp")
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    request_id = lines[-3]["envelope"]["params"]["request_id"]
    # The answer line holds the on-time allow as it arrived, and the next line says the gateway discarded it.
    assert lines[-2]["envelope"]["result"]["decision"] == "allow" and "cause" not in lines[-2]
    assert lines[-1] == {"dir": "resp", "envelope": None, "cause": "decision_timeout", "discards": request_id}
    name = "decision_applied" if mode == "enforce" else "shadow_decision"
    applied = events(audit, name)[0]
    assert (applied["cause"], applied["request_id"]) == ("decision_timeout", request_id)


def test_an_answer_late_on_arrival_gets_no_discards_line(gateway, guardian, upstream, audit, tmp_path):
    client = started(gateway, guardian, upstream, "enforce", "100")
    gw = client.app.state.gateway
    gw.guardian.transcript = SlowLine(gw.guardian.transcript, 0.3, "req")
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    assert lines[-1]["cause"] == "decision_timeout" and lines[-1]["envelope"]["result"]["decision"] == "allow"
    assert not [line for line in lines if "discards" in line]


def test_an_answer_the_loop_finds_late_is_marked_discarded(gateway, guardian, upstream, audit, tmp_path):
    client = started(gateway, guardian, upstream, "enforce", "300")
    gw = client.app.state.gateway
    real_step = gw.guardian.step

    def step(session, method, payload, token=None):
        result = real_step(session, method, payload, token)
        # The worker settled in time, then the loop resumed after the deadline.
        time.sleep(max(0.0, token.deadline - time.monotonic()) + 0.05)
        return result

    gw.guardian.step = step
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    request_id = lines[-3]["envelope"]["params"]["request_id"]
    assert "cause" not in lines[-2]
    assert lines[-1] == {"dir": "resp", "envelope": None, "cause": "decision_timeout", "discards": request_id}
    assert events(audit, "decision_applied")[0]["cause"] == "decision_timeout"


def test_an_answer_inside_the_deadline_leaves_no_discards_line(gateway, guardian, upstream, audit, tmp_path):
    client = started(gateway, guardian, upstream, "enforce", "2000")
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    assert client.post("/v1/responses", json=finbot_request()).json()["output"][0]["call_id"] == "call_1"
    assert not [line for line in transcript_lines(tmp_path) if "discards" in line]
