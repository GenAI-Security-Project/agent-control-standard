"""The gateway ends every ACS session it drops with steps/sessionEnd (rehearsal finding R9, issue #577).

Eviction, retirement, an epoch bump and a graceful shutdown each send it under the session lock, written to the
transcript before it is sent like any step, so acs-verify can check a gateway transcript's tail.
"""
import json
import time

import pytest

from conftest import call_item, finbot_request, message_item, response_body, transcript_lines


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def lines_of(tmp_path, session_id):
    """The session's own transcript file, in order."""
    path = tmp_path / "transcripts" / f"{session_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def wait_for_end(audit, session_id, within=10.0):
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        ended = [e for e in events(audit, "session_ended") if e["session_id"] == session_id]
        if ended:
            return ended[0]
        time.sleep(0.05)
    raise AssertionError(f"session {session_id} never ended")


def assert_ends_with_session_end(tmp_path, session_id, reason):
    lines = lines_of(tmp_path, session_id)
    assert lines[-2]["dir"] == "req" and lines[-2]["envelope"]["method"] == "steps/sessionEnd", lines[-2:]
    assert lines[-2]["envelope"]["params"]["payload"] == {"reason": reason}
    assert lines[-1]["dir"] == "resp" and lines[-1]["envelope"]["result"]["decision"] == "allow"
    assert lines[-1]["envelope"]["id"] == lines[-2]["envelope"]["id"]


def opened(client, upstream, user="First conversation"):
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request(user=user))


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_an_evicted_session_ends_in_its_transcript(gateway, guardian, upstream, audit, tmp_path, mode):
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="1")
    opened(client, upstream)
    opened(client, upstream, user="Second conversation")
    (evicted,) = [e["session_id"] for e in events(audit, "session_evicted")]
    ended = wait_for_end(audit, evicted)
    assert (ended["reason"], ended["cause"]) == ("abandoned", None)
    assert_ends_with_session_end(tmp_path, evicted, "abandoned")


def test_an_epoch_bump_ends_every_open_session(gateway, guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    opened(client, upstream)
    opened(client, upstream, user="Second conversation")
    sessions = [e["session_id"] for e in events(audit, "session_opened")]
    client.app.state.gateway.bump_epoch()
    for session_id in sessions:
        assert wait_for_end(audit, session_id)["reason"] == "cancelled"
        assert_ends_with_session_end(tmp_path, session_id, "cancelled")


class UnmarkableLine:
    """Stalls the next answer line past the deadline, then fails its discards line, which retires the session."""

    def __init__(self, inner):
        self.inner, self.stall = inner, True

    def append(self, session_id, direction, envelope, **kwargs):
        if kwargs.get("discards"):
            raise OSError("disk full")
        if direction == "resp" and envelope is not None and self.stall:
            self.stall = False
            time.sleep(0.5)
        self.inner.append(session_id, direction, envelope, **kwargs)


def test_a_retired_session_ends_once_its_request_lets_go(gateway, guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_DECISION_TIMEOUT_MS="300")
    opened(client, upstream)
    gw = client.app.state.gateway
    gw.guardian.transcript = UnmarkableLine(gw.guardian.transcript)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request(user="First conversation"))
    (retired,) = events(audit, "session_retired")
    ended = wait_for_end(audit, retired["session_id"])
    assert ended["reason"] == "error"
    assert_ends_with_session_end(tmp_path, retired["session_id"], "error")


def test_a_graceful_shutdown_ends_every_open_session(gateway, guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    opened(client, upstream)
    (session_id,) = [e["session_id"] for e in events(audit, "session_opened")]
    client.__exit__(None, None, None)
    try:
        # The lifespan waits for the end before it returns, so nothing is left to poll for.
        assert [e["reason"] for e in events(audit, "session_ended")] == ["cancelled"]
        assert_ends_with_session_end(tmp_path, session_id, "cancelled")
    finally:
        client.__enter__()


def test_a_session_the_guardian_refused_sends_nothing(gateway, harness_guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_FAIL_HELLOS="1"))
    opened(client, upstream)
    client.app.state.gateway.bump_epoch()
    client.__exit__(None, None, None)
    client.__enter__()
    assert events(audit, "session_ended") == []
    assert not [line for line in transcript_lines(tmp_path)
                if line["dir"] == "req" and line["envelope"]["method"] == "steps/sessionEnd"]


def test_off_mode_ends_nothing(gateway, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="off")
    opened(client, upstream)
    client.app.state.gateway.bump_epoch()
    client.__exit__(None, None, None)
    client.__enter__()
    assert events(audit, "session_ended") == [] and transcript_lines(tmp_path) == []


def test_a_failed_session_end_is_audited_and_recorded(gateway, harness_guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_FAIL_END="1"))
    opened(client, upstream)
    (session_id,) = [e["session_id"] for e in events(audit, "session_opened")]
    client.app.state.gateway.bump_epoch()
    assert wait_for_end(audit, session_id)["cause"] == "http_503_error"
    lines = lines_of(tmp_path, session_id)
    assert lines[-2]["envelope"]["method"] == "steps/sessionEnd"
    assert lines[-1] == {"dir": "resp", "envelope": {"detail": "rate limited"}, "cause": "http_503_error"}


def test_a_hanging_session_end_never_holds_shutdown_past_the_bound(gateway, harness_guardian, upstream, audit,
                                                                  tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_SLOW_END_S="30"),
                     ACS_DECISION_TIMEOUT_MS="300")
    opened(client, upstream)
    (session_id,) = [e["session_id"] for e in events(audit, "session_opened")]
    started = time.monotonic()
    client.__exit__(None, None, None)
    try:
        # One decision timeout plus the 1 s grace, with room for a slow machine.
        assert time.monotonic() - started < 3.0
        assert [e["cause"] for e in events(audit, "session_ended")] == ["decision_timeout"]
        lines = lines_of(tmp_path, session_id)
        assert lines[-2]["envelope"]["method"] == "steps/sessionEnd"
        assert lines[-1] == {"dir": "resp", "envelope": None, "cause": "decision_timeout"}
    finally:
        client.__enter__()


def test_a_hanging_session_end_never_holds_up_the_next_session(gateway, harness_guardian, upstream, audit, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_SLOW_END_S="30"),
                     ACS_DECISION_TIMEOUT_MS="300")
    opened(client, upstream)
    client.app.state.gateway.bump_epoch()
    started = time.monotonic()
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    output = client.post("/v1/responses", json=finbot_request(user="First conversation")).json()["output"]
    assert output[0]["call_id"] == "call_1"
    assert time.monotonic() - started < 3.0
