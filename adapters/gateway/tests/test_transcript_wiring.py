"""The transcript holds exactly what crossed the wire, through acs.client's on_wire hook (issue #577, PREMORTEM P6)."""
import time
import uuid

import pytest

from conftest import call_item, finbot_request, message_item, response_body, transcript_lines


def methods(lines):
    return [(line["dir"], (line["envelope"] or {}).get("method")) for line in lines]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_the_handshake_reaches_the_transcript(gateway, guardian, upstream, tmp_path, mode):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    assert methods(lines)[:3] == [("req", "handshake/hello"), ("resp", None), ("req", "steps/sessionStart")]
    hello = lines[1]["envelope"]
    assert hello["id"] == lines[0]["envelope"]["id"] and "negotiated_version" in hello["result"]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_each_envelope_is_written_once_in_send_order(gateway, guardian, upstream, tmp_path, mode):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
                                 call_item("bash", {"command": "rm -rf /"}, "call_2")))
    gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    assert [line["dir"] for line in lines] == ["req", "resp"] * 4
    ids = [line["envelope"]["params"]["request_id"] for line in lines if line["dir"] == "req"]
    assert len(set(ids)) == len(ids) == 4
    for req, resp in zip(lines[::2], lines[1::2]):
        assert resp["envelope"]["id"] == req["envelope"]["id"]


def test_a_tampered_answer_is_written_verbatim(gateway, harness_guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("tampered_tool", {}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian()).post("/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    assert lines[-2]["envelope"]["method"] == "steps/toolCallRequest"
    # The line holds the answer as it arrived, so a verifier sees the tampered signature itself.
    assert lines[-1]["envelope"]["result"]["decision"] == "allow" and "cause" not in lines[-1]


def test_a_body_that_is_no_envelope_keeps_its_gap_line(gateway, harness_guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("rate_limited_tool", {}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian()).post("/v1/responses", json=finbot_request())
    assert transcript_lines(tmp_path)[-1] == {"dir": "resp", "envelope": None, "cause": "http_429_error"}


def test_a_request_line_is_written_before_the_send(gateway, guardian, upstream, tmp_path, monkeypatch):
    from acs.client import _exchange

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request())
    seen = []
    real_post = _exchange.post

    def post(body, **kwargs):
        seen.append(methods(transcript_lines(tmp_path))[-1])
        return real_post(body, **kwargs)

    monkeypatch.setattr(_exchange, "post", post)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request())
    assert seen == [("req", "steps/toolCallRequest")]


def test_a_step_retired_after_its_request_line_never_posts(monkeypatch):
    from acs.client import _exchange

    from acs_gateway import guardian as guardian_module
    from acs_gateway.config import GatewayConfig
    from acs_gateway.guardian import StepToken

    posted = []
    monkeypatch.setattr(_exchange, "post", lambda *a, **k: posted.append(1))
    token = StepToken(time.monotonic() + 5)
    lines = []

    class RetiringTranscript:
        def append(self, session_id, direction, envelope, **kwargs):
            lines.append(direction)
            if direction == "req":
                token.retire()

    client = guardian_module.GuardianClient(GatewayConfig.from_env({"ACS_LAB_MODE": "enforce"}), RetiringTranscript())
    posture = client.posture({"on_decision_failure": "deny"})
    outcome, _ = client._send(str(uuid.uuid4()), "steps/toolCallRequest",
                              {"tool": {"name": "x"}, "arguments": {}}, posture, token)
    assert outcome is None and posted == [] and lines == ["req"]
