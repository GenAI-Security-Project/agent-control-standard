import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body, transcript_lines


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def test_startup_waits_for_the_guardian_and_fails_when_it_never_answers(gateway):
    with pytest.raises(RuntimeError, match="system/ping"):
        gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL="http://127.0.0.1:9/", ACS_GUARDIAN_READY_TIMEOUT_S="1")


def test_an_allowed_call_is_returned_unchanged(gateway, guardian, upstream, audit, tmp_path):
    reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"))
    upstream.reply(reply)
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.status_code == 200
    assert response.json() == reply
    lines = transcript_lines(tmp_path)
    methods = [(line["dir"], line["envelope"].get("method")) for line in lines]
    assert methods == [("req", "steps/sessionStart"), ("resp", None),
                       ("req", "steps/toolCallRequest"), ("resp", None)]
    request = lines[2]["envelope"]["params"]
    assert request["payload"] == {"tool": {"name": "get_vendor_details"}, "arguments": {"vendor_id": {"value": 7}}}
    assert lines[3]["envelope"]["result"]["request_id"] == request["request_id"]
    assert len(events(audit, "session_opened")) == 1
    applied = events(audit, "decision_applied")
    assert [(e["method"], e["decision"]) for e in applied] == [("steps/toolCallRequest", "allow")]


def test_a_denied_call_is_removed_and_replaced_by_the_neutral_line(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_1")))
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    output = response.json()["output"]
    assert [item["type"] for item in output] == ["message"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    applied = events(audit, "decision_applied")[0]
    assert applied["decision"] == "deny" and applied["guardian_decision"] == "deny"


def test_a_denied_call_beside_a_message_leaves_the_message_alone(gateway, guardian, upstream):
    upstream.reply(response_body(message_item("Working on it"), call_item("bash", {"command": "rm -rf /"}, "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [item["content"][0]["text"] for item in output] == ["Working on it"]


def test_a_call_with_unsignable_arguments_is_denied(gateway, guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("get_vendor_details", '{"amount": NaN}', "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "envelope_not_signable"
    assert [line["envelope"].get("method") for line in transcript_lines(tmp_path) if line["dir"] == "req"] == [
        "steps/sessionStart"]


def test_a_repeated_call_id_reapplies_the_cached_outcome(gateway, guardian, upstream, audit, tmp_path):
    reply = response_body(call_item("bash", {"command": "rm -rf /"}, "call_1"))
    upstream.reply(reply)
    upstream.reply(reply)
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    first = client.post("/v1/responses", json=finbot_request()).json()
    second = client.post("/v1/responses", json=finbot_request()).json()
    assert first["output"][0]["content"][0]["text"] == second["output"][0]["content"][0]["text"] == NEUTRAL
    requests = [line for line in transcript_lines(tmp_path) if line["envelope"].get("method") == "steps/toolCallRequest"]
    assert len(requests) == 1


def test_parameter_overrides_rewrite_the_arguments(gateway, harness_guardian, upstream):
    upstream.reply(response_body(call_item("override_tool", {"to": "x@evil.example", "body": "hi"}, "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian()).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert json.loads(output[0]["arguments"]) == {"to": "ops@ns1.finbot", "body": "hi"}
    assert output[0]["call_id"] == "call_1"


@pytest.mark.parametrize("tool,cause,extra_event", [
    ("slow_tool", "decision_timeout", None),
    ("rate_limited_tool", "http_429_error", "guardian_http_error"),
    ("tampered_tool", "response_signature_invalid", "verification_failed"),
])
def test_a_decision_failure_denies_and_says_why(gateway, harness_guardian, upstream, audit, tool, cause, extra_event):
    upstream.reply(response_body(call_item(tool, {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(), ACS_DECISION_TIMEOUT_MS="500")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    applied = events(audit, "decision_applied")[0]
    assert applied["decision"] == "deny" and applied["cause"] == cause
    if extra_event:
        assert events(audit, extra_event)[0]["cause"] == cause


@pytest.mark.parametrize("tool", ["ask_tool", "defer_tool"])
def test_ask_and_defer_deny(gateway, harness_guardian, upstream, audit, tool):
    upstream.reply(response_body(call_item(tool, {}, "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian()).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    applied = events(audit, "decision_applied")[0]
    assert applied["decision"] == "deny" and applied["guardian_decision"] == tool.split("_")[0]


@pytest.mark.parametrize("guardian_env", [{"ACS_ON_DECISION_FAILURE": "proceed"}, {"HARNESS_OMIT_POSTURE": "1"}])
def test_the_server_hello_never_loosens_the_fail_closed_posture(gateway, harness_guardian, upstream, audit,
                                                                 guardian_env):
    upstream.reply(response_body(call_item("slow_tool", {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(**guardian_env),
                     ACS_DECISION_TIMEOUT_MS="500")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "decision_timeout"


def test_a_call_without_a_call_id_is_removed(gateway, guardian, upstream):
    item = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    del item["call_id"]
    upstream.reply(response_body(item))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [i["type"] for i in output] == ["message"]
    assert output[0]["content"][0]["text"] == NEUTRAL


def test_a_transcript_that_cannot_be_written_denies(gateway, guardian, upstream, audit, tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("a file where the transcript directory should be")
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_TRANSCRIPT_DIR=str(blocker)).post(
        "/v1/responses", json=finbot_request())
    assert response.status_code == 200
    assert response.json()["output"][0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "adapter_exception"


class FailingTranscript:
    def append(self, *args):
        raise OSError("disk full")


def test_a_step_whose_transcript_line_fails_denies(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request())
    client.app.state.gateway.guardian.transcript = FailingTranscript()
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 200
    assert response.json()["output"][0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "adapter_exception"


@pytest.mark.parametrize("tool,cause", [("slow_tool", "decision_timeout"), ("rate_limited_tool", "http_429_error"),
                                        ("tampered_tool", "response_signature_invalid")])
def test_a_step_without_a_usable_answer_leaves_an_explicit_gap_in_the_transcript(gateway, harness_guardian, upstream,
                                                                                  tmp_path, tool, cause):
    upstream.reply(response_body(call_item(tool, {}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(), ACS_DECISION_TIMEOUT_MS="500").post(
        "/v1/responses", json=finbot_request())
    lines = transcript_lines(tmp_path)
    assert lines[2]["dir"] == "req" and lines[2]["envelope"]["method"] == "steps/toolCallRequest"
    assert lines[3] == {"dir": "resp", "envelope": None, "cause": cause}


def reasoning(item_id):
    return {"type": "reasoning", "id": item_id, "summary": [], "encrypted_content": "opaque"}


def test_removing_a_call_also_removes_the_reasoning_that_led_to_it(gateway, guardian, upstream):
    upstream.reply(response_body(reasoning("rs_1"), call_item("bash", {"command": "rm -rf /"}, "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [i["type"] for i in output] == ["message"]
    assert output[0]["content"][0]["text"] == NEUTRAL


def test_reasoning_before_a_kept_item_stays(gateway, guardian, upstream):
    upstream.reply(response_body(reasoning("rs_1"), message_item("thinking out loud"), reasoning("rs_2"),
                                 call_item("bash", {"command": "rm -rf /"}, "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [(i["type"], i["id"]) for i in output] == [("reasoning", "rs_1"), ("message", "msg_1")]


def test_a_failed_handshake_is_retried_on_the_next_request(gateway, harness_guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_FAIL_HELLOS="1"))
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    first = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert first[0]["content"][0]["text"] == NEUTRAL
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 8}, "call_2")))
    second = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert second[0]["call_id"] == "call_2"
    opened = events(audit, "session_opened")
    assert [e["handshake"] for e in opened] == ["NoAnswer", "Negotiated"]
    assert opened[0]["session_id"] != opened[1]["session_id"]


def test_time_queued_for_a_worker_counts_against_the_decision_timeout(gateway, guardian, upstream, audit, tmp_path):
    import time

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_DECISION_TIMEOUT_MS="500",
                     ACS_GATEWAY_WORKERS="1")
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request())
    client.app.state.gateway.executor.submit(time.sleep, 1.5)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "decision_timeout"
    assert not [line for line in transcript_lines(tmp_path) if line["envelope"]
                and line["envelope"].get("method") == "steps/toolCallRequest"]


def test_a_request_whose_transcript_line_fails_never_reaches_the_guardian(gateway, harness_guardian, upstream,
                                                                          tmp_path):
    received = tmp_path / "guardian-received.txt"
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_COUNT_FILE=str(received)))
    upstream.reply(response_body(message_item("hello")))
    client.post("/v1/responses", json=finbot_request())
    client.app.state.gateway.guardian.transcript = FailingTranscript()
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client.post("/v1/responses", json=finbot_request())
    assert "steps/toolCallRequest" not in received.read_text().split()
    assert "steps/sessionStart" in received.read_text().split()


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_server_hello_that_skips_tool_calls_denies_them(gateway, harness_guardian, upstream, audit, mode):
    url = harness_guardian(HARNESS_OMIT_METHOD="steps/toolCallRequest")
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    output = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=url).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    name = "decision_applied" if mode == "enforce" else "shadow_decision"
    assert [(e["decision"], e["cause"]) for e in events(audit, name)] == [("deny", "method_not_evaluated")]
    if mode == "enforce":
        assert output[0]["content"][0]["text"] == NEUTRAL


def test_reasoning_stays_when_a_later_call_of_its_turn_is_kept(gateway, guardian, upstream):
    upstream.reply(response_body(reasoning("rs_1"), call_item("bash", {"command": "rm -rf /"}, "call_1"),
                                 call_item("get_vendor_details", {"vendor_id": 7}, "call_2")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [(i["type"], i.get("call_id")) for i in output] == [("reasoning", None), ("function_call", "call_2")]
