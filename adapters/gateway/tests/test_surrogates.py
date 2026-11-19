"""A lone surrogate in a request never crashes the gateway (found by LAB-07).

Message text is never signed, so it passes. A value that must be signed is denied per step, and every error body and
every log line is written ASCII-escaped, so nothing can fail to encode.
"""
import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body

# JSON text with an escaped lone surrogate, which json.loads turns into a str that can't be encoded as UTF-8.
LONE = '{"model": "gpt-5-nano", "input": [{"role": "system", "content": "S"}, {"role": "user", "content": "hi \\ud800 there"}]}'


@pytest.mark.parametrize("mode", ["off", "shadow", "enforce"])
def test_a_lone_surrogate_in_a_message_is_forwarded_and_logged(gateway, guardian, upstream, mode, tmp_path):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=LONE.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert upstream.received
    logged = [json.loads(line) for line in (tmp_path / "model-inputs.jsonl").read_text().splitlines()]
    assert logged[0]["input"][1]["content"] == "hi \ud800 there"


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_lone_surrogate_in_a_tool_output_denies_only_that_result(gateway, guardian, upstream, audit, mode):
    """Tool output is data an attacker can plant, so it must not wedge the run with a 400 every turn."""
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    body = json.dumps(finbot_request(call, {"type": "function_call_output", "call_id": "call_1",
                                            "output": "bank \ud800 data"}), ensure_ascii=True)
    for turn in range(2):
        # The second turn resends the same output, as an agent does.
        response = client.post("/v1/responses", content=body.encode(), headers={"Content-Type": "application/json"})
        assert response.status_code == 200
        sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call_output"][0]
        # RFC 8785 can't sign a lone surrogate, so the step is refused: the neutral line in enforce, unchanged in shadow.
        assert sent["output"] == (NEUTRAL if mode == "enforce" else "bank \ud800 data")
    name = "decision_applied" if mode == "enforce" else "shadow_decision"
    results = [e for e in audit() if e["acs_audit_event"] == name and e["method"] == "steps/toolCallResult"]
    assert [(e["decision"], e["cause"]) for e in results] == [("deny", "envelope_not_signable")]
    assert [e for e in audit() if e["acs_audit_event"] == "lone_surrogate"] == []


def post_raw(client, body):
    text = json.dumps(body, ensure_ascii=True)
    return client.post("/v1/responses", content=text.encode(), headers={"Content-Type": "application/json"})


def test_a_resent_assistant_message_with_a_lone_surrogate_goes_through(gateway, guardian, upstream):
    relayed = {"type": "message", "role": "assistant", "content": [
        {"type": "output_text", "text": "model said \ud800", "annotations": []}]}
    response = post_raw(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian), finbot_request(relayed))
    assert response.status_code == 200
    assert upstream.received[0].json()["input"][-1] == relayed


def test_user_text_with_a_lone_surrogate_is_forwarded_in_enforce(gateway, guardian, upstream):
    response = post_raw(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian),
                        finbot_request(user="hi \ud800 there"))
    assert response.status_code == 200
    assert upstream.received[0].json()["input"][1]["content"] == "hi \ud800 there"


def test_a_model_call_whose_arguments_hold_a_lone_surrogate_is_denied_per_step(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", '{"note": "x\\ud800"}', "call_1")))
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.status_code == 200
    assert response.json()["output"][0]["content"][0]["text"] == NEUTRAL
    applied = [e for e in audit() if e["acs_audit_event"] == "decision_applied"]
    assert [(e["decision"], e["cause"]) for e in applied] == [("deny", "envelope_not_signable")]


REFUSALS = {
    "field": ({"x\ud800y": 1}, "The x\ud800y parameter is not supported by this endpoint.", "unsupported_parameter"),
    "item_type": ({"input": [{"type": "x\ud800y", "id": "i1"}]},
                  "Input items of type x\ud800y are not supported by this endpoint.", "unsupported_item_type"),
    "part_type": ({"input": [{"role": "user", "content": [{"type": "x\ud800y"}]}]},
                  "Content parts of type x\ud800y are not supported by this endpoint.", "unsupported_content_part"),
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_a_refusal_naming_a_lone_surrogate_is_encoded_safely(gateway, guardian, upstream, case):
    extra, message, code = REFUSALS[case]
    body = {**finbot_request(), **extra}
    response = post_raw(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian), body)
    assert response.status_code == 501
    # The body is ASCII-escaped JSON, so it decodes to the exact message and the name sits in param.
    assert response.content.isascii()
    error = response.json()["error"]
    assert error == {"message": message, "type": "invalid_request_error", "param": "x\ud800y", "code": code}
    assert upstream.received == []
