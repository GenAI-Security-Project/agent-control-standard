"""JSON nested past the parser's recursion limit is unparseable, never a 500 (review CR4)."""
import json

from conftest import NEUTRAL, call_item, finbot_request, response_body

DEEP = "[" * 100000 + "]" * 100000


def deep_request() -> bytes:
    return ('{"model": "gpt-5-nano", "input": ' + DEEP + "}").encode()


def test_a_deeply_nested_request_gets_400_when_governed(gateway, guardian, upstream):
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=deep_request(), headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert upstream.received == []


def test_off_relays_a_deeply_nested_request_without_parsing_it(gateway, upstream):
    response = gateway().post("/v1/responses", content=deep_request(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert upstream.received[0].body == deep_request()


def test_deeply_nested_arguments_deny_the_call(gateway, guardian, upstream):
    upstream.reply(response_body(call_item("get_vendor_details", '{"a": ' + DEEP + "}", "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL


def test_a_deeply_nested_output_is_gated_as_text(gateway, guardian, upstream, audit):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    output = {"type": "function_call_output", "call_id": "call_1", "output": DEEP}
    response = client.post("/v1/responses", json=finbot_request(call, output))
    assert response.status_code == 200
    results = [e for e in audit() if e["acs_audit_event"] == "decision_applied"
               and e["method"] == "steps/toolCallResult"]
    assert len(results) == 1
    assert json.loads(upstream.received[-1].body)["input"][-1]["output"] == DEEP
