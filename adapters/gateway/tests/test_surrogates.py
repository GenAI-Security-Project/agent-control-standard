"""A lone surrogate in a request never crashes a log or transcript write (found by LAB-07)."""
import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body

# JSON text with an escaped lone surrogate, which json.loads turns into a str that can't be encoded as UTF-8.
LONE = '{"model": "gpt-5-nano", "input": [{"role": "system", "content": "S"}, {"role": "user", "content": "hi \\ud800 there"}]}'


@pytest.mark.parametrize("mode", ["off", "shadow"])
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


def test_a_lone_surrogate_in_user_text_is_refused_in_enforce(gateway, guardian, upstream, audit):
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=LONE.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 400 and response.json()["error"]["code"] == "lone_surrogate"
    assert upstream.received == []


def test_a_lone_surrogate_in_call_arguments_is_refused_in_enforce(gateway, guardian, upstream):
    call = {"type": "function_call", "call_id": "c1", "name": "send", "arguments": '{"to": "a\\ud800"}'}
    body = json.dumps(finbot_request(call), ensure_ascii=True)
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=body.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 400 and response.json()["error"]["code"] == "lone_surrogate"


def test_an_audit_line_naming_a_lone_surrogate_key_is_written(gateway, guardian, upstream, audit):
    # Shadow, since enforce now refuses any lone surrogate before the duplicate-key check.
    arguments = json.dumps({"x": 1}).replace('"x": 1', '"\\ud800": 1, "\\ud800": 2')
    forged = {"type": "function_call", "call_id": "c9", "name": "send", "arguments": arguments}
    body = json.dumps(finbot_request(forged), ensure_ascii=True)
    response = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=body.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert [e["key"] for e in audit() if e["acs_audit_event"] == "duplicate_json_key"] == ["\ud800"]


# Each body puts a lone surrogate where an enforce refusal used to echo it into the error message, plus one in an
# ordinary value, which only the boundary check catches.
SURROGATE_BODIES = {
    "field_name": '{"model": "m", "input": "hi", "x\\ud800y": 1}',
    "input_item_type": '{"model": "m", "input": [{"type": "x\\ud800y", "id": "i1"}]}',
    "content_part_type": '{"model": "m", "input": [{"role": "user", "content": [{"type": "x\\ud800y"}]}]}',
    "plain_value": '{"model": "m", "input": "hi \\ud800 there"}',
}


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("case", sorted(SURROGATE_BODIES))
def test_a_lone_surrogate_anywhere_gets_a_documented_answer(gateway, guardian, upstream, audit, mode, case):
    raw = SURROGATE_BODIES[case].encode()
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=raw, headers={"Content-Type": "application/json"})
    if mode == "enforce":
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "lone_surrogate"
        # A fixed message, echoing nothing from the request.
        assert "x" not in error["message"].split() and "\\ud800" not in response.text
        assert upstream.received == []
    else:
        assert response.status_code == 200
        assert upstream.received[0].body == raw
    assert [e["mode"] for e in audit() if e["acs_audit_event"] == "lone_surrogate"] == [mode]
