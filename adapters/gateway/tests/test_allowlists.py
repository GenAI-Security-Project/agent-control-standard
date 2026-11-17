"""Shadow and enforce accept only what FinBot sends, by allowlist (fix round 3 principle, CR3-1 to CR3-3, CR3-7)."""
import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_every_field_finbot_sends_is_accepted(gateway, guardian, upstream, mode):
    body = {**finbot_request(), "stream": False, "temperature": 1, "max_output_tokens": 5000,
            "text": {"format": {"type": "json_schema", "name": "x", "schema": {"type": "object"}, "strict": True}}}
    assert gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=body).status_code == 200


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("field,value", [("prompt", {"id": "pmpt_1"}), ("previous_response_id", "resp_1"),
                                         ("conversation", "conv_1"), ("background", True),
                                         ("include", ["file_search_call.results"]), ("anything_new", 1)])
def test_a_field_outside_the_allowlist_is_refused_in_enforce_and_recorded_in_shadow(gateway, guardian, upstream, audit, mode, field, value):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json={**finbot_request(), field: value})
    if mode == "enforce":
        assert response.status_code == 501
        assert field in response.json()["error"]["message"]
        assert upstream.received == []
    else:
        # Shadow observes only, so it records the field and forwards the request unchanged.
        assert response.status_code == 200
        assert upstream.received[0].json()[field] == value
    assert [e["field"] for e in events(audit, "unsupported_field")] == [field]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("item", [
    {"type": "item_reference", "id": "fc_stored"},
    {"type": "mcp_call", "id": "mcp_1", "name": "send", "arguments": "{}", "server_label": "x", "output": "secret"},
    {"type": "file_search_call", "id": "fs_1", "queries": ["x"], "status": "completed"},
    {"type": "code_interpreter_call", "id": "ci_1", "code": "print(1)", "status": "completed"},
    {"type": "web_search_call", "id": "ws_1", "status": "completed"},
    {"type": "computer_call_output", "call_id": "c1", "output": {"type": "computer_screenshot"}},
    {"type": "custom_tool_call_output", "call_id": "c1", "output": "secret"},
    {"type": "mcp_approval_response", "approval_request_id": "mcpr_1", "approve": True},
    "a bare string",
])
def test_an_input_item_outside_the_allowlist_is_refused_in_enforce_and_recorded_in_shadow(gateway, guardian, upstream, audit, mode, item):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request(item))
    kind = item["type"] if isinstance(item, dict) else "str"
    if mode == "enforce":
        assert response.status_code == 501
        assert kind in response.json()["error"]["message"]
        assert upstream.received == []
    else:
        assert response.status_code == 200
        assert upstream.received[0].json()["input"][-1] == item
    assert [e["item_type"] for e in events(audit, "unsupported_item_type")] == [kind]


def test_allowed_input_items_pass(gateway, guardian, upstream):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    items = [{"type": "message", "role": "assistant", "content": "earlier"}, {"type": "reasoning", "id": "rs_1",
             "summary": []}, call, {"type": "function_call_output", "call_id": "call_1", "output": "{}"}]
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request(*items))
    assert response.status_code == 200


@pytest.mark.parametrize("item", [
    {"type": "custom_tool_call", "id": "ctc_1", "call_id": "c1", "name": "patch", "input": "rm -rf /"},
    {"type": "local_shell_call", "id": "lsh_1", "call_id": "c1", "status": "completed",
     "action": {"type": "exec", "command": ["rm"], "env": {}}},
    {"type": "computer_call", "id": "cu_1", "call_id": "c1", "action": {"type": "click", "x": 1, "y": 1}},
    {"type": "mcp_call", "id": "mcp_1", "name": "send", "arguments": "{}", "server_label": "x"},
    {"type": "mcp_approval_request", "id": "mcpr_1", "name": "send", "arguments": "{}", "server_label": "x"},
    {"type": "mcp_list_tools", "id": "mcpl_1", "server_label": "x", "tools": []},
    {"type": "image_generation_call", "id": "ig_1", "status": "completed", "result": "aGk="},
    {"type": "something_new", "id": "x_1"},
])
def test_enforce_removes_an_output_item_outside_the_allowlist(gateway, guardian, upstream, audit, item):
    upstream.reply(response_body(item))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [i["type"] for i in output] == ["message"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "unsupported_item_type")[0]["item_type"] == item["type"]


def test_shadow_records_an_output_item_outside_the_allowlist_and_forwards_it(gateway, guardian, upstream, audit):
    item = {"type": "custom_tool_call", "id": "ctc_1", "call_id": "c1", "name": "patch", "input": "x"}
    upstream.reply(response_body(message_item("hi"), item))
    output = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[1] == item
    assert events(audit, "unsupported_item_type")[0]["item_type"] == "custom_tool_call"


def test_off_forwards_any_field_and_item(gateway, upstream):
    body = {**finbot_request({"type": "item_reference", "id": "x"}), "prompt": {"id": "p"}}
    assert gateway().post("/v1/responses", json=body).status_code == 200


def test_shadow_never_blocks_a_run_that_resends_an_unknown_output_item(gateway, guardian, upstream, audit):
    item = {"type": "custom_tool_call", "id": "ctc_1", "call_id": "c1", "name": "patch", "input": "x"}
    upstream.reply(response_body(item))
    client = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian)
    first = client.post("/v1/responses", json=finbot_request()).json()["output"]
    second = client.post("/v1/responses", json=finbot_request(*first))
    assert second.status_code == 200
    assert [e["direction"] for e in events(audit, "unsupported_item_type")] == ["output", "input"]
