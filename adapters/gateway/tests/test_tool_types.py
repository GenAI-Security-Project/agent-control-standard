"""Function tools only: every other tool type is refused or neutralized in shadow and enforce (C1, S1 to S3)."""
import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body

FUNCTION_TOOL = {"type": "function", "name": "get_vendor_details", "parameters": {"type": "object"}}


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("tool", [{"type": "custom", "name": "patch"}, {"type": "local_shell"}, {"type": "shell"},
                                  {"type": "apply_patch"}, {"type": "computer_use_preview"},
                                  {"type": "mcp", "server_label": "x", "server_url": "https://mcp.example.com"},
                                  {"type": "code_interpreter"}, {"type": "web_search"}, {"type": "file_search"},
                                  "function"])
def test_a_request_declaring_a_non_function_tool_is_refused(gateway, guardian, upstream, audit, mode, tool):
    body = {**finbot_request(), "tools": [FUNCTION_TOOL, tool]}
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=body)
    assert response.status_code == 501
    assert response.json()["error"]["type"] == "invalid_request_error"
    assert upstream.received == []
    assert len(events(audit, "unsupported_tool_type")) == 1


def test_off_forwards_any_tool_type(gateway, upstream):
    body = {**finbot_request(), "tools": [{"type": "web_search"}]}
    assert gateway().post("/v1/responses", json=body).status_code == 200


@pytest.mark.parametrize("item", [
    {"type": "custom_tool_call", "id": "ctc_1", "call_id": "c1", "name": "patch", "input": "rm -rf /"},
    {"type": "local_shell_call", "id": "lsh_1", "call_id": "c1", "status": "completed",
     "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}}},
    {"type": "shell_call", "id": "sh_1", "call_id": "c1", "action": {"commands": ["rm -rf /"]}},
    {"type": "apply_patch_call", "id": "ap_1", "call_id": "c1", "operation": {"type": "delete_file", "path": "/"}},
    {"type": "computer_call", "id": "cu_1", "call_id": "c1", "action": {"type": "click", "x": 1, "y": 1}},
    {"type": "mcp_call", "id": "mcp_1", "name": "send", "arguments": "{}", "server_label": "x"},
    {"type": "mcp_approval_request", "id": "mcpr_1", "name": "send", "arguments": "{}", "server_label": "x"},
])
def test_enforce_removes_a_non_function_call_from_the_output(gateway, guardian, upstream, audit, item):
    upstream.reply(response_body(item))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert [i["type"] for i in output] == ["message"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "unsupported_tool_type")[0]["item_type"] == item["type"]


def test_shadow_records_a_non_function_call_and_forwards_it(gateway, guardian, upstream, audit):
    item = {"type": "custom_tool_call", "id": "ctc_1", "call_id": "c1", "name": "patch", "input": "x"}
    upstream.reply(response_body(message_item("hi"), item))
    output = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[1] == item
    assert events(audit, "unsupported_tool_type")[0]["item_type"] == "custom_tool_call"


@pytest.mark.parametrize("item,field,expected", [
    ({"type": "custom_tool_call_output", "call_id": "c1", "output": "secret"}, "output", NEUTRAL),
    ({"type": "local_shell_call_output", "id": "lsh_1", "output": "secret"}, "output", NEUTRAL),
    ({"type": "shell_call_output", "call_id": "c1", "output": "secret"}, "output", NEUTRAL),
    ({"type": "computer_call_output", "call_id": "c1", "output": {"type": "computer_screenshot"}}, "output", NEUTRAL),
    ({"type": "mcp_approval_response", "approval_request_id": "mcpr_1", "approve": True}, "approve", False),
])
def test_enforce_neutralizes_a_non_function_output_in_the_input(gateway, guardian, upstream, audit, item, field,
                                                                expected):
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request(item))
    sent = upstream.received[0].json()["input"][-1]
    assert sent["type"] == item["type"] and sent[field] == expected
    assert events(audit, "unsupported_tool_type")[0]["item_type"] == item["type"]
