"""Function tools only: every other tool declaration is refused in shadow and enforce (C1, S1 to S3)."""
import pytest

from conftest import finbot_request

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
