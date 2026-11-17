"""A call or output without a non-empty string call_id can't be gated or cached (review CR7-1, CR7-2, CR7-5)."""
import pytest

from conftest import finbot_request


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


BAD_IDS = [7, None, "", ["c1"]]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("kind", ["function_call", "function_call_output"])
@pytest.mark.parametrize("call_id", BAD_IDS)
def test_an_item_without_a_string_call_id_is_refused_in_enforce_and_recorded_in_shadow(
        gateway, guardian, upstream, audit, mode, kind, call_id):
    item = ({"type": "function_call", "name": "send", "arguments": "{}"} if kind == "function_call"
            else {"type": "function_call_output", "output": "secret"})
    if call_id is not None:
        item["call_id"] = call_id
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request(item))
    if mode == "enforce":
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "call_id_invalid"
        assert upstream.received == []
    else:
        assert response.status_code == 200
        assert upstream.received[0].json()["input"][-1] == item
    assert [e["item_type"] for e in events(audit, "call_id_invalid")] == [kind]


def test_a_refused_request_on_a_new_conversation_opens_no_session(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    item = {"type": "function_call_output", "call_id": 7, "output": "x"}
    response = client.post("/v1/responses", json=finbot_request(item, user="a brand new run"))
    assert response.status_code == 400
    assert events(audit, "session_opened") == []
    assert client.app.state.gateway.sessions._sessions == {}


def test_a_repeated_key_refusal_on_a_new_conversation_opens_no_session(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    item = {"type": "function_call", "call_id": "c9", "name": "send", "arguments": '{"to": "a", "to": "b"}'}
    response = client.post("/v1/responses", json=finbot_request(item, user="another new run"))
    assert response.status_code == 400
    assert events(audit, "session_opened") == []
    assert client.app.state.gateway.sessions._sessions == {}
