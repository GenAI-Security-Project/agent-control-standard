import pytest

from conftest import finbot_request


def test_other_paths_return_404_with_an_upstream_error_audit(gateway, upstream, audit):
    client = gateway()
    assert client.post("/v1/chat/completions", json={}).status_code == 404
    assert client.get("/v1/responses").status_code == 404
    assert upstream.received == []
    events = [e for e in audit() if e["acs_audit_event"] == "upstream_error"]
    assert [e["cause"] for e in events] == ["route_not_found", "route_not_found"]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_streaming_returns_501_in_shadow_and_enforce_until_lab_05(gateway, guardian, upstream, mode):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json={**finbot_request(), "stream": True})
    assert response.status_code == 501
    assert response.json()["error"]["type"] == "invalid_request_error"
    assert upstream.received == []


def test_unreachable_upstream_returns_502_without_acs_words(gateway, audit):
    client = gateway(ACS_UPSTREAM_URL="http://127.0.0.1:9/v1")
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 502
    text = response.text.lower()
    assert "acs" not in text and "guardian" not in text
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "upstream_error"] == ["upstream_unreachable"]


def test_upstream_error_status_passes_through_and_is_audited(gateway, upstream, audit):
    upstream.reply({"error": {"message": "bad key", "type": "invalid_request_error"}}, status=401)
    response = gateway().post("/v1/responses", json=finbot_request())
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "bad key"
    events = [e for e in audit() if e["acs_audit_event"] == "upstream_error"]
    assert events[0]["cause"] == "upstream_status" and events[0]["http_status"] == 401


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("field,value", [("previous_response_id", "resp_123"), ("conversation", "conv_1"),
                                         ("conversation", {"id": "conv_1"})])
def test_server_side_state_is_refused_in_enforce_and_recorded_in_shadow(gateway, guardian, upstream, audit, mode,
                                                                         field, value):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json={**finbot_request(), field: value})
    if mode == "enforce":
        assert response.status_code == 501
        assert upstream.received == []
    else:
        assert response.status_code == 200
        assert upstream.received[0].json()[field] == value
    assert [e["field"] for e in audit() if e["acs_audit_event"] == "unsupported_field"] == [field]


def test_off_forwards_server_side_state(gateway, upstream):
    assert gateway().post("/v1/responses", json={**finbot_request(), "previous_response_id": "r"}).status_code == 200
