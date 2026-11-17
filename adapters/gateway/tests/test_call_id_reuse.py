"""A call_id seen before with different content is never served from the cache (review I6, CR3)."""
import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_reused_call_id_with_new_content_is_flagged(gateway, guardian, upstream, audit, mode):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_1")))
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    second = client.post("/v1/responses", json=finbot_request()).json()["output"]
    reused = events(audit, "call_id_reused")
    assert [(e["call_id"], e["tool"]) for e in reused] == [("call_1", "bash")]
    if mode == "enforce":
        assert [i["type"] for i in second] == ["message"] and second[0]["content"][0]["text"] == NEUTRAL
        assert events(audit, "decision_applied")[-1]["cause"] == "call_id_reused"
    else:
        assert second[0]["name"] == "bash"


def test_a_reused_call_id_with_the_same_content_is_not_flagged(gateway, guardian, upstream, audit):
    reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"))
    upstream.reply(reply)
    upstream.reply(reply)
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    assert client.post("/v1/responses", json=finbot_request()).json() == reply
    assert events(audit, "call_id_reused") == []


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_resent_output_with_new_content_is_flagged(gateway, harness_guardian, upstream, audit, mode):
    call = call_item("text_tool", {}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=harness_guardian())
    client.post("/v1/responses", json=finbot_request())
    first = {"type": "function_call_output", "call_id": "call_1", "output": "original"}
    changed = {**first, "output": "something else entirely"}
    client.post("/v1/responses", json=finbot_request(call, first))
    client.post("/v1/responses", json=finbot_request(call, changed))
    sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call_output"][0]
    assert [e["call_id"] for e in events(audit, "call_id_reused")] == ["call_1"]
    assert sent["output"] == (NEUTRAL if mode == "enforce" else "something else entirely")


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_resent_call_with_a_new_name_is_restored_and_flagged(gateway, guardian, upstream, audit, mode):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    # FinBot rebuilds the call from type, name, call_id and arguments, without id or status.
    renamed = {"type": "function_call", "name": "bash", "call_id": "call_1", "arguments": call["arguments"]}
    client.post("/v1/responses", json=finbot_request(renamed))
    sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call"][0]
    assert sent["name"] == ("get_vendor_details" if mode == "enforce" else "bash")
    assert [(e["call_id"], e["method"]) for e in events(audit, "call_id_reused")] == [
        ("call_1", "steps/toolCallRequest")]


def test_a_faithful_rebuild_of_a_call_is_not_flagged(gateway, guardian, upstream, audit):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    rebuilt = {"type": "function_call", "name": call["name"], "call_id": "call_1", "arguments": call["arguments"]}
    client.post("/v1/responses", json=finbot_request(rebuilt))
    assert events(audit, "call_id_reused") == []


def test_a_reserialized_json_output_is_the_same_output(gateway, guardian, upstream, audit):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    first = {"type": "function_call_output", "call_id": "call_1", "output": '{"a": 1, "b": [1, 2]}'}
    again = {**first, "output": '{ "b":[1,2],\n "a":1 }'}
    client.post("/v1/responses", json=finbot_request(call, first))
    client.post("/v1/responses", json=finbot_request(call, again))
    assert events(audit, "call_id_reused") == []


def test_reserialized_arguments_are_the_same_call(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", '{"vendor_id": 7, "x": "y"}', "call_1")))
    upstream.reply(response_body(call_item("get_vendor_details", '{"x":"y","vendor_id":7}', "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    client.post("/v1/responses", json=finbot_request())
    assert events(audit, "call_id_reused") == []


def test_reserialized_resent_arguments_go_out_as_delivered_without_a_flag(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", '{"vendor_id": 7, "x": "y"}', "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    rebuilt = {"type": "function_call", "name": "get_vendor_details", "call_id": "call_1",
               "arguments": '{"x":"y","vendor_id":7}'}
    client.post("/v1/responses", json=finbot_request(rebuilt))
    sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call"][0]
    assert sent["arguments"] == '{"vendor_id": 7, "x": "y"}'
    assert events(audit, "call_id_reused") == []


def test_names_are_compared_exactly_not_as_json(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("100", {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    renamed = {"type": "function_call", "name": "1e2", "call_id": "call_1", "arguments": "{}"}
    client.post("/v1/responses", json=finbot_request(renamed))
    sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call"][0]
    assert sent["name"] == "100"
    assert [e["call_id"] for e in events(audit, "call_id_reused")] == ["call_1"]


def test_a_restored_resend_is_audited_as_a_modify(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    renamed = {"type": "function_call", "name": "bash", "call_id": "call_1", "arguments": '{"vendor_id": 7}'}
    client.post("/v1/responses", json=finbot_request(renamed))
    applied = [e for e in events(audit, "decision_applied") if e["cause"] == "call_id_reused"]
    assert [(e["decision"], e["method"]) for e in applied] == [("modify", "steps/toolCallRequest")]


def test_an_identical_resend_is_never_canonicalized(gateway, guardian, upstream, monkeypatch):
    import acs_gateway.app as app_module
    import acs_gateway.sessions as sessions_module

    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    output = {"type": "function_call_output", "call_id": "call_1", "output": '{"a": 1}'}
    client.post("/v1/responses", json=finbot_request(call, output))
    calls = []

    def counting(value):
        calls.append(value)
        return value

    monkeypatch.setattr(app_module, "canonical", counting)
    monkeypatch.setattr(sessions_module, "canonical", counting)
    client.post("/v1/responses", json=finbot_request(call, output))
    assert calls == []
