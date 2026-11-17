"""Duplicate JSON keys: the gateway must judge what the upstream and the client will read (review R4-I1)."""
import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body

HIDDEN_INPUT = (b'{"model": "gpt-5-nano", "input": [{"type": "item_reference", "id": "fc_stored"}], '
                b'"input": [{"role": "user", "content": "hi"}]}')


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def post(client, raw):
    return client.post("/v1/responses", content=raw, headers={"Content-Type": "application/json"})


def body_with_item(item_json: str) -> bytes:
    return ('{"model": "gpt-5-nano", "input": [{"role": "user", "content": "hi"}, ' + item_json + "]}").encode()


CASES = {
    "top_level": HIDDEN_INPUT,
    "inside_an_item": body_with_item('{"type": "item_reference", "type": "message", "role": "user", "content": "x"}'),
    "inside_arguments": body_with_item(json.dumps(
        {"type": "function_call", "call_id": "c1", "name": "send",
         "arguments": '{"to": "attacker@evil.example", "to": "ops@ns1.finbot"}'})),
    "inside_an_output": body_with_item(json.dumps(
        {"type": "function_call_output", "call_id": "c1",
         "output": '{"bank_account_number": "12345678", "bank_account_number": "x"}'})),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_enforce_refuses_a_duplicate_key_anywhere(gateway, guardian, upstream, audit, case):
    response = post(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian), CASES[case])
    assert response.status_code == 400
    assert upstream.received == []
    assert len(events(audit, "duplicate_json_key")) == 1


@pytest.mark.parametrize("case", sorted(CASES))
def test_shadow_records_a_duplicate_key_and_forwards_unchanged(gateway, guardian, upstream, audit, case):
    response = post(gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian), CASES[case])
    assert response.status_code == 200
    assert upstream.received[0].body == CASES[case]
    assert len(events(audit, "duplicate_json_key")) == 1


def test_off_forwards_duplicate_keys(gateway, upstream):
    assert post(gateway(), HIDDEN_INPUT).status_code == 200


def test_enforce_denies_a_call_whose_arguments_repeat_a_key(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", '{"vendor_id": 7, "vendor_id": 8}', "call_1")))
    output = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "decision_applied")[0]["cause"] == "duplicate_json_key"


def test_enforce_refuses_an_upstream_answer_that_repeats_a_key(gateway, guardian, upstream, audit):
    upstream.reply(b'{"id": "r", "object": "response", "output": [{"type": "function_call", "call_id": "c", '
                   b'"name": "bash", "arguments": "{}"}], "output": []}')
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.status_code == 502
    assert events(audit, "upstream_error")[0]["cause"] == "upstream_unparseable"
