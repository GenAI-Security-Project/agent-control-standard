import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body, transcript_lines

VENDOR = {"name": "Acme", "bank_account_number": "12345678", "bank_routing_number": "021000021"}


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def output_item(call_id, output):
    return {"type": "function_call_output", "call_id": call_id, "output": output}


def run_turns(client, upstream, name, output):
    """FinBot's loop: the model calls a tool, then FinBot resends everything with the tool's output."""
    upstream.reply(response_body(call_item(name, {"vendor_id": 7}, "call_1")))
    upstream.reply(response_body(message_item("done")))
    upstream.reply(response_body(message_item("done again")))
    first = client.post("/v1/responses", json=finbot_request()).json()
    history = [*first["output"], output_item("call_1", output)]
    client.post("/v1/responses", json=finbot_request(*history))
    client.post("/v1/responses", json=finbot_request(*history, {"role": "user", "content": "and again"}))
    return [r.json()["input"] for r in upstream.received]


def sent_output(model_input):
    return [i for i in model_input if i.get("type") == "function_call_output"][0]["output"]


def test_a_redacted_value_never_reaches_the_upstream(gateway, harness_guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    inputs = run_turns(client, upstream, "get_vendor_details", json.dumps(VENDOR))
    assert json.loads(sent_output(inputs[1])) == {**VENDOR, "bank_account_number": "[REDACTED]"}
    assert json.loads(sent_output(inputs[2])) == {**VENDOR, "bank_account_number": "[REDACTED]"}
    assert all("12345678" not in json.dumps(i) for i in inputs)
    results = [e for e in events(audit, "decision_applied") if e["method"] == "steps/toolCallResult"]
    assert len(results) == 1 and results[0]["decision"] == "modify"


def test_the_result_names_the_request_it_answers(gateway, harness_guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    run_turns(client, upstream, "get_vendor_details", json.dumps(VENDOR))
    requests = [line["envelope"] for line in transcript_lines(tmp_path) if line["dir"] == "req"]
    call = next(e for e in requests if e["method"] == "steps/toolCallRequest")["params"]
    result = next(e for e in requests if e["method"] == "steps/toolCallResult")["params"]
    assert result["payload"]["request_id_ref"] == call["request_id"]
    assert result["payload"]["outputs"] == [{"value": VENDOR}]


def test_a_denied_output_reaches_the_model_as_the_neutral_line(gateway, harness_guardian, upstream):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    inputs = run_turns(client, upstream, "leaky_tool", "secret ledger")
    assert sent_output(inputs[1]) == NEUTRAL
    assert sent_output(inputs[2]) == NEUTRAL


def test_a_redaction_that_does_not_resolve_withholds_the_output(gateway, harness_guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    inputs = run_turns(client, upstream, "bad_path_tool", json.dumps(VENDOR))
    assert sent_output(inputs[1]) == NEUTRAL
    applied = [e for e in events(audit, "decision_applied") if e["method"] == "steps/toolCallResult"][0]
    assert applied["decision"] == "deny" and applied["cause"] == "modify_unsupported"


def test_modified_content_replaces_a_text_output(gateway, harness_guardian, upstream):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    inputs = run_turns(client, upstream, "text_tool", "a long private summary")
    assert sent_output(inputs[1]) == "summary withheld"


def test_the_result_is_named_by_the_gateways_own_record(gateway, harness_guardian, upstream):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    client.post("/v1/responses", json=finbot_request())
    renamed = {**call, "name": "plain_tool"}
    client.post("/v1/responses", json=finbot_request(renamed, output_item("call_1", json.dumps(VENDOR))))
    assert "12345678" not in upstream.received[-1].body.decode()


def test_a_result_for_a_call_the_gateway_never_saw_uses_the_client_name_and_says_so(gateway, guardian, upstream,
                                                                                    audit, tmp_path):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_9")
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request(call, output_item("call_9", "{}")))
    requests = [line["envelope"] for line in transcript_lines(tmp_path) if line["dir"] == "req"]
    assert requests[-1]["params"]["payload"]["tool"]["name"] == "get_vendor_details"
    assert [e["call_id"] for e in events(audit, "result_name_from_client")] == ["call_9"]


ROWS = {"rows": [["Acme", "12345678"], ["Initech", "87654321"]]}


@pytest.mark.parametrize(("path", "output", "expected"), [
    # A redaction that replaces the output item, or the outputs array, leaves nothing to read back.
    ("/outputs/0", json.dumps(VENDOR), NEUTRAL),
    ("/outputs", json.dumps(VENDOR), NEUTRAL),
    ("/outputs/0/value", "secret ledger", "[REDACTED]"),
    ("/outputs/0/value", json.dumps(VENDOR), json.dumps("[REDACTED]")),
    ("/outputs/0/value/rows/1/1", json.dumps(ROWS),
     json.dumps({"rows": [["Acme", "12345678"], ["Initech", "[REDACTED]"]]})),
])
def test_a_redaction_of_the_output_itself_is_honored_without_failing(gateway, harness_guardian, upstream, audit,
                                                                      path, output, expected):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(HARNESS_REDACT_PATH=path))
    inputs = run_turns(client, upstream, "redact_path_tool", output)
    assert sent_output(inputs[1]) == expected
    assert sent_output(inputs[2]) == expected
    applied = [e for e in events(audit, "decision_applied") if e["method"] == "steps/toolCallResult"]
    assert len(applied) == 1 and applied[0]["decision"] == "modify"


@pytest.mark.parametrize("path", ["/outputs/0/value/²", "/outputs/²", "/outputs/0/value/rows/١", "/outputs/0/value/rows/01"])
def test_no_guardian_path_makes_apply_result_raise(path):
    from acs.core._decision import Decision
    from acs_gateway.apply import apply_result, result_payload
    from acs_gateway.guardian import StepResult

    item = output_item("call_1", json.dumps(ROWS))
    payload, parsed, _ = result_payload("redact_path_tool", item["output"], None)
    result = StepResult("steps/toolCallResult", "r1", Decision("modify", "", {"redactions": [{"path": path}]}))
    applied = apply_result(item, payload, parsed, result)
    assert applied.item["output"] == NEUTRAL
