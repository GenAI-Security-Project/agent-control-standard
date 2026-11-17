import json

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
