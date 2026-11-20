import json

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body, transcript_lines

VENDOR = {"name": "Acme", "bank_account_number": "12345678"}


def test_nothing_of_acs_reaches_the_client_or_the_model(gateway, harness_guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    headers = {"Authorization": "Bearer lab-dummy", "X-ACS-Lab-Session": "s1", "X-ACS-Lab-Branch": "a"}
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_0"),
                                 call_item("override_tool", {"to": "x@evil.example"}, "call_1"),
                                 call_item("get_vendor_details", {"vendor_id": 7}, "call_2")))
    upstream.reply(response_body(message_item("done")))
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_3")))
    seen_by_client = []
    first = client.post("/v1/responses", json=finbot_request(), headers=headers)
    seen_by_client.append(first)
    history = [*first.json()["output"],
               {"type": "function_call_output", "call_id": "call_1", "output": "sent"},
               {"type": "function_call_output", "call_id": "call_2", "output": json.dumps(VENDOR)}]
    seen_by_client.append(client.post("/v1/responses", json=finbot_request(*history), headers=headers))
    seen_by_client.append(client.post("/v1/responses", json=finbot_request(user="other run"), headers=headers))

    lines = transcript_lines(tmp_path)
    secrets = {"x-acs", "acs_version", "chain_hash", "guardian", "request_id", "session_id", "12345678"}
    for line in lines:
        envelope = line["envelope"]
        container = envelope.get("params") or envelope.get("result") or {}
        secrets |= {container.get("request_id"), (container.get("metadata") or {}).get("session_id"),
                    (container.get("signature") or {}).get("value"), envelope.get("id")}
        secrets |= set(container.get("reason_codes") or [])
        secrets.add(container.get("reasoning"))
    secrets.discard(None)
    assert {"destructive_command", "external_recipient", "sensitive_field_redacted"} <= secrets

    client_text = [r.text + json.dumps(dict(r.headers)) for r in seen_by_client]
    model_text = [r.body.decode() + json.dumps(r.headers) for r in upstream.received]
    for text in client_text + model_text:
        lowered = text.lower()
        for secret in secrets:
            assert secret.lower() not in lowered, secret
    disclosed = [item for r in seen_by_client for item in r.json()["output"] if item["type"] == "message"]
    assert NEUTRAL in [m["content"][0]["text"] for m in disclosed]
