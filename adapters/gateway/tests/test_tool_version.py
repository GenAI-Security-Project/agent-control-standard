"""tool.version carries the declaration digest the policy pins (LAB-07, issue #580, A.10)."""
from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

from acs_gateway.tool_digest import tool_digests

PINNED = {"type": "function", "name": "pinned_tool", "description": "Send an email to a recipient",
          "parameters": {"type": "object", "properties": {"to": {"type": "string"}}, "required": ["to"]},
          "strict": True}
CALL = response_body(call_item("pinned_tool", {"to": "ops@ns1.finbot"}, "call_1"))


def declaring(*tools, user="Pay vendor 7"):
    return {**finbot_request(user=user), "tools": list(tools)}


def sent_versions(tmp_path):
    return [line["envelope"]["params"]["payload"]["tool"].get("version") for line in transcript_lines(tmp_path)
            if line["dir"] == "req" and line["envelope"].get("method") == "steps/toolCallRequest"]


def decisions(audit):
    return [(e["decision"], e.get("reason_codes")) for e in audit() if e["acs_audit_event"] == "decision_applied"]


def test_the_policy_sees_the_declarations_digest(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    body = finbot_request()
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=body)
    assert sent_versions(tmp_path) == [tool_digests(body)["get_vendor_details"]]
    assert sent_versions(tmp_path)[0].startswith("sha256:")


def test_one_changed_description_character_turns_a_pinned_pass_into_a_mismatch_deny(
        gateway, harness_guardian, upstream, audit, tmp_path):
    clean = declaring(PINNED)
    poisoned = declaring({**PINNED, "description": PINNED["description"] + "."}, user="Pay vendor 8")
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(
        HARNESS_PINNED_VERSION=tool_digests(clean)["pinned_tool"]))
    upstream.reply(CALL)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=clean).json() == CALL
    assert client.post("/v1/responses", json=poisoned).json()["output"][0]["content"][0]["text"] == NEUTRAL
    # Each session writes its own transcript file, so the two lines come back in no fixed order.
    assert sorted(sent_versions(tmp_path)) == sorted([tool_digests(clean)["pinned_tool"],
                                                      tool_digests(poisoned)["pinned_tool"]])
    assert decisions(audit) == [("allow", []), ("deny", ["tool_content_hash_mismatch"])]


def test_a_changed_schema_changes_what_the_policy_sees(gateway, guardian, upstream, tmp_path):
    loosened = {**PINNED, "parameters": {**PINNED["parameters"], "required": []}}
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(CALL)
    upstream.reply(CALL)
    client.post("/v1/responses", json=declaring(PINNED))
    client.post("/v1/responses", json=declaring(loosened, user="Pay vendor 8"))
    assert sorted(sent_versions(tmp_path)) == sorted([tool_digests(declaring(PINNED))["pinned_tool"],
                                                      tool_digests(declaring(loosened))["pinned_tool"]])


def test_an_undeclared_call_carries_no_version(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("bash", {"command": "ls"}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    payload = [line["envelope"]["params"]["payload"] for line in transcript_lines(tmp_path)
               if line["envelope"].get("method") == "steps/toolCallRequest"]
    assert payload == [{"tool": {"name": "bash"}, "arguments": {"command": {"value": "ls"}}}]


def test_shadow_sends_the_digest_too(gateway, guardian, upstream, tmp_path):
    upstream.reply(CALL)
    gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=declaring(PINNED))
    assert sent_versions(tmp_path) == [tool_digests(declaring(PINNED))["pinned_tool"]]


def test_a_cached_call_is_gated_again_when_its_declaration_changes_in_the_same_conversation(
        gateway, harness_guardian, upstream, audit, tmp_path):
    # One conversation (same system and first user message), and the model repeats call_1 word for word.
    poisoned = {**PINNED, "description": PINNED["description"] + "."}
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(
        HARNESS_PINNED_VERSION="sha256:a6a1d60a57a24d1a6dbd9dc93e8f0cae4487ee001d3671b490dac9f046a6feb4"))
    upstream.reply(CALL)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(PINNED)).json() == CALL
    second = client.post("/v1/responses", json=declaring(poisoned)).json()
    assert second["output"][0]["content"][0]["text"] == NEUTRAL
    assert decisions(audit) == [("allow", []), ("deny", ["tool_content_hash_mismatch"])]
