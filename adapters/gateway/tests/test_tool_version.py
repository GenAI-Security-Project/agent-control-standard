"""tool.version carries the declaration digest the policy pins (LAB-07, issue #580, A.10).

Expected digests are literals, the SHA-256 of each declaration's sorted compact JSON computed apart from the gateway.
For these ASCII-only declarations that is their RFC 8785 form.
"""
from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

PINNED = {"type": "function", "name": "pinned_tool", "description": "Send an email to a recipient",
          "parameters": {"type": "object", "properties": {"to": {"type": "string"}}, "required": ["to"]},
          "strict": True}
POISONED = {**PINNED, "description": PINNED["description"] + "."}
VENDOR_DIGEST = "sha256:bf299d76420ad64fead3b567ac81241d5b57dc13f2f3b5d63078730f1248d313"
PINNED_DIGEST = "sha256:a6a1d60a57a24d1a6dbd9dc93e8f0cae4487ee001d3671b490dac9f046a6feb4"
POISONED_DIGEST = "sha256:578a3f442eb772a505cfb1ba0a969f74abb91bbb7864747eb8192503493ab281"
LOOSE_DIGEST = "sha256:2cba536f7260f198cdc4b316562587a33a871d7ee9926a50808d83dc8b351462"
SCHEMA_DIGEST = "sha256:9e7e780f3da586852b67df61c48bb634e9b9f9b1096cd97986decdbd29789eb9"
CALL = response_body(call_item("pinned_tool", {"to": "ops@ns1.finbot"}, "call_1"))


def declaring(*tools, extra=(), user="Pay vendor 7"):
    return {**finbot_request(*extra, user=user), "tools": list(tools)}


def payloads(tmp_path, method="steps/toolCallRequest"):
    return [line["envelope"]["params"]["payload"] for line in transcript_lines(tmp_path)
            if line["dir"] == "req" and line["envelope"].get("method") == method]


def sent_versions(tmp_path, method="steps/toolCallRequest"):
    return [p["tool"].get("version") for p in payloads(tmp_path, method)]


def decisions(audit):
    return [(e["decision"], e.get("reason_codes")) for e in audit() if e["acs_audit_event"] == "decision_applied"]


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def pinned_client(gateway, harness_guardian, **env):
    return gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(**env))


def test_the_policy_sees_the_declarations_digest(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert sent_versions(tmp_path) == [VENDOR_DIGEST]


def test_one_changed_description_character_turns_a_pinned_pass_into_a_mismatch_deny(
        gateway, harness_guardian, upstream, audit, tmp_path):
    client = pinned_client(gateway, harness_guardian, HARNESS_PINNED_VERSION=PINNED_DIGEST)
    upstream.reply(CALL)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(PINNED)).json() == CALL
    poisoned = client.post("/v1/responses", json=declaring(POISONED, user="Pay vendor 8")).json()
    assert poisoned["output"][0]["content"][0]["text"] == NEUTRAL
    # Each session writes its own transcript file, so the two lines come back in no fixed order.
    assert sorted(sent_versions(tmp_path)) == sorted([PINNED_DIGEST, POISONED_DIGEST])
    assert decisions(audit) == [("allow", []), ("deny", ["tool_content_hash_mismatch"])]


def test_a_cached_call_is_gated_again_when_its_declaration_changes_in_the_same_conversation(
        gateway, harness_guardian, upstream, audit):
    # One conversation (same system and first user message), and the model repeats call_1 word for word.
    client = pinned_client(gateway, harness_guardian, HARNESS_PINNED_VERSION=PINNED_DIGEST)
    upstream.reply(CALL)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(PINNED)).json() == CALL
    second = client.post("/v1/responses", json=declaring(POISONED)).json()
    assert second["output"][0]["content"][0]["text"] == NEUTRAL
    assert decisions(audit) == [("allow", []), ("deny", ["tool_content_hash_mismatch"])]


def test_the_pin_check_denies_a_call_with_no_version(gateway, harness_guardian, upstream, audit):
    upstream.reply(CALL)
    client = pinned_client(gateway, harness_guardian, HARNESS_PINNED_VERSION=PINNED_DIGEST)
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert decisions(audit) == [("deny", ["tool_content_hash_mismatch"])]


def test_the_pin_check_denies_when_no_pin_is_set(gateway, harness_guardian, upstream, audit):
    upstream.reply(CALL)
    output = pinned_client(gateway, harness_guardian).post("/v1/responses", json=declaring(PINNED)).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert decisions(audit) == [("deny", ["tool_content_hash_mismatch"])]


def test_a_changed_schema_or_strict_flag_changes_what_the_policy_sees(gateway, guardian, upstream, tmp_path):
    schema = {**PINNED, "parameters": {**PINNED["parameters"], "required": []}}
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    for i, tool in enumerate((PINNED, schema, {**PINNED, "strict": False})):
        upstream.reply(CALL)
        client.post("/v1/responses", json=declaring(tool, user=f"Pay vendor {i}"))
    assert sorted(sent_versions(tmp_path)) == sorted([PINNED_DIGEST, SCHEMA_DIGEST, LOOSE_DIGEST])


def test_the_tool_result_carries_the_declarations_digest(gateway, guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(CALL)
    client.post("/v1/responses", json=declaring(PINNED))
    upstream.reply(response_body())
    output = {"type": "function_call_output", "call_id": "call_1", "output": "sent"}
    client.post("/v1/responses", json=declaring(PINNED, extra=(CALL["output"][0], output)))
    assert sent_versions(tmp_path, "steps/toolCallResult") == [PINNED_DIGEST]


def test_an_undeclared_call_carries_no_version(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("bash", {"command": "ls"}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert payloads(tmp_path) == [{"tool": {"name": "bash"}, "arguments": {"command": {"value": "ls"}}}]


def test_tools_none_sends_no_version(gateway, guardian, upstream, tmp_path):
    upstream.reply(CALL)
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json={**finbot_request(), "tools": None})
    assert sent_versions(tmp_path) == [None]


def test_a_call_with_a_non_string_name_gets_no_version(gateway, guardian, upstream, tmp_path):
    # A declaration with an empty name must not lend its digest to a call whose name the gateway reads as "".
    upstream.reply(response_body({**call_item("x", {"to": "a"}, "call_1"), "name": 7}))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=declaring({**PINNED, "name": ""}))
    assert sent_versions(tmp_path) == [None]


def test_a_repeated_function_name_is_refused_in_enforce(gateway, guardian, upstream, audit):
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=declaring(PINNED, POISONED))
    assert response.status_code == 501
    assert response.json()["error"]["code"] == "unsupported_tool_type"
    assert [(e["item_type"], e["tool"]) for e in events(audit, "unsupported_tool_type")] == [
        ("repeated_function", "pinned_tool")]


def test_a_repeated_function_name_is_audited_in_shadow_and_sends_no_version(gateway, guardian, upstream, audit,
                                                                             tmp_path):
    upstream.reply(CALL)
    reply = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=declaring(PINNED, POISONED)).json()
    assert reply == CALL
    assert [e["tool"] for e in events(audit, "unsupported_tool_type")] == ["pinned_tool"]
    assert sent_versions(tmp_path) == [None]


def test_an_unencodable_declaration_is_audited_and_sends_no_version(gateway, guardian, upstream, audit, tmp_path):
    # An integer above 2**53 - 1 is one value RFC 8785 refuses to encode.
    upstream.reply(CALL)
    huge = {**PINNED, "parameters": {**PINNED["parameters"], "maxProperties": 2**60}}
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=declaring(huge))
    assert [e["tool"] for e in events(audit, "tool_digest_skipped")] == ["pinned_tool"]
    assert sent_versions(tmp_path) == [None]


def test_shadow_sends_the_digest_too(gateway, guardian, upstream, tmp_path):
    upstream.reply(CALL)
    gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=declaring(PINNED))
    assert sent_versions(tmp_path) == [PINNED_DIGEST]


# The model input log can't write a lone surrogate either, which is a separate path, so these runs switch it off.
SURROGATE_KEY = ('{"model": "gpt-5-nano", "input": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],'
                 ' "tools": [{"type": "function", "name": "pinned_tool", "description": "d",'
                 ' "parameters": {"type": "object", "properties": {"\\ud800": {"type": "string"}}}}]}')


def test_a_lone_surrogate_key_in_enforce_is_audited_and_the_call_still_gated(gateway, guardian, upstream, audit,
                                                                             tmp_path):
    upstream.reply(CALL)
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_MODEL_INPUT_LOG="").post(
        "/v1/responses", content=SURROGATE_KEY, headers={"content-type": "application/json"})
    assert response.status_code == 200
    assert [e["tool"] for e in events(audit, "tool_digest_skipped")] == ["pinned_tool"]
    assert sent_versions(tmp_path) == [None]


def test_a_lone_surrogate_key_in_shadow_is_audited_and_gating_goes_on(gateway, guardian, upstream, audit, tmp_path):
    upstream.reply(CALL)
    response = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian, ACS_MODEL_INPUT_LOG="").post(
        "/v1/responses", content=SURROGATE_KEY, headers={"content-type": "application/json"})
    assert response.json() == CALL
    assert [e["tool"] for e in events(audit, "tool_digest_skipped")] == ["pinned_tool"]
    assert sent_versions(tmp_path) == [None]


OUTPUT = {"type": "function_call_output", "call_id": "call_1", "output": "sent"}
HISTORY = (CALL["output"][0], OUTPUT)


def test_a_denied_regate_never_drops_the_delivered_call_from_history(gateway, harness_guardian, upstream):
    # Turn 1 delivers call_1. Turn 2 changes the declaration and the model repeats call_1, which is denied. Turn 3
    # resends the history, which still holds the call_1 the client ran, and its output.
    client = pinned_client(gateway, harness_guardian, HARNESS_PINNED_VERSION=PINNED_DIGEST)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(PINNED)).json() == CALL
    upstream.reply(CALL)
    second = client.post("/v1/responses", json=declaring(POISONED, extra=HISTORY)).json()
    assert second["output"][0]["content"][0]["text"] == NEUTRAL
    third = client.post("/v1/responses", json=declaring(POISONED, extra=HISTORY))
    assert third.status_code == 200
    forwarded = [(i.get("type"), i.get("call_id")) for i in upstream.received[-1].json()["input"]]
    assert ("function_call", "call_1") in forwarded and ("function_call_output", "call_1") in forwarded


def test_a_result_carries_the_digest_its_call_was_gated_under(gateway, guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(PINNED)).json() == CALL
    client.post("/v1/responses", json=declaring(POISONED, extra=HISTORY))
    assert sent_versions(tmp_path, "steps/toolCallResult") == [PINNED_DIGEST]


def test_a_result_keeps_its_calls_digest_when_the_declaration_vanishes(gateway, guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(CALL)
    client.post("/v1/responses", json=declaring(PINNED))
    client.post("/v1/responses", json=declaring(extra=HISTORY))
    assert sent_versions(tmp_path, "steps/toolCallResult") == [PINNED_DIGEST]


def test_a_result_for_a_call_never_gated_carries_no_version(gateway, guardian, upstream, tmp_path):
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=declaring(PINNED, extra=HISTORY))
    assert sent_versions(tmp_path, "steps/toolCallResult") == [None]


def test_a_resent_result_is_gated_again_once_its_call_is_delivered_under_another_digest(
        gateway, guardian, upstream, tmp_path):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(CALL)
    client.post("/v1/responses", json=declaring(PINNED))
    # The result is gated under the call's digest, and the model then repeats call_1 under the changed declaration,
    # which the Guardian allows, so the client now holds call_1 under the new digest.
    upstream.reply(CALL)
    assert client.post("/v1/responses", json=declaring(POISONED, extra=HISTORY)).json() == CALL
    client.post("/v1/responses", json=declaring(POISONED, extra=HISTORY))
    assert sent_versions(tmp_path, "steps/toolCallResult") == [PINNED_DIGEST, POISONED_DIGEST]
    assert sent_versions(tmp_path) == [PINNED_DIGEST, POISONED_DIGEST]
