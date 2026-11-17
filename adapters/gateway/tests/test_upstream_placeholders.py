"""Placeholders for FinBot's namespace and generated ids, and the replay key (PREMORTEM P2 and P11)."""
from acs_gateway.upstream import fill, placeholder_map, replay_key, to_placeholders

from conftest import NEUTRAL

# Shaped like FinBot's own ids at 1450fc4: user_<token_urlsafe(12)>, ns_ + user id, tr_<token_hex(12)>.
USER_A, USER_B = "user_AbCdEfGh-_123456", "user_ZyXwVuTs_-987654"
NS_A, NS_B = "ns_" + USER_A, "ns_" + USER_B


def system(user: str, ns: str) -> str:
    return (f"Send internal mail to admin@{ns}.finbot.\n<GLOBAL_CONTEXT>\nUser ID: {user}\n"
            "Current Date and Time: 2026-12-09T10:15:00.123456Z\n</GLOBAL_CONTEXT>")


def body(user: str, ns: str, *extra, first_user: str = "Pay vendor 7") -> dict:
    return {"model": "gpt-5-nano", "input": [{"role": "system", "content": system(user, ns)},
                                              {"role": "user", "content": first_user}, *extra]}


def output(call_id: str, text: str) -> dict:
    return {"type": "function_call_output", "call_id": call_id, "output": text}


def test_two_namespaces_normalize_to_the_same_text():
    a, b = body(USER_A, NS_A), body(USER_B, NS_B)
    assert to_placeholders(a, placeholder_map(a)) == to_placeholders(b, placeholder_map(b))
    normalized = to_placeholders(a, placeholder_map(a))["input"][0]["content"]
    assert NS_A not in normalized and USER_A not in normalized
    assert "admin@{{acs:ns:1}}.finbot" in normalized and "User ID: {{acs:user:1}}" in normalized


def test_fill_restores_the_live_namespace():
    recorded = to_placeholders({"text": f"Mailed admin@{NS_A}.finbot for {USER_A}"}, placeholder_map(body(USER_A, NS_A)))
    filled, complete = fill(recorded, placeholder_map(body(USER_B, NS_B)))
    assert complete
    assert filled == {"text": f"Mailed admin@{NS_B}.finbot for {USER_B}"}


def test_generated_ids_in_tool_output_round_trip():
    tr_a, tr_b = "tr_" + "a1" * 12, "tr_" + "b2" * 12
    uuid_a, uuid_b = "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "9b2c1f3e-1111-4222-8333-444455556666"
    live_a = body(USER_A, NS_A, output("call_1", f'{{"transfer": "{tr_a}", "ref": "{uuid_a}"}}'))
    live_b = body(USER_B, NS_B, output("call_1", f'{{"transfer": "{tr_b}", "ref": "{uuid_b}"}}'))
    recorded = to_placeholders(f"Transfer {tr_a} ({uuid_a}) done", placeholder_map(live_a))
    assert recorded == "Transfer {{acs:tr:1}} ({{acs:uuid:1}}) done"
    assert fill(recorded, placeholder_map(live_b)) == (f"Transfer {tr_b} ({uuid_b}) done", True)


def test_a_value_the_request_never_held_stays_verbatim():
    stranger = "user_QQQQQQQQQQQQQQQQ"
    assert to_placeholders(f"hi {stranger}", placeholder_map(body(USER_A, NS_A))) == f"hi {stranger}"


def test_a_placeholder_the_live_request_cant_fill_is_incomplete():
    filled, complete = fill("Transfer {{acs:tr:1}}", placeholder_map(body(USER_B, NS_B)))
    assert not complete


def test_a_longer_token_is_not_split():
    # A namespace holds a user id, and an id-shaped run inside a longer word is not an id.
    mapping = placeholder_map(body(USER_A, NS_A))
    assert to_placeholders(f"x{USER_A}", mapping) == f"x{USER_A}"
    assert to_placeholders(NS_A, mapping) == "{{acs:ns:1}}"


def test_the_key_takes_the_step_from_outputs_and_the_branch_from_their_content():
    live = body(USER_A, NS_A,
                {"type": "function_call", "call_id": "call_1", "name": "a", "arguments": "{}"},
                output("call_1", '{"ok": true}'),
                {"type": "function_call", "call_id": "call_2", "name": "b", "arguments": "{}"},
                output("call_2", NEUTRAL),
                {"type": "function_call", "call_id": "call_3", "name": "c", "arguments": "{}"},
                output("call_3", '{"bank_account_number": "[REDACTED]"}'),
                first_user=f"Mail admin@{NS_A}.finbot")
    assert replay_key(live, placeholder_map(live)) == ("Mail admin@{{acs:ns:1}}.finbot", 3, "a,d,m")


def test_a_first_user_message_in_parts_is_joined():
    live = {"input": [{"role": "user", "content": [{"type": "input_text", "text": "Pay "},
                                                   {"type": "input_text", "text": "vendor 7"}]}]}
    assert replay_key(live, placeholder_map(live)) == ("Pay vendor 7", 0, "")
