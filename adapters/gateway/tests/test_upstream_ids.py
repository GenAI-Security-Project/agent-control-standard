"""No namespace leaks across FinBots, and no id is filled into the wrong place (fix round 2, R2 and R3)."""
import json

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body

USER_A, USER_B = "user_AbCdEfGh-_123456", "user_ZyXwVuTs_-987654"
NS_A, NS_B = "ns_" + USER_A, "ns_" + USER_B
TR_1, TR_2, TR_3 = "tr_" + "a1" * 12, "tr_" + "b2" * 12, "tr_" + "c3" * 12


def capture(gateway, tmp_path):
    return gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))


def replay(gateway, tmp_path):
    return gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))


def text(reply):
    return reply["output"][0]["content"][0]["text"]


def recorded(tmp_path):
    path = tmp_path / "rec" / "capture.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def test_a_namespace_in_the_answer_maps_through_a_bare_user_id_in_the_request(gateway, upstream, tmp_path):
    # FinBot's agents carry only "User ID: user_..." in GLOBAL_CONTEXT, while the model may still write the namespace.
    upstream.reply(response_body(message_item(f"Mail admin@{NS_A}.finbot")))
    capture(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=f"User ID: {USER_A}"))
    assert USER_A not in json.dumps(recorded(tmp_path))
    reply = replay(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=f"User ID: {USER_B}")).json()
    assert text(reply) == f"Mail admin@{NS_B}.finbot"


def test_a_bare_user_id_in_the_answer_maps_through_a_namespace_in_the_request(gateway, upstream, tmp_path):
    upstream.reply(response_body(message_item(f"Acting for {USER_A}")))
    capture(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=f"Mail admin@{NS_A}.finbot"))
    reply = replay(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=f"Mail admin@{NS_B}.finbot")).json()
    assert text(reply) == f"Acting for {USER_B}"


def test_capture_refuses_an_answer_that_would_still_carry_a_namespace(gateway, upstream, tmp_path, audit):
    # The request names no user, so nothing maps the namespace the model wrote, and the line would leak it.
    upstream.reply(response_body(message_item(f"Mail admin@{NS_A}.finbot")))
    response = capture(gateway, tmp_path).post("/v1/responses", json=finbot_request())
    assert text(response.json()) == f"Mail admin@{NS_A}.finbot"
    assert recorded(tmp_path) == []
    assert [e["cause"] for e in events(audit, "capture_skipped")] == ["unmapped_id"]


def tool_turn(*transfers):
    """A request resending one tool output per transfer id, in order."""
    items = []
    for i, transfer in enumerate(transfers):
        items += [call_item("get_transfer", {}, f"call_{i}"),
                  {"type": "function_call_output", "call_id": f"call_{i}", "output": json.dumps({"id": transfer})}]
    return finbot_request(*items)


def test_an_extra_id_that_shifts_the_numbering_is_a_miss(gateway, upstream, tmp_path, audit):
    upstream.reply(response_body(message_item(f"Transfer {TR_1} checked")))
    capture(gateway, tmp_path).post("/v1/responses", json=tool_turn(TR_1, NEUTRAL))
    # Same step and branch, but an earlier output now holds a transfer id, so tr:1 would name the wrong transfer.
    reply = replay(gateway, tmp_path).post("/v1/responses", json=tool_turn(TR_2, TR_3)).json()
    assert text(reply) == NEUTRAL
    assert [e["cause"] for e in events(audit, "replay_miss")] == ["placeholder_mismatch"]


def test_the_same_shape_with_new_values_fills(gateway, upstream, tmp_path, audit):
    upstream.reply(response_body(message_item(f"Transfer {TR_1} checked")))
    capture(gateway, tmp_path).post("/v1/responses", json=tool_turn(TR_1))
    reply = replay(gateway, tmp_path).post("/v1/responses", json=tool_turn(TR_2)).json()
    assert text(reply) == f"Transfer {TR_2} checked"
    assert recorded(tmp_path)[0]["ids"] == ["tr:1"]
    assert events(audit, "replay_miss") == []
