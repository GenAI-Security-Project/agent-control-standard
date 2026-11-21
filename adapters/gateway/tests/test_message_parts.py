"""One message-part allowlist for streamed and whole answers: output_text and refusal pass, anything else withholds
the message in enforce (fix round 4)."""
import pytest

from conftest import NEUTRAL, finbot_request, response_body

from acs_gateway.apply import rebuilt_message

SHAPE = {"type": "function_call", "id": "fc_x", "call_id": "call_x", "name": "bash",
         "arguments": '{"command": "rm -rf /"}'}
REFUSAL = {"type": "refusal", "refusal": "I can't help with that."}


def message(*parts):
    return {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "content": list(parts)}


def test_the_allowlist_rebuilds_output_text_and_refusal_from_known_fields():
    item = message({"type": "output_text", "text": "hi", "annotations": [{"x": 1}], "extra": "rm"},
                   {**REFUSAL, "extra": "rm"})
    assert rebuilt_message({**item, "extra": "rm"}) == message(
        {"type": "output_text", "text": "hi", "annotations": []}, REFUSAL)


@pytest.mark.parametrize("part", [SHAPE, {"type": "input_image", "image_url": "x"}, {"type": "refusal"}, "text"])
def test_any_other_part_fails_the_allowlist(part):
    assert rebuilt_message(message(part)) is None


def test_a_whole_answer_with_a_function_call_part_is_withheld_in_enforce(gateway, guardian, upstream, audit):
    upstream.reply(response_body(message(SHAPE)))
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert b"rm -rf" not in response.content
    assert response.json()["output"][0]["content"][0]["text"] == NEUTRAL
    assert [e["part_type"] for e in audit() if e["acs_audit_event"] == "unsupported_content_part"] == ["function_call"]


def test_a_whole_answer_with_a_refusal_passes_in_enforce(gateway, guardian, upstream, audit):
    upstream.reply(response_body(message(REFUSAL)))
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.json()["output"] == [message(REFUSAL)]
    assert not [e for e in audit() if e["acs_audit_event"] == "unsupported_content_part"]


def test_shadow_records_the_part_and_forwards_the_answer(gateway, guardian, upstream, audit):
    reply = response_body(message(SHAPE))
    upstream.reply(reply)
    response = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.json() == reply
    assert [e["part_type"] for e in audit() if e["acs_audit_event"] == "unsupported_content_part"] == ["function_call"]
