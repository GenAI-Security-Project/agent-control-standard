"""ACS_UPSTREAM_MODEL (fix round 2, R4) and the conversation turn in the replay key (CR1)."""
import json

from conftest import finbot_request, message_item, response_body


def logged(tmp_path):
    return [json.loads(line) for line in (tmp_path / "model-inputs.jsonl").read_text().splitlines()]


def test_live_overrides_the_model_and_logs_the_body_it_sent(gateway, upstream, tmp_path):
    upstream.reply(response_body(message_item("ok")))
    gateway(ACS_UPSTREAM_MODEL="gpt-5-mini").post("/v1/responses", json=finbot_request())
    assert upstream.received[0].json()["model"] == "gpt-5-mini"
    assert logged(tmp_path)[0]["model"] == "gpt-5-mini"


def test_capture_under_enforce_overrides_the_model(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(message_item("ok")))
    gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_UPSTREAM_MODEL="gpt-5-mini",
            ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert upstream.received[0].json()["model"] == "gpt-5-mini"
    assert logged(tmp_path)[0]["model"] == "gpt-5-mini"


def test_without_the_setting_the_model_is_untouched(gateway, upstream):
    upstream.reply(response_body(message_item("ok")))
    gateway().post("/v1/responses", json={**finbot_request(), "model": "gpt-5-nano"})
    assert upstream.received[0].json()["model"] == "gpt-5-nano"


def chat(*turns):
    """A chat with no tool calls: each earlier user turn is followed by the assistant's answer."""
    items = [{"role": "system", "content": "You are FinBot."}]
    for i, text in enumerate(turns):
        items.append({"role": "user", "content": text})
        if i < len(turns) - 1:
            items.append({"role": "assistant", "content": f"answer {i + 1}"})
    return {"model": "gpt-5-nano", "input": items}


def test_each_turn_of_a_chat_replays_its_own_answer(gateway, upstream, tmp_path):
    upstream.reply(response_body(message_item("answer 1")))
    upstream.reply(response_body(message_item("answer 2")))
    client = gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    client.post("/v1/responses", json=chat("Hello"))
    client.post("/v1/responses", json=chat("Hello", "And my invoices?"))
    lines = [json.loads(line) for line in (tmp_path / "rec" / "capture.jsonl").read_text().splitlines()]
    assert [(line["turn"], line["step"]) for line in lines] == [(1, 0), (2, 0)]
    replay = gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    second = replay.post("/v1/responses", json=chat("Hello", "And my invoices?")).json()
    first = replay.post("/v1/responses", json=chat("Hello")).json()
    assert [r["output"][0]["content"][0]["text"] for r in (first, second)] == ["answer 1", "answer 2"]
