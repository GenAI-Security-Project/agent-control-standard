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


def test_a_compressed_body_goes_on_unchanged_and_the_skipped_override_is_audited(gateway, guardian, upstream,
                                                                                 audit):
    """Fix round 3, CR3-6: no relay path skips the override silently. The gateway can't read a compressed body, so it
    can't set its model, and says so."""
    import gzip

    raw = gzip.compress(json.dumps(finbot_request()).encode())
    for env in ({}, {"ACS_LAB_MODE": "shadow", "ACS_GUARDIAN_URL": guardian}):
        upstream.reply(response_body(message_item("ok")))
        gateway(ACS_UPSTREAM_MODEL="gpt-5-mini", **env).post(
            "/v1/responses", content=raw, headers={"content-type": "application/json", "content-encoding": "gzip"})
        assert upstream.received[-1].body == raw
    skipped = [e for e in audit() if e["acs_audit_event"] == "model_override_skipped"]
    assert [(e["cause"], e["mode"]) for e in skipped] == [("unreadable_request", "off"),
                                                          ("unreadable_request", "shadow")]


def test_off_mode_parses_the_body_once(gateway, upstream, tmp_path, monkeypatch):
    """Fix round 3, CR3-9: the override, the branch and the model input log share one parse."""
    from acs_gateway import app

    calls = []
    real = app._parse

    def counting(raw):
        calls.append(len(raw))
        return real(raw)

    monkeypatch.setattr(app, "_parse", counting)
    upstream.reply(response_body(message_item("ok")))
    gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_UPSTREAM_MODEL="gpt-5-mini").post(
        "/v1/responses", json=finbot_request())
    assert len(calls) == 1
    assert upstream.received[0].json()["model"] == "gpt-5-mini"
    assert logged(tmp_path)[0]["model"] == "gpt-5-mini"
