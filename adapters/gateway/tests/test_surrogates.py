"""A lone surrogate in a request never crashes a log or transcript write (found by LAB-07)."""
import json

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body

# JSON text with an escaped lone surrogate, which json.loads turns into a str that can't be encoded as UTF-8.
LONE = '{"model": "gpt-5-nano", "input": [{"role": "system", "content": "S"}, {"role": "user", "content": "hi \\ud800 there"}]}'


@pytest.mark.parametrize("mode", ["off", "shadow", "enforce"])
def test_a_lone_surrogate_in_a_message_is_forwarded_and_logged(gateway, guardian, upstream, mode, tmp_path):
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=LONE.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert upstream.received
    logged = [json.loads(line) for line in (tmp_path / "model-inputs.jsonl").read_text().splitlines()]
    assert logged[0]["input"][1]["content"] == "hi \ud800 there"


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_lone_surrogate_in_a_tool_output_gets_a_documented_answer(gateway, guardian, upstream, audit, mode,
                                                                   tmp_path):
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request())
    body = json.dumps(finbot_request(call, {"type": "function_call_output", "call_id": "call_1",
                                            "output": "bank \ud800 data"}), ensure_ascii=True)
    response = client.post("/v1/responses", content=body.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    sent = [i for i in upstream.received[-1].json()["input"] if i.get("type") == "function_call_output"][0]
    # RFC 8785 can't sign a lone surrogate, so the step is refused and, in enforce, denied with the neutral line.
    assert sent["output"] == (NEUTRAL if mode == "enforce" else "bank \ud800 data")
    name = "decision_applied" if mode == "enforce" else "shadow_decision"
    results = [e for e in audit() if e["acs_audit_event"] == name and e["method"] == "steps/toolCallResult"]
    assert [(e["decision"], e["cause"]) for e in results] == [("deny", "envelope_not_signable")]


def test_every_log_and_transcript_writer_takes_a_lone_surrogate(tmp_path):
    import uuid

    from acs_gateway.transcript import ModelInputLog, Transcript

    ModelInputLog(tmp_path / "m.jsonl").append({"input": "x \ud800 y"})
    session_id = str(uuid.uuid4())
    Transcript(tmp_path / "t").append(session_id, "req", {"params": {"note": "x \udfff y"}})
    Transcript(tmp_path / "t").append(session_id, "resp", None, cause="bad \ud800 cause")
    assert json.loads((tmp_path / "m.jsonl").read_text()) == {"input": "x \ud800 y"}
    lines = (tmp_path / "t" / f"{session_id}.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["envelope"]["params"]["note"] == "x \udfff y"


def test_an_audit_line_naming_a_lone_surrogate_key_is_written(gateway, guardian, upstream, audit):
    arguments = json.dumps({"x": 1}).replace('"x": 1', '"\\ud800": 1, "\\ud800": 2')
    forged = {"type": "function_call", "call_id": "c9", "name": "send", "arguments": arguments}
    body = json.dumps(finbot_request(forged), ensure_ascii=True)
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=body.encode(), headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert [e["key"] for e in audit() if e["acs_audit_event"] == "duplicate_json_key"] == ["\ud800"]
