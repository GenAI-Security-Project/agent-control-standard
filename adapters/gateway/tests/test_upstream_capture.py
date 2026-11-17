"""Capture and the live model key (issue #579, A.8)."""
import json
import os

import pytest

from conftest import SSE, call_item, finbot_request, message_item, response_body, sse_events

USER_A = "user_AbCdEfGh-_123456"
NS_A = "ns_" + USER_A
KEY = "sk-lab-" + "z" * 40


def system(ns: str) -> str:
    return f"You are FinBot. Internal mail goes to admin@{ns}.finbot."


def key_file(tmp_path):
    path = tmp_path / "secrets" / "openai.key"
    path.parent.mkdir()
    path.write_text(KEY + "\n")
    path.chmod(0o600)
    return path


def capture(gateway, tmp_path, **env):
    return gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_CAPTURE_SCENARIO="s1", **env)


def recorded(tmp_path):
    path = tmp_path / "rec" / "s1.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_capture_writes_one_placeholder_line_per_exchange(gateway, upstream, tmp_path):
    reply = response_body(call_item("finmail__send_email", {"to": f"admin@{NS_A}.finbot"}, "call_1"))
    upstream.reply(reply)
    client = capture(gateway, tmp_path)
    response = client.post("/v1/responses", json=finbot_request(system=system(NS_A)))
    assert response.json() == reply
    [line] = recorded(tmp_path)
    assert {k: line[k] for k in ("scenario", "match", "step", "branch", "stream")} == {
        "scenario": "s1", "match": "Pay\\ vendor\\ 7", "step": 0, "branch": "", "stream": False}
    assert json.loads(line["response"]["output"][0]["arguments"]) == {"to": "admin@ns_{{acs:user:1}}.finbot"}
    assert NS_A not in (tmp_path / "rec" / "s1.jsonl").read_text()


def test_a_capture_replays_into_another_namespace(gateway, upstream, tmp_path):
    upstream.reply(response_body(message_item(f"Mailed admin@{NS_A}.finbot")))
    capture(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=system(NS_A)))
    other = "ns_user_ZyXwVuTs_-987654"
    reply = gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec")).post(
        "/v1/responses", json=finbot_request(system=system(other))).json()
    assert reply["output"][0]["content"][0]["text"] == f"Mailed admin@{other}.finbot"


def test_a_failed_exchange_writes_nothing(gateway, upstream, tmp_path):
    upstream.reply({"error": {"message": "overloaded"}}, status=503)
    response = capture(gateway, tmp_path).post("/v1/responses", json=finbot_request())
    assert response.status_code == 503
    assert recorded(tmp_path) == []


def test_a_capture_write_failure_still_answers(gateway, upstream, tmp_path, audit):
    (tmp_path / "rec").mkdir()
    (tmp_path / "rec" / "s1.jsonl").mkdir()  # a directory where the file should be, so the append fails
    upstream.reply(response_body(message_item("still here")))
    response = capture(gateway, tmp_path).post("/v1/responses", json=finbot_request())
    assert response.json()["output"][0]["content"][0]["text"] == "still here"
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_failed"] == ["write_error"]


def test_a_streamed_exchange_is_captured_as_events(gateway, upstream, tmp_path):
    upstream.reply(SSE(sse_events(f"hello admin@{NS_A}.finbot")))
    response = capture(gateway, tmp_path).post("/v1/responses",
                                               json={**finbot_request(system=system(NS_A)), "stream": True})
    assert f"hello admin@{NS_A}.finbot" in response.text
    [line] = recorded(tmp_path)
    assert line["stream"] is True
    assert [e["event"] for e in line["response"]] == ["response.created", "response.output_text.delta",
                                                      "response.output_item.done", "response.completed"]
    assert line["response"][1]["data"]["delta"] == "hello admin@ns_{{acs:user:1}}.finbot"


def test_the_key_reaches_only_the_upstream_header(gateway, upstream, tmp_path, audit, capfd):
    upstream.reply(response_body(message_item("ok")))
    client = capture(gateway, tmp_path, ACS_UPSTREAM_KEY_FILE=str(key_file(tmp_path)))
    client.post("/v1/responses", json=finbot_request(), headers={"authorization": "Bearer lab-dummy"})
    assert upstream.received[0].headers["authorization"] == f"Bearer {KEY}"
    for path in (tmp_path / "rec" / "s1.jsonl", tmp_path / "model-inputs.jsonl"):
        assert KEY not in path.read_text()
    assert KEY not in json.dumps(audit())
    out, err = capfd.readouterr()
    assert KEY not in out + err


def test_live_with_a_key_replaces_the_client_header(gateway, upstream, tmp_path):
    upstream.reply(response_body(message_item("ok")))
    gateway(ACS_UPSTREAM_KEY_FILE=str(key_file(tmp_path))).post(
        "/v1/responses", json=finbot_request(), headers={"authorization": "Bearer lab-dummy"})
    assert upstream.received[0].headers["authorization"] == f"Bearer {KEY}"


def test_live_without_a_key_leaves_the_client_header(gateway, upstream):
    upstream.reply(response_body(message_item("ok")))
    gateway().post("/v1/responses", json=finbot_request(), headers={"authorization": "Bearer lab-dummy"})
    assert upstream.received[0].headers["authorization"] == "Bearer lab-dummy"
