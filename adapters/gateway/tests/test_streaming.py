"""Governed streaming through the gateway: the example Guardian decides, the client reads Server-Sent Events."""
import json
import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from conftest import NEUTRAL, SSE, call_item, finbot_request, message_item, response_body, transcript_lines
from streams import decode, encode, rebuilt_output, stream_events

from acs_gateway.sessions import conversation_key

VENDOR = {"name": "Acme", "bank_account_number": "12345678", "bank_routing_number": "021000021"}
BASH = call_item("bash", {"command": "rm -rf /"}, "call_bash")
LOOKUP = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def streamed(client, *extra, headers=None):
    """POST a streamed request and return (status, content type, decoded events, raw bytes)."""
    body = {**finbot_request(*extra), "stream": True}
    with client.stream("POST", "/v1/responses", json=body, headers=headers or {}) as response:
        raw = b"".join(response.iter_bytes())
        return response.status_code, response.headers.get("content-type", ""), decode(raw), raw


def finbot_reads(events_):
    """What FinBot's chat.py takes from a stream: the text deltas and the function calls in output_item.done."""
    text = "".join(e["delta"] for e in events_ if e["type"] == "response.output_text.delta")
    calls = [(e["item"]["name"], json.loads(e["item"]["arguments"])) for e in events_
             if e["type"] == "response.output_item.done" and e["item"]["type"] == "function_call"]
    return text, calls


def test_enforce_streams_a_denied_call_out(gateway, guardian, upstream, audit):
    upstream.reply(SSE(encode(stream_events(message_item("Cleaning up"), BASH))))
    status, kind, received, raw = streamed(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian))
    assert status == 200 and kind.startswith("text/event-stream")
    assert finbot_reads(received) == ("Cleaning up", [])
    assert b"rm -rf" not in raw and b"call_bash" not in raw
    assert received[-1]["type"] == "response.completed"
    assert received[-1]["response"]["output"] == rebuilt_output(received) == [message_item("Cleaning up")]
    applied = events(audit, "decision_applied")
    assert [(e["tool"], e["decision"]) for e in applied] == [("bash", "deny")]


def test_enforce_streams_the_neutral_line_when_the_denied_call_was_all(gateway, guardian, upstream):
    upstream.reply(SSE(encode(stream_events(BASH))))
    _, _, received, _ = streamed(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian))
    assert finbot_reads(received) == (NEUTRAL, [])
    assert [i["type"] for i in received[-1]["response"]["output"]] == ["message"]


def test_enforce_streams_a_redacted_result(gateway, harness_guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    upstream.reply(SSE(encode(stream_events(LOOKUP))))
    upstream.reply(SSE(encode(stream_events(message_item("Acme is on file")))))
    _, _, first, _ = streamed(client)
    assert finbot_reads(first) == ("", [("get_vendor_details", {"vendor_id": 7})])
    output = {"type": "function_call_output", "call_id": "call_1", "output": json.dumps(VENDOR)}
    # FinBot's chat rebuilds the call from output_item.done and appends the tool's output.
    _, _, second, raw = streamed(client, rebuilt_output(first)[0], output)
    assert finbot_reads(second) == ("Acme is on file", [])
    sent = upstream.received[1].json()
    assert sent["stream"] is True
    assert json.loads(sent["input"][-1]["output"]) == {**VENDOR, "bank_account_number": "[REDACTED]"}
    assert "12345678" not in upstream.received[1].body.decode()
    results = [e for e in events(audit, "decision_applied") if e["method"] == "steps/toolCallResult"]
    assert [e["decision"] for e in results] == ["modify"]


def test_enforce_streams_an_override(gateway, harness_guardian, upstream):
    mail = call_item("override_tool", {"to": "x@evil.example", "body": "hi"}, "call_mail")
    upstream.reply(SSE(encode(stream_events(message_item("Sending"), mail))))
    _, _, received, raw = streamed(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian()))
    assert finbot_reads(received) == ("Sending", [("override_tool", {"to": "ops@ns1.finbot", "body": "hi"})])
    assert b"evil" not in raw
    assert received[-1]["response"]["output"] == rebuilt_output(received)


def test_shadow_streams_unchanged_and_records(gateway, guardian, upstream, audit, tmp_path):
    raw = encode(stream_events(message_item("Cleaning up"), BASH))
    upstream.reply(SSE(raw))
    _, _, _, received = streamed(gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian))
    assert received == b"".join(raw)
    recorded = events(audit, "shadow_decision")
    assert [(e["tool"], e["decision"], e["guardian_decision"]) for e in recorded] == [("bash", "deny", "deny")]
    assert [line["envelope"].get("method") for line in transcript_lines(tmp_path) if line["dir"] == "req"] == [
        "steps/sessionStart", "steps/toolCallRequest"]


def test_nothing_acs_reaches_the_streaming_client(gateway, guardian, upstream):
    upstream.reply(SSE(encode(stream_events(message_item("hi"), BASH, LOOKUP))))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    body = {**finbot_request(), "stream": True}
    with client.stream("POST", "/v1/responses", json=body, headers={"X-ACS-Lab-Session": "s1"}) as response:
        raw = b"".join(response.iter_bytes())
        names = [k.lower() for k in response.headers]
    text = raw.decode().lower()
    for word in ("acs", "guardian", "reason_code", "signature", "session_id", "request_id", "destructive"):
        assert word not in text, word
    assert not any(name.startswith("x-acs") for name in names)
    assert "x-acs-lab-session" not in upstream.received[0].headers


def test_an_upstream_error_status_is_relayed(gateway, guardian, upstream, audit):
    upstream.reply({"error": {"message": "bad key", "type": "invalid_request_error"}}, status=401)
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    response = client.post("/v1/responses", json={**finbot_request(), "stream": True})
    assert response.status_code == 401 and response.json()["error"]["message"] == "bad key"
    assert events(audit, "upstream_error")[0]["cause"] == "upstream_status"


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_success_that_is_not_a_stream(gateway, guardian, upstream, audit, mode):
    reply = response_body(BASH)
    upstream.reply(reply)
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json={**finbot_request(), "stream": True})
    if mode == "enforce":
        assert response.status_code == 502 and b"bash" not in response.content
    else:
        assert response.status_code == 200 and response.json() == reply
    assert events(audit, "upstream_error")[0]["cause"] == "upstream_unparseable"


def test_the_session_is_free_after_a_stream(gateway, guardian, upstream):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    upstream.reply(SSE(encode(stream_events(message_item("hi"), LOOKUP))))
    streamed(client)
    session = client.app.state.gateway.sessions.peek(conversation_key(finbot_request()))
    assert session.active == 0 and not session.lock.locked()
    upstream.reply(response_body(message_item("again")))
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200


def test_an_unreadable_stream_ends_with_an_error_event(gateway, guardian, upstream):
    raw = encode(stream_events(message_item("hi"), LOOKUP))
    upstream.reply(SSE([*raw[:3], b"data: {broken\n\n", *raw[3:]]))
    _, _, received, raw_out = streamed(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian))
    assert received[-1]["type"] == "error"
    assert b"call_1" not in raw_out


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_text_reaches_the_client_before_a_slow_decision(tmp_path, harness_guardian, upstream):
    """Through a real HTTP server, since the test client buffers a whole response."""
    from acs_gateway.app import create_app
    from acs_gateway.config import GatewayConfig

    guardian_url = harness_guardian(HARNESS_SLOW_S="1.5")
    upstream.reply(SSE(encode(stream_events(message_item("Checking the ledger"),
                                            call_item("slow_tool", {"x": 1}, "call_slow")))))
    config = GatewayConfig.from_env({"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": guardian_url,
                                     "ACS_UPSTREAM_URL": upstream.url, "ACS_DECISION_TIMEOUT_MS": "5000",
                                     "ACS_TRANSCRIPT_DIR": str(tmp_path / "transcripts"),
                                     "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"]})
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(config), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        arrivals = []
        start = time.monotonic()
        with httpx.stream("POST", f"http://127.0.0.1:{port}/v1/responses", timeout=30,
                          json={**finbot_request(), "stream": True}) as response:
            for line in response.iter_lines():
                if line.startswith("data:"):
                    arrivals.append((time.monotonic() - start, json.loads(line[5:])))
    finally:
        server.should_exit = True
        thread.join(10)
    first_text = next(t for t, e in arrivals if e["type"] == "response.output_text.delta")
    first_call = next(t for t, e in arrivals if e.get("item", {}).get("type") == "function_call")
    assert first_text < 1.0 and first_call > 1.4
    assert finbot_reads([e for _, e in arrivals]) == ("Checking the ledger", [("slow_tool", {"x": 1})])
