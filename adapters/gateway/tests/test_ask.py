"""ASK through the approver page (LAB-08, issue #581, tmp_path): the approver answers, the Guardian decides, and silence denies."""
from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

ANSWER_FIELD = "x_acs_lab_ask_answer"


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def approver(client: Any, *choices: str) -> threading.Thread:
    """A person at the approver page: answers each listed call in turn, one choice per call."""
    approvals = client.app.state.gateway.approvals

    def run() -> None:
        answered: set[str] = set()
        end = time.monotonic() + 10
        while len(answered) < len(choices) and time.monotonic() < end:
            for item in approvals.pending():
                if item.ask_id not in answered:
                    assert approvals.answer(item.ask_id, choices[len(answered)])
                    answered.add(item.ask_id)
            time.sleep(0.01)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def token_file(tmp_path) -> str:
    path = tmp_path / "approver.token"
    path.write_text("approver-secret-" + "0123456789abcdef" * 2)
    path.chmod(0o600)
    return str(path)


def enforce(gateway, harness_guardian, tmp_path, **env: str) -> Any:
    # A short ASK timeout bounds any test that stalls, such as an approver thread whose assert failed (T1).
    guardian_env = {"HARNESS_ASK_TIMEOUT_S": "10", **{k: v for k, v in env.items() if k.startswith("HARNESS_")}}
    gateway_env = {k: v for k, v in env.items() if not k.startswith("HARNESS_")}
    mode = gateway_env.pop("ACS_LAB_MODE", "enforce")
    return gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=harness_guardian(**guardian_env),
                   ACS_GATEWAY_APPROVER_PORT="8090", ACS_GATEWAY_APPROVER_TOKEN_FILE=token_file(tmp_path),
                   **gateway_env)


def tool_requests(tmp_path) -> list[dict[str, Any]]:
    return [line["envelope"]["params"] for line in transcript_lines(tmp_path)
            if line["dir"] == "req" and line["envelope"]["method"] == "steps/toolCallRequest"]


def test_an_approved_ask_delivers_the_call_once_the_guardian_allows_the_resend(gateway, harness_guardian, upstream,
                                                                              audit, tmp_path):
    call = call_item("ask_tool", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = enforce(gateway, harness_guardian, tmp_path)
    thread = approver(client, "approve")
    response = client.post("/v1/responses", json=finbot_request())
    thread.join()
    assert response.json()["output"] == [call]
    first, resent = tool_requests(tmp_path)
    assert ANSWER_FIELD not in first["payload"]
    assert resent["payload"][ANSWER_FIELD] == {"ask_request_id": first["request_id"], "answer": "approve",
                                               "approver": {"type": "human", "id": "lab-approver"},
                                               "assurance": "declared"}
    assert {k: v for k, v in resent["payload"].items() if k != ANSWER_FIELD} == first["payload"]
    assert resent["request_id"] != first["request_id"]
    pending = events(audit, "ask_pending")
    assert [(p["request_id"], p["tool"]) for p in pending] == [(first["request_id"], "ask_tool")]
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["ask_request_id"], r["request_id"], r["guardian_decision"], r["decision"])
            for r in resolved] == [("approved", first["request_id"], resent["request_id"], "allow", "allow")]
    applied = events(audit, "decision_applied")
    assert [(a["decision"], a["guardian_decision"], a["request_id"]) for a in applied] == [
        ("allow", "allow", resent["request_id"])]


def test_a_rejected_ask_blocks_the_call(gateway, harness_guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {"vendor_id": 7}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path)
    thread = approver(client, "reject")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    thread.join()
    assert [i["type"] for i in output] == ["message"] and output[0]["content"][0]["text"] == NEUTRAL
    # A rejection denies at once. No resend goes out, since its decision could change nothing (CR6).
    assert len(tool_requests(tmp_path)) == 1
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"], r["cause"], r["request_id"]) for r in resolved] == [
        ("rejected", "deny", "ask_rejected", None)]


def test_one_approve_and_one_reject_give_matching_outcomes_and_two_audit_entries(gateway, harness_guardian, upstream,
                                                                                audit, tmp_path):
    client = enforce(gateway, harness_guardian, tmp_path)
    outcomes = []
    for choice, run in (("approve", "Pay vendor 7"), ("reject", "Pay vendor 8")):
        upstream.reply(response_body(call_item("ask_tool", {"run": run}, f"call_{choice}")))
        thread = approver(client, choice)
        output = client.post("/v1/responses", json=finbot_request(user=run)).json()["output"]
        thread.join()
        outcomes.append(output[0]["type"])
    assert outcomes == ["function_call", "message"]
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"]) for r in resolved] == [("approved", "allow"), ("rejected", "deny")]


def test_approval_releases_nothing_when_the_guardian_denies_the_resend(gateway, harness_guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("ask_deny_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path)
    thread = approver(client, "approve")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    thread.join()
    assert output[0]["content"][0]["text"] == NEUTRAL
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["guardian_decision"], r["decision"]) for r in resolved] == [("approved", "deny", "deny")]


def test_no_answer_before_the_guardians_timeout_denies_without_a_resend(gateway, harness_guardian, upstream, audit,
                                                                       tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path, HARNESS_ASK_TIMEOUT_S="1")
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert 0.9 <= time.monotonic() - started < 3
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert len(tool_requests(tmp_path)) == 1
    assert client.app.state.gateway.approvals.pending() == []
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"]) for r in resolved] == [("timed_out", "deny")]
    assert events(audit, "decision_applied")[0]["cause"] == "ask_timeout"


def test_two_asks_in_one_response_share_one_deadline(gateway, harness_guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {"n": 1}, "call_1"), call_item("ask_tool", {"n": 2}, "call_2")))
    # The Guardian asks for 60 s each. The cap stands in for 240 s, and both calls must fit inside one of it.
    client = enforce(gateway, harness_guardian, tmp_path, ACS_GATEWAY_ASK_MAX_S="2",
                     ACS_DECISION_TIMEOUT_MS="200")
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    elapsed = time.monotonic() - started
    assert elapsed < 1.8, elapsed
    assert output[0]["content"][0]["text"] == NEUTRAL
    resolved = events(audit, "ask_resolved")
    assert [r["outcome"] for r in resolved] == ["timed_out", "timed_out"]
    # One budget for the response: the second ASK found it already spent and waited for nothing.
    assert resolved[0]["deadline_s"] == resolved[1]["deadline_s"] == 2
    assert resolved[1]["waited_s"] < 0.1


def test_a_second_ask_waits_only_for_what_is_left_of_the_first(gateway, harness_guardian, upstream, audit, tmp_path):
    calls = [call_item("ask_tool", {"n": 1}, "call_1"), call_item("ask_tool", {"n": 2}, "call_2")]
    upstream.reply(response_body(*calls))
    client = enforce(gateway, harness_guardian, tmp_path, ACS_GATEWAY_ASK_MAX_S="2.6",
                     ACS_DECISION_TIMEOUT_MS="200")
    approvals = client.app.state.gateway.approvals

    def first_only() -> None:
        # Answer the first call late, then never the second.
        end = time.monotonic() + 5
        while not approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)
        time.sleep(0.9)
        approvals.answer(approvals.pending()[0].ask_id, "approve")

    thread = threading.Thread(target=first_only, daemon=True)
    thread.start()
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    elapsed = time.monotonic() - started
    thread.join()
    assert elapsed < 2.3, elapsed
    assert output == [calls[0]]
    assert [r["outcome"] for r in events(audit, "ask_resolved")] == ["approved", "timed_out"]


def test_without_the_approver_page_an_ask_denies_as_before(gateway, harness_guardian, upstream, audit):
    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "ask_pending") == [] and events(audit, "ask_resolved") == []


def test_shadow_records_the_ask_and_delivers(gateway, harness_guardian, upstream, audit, tmp_path):
    call = call_item("ask_tool", {}, "call_1")
    upstream.reply(response_body(call))
    client = enforce(gateway, harness_guardian, tmp_path, ACS_LAB_MODE="shadow")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output == [call]
    assert len(tool_requests(tmp_path)) == 1
    assert events(audit, "ask_pending") == []
    # Shadow never holds, so it keeps no approvals and the page has nothing to serve (CR8).
    assert client.app.state.gateway.approvals is None
    assert [(e["guardian_decision"], e["decision"]) for e in events(audit, "shadow_decision")] == [("ask", "deny")]


HUMAN = {"approver": {"type": "human", "id": "lab-approver"}, "question": "Pay?", "timeout_seconds": 30}


@pytest.mark.parametrize(("details", "field"), [
    (None, "ask_details"), ({}, "approver.id"),
    ({**HUMAN, "approver": {"type": "human"}}, "approver.id"),
    ({**HUMAN, "approver": {"type": "agent", "id": "bot", "endpoint": "https://example.com/approve"}}, "approver.type"),
    ({**HUMAN, "approver": {"type": "service", "id": "svc"}}, "approver.type"),
    ({**HUMAN, "question": 3}, "question"),
    ({k: v for k, v in HUMAN.items() if k != "timeout_seconds"}, "timeout_seconds"),
    ({**HUMAN, "timeout_seconds": 0}, "timeout_seconds"), ({**HUMAN, "timeout_seconds": True}, "timeout_seconds"),
    ({**HUMAN, "options": ["approve_once", "deny"]}, "options"), ({**HUMAN, "options": ["approve"]}, "options"),
    ({**HUMAN, "timeout_disposition": "allow"}, "timeout_disposition"),
    ({**HUMAN, "context": 5}, "context"),
])
def test_unusable_or_unsupported_ask_details_name_the_field(details, field):
    from acs_gateway.app import ask_settings

    assert ask_settings(details) == field


def test_usable_ask_details_are_read():
    from acs_gateway.app import AskSettings, ask_settings

    assert ask_settings(HUMAN) == AskSettings("Pay?", "lab-approver", 30, None)
    assert ask_settings({**HUMAN, "options": ["reject", "approve"], "timeout_disposition": "deny",
                         "context": "New vendor"}) == AskSettings("Pay?", "lab-approver", 30, "New vendor")


def test_an_ask_for_a_non_human_approver_denies_at_once_and_names_the_field(gateway, harness_guardian, upstream,
                                                                           audit, tmp_path):
    upstream.reply(response_body(call_item("ask_agent_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path)
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert time.monotonic() - started < 2
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert [(e["field"], e["tool"]) for e in events(audit, "ask_unsupported")] == [("approver.type", "ask_agent_tool")]
    assert events(audit, "ask_pending") == []
    assert events(audit, "decision_applied")[0]["cause"] == "ask_unsupported"


def test_an_epoch_bump_during_a_hold_denies_without_a_resend(gateway, harness_guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path)
    gateway_ = client.app.state.gateway

    def bump_then_approve() -> None:
        end = time.monotonic() + 5
        while not gateway_.approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)
        ask_id = gateway_.approvals.pending()[0].ask_id
        gateway_.bump_epoch()
        gateway_.approvals.answer(ask_id, "approve")

    thread = threading.Thread(target=bump_then_approve, daemon=True)
    thread.start()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    thread.join()
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert len(tool_requests(tmp_path)) == 1
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["cause"], r["decision"]) for r in resolved] == [("abandoned", "epoch_bumped", "deny")]


def test_a_slow_upstream_still_lands_the_response_inside_the_budget(gateway, harness_guardian, audit, tmp_path,
                                                                    upstream):
    """The budget runs from the request's arrival, so time the model spent counts against the hold (CR3)."""
    import json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    reply = json.dumps(response_body(call_item("ask_tool", {}, "call_1"))).encode()

    class Slow(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            time.sleep(0.8)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = enforce(gateway, harness_guardian, tmp_path, ACS_GATEWAY_ASK_MAX_S="2.5",
                         ACS_DECISION_TIMEOUT_MS="300",
                         ACS_UPSTREAM_URL=f"http://127.0.0.1:{server.server_address[1]}/v1")
        started = time.monotonic()
        output = client.post("/v1/responses", json=finbot_request()).json()["output"]
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        server.server_close()
    # 2.5 s budget, less 1.3 s kept for the resend, so the hold ends 1.2 s after arrival, model time included.
    assert 1.0 <= elapsed < 2.5, elapsed
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert [r["outcome"] for r in events(audit, "ask_resolved")] == ["timed_out"]


def _serve(app: Any) -> tuple[Any, threading.Thread, int]:
    import socket

    import uvicorn

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    end = time.monotonic() + 20
    while not server.started and time.monotonic() < end:
        time.sleep(0.05)
    return server, thread, port


def _live_gateway(harness_guardian, upstream, tmp_path) -> Any:
    from acs_gateway.app import create_app
    from acs_gateway.config import GatewayConfig

    import os

    return create_app(GatewayConfig.from_env({
        "ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": harness_guardian(), "ACS_UPSTREAM_URL": upstream.url,
        "ACS_TRANSCRIPT_DIR": str(tmp_path / "transcripts"), "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"],
        "ACS_GATEWAY_APPROVER_PORT": "8090", "ACS_GATEWAY_APPROVER_TOKEN_FILE": token_file(tmp_path)}))


@pytest.mark.parametrize("delay_s", [0.0, 0.05, 0.15, 0.4])
def test_an_approval_just_after_a_disconnect_sends_no_resend(harness_guardian, upstream, audit, tmp_path, delay_s):
    """The client closes, then the approver clicks approve delay_s later, inside one disconnect poll (R-I1)."""
    import json
    import socket

    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    app = _live_gateway(harness_guardian, upstream, tmp_path)
    approvals = app.state.gateway.approvals
    server, thread, port = _serve(app)
    try:
        raw = json.dumps(finbot_request()).encode()
        sock = socket.create_connection(("127.0.0.1", port))
        sock.sendall(b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                     + f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        end = time.monotonic() + 10
        while not approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)
        ask_id = approvals.pending()[0].ask_id
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        time.sleep(delay_s)
        approvals.answer(ask_id, "approve")
        end = time.monotonic() + 5
        while not events(audit, "ask_resolved") and time.monotonic() < end:
            time.sleep(0.05)
    finally:
        server.should_exit = True
        thread.join(10)
    resolved = [(r["outcome"], r["cause"], r["decision"]) for r in events(audit, "ask_resolved")]
    assert len(tool_requests(tmp_path)) == 1, resolved
    assert resolved == [("abandoned", "client_disconnected", "deny")]


@pytest.mark.parametrize("stream", [False, True])
def test_a_client_disconnect_ends_the_hold_with_a_deny_and_no_resend(harness_guardian, upstream, audit, tmp_path,
                                                                     stream):
    """Through a real HTTP server, since only a real connection can drop."""
    import httpx

    from conftest import SSE
    from streams import encode, stream_events

    call = call_item("ask_tool", {}, "call_1")
    upstream.reply(SSE(encode(stream_events(call))) if stream else response_body(call))
    app = _live_gateway(harness_guardian, upstream, tmp_path)
    approvals = app.state.gateway.approvals
    server, thread, port = _serve(app)
    try:
        url = f"http://127.0.0.1:{port}/v1/responses"
        body = {**finbot_request(), "stream": True} if stream else finbot_request()
        with pytest.raises(httpx.ReadTimeout):
            with httpx.stream("POST", url, json=body, timeout=httpx.Timeout(10, read=1.0)) as response:
                for _ in response.iter_bytes():
                    pass
        # The client gave up and closed. The call leaves the page, and a late approval finds nothing to take.
        end = time.monotonic() + 3
        while approvals.pending() and time.monotonic() < end:
            time.sleep(0.05)
        assert approvals.pending() == []
        end = time.monotonic() + 3
        while not events(audit, "ask_resolved") and time.monotonic() < end:
            time.sleep(0.05)
    finally:
        server.should_exit = True
        thread.join(10)
    assert len(tool_requests(tmp_path)) == 1
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["cause"], r["decision"]) for r in resolved] == [
        ("abandoned", "client_disconnected", "deny")]


def _streamed(client: Any) -> list[dict[str, Any]]:
    from streams import decode

    with client.stream("POST", "/v1/responses", json={**finbot_request(), "stream": True}) as response:
        return decode(b"".join(response.iter_bytes()))


def _streamed_calls(received: list[dict[str, Any]]) -> list[str]:
    return [e["item"]["call_id"] for e in received
            if e["type"] == "response.output_item.done" and e["item"]["type"] == "function_call"]


def test_a_streamed_ask_is_held_and_released_after_approval(gateway, harness_guardian, upstream, audit, tmp_path):
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"vendor_id": 7}, "call_1")))))
    client = enforce(gateway, harness_guardian, tmp_path)
    thread = approver(client, "approve")
    received = _streamed(client)
    thread.join()
    assert _streamed_calls(received) == ["call_1"]
    assert [(r["outcome"], r["decision"]) for r in events(audit, "ask_resolved")] == [("approved", "allow")]


def test_two_streamed_asks_share_one_deadline(gateway, harness_guardian, upstream, audit, tmp_path):
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"n": 1}, "call_1"),
                                            call_item("ask_tool", {"n": 2}, "call_2")))))
    client = enforce(gateway, harness_guardian, tmp_path, ACS_GATEWAY_ASK_MAX_S="2",
                     ACS_DECISION_TIMEOUT_MS="200")
    started = time.monotonic()
    received = _streamed(client)
    assert time.monotonic() - started < 1.8
    assert _streamed_calls(received) == []
    assert [r["outcome"] for r in events(audit, "ask_resolved")] == ["timed_out", "timed_out"]


def test_a_held_stream_sends_a_comment_line_to_keep_the_connection_open(gateway, harness_guardian, upstream, audit,
                                                                        tmp_path, monkeypatch):
    from conftest import SSE
    from streams import encode, stream_events

    import acs_gateway.stream

    monkeypatch.setattr(acs_gateway.stream, "KEEPALIVE_S", 0.1)
    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {}, "call_1")))))
    client = enforce(gateway, harness_guardian, tmp_path)
    approvals = client.app.state.gateway.approvals

    def late() -> None:
        end = time.monotonic() + 5
        while not approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)
        time.sleep(0.5)
        approvals.answer(approvals.pending()[0].ask_id, "approve")

    thread = threading.Thread(target=late, daemon=True)
    thread.start()
    with client.stream("POST", "/v1/responses", json={**finbot_request(), "stream": True}) as response:
        raw = b"".join(response.iter_bytes())
    thread.join()
    assert raw.count(b": keepalive\n\n") >= 2
    from streams import decode

    assert _streamed_calls(decode(raw)) == ["call_1"]


def _raw_request(port: int, body: dict[str, Any]) -> Any:
    import json
    import socket

    raw = json.dumps(body).encode()
    sock = socket.create_connection(("127.0.0.1", port))
    sock.sendall(b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                 + f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    return sock


def _hang_up(sock: Any) -> None:
    import socket

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


def _first_pending(approvals: Any) -> Any:
    end = time.monotonic() + 10
    while not approvals.pending() and time.monotonic() < end:
        time.sleep(0.01)
    return approvals.pending()[0]


def _resolved_after(audit, seconds: float = 5.0) -> list[tuple[Any, Any, Any]]:
    """The ask_resolved lines once one has landed, then a moment more, so a second line would be seen too."""
    end = time.monotonic() + seconds
    while not events(audit, "ask_resolved") and time.monotonic() < end:
        time.sleep(0.02)
    time.sleep(0.3)
    return [(r["outcome"], r["cause"], r["decision"]) for r in events(audit, "ask_resolved")]


@pytest.mark.parametrize("delay_s", [0.0, 0.05, 0.15, 0.4])
def test_a_streamed_approval_just_after_a_disconnect_sends_no_resend(harness_guardian, upstream, audit, tmp_path,
                                                                     delay_s):
    """The streamed twin of R-I1 (round 4, I-1): one disconnect signal for both paths, and one outcome line."""
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"v": 1}, "call_1")))))
    app = _live_gateway(harness_guardian, upstream, tmp_path)
    approvals = app.state.gateway.approvals
    server, thread, port = _serve(app)
    try:
        sock = _raw_request(port, {**finbot_request(), "stream": True})
        ask_id = _first_pending(approvals).ask_id
        _hang_up(sock)
        time.sleep(delay_s)
        approvals.answer(ask_id, "approve")
        resolved = _resolved_after(audit)
    finally:
        server.should_exit = True
        thread.join(10)
    assert len(tool_requests(tmp_path)) == 1, resolved
    assert resolved == [("abandoned", "client_disconnected", "deny")]


@pytest.mark.parametrize("stream", [True, False])
@pytest.mark.parametrize("run", range(20))
def test_an_approval_racing_a_disconnect_never_resends(harness_guardian, upstream, audit, tmp_path, run, stream):
    """The zero-delay race, repeated so a scheduling window can't hide it."""
    from conftest import SSE
    from streams import encode, stream_events

    call = call_item("ask_tool", {"v": 1}, "call_1")
    upstream.reply(SSE(encode(stream_events(call))) if stream else response_body(call))
    app = _live_gateway(harness_guardian, upstream, tmp_path)
    approvals = app.state.gateway.approvals
    server, thread, port = _serve(app)
    try:
        sock = _raw_request(port, {**finbot_request(), "stream": True} if stream else finbot_request())
        ask_id = _first_pending(approvals).ask_id
        _hang_up(sock)
        approvals.answer(ask_id, "approve")
        resolved = _resolved_after(audit)
    finally:
        server.should_exit = True
        thread.join(10)
    assert len(tool_requests(tmp_path)) == 1, resolved
    assert resolved == [("abandoned", "client_disconnected", "deny")]


def test_a_streamed_disconnect_during_the_approved_resend_writes_one_outcome(harness_guardian, upstream, audit,
                                                                            tmp_path):
    """Approve first, then the client leaves while the resend is still at the Guardian. The resend went out, and
    exactly one ask_resolved line says the request ended."""
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"v": 1}, "call_1")))))
    app = _live_gateway(harness_guardian, upstream, tmp_path)
    gateway_ = app.state.gateway
    real = gateway_.guardian.step

    def slow_resend(session, method, payload, token):
        if ANSWER_FIELD in payload:
            time.sleep(1.0)
        return real(session, method, payload, token)

    gateway_.guardian.step = slow_resend
    server, thread, port = _serve(app)
    try:
        sock = _raw_request(port, {**finbot_request(), "stream": True})
        assert gateway_.approvals.answer(_first_pending(gateway_.approvals).ask_id, "approve")
        time.sleep(0.3)
        _hang_up(sock)
        resolved = _resolved_after(audit, seconds=8)
        time.sleep(1.5)
        resolved = [(r["outcome"], r["cause"], r["decision"]) for r in events(audit, "ask_resolved")]
    finally:
        server.should_exit = True
        thread.join(10)
    assert resolved == [("abandoned", "client_disconnected", "deny")]
