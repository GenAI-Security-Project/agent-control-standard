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
    client = capture(gateway, tmp_path)
    (tmp_path / "rec").mkdir()
    (tmp_path / "rec" / "s1.jsonl").mkdir()  # a directory where the file should be, so the append fails
    upstream.reply(response_body(message_item("still here")))
    response = client.post("/v1/responses", json=finbot_request())
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


def test_capture_refuses_to_start_over_an_existing_scenario_file(gateway, tmp_path):
    (tmp_path / "rec").mkdir()
    (tmp_path / "rec" / "s1.jsonl").write_text("stale\n")
    with pytest.raises(ValueError, match="s1.jsonl"):
        capture(gateway, tmp_path)


def test_capture_never_follows_a_symlinked_scenario_file(gateway, upstream, tmp_path, audit):
    client = capture(gateway, tmp_path)
    target = tmp_path / "elsewhere.txt"
    target.write_text("untouched\n")
    (tmp_path / "rec").mkdir(exist_ok=True)
    (tmp_path / "rec" / "s1.jsonl").symlink_to(target)
    upstream.reply(response_body(message_item("ok")))
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    assert target.read_text() == "untouched\n"
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_failed"] == ["write_error"]


def test_capture_stops_buffering_past_the_body_limit(gateway, upstream, tmp_path, audit):
    upstream.reply(response_body(message_item("x" * 4000)))
    response = capture(gateway, tmp_path, ACS_GATEWAY_MAX_BODY_BYTES="1000").post("/v1/responses",
                                                                                   json=finbot_request())
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_too_large"
    assert recorded(tmp_path) == []
    assert "upstream_too_large" in [e["cause"] for e in audit() if e["acs_audit_event"] == "upstream_error"]


def test_capture_bounds_the_decompressed_answer(gateway, upstream, tmp_path, audit):
    """Fix round 3, CR3-4: a small gzip body that inflates past the limit stops as upstream_too_large."""
    import gzip

    bomb = gzip.compress(b'{"output": [], "pad": "' + b"0" * 4_000_000 + b'"}')
    assert len(bomb) < 100_000
    upstream.reply(bomb, headers={"Content-Encoding": "gzip"})
    response = capture(gateway, tmp_path, ACS_GATEWAY_MAX_BODY_BYTES="100000").post("/v1/responses",
                                                                                     json=finbot_request())
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_too_large"
    assert recorded(tmp_path) == []


def test_capture_records_a_gzip_answer_under_the_limit(gateway, upstream, tmp_path):
    import gzip

    body = response_body(message_item("compressed ok"))
    upstream.reply(gzip.compress(json.dumps(body).encode()), headers={"Content-Encoding": "gzip"})
    response = capture(gateway, tmp_path).post("/v1/responses", json=finbot_request())
    assert response.json() == body
    assert recorded(tmp_path)[0]["response"]["output"][0]["content"][0]["text"] == "compressed ok"


@pytest.mark.parametrize("leak", [
    "admin@NS_USER_ABCDEFGH-_123456.finbot",
    f"admin@{NS_A}x.finbot",
    f"{USER_A}7",
])
def test_capture_refuses_any_form_of_a_mapped_user_id(gateway, upstream, tmp_path, audit, leak):
    """Fix round 3, R-M2: an uppercase namespace, a suffixed one, or the id with one more character still leaks."""
    upstream.reply(response_body(message_item(f"Mail {leak}")))
    capture(gateway, tmp_path).post("/v1/responses", json=finbot_request(system=f"User ID: {USER_A}"))
    assert recorded(tmp_path) == []
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_skipped"] == ["unmapped_id"]


def split_stream(*pieces):
    """A streamed answer whose text arrives only as deltas, split where the caller says."""
    events = [("response.created", {"type": "response.created", "sequence_number": 0,
                                    "response": {**response_body(), "status": "in_progress", "output": []}})]
    events += [("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": i + 1,
                                               "item_id": "msg_1", "output_index": 0, "content_index": 0,
                                               "delta": piece, "logprobs": []}) for i, piece in enumerate(pieces)]
    events.append(("response.completed", {"type": "response.completed", "sequence_number": len(pieces) + 1,
                                          "response": {**response_body(), "output": []}}))
    return SSE([f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events])


@pytest.mark.parametrize("pieces", [
    (f"Mail admin@{NS_A[:10]}", f"{NS_A[10:]}.finbot"),
    (f"Mail admin@{NS_A[:6]}", NS_A[6:15], f"{NS_A[15:]}.finbot"),
])
def test_capture_refuses_an_id_split_across_streamed_deltas(gateway, upstream, tmp_path, audit, pieces):
    """Fix round 4, I-2: no single delta holds the namespace, but the deltas rejoin into it on replay."""
    upstream.reply(split_stream(*pieces))
    response = capture(gateway, tmp_path).post("/v1/responses", json={
        **finbot_request(system=f"User ID: {USER_A}"), "stream": True})
    assert response.status_code == 200
    assert recorded(tmp_path) == []
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_skipped"] == ["unmapped_id"]


def test_split_deltas_without_an_id_are_captured(gateway, upstream, tmp_path):
    upstream.reply(split_stream("Hello ", "there"))
    capture(gateway, tmp_path).post("/v1/responses", json={**finbot_request(), "stream": True})
    assert [e["data"]["delta"] for e in recorded(tmp_path)[0]["response"][1:3]] == ["Hello ", "there"]


def test_an_output_with_no_call_id_takes_no_step_and_the_line_loads(gateway, upstream, tmp_path):
    """Fix round 3, CR3-5: step counts only outputs the gateway governs, the same ones the branch counts."""
    upstream.reply(response_body(message_item("ok")))
    capture(gateway, tmp_path).post("/v1/responses", json=finbot_request(
        {"type": "function_call_output", "output": "orphan"}))
    [line] = recorded(tmp_path)
    assert (line["step"], line["branch"]) == (0, "")
    gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))


def test_capture_never_writes_a_line_the_loader_rejects(gateway, upstream, tmp_path, audit, monkeypatch):
    from acs_gateway import upstream as module

    def reject(raw):
        raise ValueError("rejected for the test")

    client = capture(gateway, tmp_path)
    monkeypatch.setattr(module, "_recording", reject)
    upstream.reply(response_body(message_item("ok")))
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    assert recorded(tmp_path) == []
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_skipped"] == ["invalid_line"]


class _SlowFirstUpstream:
    """A live transport whose first attempt answers after its retry, as when a client times out on a slow model and
    retries while the first attempt is still running upstream. It answers as a stream when the request asks for one.
    It also keeps the extensions each request reached it with."""

    def __init__(self, delays, status=200):
        self.delays = list(delays)
        self.status = status
        self.n = 0
        self.extensions = []

    async def handle_async_request(self, request):
        import asyncio

        import httpx

        self.n += 1
        attempt = self.n
        self.extensions.append(dict(request.extensions))
        await asyncio.sleep(self.delays[attempt - 1])
        status = self.status if attempt > 1 else 200
        if json.loads(request.content).get("stream"):
            return httpx.Response(status, headers={"content-type": "text/event-stream"},
                                  stream=httpx.ByteStream(b"".join(sse_events(f"REPLY-{attempt}"))))
        body = response_body(message_item(f"REPLY-{attempt}"), response_id=f"resp_{attempt}")
        return httpx.Response(status, headers={"content-type": "application/json"},
                              stream=httpx.ByteStream(json.dumps(body).encode()))

    async def aclose(self):
        pass


def _text(response, stream):
    if stream:
        return "".join(e["data"]["delta"] for e in response if isinstance(e["data"].get("delta"), str))
    return response["output"][0]["content"][0]["text"]


def _overlapping_retry(tmp_path, live, stream=False, numbers=(1, 2)):
    """Two byte-identical requests through CaptureTransport, the second sent while the first is in flight, each
    carrying the arrival the gateway took for it under the session lock. numbers are those arrivals, in the order
    the requests reach the transport. Returns the lines written and what replay serves for the request."""
    import asyncio

    import httpx

    from acs_gateway import upstream as up
    from acs_gateway.sessions import Session

    path = tmp_path / "s.jsonl"
    transport = up.CaptureTransport(live, path, "s", 1 << 20)
    request = {**finbot_request(), "stream": True} if stream else finbot_request()
    raw = json.dumps(request).encode()
    session = Session(session_id="s", epoch=0)
    arrivals = {n: up.note_arrival(session, request) for n in sorted(numbers)}

    async def send(delay, number):
        await asyncio.sleep(delay)
        sent = httpx.Request("POST", "http://x/v1/responses", content=raw, headers={up.BRANCH_HEADER: ""},
                             extensions={up.ARRIVAL_EXTENSION: arrivals[number]})
        await (await transport.handle_async_request(sent)).aread()

    async def both():
        await asyncio.gather(send(0, numbers[0]), send(0.1, numbers[1]))

    asyncio.run(both())
    texts = [_text(json.loads(line)["response"], stream) for line in path.read_text().splitlines()] \
        if path.exists() else []
    store = up.RecordingStore.load(tmp_path)
    mapping = up.placeholder_map(request)
    first, turn, step = up.replay_key(request, mapping)
    found, _ = store.find(first, turn, step, "", stream, up.id_skeleton(request, mapping))
    return texts, _text(found.response, stream) if found else None


def test_a_retry_that_overtakes_its_first_attempt_is_the_line_replay_serves(tmp_path, audit):
    """Final review I-1: the first attempt finishes after its retry, but the client kept the retry's reply, so the
    first attempt's line is dropped however late it lands."""
    texts, served = _overlapping_retry(tmp_path, _SlowFirstUpstream([0.3, 0.05]))
    assert texts == ["REPLY-2"]
    assert served == "REPLY-2"
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_skipped"] == ["superseded_attempt"]


def test_a_streamed_retry_that_overtakes_its_first_attempt_is_the_line_replay_serves(tmp_path, audit):
    """Round 2: the same for a stream, which capture buffers whole before the line is written."""
    texts, served = _overlapping_retry(tmp_path, _SlowFirstUpstream([0.3, 0.05]), stream=True)
    assert texts == ["REPLY-2"]
    assert served == "REPLY-2"
    assert [e["cause"] for e in audit() if e["acs_audit_event"] == "capture_skipped"] == ["superseded_attempt"]


def test_a_failed_retry_still_drops_the_attempt_it_replaced(tmp_path):
    """The client kept the retry's error, not the first attempt's reply, so neither is a line."""
    texts, served = _overlapping_retry(tmp_path, _SlowFirstUpstream([0.3, 0.05], status=503))
    assert texts == []
    assert served is None


def test_capture_follows_the_gateway_arrival_not_the_order_requests_reach_it(tmp_path):
    """Round 2, R5: the arrival number the gateway took under the session lock decides, so a later arrival that
    reaches the transport first is still the attempt the client kept. The transport keeps no order of its own."""
    texts, served = _overlapping_retry(tmp_path, _SlowFirstUpstream([0.3, 0.05]), numbers=(2, 1))
    assert texts == ["REPLY-1"]
    assert served == "REPLY-1"


def test_the_arrival_never_reaches_the_live_upstream():
    import asyncio

    import httpx

    from acs_gateway import upstream as up
    from acs_gateway.sessions import Session

    seen = []

    def handler(request):
        seen.append(dict(request.extensions))
        return httpx.Response(200, json=response_body(message_item("ok")))

    async def run():
        live = up.LiveTransport(None)
        await live._client.aclose()
        live._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        arrival = up.note_arrival(Session(session_id="s", epoch=0), finbot_request())
        request = httpx.Request("POST", "http://x/v1/responses", content=b"{}",
                                extensions={up.ARRIVAL_EXTENSION: arrival})
        await (await live.handle_async_request(request)).aread()
        await live.aclose()

    asyncio.run(run())
    assert seen and up.ARRIVAL_EXTENSION not in seen[0]


def test_off_mode_capture_keeps_the_overtaking_retrys_line(gateway, upstream, tmp_path):
    """Round 2, R5: off mode has no sessions, so the gateway counts its arrivals as it relays them and capture still
    keeps the line of the attempt the client kept."""
    import threading
    import time

    client = capture(gateway, tmp_path)
    upstream.reply(response_body(message_item("abandoned")), delay=1.0)
    upstream.reply(response_body(message_item("kept")))

    def send(delay):
        time.sleep(delay)
        client.post("/v1/responses", json=finbot_request())

    threads = [threading.Thread(target=send, args=(d,)) for d in (0, 0.3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [line["response"]["output"][0]["content"][0]["text"] for line in recorded(tmp_path)] == ["kept"]
