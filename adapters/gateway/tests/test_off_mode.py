import json

from conftest import call_item, finbot_request, response_body, transcript_lines


def test_off_forwards_the_request_and_response_bytes_untouched(gateway, upstream, audit, tmp_path):
    reply = response_body(call_item("bash", {"command": "rm -rf /"}, "call_1"))
    upstream.reply(reply)
    body = json.dumps(finbot_request()).encode()
    client = gateway()
    response = client.post("/v1/responses", content=body,
                           headers={"Content-Type": "application/json", "Authorization": "Bearer lab-dummy",
                                    "X-ACS-Lab-Session": "s1"})
    assert response.status_code == 200
    assert response.json() == reply
    assert upstream.received[0].body == body
    assert upstream.received[0].path == "/v1/responses"
    assert upstream.received[0].headers["authorization"] == "Bearer lab-dummy"
    assert "x-acs-lab-session" not in upstream.received[0].headers
    assert transcript_lines(tmp_path) == []
    assert audit() == []


def test_off_writes_the_model_input_log(gateway, upstream, tmp_path):
    gateway().post("/v1/responses", json=finbot_request())
    logged = [json.loads(line) for line in (tmp_path / "model-inputs.jsonl").read_text().splitlines()]
    assert logged == [finbot_request()]


def test_off_relays_a_streamed_response_byte_for_byte(gateway, upstream, audit, tmp_path):
    from conftest import SSE, sse_events

    events = sse_events("Hello from the vendor desk")
    upstream.reply(SSE(events))
    body = json.dumps({**finbot_request(), "stream": True}).encode()
    client = gateway()
    with client.stream("POST", "/v1/responses", content=body,
                       headers={"Content-Type": "application/json", "X-ACS-Lab-Session": "s1"}) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        received = b"".join(response.iter_bytes())
    assert received == b"".join(events)
    assert upstream.received[0].body == body
    assert "x-acs-lab-session" not in upstream.received[0].headers
    assert transcript_lines(tmp_path) == []
    assert audit() == []


def test_off_without_a_model_input_log_never_decodes_the_body(gateway, upstream, monkeypatch):
    import acs_gateway.app as app_module

    def refuse(*args, **kwargs):
        raise AssertionError("off mode decoded a body it had no log for")

    client = gateway(ACS_MODEL_INPUT_LOG="")
    monkeypatch.setattr(app_module, "_parse", refuse)
    client.app.state.gateway.model_inputs.append = refuse
    response = client.post("/v1/responses", content=b"\xff\xfe not utf-8", headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert upstream.received[0].body == b"\xff\xfe not utf-8"
