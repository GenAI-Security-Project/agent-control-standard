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
