"""Upstream answers and encodings (review I1, CR6)."""
import gzip
import json

import pytest

from conftest import finbot_request, message_item, response_body


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("reply", [b"not json", b"[1, 2]", json.dumps({"id": "resp_1"}).encode()])
def test_a_2xx_answer_that_is_not_a_response_object_gets_502(gateway, guardian, upstream, audit, mode, reply):
    upstream.reply(reply)
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.status_code == 502
    assert events(audit, "upstream_error")[0]["cause"] == "upstream_unparseable"


@pytest.mark.parametrize("stream", ["true", 1, "yes", None])
def test_any_stream_value_but_false_counts_as_streaming(gateway, guardian, upstream, stream):
    body = {**finbot_request(), "stream": stream}
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=body)
    assert response.status_code == 501
    assert upstream.received == []


def test_stream_false_is_not_streaming(gateway, guardian, upstream):
    body = {**finbot_request(), "stream": False}
    assert gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=body).status_code == 200


def test_governed_modes_ask_upstream_only_for_encodings_they_decode(gateway, guardian, upstream):
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request(), headers={"Accept-Encoding": "br, zstd"})
    assert upstream.received[0].headers["accept-encoding"] == "gzip, deflate"


def test_governed_modes_refuse_a_compressed_request_body(gateway, guardian, upstream):
    body = gzip.compress(json.dumps(finbot_request()).encode())
    response = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", content=body, headers={"Content-Encoding": "gzip", "Content-Type": "application/json"})
    assert response.status_code == 415
    assert upstream.received == []


def test_off_relays_encodings_and_headers_verbatim(gateway, upstream):
    raw = gzip.compress(json.dumps(response_body(message_item("hi"))).encode())
    upstream.reply(raw, headers={"Content-Encoding": "gzip"})
    client = gateway()
    response = client.post("/v1/responses", json=finbot_request(), headers={"Accept-Encoding": "br, gzip"})
    assert upstream.received[0].headers["accept-encoding"] == "br, gzip"
    assert response.headers["content-encoding"] == "gzip"
    assert response.json() == response_body(message_item("hi"))


@pytest.mark.parametrize("mode", ["off", "enforce"])
def test_lab_headers_from_the_upstream_never_reach_the_client(gateway, guardian, upstream, mode):
    upstream.reply(response_body(message_item("hi")), headers={"X-ACS-Lab-Branch": "a,d"})
    response = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    assert response.status_code == 200
    assert not [h for h in response.headers if h.lower().startswith("x-acs-")]
    assert response.headers["x-request-id"] == "req_upstream_1"
