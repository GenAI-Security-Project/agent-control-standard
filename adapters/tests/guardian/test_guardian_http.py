"""The example Guardian over real HTTP: every request gets a JSON-RPC answer, and no connection is dropped.

A dropped connection reads as transport_failure, which a proceed posture runs ungoverned. These tests talk to a
GuardianHandler served in-process, so a test can also make handle_request fail on purpose.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading

import pytest

from acs.guardian import example_guardian


@pytest.fixture
def served(monkeypatch):
    """Serve GuardianHandler on a free port in this process. Yields (host, port)."""
    monkeypatch.setenv("ACS_HMAC_SECRET", "guardian-http-test-secret-32-bytes-long")
    monkeypatch.setenv("ACS_HMAC_KEY_ID", "test-key")
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(example_guardian, "OPA_CONFIG", None)
    monkeypatch.setattr(example_guardian, "POLICY_BACKEND_NAME", "")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), example_guardian.GuardianHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address
    server.shutdown()
    server.server_close()


def send_raw(address: tuple[str, int], head: str, body: bytes = b"") -> tuple[int, dict]:
    """Send one raw HTTP request and return (status, JSON body). A dropped connection fails the test."""
    with socket.create_connection(address, timeout=5) as sock:
        sock.sendall(head.encode("latin-1") + b"\r\n\r\n" + body)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    assert raw, "the Guardian closed the connection without an answer"
    header, _, payload = raw.partition(b"\r\n\r\n")
    status = int(header.split(b" ", 2)[1])
    return status, json.loads(payload)


def post(address: tuple[str, int], body: bytes) -> tuple[int, dict]:
    head = f"POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Type: application/json\r\nContent-Length: {len(body)}"
    return send_raw(address, head, body)


def test_an_unexpected_error_is_answered_with_an_unsigned_internal_error(served, monkeypatch):
    def broken(request):
        raise RuntimeError("anything at all")
    monkeypatch.setattr(example_guardian, "handle_request", broken)
    status, body = post(served, b'{"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": {}}')
    assert body["error"]["code"] == -32603
    assert "anything at all" not in body["error"]["message"]
    assert "signature" not in body["error"] and body["id"] is None


def test_an_integer_too_long_to_parse_is_a_parse_error(served):
    # Python refuses to parse an integer of more than 4,300 digits with a plain ValueError.
    body = b'{"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": {"x": ' + b"9" * 5000 + b"}}"
    status, answer = post(served, body)
    assert (status, answer["error"]["code"]) == (400, -32700)


@pytest.mark.parametrize("length_header", ["", "Content-Length: -5", "Content-Length: abc", "Content-Length: 1.5"])
def test_a_missing_negative_or_non_integer_content_length_is_refused_without_reading(served, length_header):
    head = "POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Type: application/json"
    if length_header:
        head += "\r\n" + length_header
    status, answer = send_raw(served, head, b'{"jsonrpc": "2.0"}')
    assert (status, answer["error"]["code"]) == (400, -32600)
    assert "signature" not in answer["error"]


def _ping(request_id) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "system/ping", "params": {"payload": {}}}).encode()


@pytest.mark.parametrize("request_id", ["abc", 7, 1.0, 1.5, -2, None])
def test_an_id_that_is_a_string_a_finite_number_or_null_is_answered_with_that_id(served, request_id):
    status, answer = post(served, _ping(request_id))
    assert answer["id"] == request_id and "result" in answer


@pytest.mark.parametrize("raw_id", [b"true", b"false", b"NaN", b"Infinity", b"[1]", b'{"a": 1}'])
def test_an_id_that_is_a_bool_a_non_finite_number_or_a_container_is_refused_with_a_null_id(served, raw_id):
    body = b'{"jsonrpc": "2.0", "id": ' + raw_id + b', "method": "system/ping", "params": {"payload": {}}}'
    status, answer = post(served, body)
    assert (answer["id"], answer["error"]["code"]) == (None, -32600)


@pytest.mark.parametrize("params", [None, {"metadata": None, "payload": {}}, {"request_id": None, "payload": {}},
                                    {"metadata": {"session_id": None}, "payload": {}}])
def test_null_params_metadata_request_id_and_session_id_read_as_absent_on_ping(served, params):
    body = json.dumps({"jsonrpc": "2.0", "id": "p", "method": "system/ping", "params": params}).encode()
    status, answer = post(served, body)
    assert (status, answer["result"]["decision"]) == (200, "allow")


@pytest.mark.parametrize("field,read_as", [("metadata", ("metadata", {})), ("request_id", ("request_id", "")),
                                           ("session_id", ("session_id", ""))])
def test_null_fields_read_as_absent_on_a_step(field, read_as):
    params = {"metadata": {"session_id": "s"}, "request_id": "r", "payload": {}}
    if field == "session_id":
        params["metadata"]["session_id"] = None
    else:
        params[field] = None
    fields, problem, _ = example_guardian.read_request(
        {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": params})
    assert problem is None
    name, value = read_as
    assert getattr(fields, name) == value


@pytest.mark.parametrize("method", ["system/ping", "handshake/hello"])
@pytest.mark.parametrize("payload", ["x", [1], 5, None])
def test_a_payload_that_is_not_an_object_is_refused_on_ping_and_hello(served, method, payload):
    body = json.dumps({"jsonrpc": "2.0", "id": "1", "method": method,
                       "params": {"metadata": {"session_id": "s"}, "payload": payload}}).encode()
    status, answer = post(served, body)
    assert answer["error"]["code"] == -32600
