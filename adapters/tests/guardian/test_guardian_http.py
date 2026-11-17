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
    # In memory, so no test writes Guardian state to the home directory, and a test can read STATE directly.
    monkeypatch.setattr(example_guardian, "PERSIST_ENABLED", False)
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
    def broken(request, read=None):
        raise RuntimeError("anything at all")
    monkeypatch.setattr(example_guardian, "handle_request", broken)
    status, body = post(served, b'{"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": {}}')
    assert body["error"]["code"] == -32603
    assert "anything at all" not in body["error"]["message"]
    # The id parsed and passed the id rule, so the floor echoes it (CR10-5).
    assert "signature" not in body["error"] and body["id"] == "1"


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


@pytest.mark.parametrize("field,read_as", [("metadata", ("session_id", "")), ("request_id", ("request_id", "")),
                                           ("session_id", ("session_id", ""))])
def test_null_fields_read_as_absent_on_a_step(field, read_as):
    params = {"metadata": {"session_id": "s"}, "request_id": "r", "payload": {}}
    if field == "session_id":
        params["metadata"]["session_id"] = None
    else:
        params[field] = None
    fields, problem, _, _ = example_guardian.read_request(
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


# UUIDs, so the envelope passes the schema and only the step under test can refuse it.
SCHEMA_SESSION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SIG_SESSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
DEEP_SESSION = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
STRUCT_SESSION = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
FLOOR_SESSION = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


def _envelope_text(session_id: str = "ok-session", key_id: str = "test-key", depth: int = 0,
                   request_id: object = "1", acs_request_id: str = "11111111-1111-4111-8111-111111111111") -> bytes:
    """A step envelope with a made-up signature, so nothing here is a verified sender."""
    deep: list = []
    for _ in range(depth):
        deep = [deep]
    envelope = {"jsonrpc": "2.0", "id": request_id, "method": "steps/toolCallRequest",
                "params": {"acs_version": "0.1.0", "request_id": acs_request_id,
                           "timestamp": "2026-11-17T00:00:00Z",
                           "metadata": {"agent_id": "a", "session_id": session_id, "platform": "p"},
                           "payload": {"tool": {"name": "ls"}, "arguments": {"x": {"value": deep}}},
                           "signature": {"algorithm": "HMAC-SHA256", "value": "AAAA", "key_id": key_id}}}
    return json.dumps(envelope).encode()


def _assert_unsigned_and_stateless(answer: dict, code: int, session_id: str) -> None:
    assert answer["error"]["code"] == code
    assert "signature" not in answer["error"] and "signature" not in answer
    assert session_id not in example_guardian.STATE.sessions, "an unverified request changed Guardian state"


def _classify(body: bytes, answer: dict, session_id: str):
    """How acs.client reads this answer to this request, with the same secret the served Guardian uses."""
    from acs.client import classify_response
    return classify_response(json.loads(body), answer, session_id=session_id)


def _assert_signed_malformed(body: bytes, answer: dict, session_id: str) -> None:
    # Signed per spec section 10, so the client classifies it as the malformed envelope it is, not as a forgery.
    assert answer["error"]["code"] == -32600
    assert "signature" in answer["error"]
    assert _classify(body, answer, session_id).cause == "malformed_envelope_response"
    assert session_id not in example_guardian.STATE.sessions, "a refused request changed Guardian state"


def test_a_too_deep_body_gets_a_signed_error(served):
    body = _envelope_text(session_id=DEEP_SESSION, depth=example_guardian.MAX_REQUEST_DEPTH + 50)
    status, answer = post(served, body)
    _assert_signed_malformed(body, answer, DEEP_SESSION)


def test_a_foreign_key_id_gets_the_unsigned_minus_32004_before_depth_or_structure(served):
    # The key_id is checked first whenever the signature object is readable, so key_id_rejected is never hidden
    # behind an error signed with this Guardian's key.
    deep = _envelope_text(session_id=DEEP_SESSION, key_id="someone-else", depth=example_guardian.MAX_REQUEST_DEPTH + 50)
    bad_structure = json.loads(_envelope_text(session_id=STRUCT_SESSION, key_id="someone-else"))
    bad_structure["params"]["request_id"] = 5
    for body, session in ((deep, DEEP_SESSION), (json.dumps(bad_structure).encode(), STRUCT_SESSION)):
        status, answer = post(served, body)
        _assert_unsigned_and_stateless(answer, -32004, session)
        assert _classify(body, answer, session).cause == "key_id_rejected"


def test_a_non_uuid_session_id_gets_a_signed_schema_error(served):
    body = _envelope_text(session_id="not-a-uuid")
    status, answer = post(served, body)
    _assert_signed_malformed(body, answer, "not-a-uuid")


def test_a_structure_error_with_a_readable_session_is_signed(served):
    body = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart",
                       "params": {"metadata": {"session_id": STRUCT_SESSION}, "request_id": 5}}).encode()
    status, answer = post(served, body)
    _assert_signed_malformed(body, answer, STRUCT_SESSION)


def test_an_error_that_cannot_be_signed_gets_the_unsigned_floor_never_a_drop(served):
    # An id beyond 2^53 is now refused as an invalid id, signed with id null, so the unsignable case left is a
    # session_id JCS can't encode.
    depth = example_guardian.MAX_REQUEST_DEPTH + 50
    body = _envelope_text(depth=depth, session_id="SURROGATE").replace(b'"SURROGATE"', b'"\\ud800"')
    session = "\ud800"
    status, answer = post(served, body)
    _assert_unsigned_and_stateless(answer, -32603, session)


def test_a_schema_error_is_signed(served):
    body = _envelope_text(session_id=SCHEMA_SESSION, acs_request_id="not-a-uuid")
    status, answer = post(served, body)
    _assert_signed_malformed(body, answer, SCHEMA_SESSION)


def test_a_signature_that_does_not_verify_gets_a_signed_minus_32004_and_no_state_change(served):
    # §10 exempts only an unknown key_id from signing, and the conformance suite (Core08) requires a signed -32004
    # here, so acs.client can tell a bad signature from a refused key_id.
    from acs.client import verify_signature
    status, answer = post(served, _envelope_text(session_id=SIG_SESSION))
    assert answer["error"]["code"] == -32004
    assert verify_signature(answer, session_id=SIG_SESSION)
    assert SIG_SESSION not in example_guardian.STATE.sessions


def test_an_unknown_key_id_gets_an_unsigned_minus_32004(served):
    status, answer = post(served, _envelope_text(session_id=SIG_SESSION, key_id="someone-else"))
    _assert_unsigned_and_stateless(answer, -32004, SIG_SESSION)


# Round 10 items below.


def test_a_400_digit_integer_id_is_refused_never_500(served):
    # JCS signs only integers within 2^53, so a longer one is refused as an invalid id, with id null.
    status, answer = post(served, _ping(int("9" * 400)))
    assert status != 500 and (answer["id"], answer["error"]["code"]) == (None, -32600)


@pytest.mark.parametrize("request_id", [2**53, -(2**53), 2**60, int("9" * 400)])
def test_a_signed_step_with_an_id_beyond_2_53_is_refused_before_any_state_change(served, request_id):
    from acs.client import verify_signature
    from acs.testing.harness import make_envelope
    secret = "guardian-http-test-secret-32-bytes-long"
    envelope = make_envelope("steps/sessionStart", {}, sign_with_secret=secret)
    session_id = envelope["params"]["metadata"]["session_id"]
    envelope["id"] = request_id
    status, answer = post(served, json.dumps(envelope).encode())
    assert (answer["id"], answer["error"]["code"]) == (None, -32600)
    assert verify_signature(answer, session_id=session_id)
    assert session_id not in example_guardian.STATE.sessions


@pytest.mark.parametrize("request_id", [2**53 - 1, -(2**53 - 1)])
def test_an_id_at_the_edge_of_2_53_is_echoed(served, request_id):
    status, answer = post(served, _ping(request_id))
    assert answer["id"] == request_id


def test_the_floor_echoes_an_id_that_parsed(served, monkeypatch):
    def broken(request, read=None):
        raise RuntimeError("boom")
    monkeypatch.setattr(example_guardian, "handle_request", broken)
    status, answer = post(served, _ping("keep-me"))
    assert (answer["error"]["code"], answer["id"]) == (-32603, "keep-me")


# Headers are Latin-1 on the wire, so non-ASCII digits can't be sent here.
@pytest.mark.parametrize("value", ["+10", " 10 ", "1_0", "0x10", "1e1"])
def test_a_content_length_that_is_not_plain_digits_is_refused_without_reading(served, value):
    head = f"POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Type: application/json\r\nContent-Length: {value}"
    status, answer = send_raw(served, head, b'{"jsonrpc": "2.0"}')
    assert (status, answer["error"]["code"]) == (400, -32600)


def test_a_step_payload_that_is_not_an_object_is_refused_on_the_wire(served):
    body = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "steps/toolCallRequest",
                       "params": {"metadata": {"session_id": STRUCT_SESSION}, "payload": "x"}}).encode()
    status, answer = post(served, body)
    assert answer["error"]["code"] == -32600


def test_a_client_that_never_finishes_its_body_is_cut_off(served, monkeypatch):
    # The real handler waits 30 s. A short timeout here shows the connection is answered or closed and the
    # handler thread ends.
    monkeypatch.setattr(example_guardian.GuardianHandler, "timeout", 0.5)
    import time
    before = threading.active_count()
    with socket.create_connection(served, timeout=5) as sock:
        sock.sendall(b"POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Length: 100\r\n\r\n{\"partial\":")
        started = time.monotonic()
        data = sock.recv(65536)  # an answer or EOF, never a hang
        assert time.monotonic() - started < 4
    deadline = time.monotonic() + 3
    while threading.active_count() > before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= before, "the handler thread outlived the timeout"
    assert data == b"" or b"HTTP/1." in data


def test_a_request_is_read_once(served, monkeypatch):
    calls = []
    real = example_guardian.read_request

    def counting(request):
        calls.append(1)
        return real(request)
    monkeypatch.setattr(example_guardian, "read_request", counting)
    post(served, _ping("once"))
    assert len(calls) == 1


def test_an_invalid_request_logs_its_problem_and_method(served, capsys):
    body = b'{"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": [1]}'
    post(served, body)
    err = capsys.readouterr().err
    assert "params must be an object" in err and "steps/se" in err


SURROGATE_SESSION = "\ud800"


def _nested_list(depth: int) -> list:
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("envelope", [
    # An id beyond 2^53 with a structure error: refused as an invalid id, signed with id null.
    {"jsonrpc": "2.0", "id": 2**60, "method": "steps/sessionStart", "params": [1]},
    # A session_id JCS can't encode, on the structure path.
    {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart",
     "params": {"metadata": {"session_id": SURROGATE_SESSION}, "request_id": 5}},
    # The same session_id on the depth path.
    {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart",
     "params": {"metadata": {"session_id": SURROGATE_SESSION}, "payload": {"deep": _nested_list(200)}}},
])
def test_handle_request_never_raises_for_a_direct_caller(served, envelope):
    answer = example_guardian.handle_request(envelope)
    assert "error" in answer
    if answer["error"]["code"] == -32603:
        assert answer["error"]["message"] == example_guardian.INTERNAL_ERROR_MESSAGE
        assert "signature" not in answer["error"]
