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
