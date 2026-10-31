from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import Decided, FailPosture, Refused, Undecided, exchange
from acs.client import _exchange
from acs.core import MAX_REQUEST_BODY_BYTES, derive_session_key, sign_with_key

SECRET = "exchange-test-secret"
SESSION = "session-exchange"
URL = "http://127.0.0.1:8787/acs"


def _request(**payload: Any) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": "steps/toolCallRequest",
            "params": {"request_id": "req-1", "metadata": {"session_id": SESSION},
                       "payload": payload}}


def _signed(response: dict) -> dict:
    return sign_with_key(response, derive_session_key(SECRET.encode(), SESSION))


def _result(**overrides: Any) -> dict:
    result = {"request_id": "req-1", "decision": "allow", **overrides}
    return {"jsonrpc": "2.0", "id": "rpc-1", "result": result}


def _error(code: Any, message: str = "refused") -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "error": {"code": code, "message": message}}


def _tampered(response: dict) -> dict:
    response["result"]["decision"] = "deny"
    return response


FORGED = {"algorithm": "HMAC-SHA256", "value": "AAAA"}


def _forged_result(**extra: Any) -> dict:
    response = _result(**extra)
    response["result"]["signature"] = FORGED
    return response


def _forged_error(code: int) -> dict:
    response = _error(code)
    response["error"]["signature"] = FORGED
    return response


class _Body:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self.raw


def _replies(raw: bytes):
    return lambda *a, **k: _Body(raw)


def _json(obj: Any):
    import json
    return _replies(json.dumps(obj).encode())


def _raises(exc: BaseException):
    def urlopen(*a: Any, **k: Any):
        raise exc
    return urlopen


def _http(status: int, body: Any = None):
    import json
    raw = b"" if body is None else json.dumps(body).encode()
    return _raises(urllib.error.HTTPError(URL, status, "status", {}, io.BytesIO(raw)))


# (name, urlopen, expected outcome type, expected cause, expected fields subset)
CASES = [
    ("bare http 400", _http(400), Refused, "http_400_refusal", {"http_status": 400}),
    ("bare http 413", _http(413), Refused, "http_413_refusal", {"http_status": 413}),
    ("http 413 with a non-JSON-RPC body", _http(413, {"detail": "too large"}),
     Refused, "http_413_refusal", {"http_status": 413}),
    ("bare http 503", _http(503), Undecided, "http_503_error", {"http_status": 503}),
    ("http 502 with a non-JSON-RPC body", _http(502, {"detail": "bad gateway"}),
     Undecided, "http_502_error", {"http_status": 502}),
    ("bare http 404", _http(404), Undecided, "http_404_error", {"http_status": 404}),
    ("socket timeout", _raises(TimeoutError("timed out")),
     Undecided, "decision_timeout", {"request_id": "req-1", "method": "steps/toolCallRequest"}),
    ("urlopen timeout", _raises(urllib.error.URLError(TimeoutError("timed out"))),
     Undecided, "decision_timeout", {"request_id": "req-1"}),
    ("connection refused", _raises(urllib.error.URLError(ConnectionRefusedError(61, "refused"))),
     Undecided, "transport_failure", {"request_id": "req-1"}),
    ("connection reset", _raises(ConnectionResetError(54, "reset")),
     Undecided, "transport_failure", {"request_id": "req-1"}),
    ("body is not JSON", _replies(b"<html>bad gateway</html>"),
     Undecided, "malformed_response", {"request_id": "req-1"}),
    ("body is not UTF-8", _replies(b"\xff\xfe"), Undecided, "malformed_response", {}),
    ("unexpected exception", _raises(RuntimeError("boom")),
     Undecided, "adapter_exception", {"error": "boom"}),
    ("JSON array", _json([1, 2]), Undecided, "malformed_response", {}),
    ("result is not an object", _json({"jsonrpc": "2.0", "id": "rpc-1", "result": "allow"}),
     Undecided, "malformed_response", {}),
    ("error is not an object", _json({"jsonrpc": "2.0", "id": "rpc-1", "error": "nope"}),
     Undecided, "malformed_response", {}),
    ("neither result nor error", _json({"jsonrpc": "2.0", "id": "rpc-1"}),
     Undecided, "malformed_response", {}),
    ("JSON-RPC id of another request", _json(_signed({**_result(), "id": "rpc-2"})),
     Refused, "response_binding_mismatch", {}),
    ("result for another request_id", _json(_signed(_result(request_id="req-2"))),
     Refused, "response_binding_mismatch", {}),
    ("signed replay refusal", _json(_signed(_error(-32005))),
     Refused, "replay_detected_response", {"error_code": -32005, "error_message": "refused"}),
    ("signed session refusal", _json(_signed(_error(-32000))),
     Refused, "session_refused_response", {"error_code": -32000}),
    ("signed non-refusal error", _json(_signed(_error(-32603))),
     Undecided, "internal_error_response", {"error_code": -32603}),
    ("signed error with an unregistered code", _json(_signed(_error(-32050))),
     Undecided, "guardian_error_response", {"error_code": -32050}),
    ("signed error with a non-integer code", _json(_signed(_error([-32004]))),
     Undecided, "guardian_error_response", {"error_code": [-32004]}),
    ("unsigned error", _json(_error(-32603)),
     Refused, "error_signature_invalid", {"claimed_error_code": -32603}),
    ("error with a forged signature", _json(_forged_error(-32603)),
     Refused, "error_signature_invalid", {"claimed_error_code": -32603}),
    ("result changed after signing", _json(_tampered(_signed(_result()))),
     Refused, "response_signature_invalid", {}),
    ("forged signature over an integer RFC 8785 cannot encode", _json(_forged_result(n=2**53)),
     Refused, "response_signature_invalid", {}),
    ("unsigned result", _json(_result()), Refused, "response_signature_invalid", {}),
    ("signature is not an object", _json(_result(signature="AAAA")),
     Refused, "response_signature_invalid", {}),
]


@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_SECRET_FILE": ""})
class ExchangeCauses(unittest.TestCase):
    def _exchange(self, urlopen: Any, *, request: dict | None = None, url: str = URL,
                  timeout_s: float = 2.5):
        with mock.patch.object(_exchange, "_open", side_effect=urlopen) as fake:
            outcome = exchange(request or _request(), guardian_url=url,
                               timeout_s=timeout_s, session_id=SESSION)
        return outcome, fake

    def test_every_cause(self) -> None:
        for name, urlopen, kind, cause, fields in CASES:
            with self.subTest(name):
                outcome, _ = self._exchange(urlopen)
                self.assertIsInstance(outcome, kind)
                self.assertEqual(outcome.cause, cause)
                for key, value in fields.items():
                    self.assertEqual(outcome.fields.get(key), value, key)
                self.assertTrue(outcome.message, "every failure carries a message for the block reason")

    def test_a_signed_bound_result_is_decided(self) -> None:
        response = _signed(_result())
        outcome, fake = self._exchange(_json(response), timeout_s=0.25)
        self.assertEqual(outcome, Decided(response))
        self.assertEqual(fake.call_args.kwargs["timeout"], 0.25,
            "the caller's timeout, negotiated or local, bounds the round trip")

    def test_a_rejected_url_is_never_contacted(self) -> None:
        outcome, fake = self._exchange(_json(_signed(_result())), url="file:///etc/passwd")
        self.assertIsInstance(outcome, Undecided)
        self.assertEqual(outcome.cause, "guardian_url_rejected")
        fake.assert_not_called()

    def test_an_oversized_envelope_is_refused_before_the_wire(self) -> None:
        request = _request(blob="x" * MAX_REQUEST_BODY_BYTES)
        outcome, fake = self._exchange(_json(_signed(_result())), request=request)
        self.assertIsInstance(outcome, Refused)
        self.assertEqual(outcome.cause, "request_exceeds_max_payload")
        self.assertGreater(outcome.fields["body_bytes"], MAX_REQUEST_BODY_BYTES)
        fake.assert_not_called()

    def test_an_answer_that_cannot_be_verified_is_refused(self) -> None:
        """exchange never raises, and a verifier that fails by raising still fails closed."""
        for name, body in (("result", _signed(_result())), ("error", _signed(_error(-32603)))):
            with self.subTest(name), mock.patch.object(_exchange, "verify_signature",
                                                       side_effect=RuntimeError("verifier bug")):
                outcome, _ = self._exchange(_json(body))
                self.assertIsInstance(outcome, Refused)
                self.assertEqual(outcome.cause, "response_unverifiable")
                self.assertFalse(PROCEED.resolve(outcome).proceed)

    def test_a_secret_that_cannot_be_loaded_refuses_the_answer(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            secret_file = Path(d) / "hmac.key"
            secret_file.write_text(SECRET)
            secret_file.chmod(0o644)
            with mock.patch.dict(os.environ, {"ACS_HMAC_SECRET_FILE": str(secret_file)}):
                outcome, _ = self._exchange(_json(_signed(_result())))
        self.assertIsInstance(outcome, Refused)
        self.assertEqual(outcome.cause, "response_unverifiable")


class _DrippingGuardian:
    """A real HTTP Guardian that answers with a signed deny, sending its body a few bytes at a time."""

    def __init__(self, interval_s: float, *, handshake: bool = False) -> None:
        import http.server
        import threading
        import time

        def respond(request: dict) -> dict:
            if handshake:
                result = {"negotiated_version": "0.1.0", "methods_evaluated": [], "selected_transport": "http",
                          "timeout_config": {"default_ms": 5000}}
            else:
                result = {"request_id": request["params"]["request_id"], "decision": "deny"}
            return _signed({"jsonrpc": "2.0", "id": request["id"], "result": result})

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps(respond(request)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for i in range(0, len(body), 16):
                        self.wfile.write(body[i:i + 16])
                        self.wfile.flush()
                        time.sleep(interval_s)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args: Any) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/acs"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_SECRET_FILE": ""})
class OverallDeadline(unittest.TestCase):
    """§6.4: the negotiated timeout bounds the whole wait, including a body that arrives slowly."""

    def test_a_slowly_delivered_decision_times_out_at_the_deadline(self) -> None:
        import time
        guardian = _DrippingGuardian(0.08)
        self.addCleanup(guardian.close)
        started = time.monotonic()
        outcome = exchange(_request(), guardian_url=guardian.url, timeout_s=0.15, session_id=SESSION)
        elapsed = time.monotonic() - started
        self.assertIsInstance(outcome, Undecided, "a deny that finishes arriving after the deadline must not apply")
        self.assertEqual(outcome.cause, "decision_timeout")
        self.assertLess(elapsed, 0.6, f"the exchange returned {elapsed:.2f}s after it started")
        import threading
        stop = time.monotonic() + 0.5
        while any(t.name == "acs-exchange" for t in threading.enumerate()) and time.monotonic() < stop:
            time.sleep(0.01)
        self.assertEqual([t for t in threading.enumerate() if t.name == "acs-exchange"], [],
                         "the worker reading the slow body must end within 0.5 s of the deadline")

    def test_the_same_decision_within_the_deadline_applies(self) -> None:
        guardian = _DrippingGuardian(0.0)
        self.addCleanup(guardian.close)
        outcome = exchange(_request(), guardian_url=guardian.url, timeout_s=2.0, session_id=SESSION)
        self.assertIsInstance(outcome, Decided)
        self.assertEqual(outcome.response["result"]["decision"], "deny")

    def test_timed_out_workers_stop_and_send_nothing_more(self) -> None:
        """Expiry shuts the exchange's sockets, so a worker blocked on slow headers ends promptly."""
        import socketserver
        import threading
        import time
        connections: list[float] = []

        class SlowHeaders(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                connections.append(time.monotonic())
                self.request.recv(65536)
                try:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\n")
                    for i in range(100):
                        time.sleep(0.03)
                        self.request.sendall(b"X-Slow-%d: 1\r\n" % i)
                except OSError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlowHeaders)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}/acs"
        for _ in range(4):
            started = time.monotonic()
            outcome = exchange(_request(), guardian_url=url, timeout_s=0.1, session_id=SESSION)
            self.assertEqual(outcome.cause, "decision_timeout")
            self.assertLess(time.monotonic() - started, 0.5)
        deadline = time.monotonic() + 0.5
        while any(t.name == "acs-exchange" for t in threading.enumerate()) and time.monotonic() < deadline:
            time.sleep(0.01)
        alive = [t for t in threading.enumerate() if t.name == "acs-exchange"]
        self.assertEqual(alive, [], "every timed-out worker must end within 0.5 s of its deadline")
        time.sleep(0.2)
        self.assertEqual(len(connections), 4, "no request after a caller timed out")

    def test_an_https_guardian_goes_through_the_abortable_transport(self) -> None:
        """Builds the HTTPS connection on this Python version; a refused port is a transport failure, not an adapter error."""
        outcome = exchange(_request(), guardian_url="https://127.0.0.1:1/acs", timeout_s=2.0, session_id=SESSION)
        self.assertIsInstance(outcome, Undecided)
        self.assertEqual(outcome.cause, "transport_failure", outcome.fields)

    def test_a_redirect_is_an_http_error_not_another_request(self) -> None:
        import http.server
        import threading
        requests: list[str] = []
        status = {"code": 307}

        class Redirect(http.server.BaseHTTPRequestHandler):
            def _redirect(self) -> None:
                requests.append(f"{self.command} {self.path}")
                if self.command == "POST":
                    self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(status["code"])
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = _redirect  # noqa: N815

            def log_message(self, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code):
                status["code"] = code
                requests.clear()
                outcome = exchange(_request(), guardian_url=f"http://127.0.0.1:{server.server_address[1]}/acs",
                                   timeout_s=2.0, session_id=SESSION)
                self.assertIsInstance(outcome, Undecided)
                self.assertEqual(outcome.cause, f"http_{code}_error")
                self.assertEqual(requests, ["POST /acs"], "a redirect must not send another request")

    def test_a_slowly_delivered_server_hello_is_no_answer(self) -> None:
        import tempfile
        from pathlib import Path
        from acs.client import Config, NoAnswer, open_session
        from acs.client import _handshake
        guardian = _DrippingGuardian(0.08, handshake=True)
        self.addCleanup(guardian.close)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(d)):
            decision = open_session(config=Config.from_env({"ACS_GUARDIAN_URL": guardian.url}),
                                    session_id=SESSION, agent_id="t", platform="t", methods_implemented=[],
                                    timeout=0.15)
        self.assertIsInstance(decision, NoAnswer)
        self.assertEqual(decision.cause, "handshake_timeout")


def _exchange_workers_end(test: unittest.TestCase, within_s: float = 0.5) -> None:
    import threading
    import time
    stop = time.monotonic() + within_s
    while any(t.name == "acs-exchange" for t in threading.enumerate()) and time.monotonic() < stop:
        time.sleep(0.01)
    test.assertEqual([t for t in threading.enumerate() if t.name == "acs-exchange"], [],
                     f"every timed-out worker must end within {within_s} s of its deadline")


class TlsDeadline(unittest.TestCase):
    """The deadline ends TLS handshakes and TLS reads too, with certificate verification on."""

    @classmethod
    def setUpClass(cls) -> None:
        import shutil
        import subprocess
        import tempfile
        if shutil.which("openssl") is None:
            raise AssertionError("these tests make a throwaway certificate with the openssl command")
        cls._tmp = tempfile.TemporaryDirectory(prefix="acs-tls-")
        d = Path(cls._tmp.name)
        (d / "cert.cfg").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                                    "[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\n"
                                    "basicConstraints=critical,CA:TRUE\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"), "-config", str(d / "cert.cfg")],
                       check=True, capture_output=True, timeout=60)
        cls.cert, cls.key = str(d / "cert.pem"), str(d / "key.pem")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _serve(self, mode: str) -> str:
        import socketserver
        import ssl
        import threading
        import time
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                if mode == "stalled handshake":
                    time.sleep(3)
                    return
                try:
                    with context.wrap_socket(self.request, server_side=True) as tls:
                        self._answer(tls)
                except (OSError, ssl.SSLError):
                    pass

            def _answer(self, tls: ssl.SSLSocket) -> None:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += tls.recv(65536)
                head, _, body = data.partition(b"\r\n\r\n")
                length = int([h.split(b":")[1] for h in head.split(b"\r\n")
                              if h.lower().startswith(b"content-length")][0])
                while len(body) < length:
                    body += tls.recv(65536)
                if mode == "slow headers":
                    tls.sendall(b"HTTP/1.1 200 OK\r\n")
                    for i in range(100):
                        time.sleep(0.03)
                        tls.sendall(b"X-Slow-%d: 1\r\n" % i)
                    return
                request = json.loads(body)
                answer = json.dumps(_signed({"jsonrpc": "2.0", "id": request["id"], "result": {
                    "request_id": request["params"]["request_id"], "decision": "deny"}})).encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(answer) + answer)

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"https://127.0.0.1:{server.server_address[1]}/acs"

    def _exchange(self, url: str, timeout_s: float):
        env = {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_SECRET_FILE": "", "SSL_CERT_FILE": self.cert}
        with mock.patch.dict(os.environ, env):
            return exchange(_request(), guardian_url=url, timeout_s=timeout_s, session_id=SESSION)

    def test_a_verified_https_decision_applies(self) -> None:
        outcome = self._exchange(self._serve("signed"), 5.0)
        self.assertIsInstance(outcome, Decided, outcome)
        self.assertEqual(outcome.response["result"]["decision"], "deny")

    def test_slow_tls_headers_end_at_the_deadline(self) -> None:
        import time
        url = self._serve("slow headers")
        for _ in range(4):
            started = time.monotonic()
            outcome = self._exchange(url, 0.1)
            self.assertEqual(outcome.cause, "decision_timeout")
            self.assertLess(time.monotonic() - started, 0.5)
        _exchange_workers_end(self)

    def test_a_stalled_tls_handshake_ends_at_the_deadline(self) -> None:
        outcome = self._exchange(self._serve("stalled handshake"), 0.1)
        self.assertEqual(outcome.cause, "decision_timeout")
        _exchange_workers_end(self)


# Each JSON-RPC envelope is checked the same way whatever HTTP status carries it.
STATUSES = (200, 400, 413, 500, 503)
MATRIX = [
    ("unsigned non-refusal error", lambda: _error(-32603), Refused, "error_signature_invalid"),
    ("unsigned refusal error", lambda: _error(-32004), Refused, "error_signature_invalid"),
    ("error with a forged signature", lambda: _forged_error(-32603), Refused, "error_signature_invalid"),
    ("signed error for another request", lambda: _signed({**_error(-32603), "id": "rpc-2"}),
     Refused, "response_binding_mismatch"),
    ("error with a null id", lambda: {**_error(-32600), "id": None}, Refused, "response_binding_mismatch"),
    ("signed refusal", lambda: _signed(_error(-32005)), Refused, "replay_detected_response"),
    ("signed non-refusal error", lambda: _signed(_error(-32603)), Undecided, "internal_error_response"),
    ("result with a forged signature", lambda: _forged_result(), Refused, "response_signature_invalid"),
    ("forged signature over an integer RFC 8785 cannot encode", lambda: _forged_result(n=2**53),
     Refused, "response_signature_invalid"),
    ("signed bound result", lambda: _signed(_result()), Decided, None),
]
PROCEED = FailPosture(deny_on_failure=False, timeout_s=1.0)

# Bodies that are not JSON-RPC 2.0 responses, so the HTTP status classifies them.
NON_ENVELOPES = [
    ("detail body", {"detail": "Bad Request"}),
    ("string error", {"error": "Bad Request"}),
    ("null error", {"error": None}),
    ("JSON-RPC version with a string error", {"jsonrpc": "2.0", "error": "Bad Request"}),
    ("error object without the JSON-RPC version", {"error": {"code": 400, "message": "Bad Request"}}),
]


@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_SECRET_FILE": ""})
class HttpStatusMatrix(unittest.TestCase):
    def test_every_envelope_under_every_status(self) -> None:
        for status in STATUSES:
            for name, body, kind, cause in MATRIX:
                with self.subTest(status=status, body=name):
                    urlopen = _json(body()) if status == 200 else _http(status, body())
                    with mock.patch.object(_exchange, "_open", side_effect=urlopen):
                        outcome = exchange(_request(), guardian_url=URL, timeout_s=1.0, session_id=SESSION)
                    self.assertIsInstance(outcome, kind)
                    if kind is Decided:
                        continue
                    self.assertEqual(outcome.cause, cause)
                    self.assertEqual(outcome.fields.get("http_status"), None if status == 200 else status)
                    if kind is Refused:
                        self.assertFalse(PROCEED.resolve(outcome).proceed,
                            "an answer that fails its checks blocks even under fail-open")

    def test_bodies_that_are_not_jsonrpc_are_classified_by_status(self) -> None:
        expected = {200: (Undecided, "malformed_response"),
                    400: (Refused, "http_400_refusal"), 413: (Refused, "http_413_refusal"),
                    500: (Undecided, "http_500_error"), 503: (Undecided, "http_503_error")}
        for status in STATUSES:
            kind, cause = expected[status]
            for name, body in NON_ENVELOPES:
                with self.subTest(status=status, body=name):
                    urlopen = _json(body) if status == 200 else _http(status, body)
                    with mock.patch.object(_exchange, "_open", side_effect=urlopen):
                        outcome = exchange(_request(), guardian_url=URL, timeout_s=1.0, session_id=SESSION)
                    self.assertIsInstance(outcome, kind)
                    self.assertEqual(outcome.cause, cause)
                    if kind is Refused:
                        self.assertFalse(PROCEED.resolve(outcome).proceed)


if __name__ == "__main__":
    unittest.main()
