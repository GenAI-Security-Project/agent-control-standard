from __future__ import annotations

import io
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
        with mock.patch.object(_exchange.urllib.request, "urlopen", side_effect=urlopen) as fake:
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
                    with mock.patch.object(_exchange.urllib.request, "urlopen", side_effect=urlopen):
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
                    with mock.patch.object(_exchange.urllib.request, "urlopen", side_effect=urlopen):
                        outcome = exchange(_request(), guardian_url=URL, timeout_s=1.0, session_id=SESSION)
                    self.assertIsInstance(outcome, kind)
                    self.assertEqual(outcome.cause, cause)
                    if kind is Refused:
                        self.assertFalse(PROCEED.resolve(outcome).proceed)


if __name__ == "__main__":
    unittest.main()
