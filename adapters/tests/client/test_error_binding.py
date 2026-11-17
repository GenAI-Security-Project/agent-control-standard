"""A signed error binds by its JSON-RPC id alone, whatever the request's request_id (review finding CR8-1)."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from acs.client import _exchange
from acs.client._outcome import Refused
from acs.core import derive_session_key, sign_with_key

SECRET = "error-binding-test-secret-padded-to-32"
SESSION = "session-error-binding"


def _request(params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": "steps/toolCallRequest",
            "params": {"metadata": {"session_id": SESSION}, **params}}


def _signed_error(code: int) -> dict:
    error = {"jsonrpc": "2.0", "id": "rpc-1", "error": {"code": code, "message": "refused"}}
    return sign_with_key(error, derive_session_key(SECRET.encode(), SESSION), key_id="test-key")


class ErrorsBindById(unittest.TestCase):
    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        patcher = mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"},
                                  clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_signed_error_is_classified_by_its_code_without_a_request_id(self) -> None:
        for code in (-32000, -32603):
            with_id = _exchange.classify_response(_request({"request_id": "req-1"}), _signed_error(code),
                                                  session_id=SESSION)
            without_id = _exchange.classify_response(_request({}), _signed_error(code), session_id=SESSION)
            with self.subTest(code=code):
                # The outcomes echo the request's own request_id, so compare what they decide.
                self.assertEqual((type(without_id), without_id.cause), (type(with_id), with_id.cause))
                self.assertNotEqual(getattr(without_id, "cause", None), "response_binding_mismatch")


class TheStepExchangeUsesTheOneRule(unittest.TestCase):
    """Review findings R10-M2, CR10-3: classify_response decides binding through response_binding_problem."""

    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        patcher = mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"},
                                  clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_non_mapping_request_is_refused_never_an_attribute_error(self) -> None:
        for request in ("request", ["request"], None):
            with self.subTest(request=request):
                outcome = _exchange.classify_response(request, _signed_error(-32000), session_id=SESSION)  # type: ignore[arg-type]
                self.assertIsInstance(outcome, Refused)
                self.assertEqual(outcome.cause, "response_binding_mismatch")

    def test_a_response_carrying_method_is_malformed(self) -> None:
        response = {**_signed_error(-32000), "method": "steps/toolCallRequest"}
        outcome = _exchange.classify_response(_request({"request_id": "req-1"}), response, session_id=SESSION)
        self.assertEqual(outcome.cause, "malformed_response")


if __name__ == "__main__":
    unittest.main()
