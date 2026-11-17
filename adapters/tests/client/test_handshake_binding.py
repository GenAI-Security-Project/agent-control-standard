"""The handshake binds a ServerHello to its ClientHello (review findings R6-M2, CR6-6, CR7-1, CR7-2, CR7-7)."""
from __future__ import annotations

import unittest

from acs.client import _handshake
from acs.client._outcome import Negotiated, NoAnswer, SessionRefused
from acs.core import HANDSHAKE_METHOD
from tests.client.test_session import HELLO, _answer, _result, _SessionTest

SESSION_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _client_hello(json_rpc_id: object = 1) -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": HANDSHAKE_METHOD,
            "params": {"acs_version": "0.1.0", "request_id": "hello-request-1",
                       "metadata": {"session_id": SESSION_ID}}}


def _cause(client_hello: dict, response: dict) -> str | None:
    outcome = _handshake._classify_hello(client_hello, response, SESSION_ID)
    return outcome.cause if isinstance(outcome, SessionRefused) else None


class ServerHelloIdBinding(unittest.TestCase):
    def test_an_id_that_differs_only_as_a_bool_is_a_binding_mismatch(self) -> None:
        # Python's != treats True as 1. JSON doesn't.
        response = {"jsonrpc": "2.0", "id": True, "result": dict(HELLO)}
        self.assertEqual(_cause(_client_hello(1), response), "response_binding_mismatch")

    def test_a_matching_id_passes_the_binding_check(self) -> None:
        for response_id in (1, 1.0):
            response = {"jsonrpc": "2.0", "id": response_id, "result": dict(HELLO)}
            with self.subTest(id=response_id):
                self.assertNotEqual(_cause(_client_hello(1), response), "response_binding_mismatch")


class SignedServerHellos(_SessionTest):
    """CR7-1, CR7-2: real HMAC signatures and an otherwise complete ServerHello, through open_session."""

    def test_a_complete_signed_server_hello_negotiates(self) -> None:
        decision, _ = self._open(_answer(lambda h: _result(h, HELLO)), session_id="hello-ok")
        self.assertIsInstance(decision, Negotiated)

    def test_a_signed_server_hello_carrying_request_id_is_no_answer(self) -> None:
        # A ServerHello carries no request_id. One that does is a step answer in disguise, so it
        # gets the fail posture, as the keyring path refuses it, instead of negotiating.
        build = _answer(lambda h: _result(h, {**HELLO, "request_id": h["params"]["request_id"]}))
        decision, _ = self._open(build, session_id="hello-with-request-id")
        self.assertIsInstance(decision, NoAnswer)
        self.assertEqual(decision.cause, "invalid_server_hello")

    def test_the_client_hello_sent_uses_the_core_constant(self) -> None:
        # CR7-7: the ClientHello actually sent, not a grep of the source.
        sent: list[dict] = []

        def record(hello: dict) -> dict:
            sent.append(hello)
            return _result(hello, HELLO)
        self._open(_answer(record), session_id="hello-method")
        self.assertEqual([h["method"] for h in sent], [HANDSHAKE_METHOD])


if __name__ == "__main__":
    unittest.main()
