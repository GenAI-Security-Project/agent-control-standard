"""The handshake binds a ServerHello to its ClientHello by id, compared as JSON values (review findings R6-M2, CR6-6)."""
from __future__ import annotations

import unittest
from pathlib import Path

from acs.client import _handshake
from acs.client._outcome import Negotiated, SessionRefused
from acs.core import HANDSHAKE_METHOD

SESSION_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
SERVER_HELLO = {"negotiated_version": "0.1.0", "methods_evaluated": ["steps/toolCallRequest"],
                "selected_transport": "http", "timeout_config": {"default_ms": 5000}}


def _client_hello(json_rpc_id: object = 1) -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": HANDSHAKE_METHOD,
            "params": {"acs_version": "0.1.0", "request_id": "hello-request-1",
                       "metadata": {"session_id": SESSION_ID}}}


def _cause(client_hello: dict, response: dict) -> str | None:
    outcome = _handshake._classify_hello(client_hello, response, SESSION_ID)
    return outcome.cause if isinstance(outcome, SessionRefused) else None


class ServerHelloBinding(unittest.TestCase):
    def test_an_id_that_differs_only_as_a_bool_is_a_binding_mismatch(self) -> None:
        # Python's != treats True as 1. JSON doesn't.
        response = {"jsonrpc": "2.0", "id": True, "result": dict(SERVER_HELLO)}
        self.assertEqual(_cause(_client_hello(1), response), "response_binding_mismatch")

    def test_a_result_carrying_request_id_never_negotiates(self) -> None:
        # A step decision with a colliding id never answers a ClientHello. The default path keeps
        # its existing classification for that case (no answer, or a refusal when unsigned), which
        # tests/common/test_serverhello_contract.py pins, so this asserts only that it never negotiates.
        response = {"jsonrpc": "2.0", "id": 1, "result": {"request_id": "hello-request-1", "decision": "allow"}}
        outcome = _handshake._classify_hello(_client_hello(1), response, SESSION_ID)
        self.assertNotIsInstance(outcome, Negotiated)

    def test_a_matching_id_passes_the_binding_check(self) -> None:
        for response_id in (1, 1.0):
            response = {"jsonrpc": "2.0", "id": response_id, "result": dict(SERVER_HELLO)}
            with self.subTest(id=response_id):
                self.assertNotEqual(_cause(_client_hello(1), response), "response_binding_mismatch")

    def test_the_client_hello_uses_the_core_constant(self) -> None:
        self.assertEqual(HANDSHAKE_METHOD, "handshake/hello")
        source = Path(_handshake.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"handshake/hello"', source)


if __name__ == "__main__":
    unittest.main()
