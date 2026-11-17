"""The handshake binds a ServerHello to its ClientHello (review findings R6-M2, CR6-6, CR7-1, CR7-2, CR7-7)."""
from __future__ import annotations

import unittest

from acs.client import _handshake
from acs.client._outcome import Negotiated, NoAnswer, SessionRefused
from acs.core import HANDSHAKE_METHOD
from tests.client.test_session import HELLO, _answer, _result, _SessionTest, _signed

SESSION_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _client_hello(json_rpc_id: object = 1) -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": HANDSHAKE_METHOD,
            "params": {"acs_version": "0.1.0", "request_id": "hello-request-1",
                       "metadata": {"session_id": SESSION_ID}, "payload": {}}}


def _cause(client_hello: dict, response: dict) -> str | None:
    outcome = _handshake._classify_hello(client_hello, response, SESSION_ID)
    return outcome.cause if isinstance(outcome, SessionRefused) else None


class ServerHelloIdBinding(unittest.TestCase):
    def test_an_id_that_differs_only_as_a_bool_is_a_binding_mismatch(self) -> None:
        # Python's != treats True as 1. JSON doesn't.
        response = {"jsonrpc": "2.0", "id": True, "result": dict(HELLO)}
        self.assertEqual(_cause(_client_hello(1), response), "response_binding_mismatch")

    def test_a_client_hello_with_a_bool_id_binds_nothing(self) -> None:
        # Review finding CR9-4: the keyring path refuses such a ClientHello, so the HMAC path does too.
        for json_rpc_id in (True, False):
            response = {"jsonrpc": "2.0", "id": json_rpc_id, "result": dict(HELLO)}
            with self.subTest(id=json_rpc_id):
                self.assertEqual(_cause(_client_hello(json_rpc_id), response), "response_binding_mismatch")

    def test_a_bool_id_client_hello_is_a_request_problem_whatever_the_response(self) -> None:
        # Review findings CR11-6, CR11-7: the request is checked before the response's shape.
        for response in ({"id": True, "result": dict(HELLO)}, "not a response", None):
            with self.subTest(response=response):
                self.assertEqual(_cause(_client_hello(True), response), "response_binding_mismatch")

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

    def test_an_id_with_neither_result_nor_error_fails_the_shape_gate(self) -> None:
        # Review findings R8-M5, CR9-9. is_jsonrpc_response refuses it before binding runs, so it
        # is no answer (malformed_response). This pins that shape gate, not binding. The binding
        # rule itself is pinned directly by test_a_response_with_neither_result_nor_error_binds_nothing
        # in tests/core/test_response_binding.py. A signature can't be attached, since it lives
        # inside the result or error object.
        for body in ({"jsonrpc": "2.0"}, {"jsonrpc": "2.0", "result": None}, {"jsonrpc": "2.0", "error": None}):
            with self.subTest(body=body):
                decision, _ = self._open(_answer(lambda h, body=body: {**body, "id": h["id"]}),
                                         session_id=f"hello-bare-{len(body)}-{list(body)[-1]}")
                self.assertEqual(decision, NoAnswer("malformed_response"))

    def test_a_signed_refusal_binds_by_id_whatever_the_client_hello_params(self) -> None:
        # Review findings CR10-1, CR10-4: the handshake decides binding through the one rule, so a
        # signed error binds by id and keeps the Guardian's cause, as response_matches_request says.
        from acs.core import response_matches_request
        hello = {"jsonrpc": "2.0", "id": "hello-odd", "method": HANDSHAKE_METHOD, "params": "not an object"}
        refusal = _signed({"jsonrpc": "2.0", "id": "hello-odd", "error": {"code": -32000, "message": "refused"}},
                          SESSION_ID)
        self.assertTrue(response_matches_request(hello, refusal))
        outcome = _handshake._classify_hello(hello, refusal, SESSION_ID)
        self.assertIsInstance(outcome, SessionRefused)
        self.assertEqual(outcome.cause, "session_refused_response")

    def test_a_result_answers_only_a_real_client_hello(self) -> None:
        # Review findings CR11-4, R11-M1: a signed, complete ServerHello goes on to its checks only
        # when the request is a real ClientHello. Anything else refuses the session, never raises.
        base = {"jsonrpc": "2.0", "id": "hello-x", "method": HANDSHAKE_METHOD,
                "params": {"acs_version": "0.1.0", "request_id": "r-x", "payload": {}}}
        step_like = {**base, "method": "steps/toolCallRequest"}
        cases = {
            "params not an object": {**base, "params": "odd"},
            "no params": {k: v for k, v in base.items() if k != "params"},
            "payload not an object": {**base, "params": {"request_id": "r-x", "payload": "odd"}},
            "not handshake/hello": step_like,
        }
        for name, hello in cases.items():
            result = dict(HELLO)
            if name == "not handshake/hello":
                result["request_id"] = "r-x"   # so it would bind as a step answer
            response = _signed({"jsonrpc": "2.0", "id": "hello-x", "result": result}, SESSION_ID)
            with self.subTest(name):
                outcome = _handshake._classify_hello(hello, response, SESSION_ID)
                self.assertEqual(outcome, SessionRefused("response_binding_mismatch"))

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
