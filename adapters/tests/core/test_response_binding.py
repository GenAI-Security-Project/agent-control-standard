"""response_matches_request binds a response to the request it answers (D-029). Runs without the pqc extra."""
from __future__ import annotations

import unittest

from acs.core import response_matches_request
from acs.core._envelope import same_json_rpc_id


def _request(json_rpc_id: object, request_id: object = "r-1") -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": "steps/toolCallRequest",
            "params": {"request_id": request_id}}


def _response(json_rpc_id: object, request_id: object = "r-1") -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "result": {"request_id": request_id, "decision": "allow"}}


class JsonRpcIdsMatchAsJsonValues(unittest.TestCase):
    """Review findings R5-M2 and CR6-3: ids compare as JSON values. A bool never equals a number,
    and 1 equals 1.0, since JSON and JCS treat them as one number."""

    def test_equal_ids_match(self) -> None:
        for a, b in (("1", "1"), (1, 1), (1, 1.0), (1.0, 1), (True, True), (False, False),
                     ("c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60", "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60")):
            with self.subTest(a=a, b=b):
                self.assertTrue(same_json_rpc_id(a, b))
                self.assertTrue(response_matches_request(_request(a), _response(b)))

    def test_ids_of_different_json_types_do_not_match(self) -> None:
        for a, b in ((1, True), (True, 1), (0, False), (1.0, True), ("1", 1), (None, 0), (None, ""), ("a", "b")):
            with self.subTest(a=a, b=b):
                self.assertFalse(same_json_rpc_id(a, b))
                self.assertFalse(response_matches_request(_request(a), _response(b)))

    def test_a_missing_or_null_id_never_matches(self) -> None:
        # Review finding CR7-5: a request with no id must not bind to a response with no id.
        self.assertFalse(same_json_rpc_id(None, None))
        no_id_request = {k: v for k, v in _request("1").items() if k != "id"}
        no_id_response = {k: v for k, v in _response("1").items() if k != "id"}
        self.assertFalse(response_matches_request(no_id_request, no_id_response))
        self.assertFalse(response_matches_request(_request(None), _response(None)))

    def test_an_error_binds_by_id_with_the_same_rule(self) -> None:
        error = {"jsonrpc": "2.0", "id": True, "error": {"code": -32000, "message": "refused"}}
        self.assertFalse(response_matches_request(_request(1), error))
        self.assertTrue(response_matches_request(_request(True), error))

    def test_request_id_uses_the_same_rule(self) -> None:
        # Review finding CR6-4: no plain != for request_id either.
        self.assertFalse(response_matches_request(_request("1", request_id="r-1"), _response("1", request_id="r-2")))
        self.assertTrue(response_matches_request(_request("1", request_id="r-1"), _response("1", request_id="r-1")))


SERVER_HELLO = {"negotiated_version": "0.1.0", "methods_evaluated": [], "selected_transport": "http",
                "timeout_config": {"default_ms": 5000}}


def _client_hello(json_rpc_id: object = "hello-1") -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": "handshake/hello",
            "params": {"acs_version": "0.1.0", "request_id": "hello-request-1"}}


class OneHandshakeAwareRule(unittest.TestCase):
    """Review findings CR6-5, CR6-6, R6-M1: one rule, keyed on the request, for both paths."""

    def test_the_handshake_method_is_defined_once_in_core(self) -> None:
        from acs.core import HANDSHAKE_METHOD
        self.assertEqual(HANDSHAKE_METHOD, "handshake/hello")

    def test_a_server_hello_answers_its_client_hello_by_id(self) -> None:
        self.assertTrue(response_matches_request(_client_hello(), {"jsonrpc": "2.0", "id": "hello-1",
                                                                   "result": dict(SERVER_HELLO)}))
        self.assertFalse(response_matches_request(_client_hello(), {"jsonrpc": "2.0", "id": "hello-2",
                                                                    "result": dict(SERVER_HELLO)}))

    def test_an_error_answers_a_client_hello_by_id(self) -> None:
        error = {"jsonrpc": "2.0", "id": "hello-1", "error": {"code": -32000, "message": "refused"}}
        self.assertTrue(response_matches_request(_client_hello(), error))

    def test_a_step_decision_never_answers_a_client_hello(self) -> None:
        # R6-M1: a result carrying request_id is a step answer, even with a matching id.
        decision = {"jsonrpc": "2.0", "id": "hello-1",
                    "result": {"request_id": "hello-request-1", "decision": "allow"}}
        self.assertFalse(response_matches_request(_client_hello(), decision))

    def test_a_result_that_is_not_an_object_answers_nothing(self) -> None:
        # R6-M4, CR6-1: False, never an AttributeError.
        for request in (_request("1"), _client_hello("1")):
            for result in ("allow", ["allow"], 7):
                with self.subTest(method=request["method"], result=result):
                    self.assertFalse(response_matches_request(request, {"jsonrpc": "2.0", "id": "1", "result": result}))

    def test_a_step_result_must_carry_the_request_id(self) -> None:
        # CR6-2: present and equal. A step request without one binds nothing beyond the id.
        bare_request = {"jsonrpc": "2.0", "id": "1", "method": "steps/toolCallRequest", "params": {}}
        bare_result = {"jsonrpc": "2.0", "id": "1", "result": {"decision": "allow"}}
        self.assertFalse(response_matches_request(bare_request, bare_result))
        self.assertFalse(response_matches_request(_request("1"), bare_result))

    def test_a_server_hello_never_answers_a_step_request(self) -> None:
        self.assertFalse(response_matches_request(_request("1"), {"jsonrpc": "2.0", "id": "1",
                                                                  "result": dict(SERVER_HELLO)}))


if __name__ == "__main__":
    unittest.main()
