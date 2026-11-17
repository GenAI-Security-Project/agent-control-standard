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
                # CR8-3: a bool is no request id, so a request carrying one binds no result.
                self.assertEqual(response_matches_request(_request(a), _response(b)), not isinstance(a, bool))

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

    def test_a_response_with_neither_result_nor_error_binds_nothing(self) -> None:
        # Review finding R7-M2: an id alone is not an answer.
        for request in (_request("1"), {**_request("1"), "method": "handshake/hello"}):
            with self.subTest(method=request["method"]):
                self.assertFalse(response_matches_request(request, {"jsonrpc": "2.0", "id": "1"}))
                self.assertFalse(response_matches_request(request, {"jsonrpc": "2.0", "id": "1", "result": None}))

    def test_an_error_binds_by_id_whatever_the_request_id(self) -> None:
        # Review finding CR8-1: the request_id precondition applies to results only.
        error = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32000, "message": "refused"}}
        for params in ({}, {"request_id": 7}, {"request_id": ""}):
            with self.subTest(params=params):
                self.assertTrue(response_matches_request({**_request("1"), "params": params}, error))

    def test_an_error_that_is_not_an_object_answers_nothing(self) -> None:
        # Review finding CR8-4.
        for error in (False, 0, "x", ["refused"]):
            with self.subTest(error=error):
                self.assertFalse(response_matches_request(_request("1"), {"jsonrpc": "2.0", "id": "1", "error": error}))

    def test_an_error_binds_by_id_with_the_same_rule(self) -> None:
        error = {"jsonrpc": "2.0", "id": True, "error": {"code": -32000, "message": "refused"}}
        self.assertFalse(response_matches_request(_request(1), error))
        # CR8-3, CR9-1: a bool is no request id, so a request carrying one binds even no error.
        self.assertFalse(response_matches_request(_request(True), error))
        self.assertTrue(response_matches_request(_request(1), {**error, "id": 1.0}))

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
        # CR6-2: present and equal. A step request without one binds nothing (review finding CR7-9).
        bare_request = {"jsonrpc": "2.0", "id": "1", "method": "steps/toolCallRequest", "params": {}}
        bare_result = {"jsonrpc": "2.0", "id": "1", "result": {"decision": "allow"}}
        self.assertFalse(response_matches_request(bare_request, bare_result))
        self.assertFalse(response_matches_request(_request("1"), bare_result))

    def test_a_server_hello_never_answers_a_step_request(self) -> None:
        self.assertFalse(response_matches_request(_request("1"), {"jsonrpc": "2.0", "id": "1",
                                                                  "result": dict(SERVER_HELLO)}))


class TheRuleOwnsTheResponseShape(unittest.TestCase):
    """Review findings CR10-3, R10-M3: the shape gate is part of the one rule, so every path gets it."""

    def test_a_response_carrying_method_binds_nothing(self) -> None:
        # A request envelope is not an answer, even one whose id and request_id match.
        self.assertFalse(response_matches_request(_request("1"), {**_response("1"), "method": "steps/toolCallRequest"}))

    def test_a_response_without_jsonrpc_2_0_binds_nothing(self) -> None:
        for jsonrpc in (None, "1.0", 2.0):
            response = _response("1")
            if jsonrpc is None:
                del response["jsonrpc"]
            else:
                response["jsonrpc"] = jsonrpc
            with self.subTest(jsonrpc=jsonrpc):
                self.assertFalse(response_matches_request(_request("1"), response))

    def test_a_response_with_both_result_and_error_binds_nothing(self) -> None:
        both = {**_response("1"), "error": {"code": -32000, "message": "refused"}}
        self.assertFalse(response_matches_request(_request("1"), both))

    def test_a_response_that_is_not_a_mapping_binds_nothing(self) -> None:
        for response in ("response", [], None):
            with self.subTest(response=response):
                self.assertFalse(response_matches_request(_request("1"), response))  # type: ignore[arg-type]

    def test_each_reason_has_one_name(self) -> None:
        from acs.core import (
            BINDING_ID,
            BINDING_REQUEST,
            BINDING_RESULT,
            BINDING_SHAPE,
            response_binding_problem,
        )
        error = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32000, "message": "refused"}}
        self.assertIsNone(response_binding_problem(_request("1"), _response("1")))
        self.assertIsNone(response_binding_problem(_request("1"), error))
        self.assertEqual(response_binding_problem(_request("1"), {"jsonrpc": "2.0", "id": "1"}), BINDING_SHAPE)
        self.assertEqual(response_binding_problem(_request(True), _response(True)), BINDING_REQUEST)
        self.assertEqual(response_binding_problem(_request("1"), _response("2")), BINDING_ID)
        self.assertEqual(response_binding_problem(_request("1"), _response("1", request_id="r-2")), BINDING_RESULT)


class NonFiniteIdsBindNothing(unittest.TestCase):
    """Review finding CR10-7: a NaN or infinite id binds nothing through the rule, not only the precondition."""

    def test_a_non_finite_request_id_binds_no_result_and_no_error(self) -> None:
        error = {"jsonrpc": "2.0", "error": {"code": -32000, "message": "refused"}}
        for json_rpc_id in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(id=json_rpc_id):
                self.assertFalse(response_matches_request(_request(json_rpc_id), _response(json_rpc_id)))
                self.assertFalse(response_matches_request(_request(json_rpc_id), {**error, "id": json_rpc_id}))


class OneRequestPrecondition(unittest.TestCase):
    """Review finding CR7-6: request_binding_problem states the precondition once, for both paths."""

    def test_a_well_formed_request_has_no_problem(self) -> None:
        from acs.core._envelope import request_binding_problem
        self.assertIsNone(request_binding_problem(_request("1")))
        self.assertIsNone(request_binding_problem(_client_hello()))
        hello_without_request_id = {**_client_hello(), "params": {"acs_version": "0.1.0"}}
        self.assertIsNone(request_binding_problem(hello_without_request_id), "a ClientHello needs no request_id")

    def test_a_request_id_must_be_a_string_or_a_number(self) -> None:
        # Review findings CR8-3, R8-M4: bool, object and array ids are refused.
        from acs.core._envelope import request_binding_problem
        for json_rpc_id in (True, False, {}, {"id": 1}, [], [1]):
            with self.subTest(id=json_rpc_id):
                self.assertEqual(request_binding_problem(_request(json_rpc_id)),
                                 "request must carry a string or numeric JSON-RPC id")
        for json_rpc_id in ("1", 1, 1.5, 0):
            with self.subTest(id=json_rpc_id):
                self.assertIsNone(request_binding_problem(_request(json_rpc_id)))

    def test_a_non_finite_numeric_id_is_refused(self) -> None:
        # Review finding CR9-7: NaN never equals itself and an infinity binds nothing useful.
        from acs.core._envelope import request_envelope_problem
        for json_rpc_id in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(id=json_rpc_id):
                self.assertEqual(request_envelope_problem(_request(json_rpc_id)),
                                 "request must carry a string or numeric JSON-RPC id")

    def test_a_request_that_is_not_a_mapping_binds_nothing(self) -> None:
        for request in ("request", ["request"], None, 7):
            with self.subTest(request=request):
                self.assertFalse(response_matches_request(request, _response("1")))  # type: ignore[arg-type]

    def test_a_read_only_mapping_request_binds(self) -> None:
        # Review finding CR8-5: _handshake passes a Mapping such as MappingProxyType, not a dict.
        from types import MappingProxyType

        from acs.core._envelope import request_binding_problem
        request = _request("1")
        frozen = MappingProxyType({**request, "params": MappingProxyType(dict(request["params"]))})
        self.assertIsNone(request_binding_problem(frozen))
        self.assertTrue(response_matches_request(frozen, _response("1")))
        self.assertFalse(response_matches_request(frozen, _response("1", request_id="r-2")))

    def test_each_malformed_request_names_its_problem_and_binds_nothing(self) -> None:
        from acs.core._envelope import request_binding_problem
        cases = {
            "not an object": "request",
            "no id": {k: v for k, v in _request("1").items() if k != "id"},
            "null id": _request(None),
            "params not an object": {**_request("1"), "params": "params"},
            "no request_id": {**_request("1"), "params": {}},
            "request_id not a string": _request("1", request_id=7),
            "empty request_id": _request("1", request_id=""),
        }
        for name, request in cases.items():
            with self.subTest(name):
                problem = request_binding_problem(request)  # type: ignore[arg-type]
                self.assertIsInstance(problem, str)
                if isinstance(request, dict):
                    self.assertFalse(response_matches_request(request, _response("1")))


if __name__ == "__main__":
    unittest.main()
