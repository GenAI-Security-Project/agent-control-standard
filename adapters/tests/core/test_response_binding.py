"""response_matches_request binds a response to the request it answers (D-029). Runs without the pqc extra."""
from __future__ import annotations

import unittest

from acs.core import response_matches_request


def _request(json_rpc_id: object) -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "method": "steps/toolCallRequest", "params": {"request_id": "r-1"}}


def _response(json_rpc_id: object) -> dict:
    return {"jsonrpc": "2.0", "id": json_rpc_id, "result": {"request_id": "r-1", "decision": "allow"}}


class JsonRpcIdsMatchOnTypeAndValue(unittest.TestCase):
    """Review finding R5-M2: Python's == treats True, 1 and 1.0 as one id, and JSON doesn't."""

    def test_equal_ids_of_one_type_match(self) -> None:
        for json_rpc_id in ("1", 1, "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60"):
            with self.subTest(id=json_rpc_id):
                self.assertTrue(response_matches_request(_request(json_rpc_id), _response(json_rpc_id)))

    def test_ids_that_differ_only_in_type_do_not_match(self) -> None:
        for request_id, response_id in ((1, True), (True, 1), (1, 1.0), (1.0, 1), (0, False), ("1", 1)):
            with self.subTest(request=request_id, response=response_id):
                self.assertFalse(response_matches_request(_request(request_id), _response(response_id)))

    def test_an_error_binds_by_id_with_the_same_rule(self) -> None:
        error = {"jsonrpc": "2.0", "id": True, "error": {"code": -32000, "message": "refused"}}
        self.assertFalse(response_matches_request(_request(1), error))
        self.assertTrue(response_matches_request(_request(True), error))


if __name__ == "__main__":
    unittest.main()
