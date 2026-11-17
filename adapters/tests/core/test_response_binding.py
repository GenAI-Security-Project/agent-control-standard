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
        for a, b in (("1", "1"), (1, 1), (1, 1.0), (1.0, 1), (True, True), (False, False), (None, None),
                     ("c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60", "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60")):
            with self.subTest(a=a, b=b):
                self.assertTrue(same_json_rpc_id(a, b))
                self.assertTrue(response_matches_request(_request(a), _response(b)))

    def test_ids_of_different_json_types_do_not_match(self) -> None:
        for a, b in ((1, True), (True, 1), (0, False), (1.0, True), ("1", 1), (None, 0), (None, ""), ("a", "b")):
            with self.subTest(a=a, b=b):
                self.assertFalse(same_json_rpc_id(a, b))
                self.assertFalse(response_matches_request(_request(a), _response(b)))

    def test_an_error_binds_by_id_with_the_same_rule(self) -> None:
        error = {"jsonrpc": "2.0", "id": True, "error": {"code": -32000, "message": "refused"}}
        self.assertFalse(response_matches_request(_request(1), error))
        self.assertTrue(response_matches_request(_request(True), error))

    def test_request_id_uses_the_same_rule(self) -> None:
        # Review finding CR6-4: no plain != for request_id either.
        self.assertFalse(response_matches_request(_request("1", request_id="r-1"), _response("1", request_id="r-2")))
        self.assertTrue(response_matches_request(_request("1", request_id="r-1"), _response("1", request_id="r-1")))


if __name__ == "__main__":
    unittest.main()
