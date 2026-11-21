"""request_sha256 raises only when a request has no signed input (issue #576, review round 4 CR4).

A request that isn't an object, or whose params aren't one, raises NoSignedInput. A request RFC 8785 can't encode
raises one of CANONICALIZATION_ERRORS, as signing_input does. Every other request hashes, and nothing else is caught,
so a bug surfaces instead of turning into a missing hash.
"""
from __future__ import annotations

import hashlib
import unittest

from acs.core import NoSignedInput, request_sha256, signing_input
from acs.core._canonical import CANONICALIZATION_ERRORS

REQUEST = {"jsonrpc": "2.0", "id": "1", "method": "steps/toolCallRequest",
           "params": {"request_id": "r", "metadata": {"session_id": "s"}, "payload": {}}}


class RequestSha256(unittest.TestCase):
    def test_a_request_hashes_its_signed_input(self) -> None:
        self.assertEqual(request_sha256(REQUEST), hashlib.sha256(signing_input(REQUEST)).hexdigest())

    def test_missing_params_hash_as_an_empty_object(self) -> None:
        request = {"jsonrpc": "2.0", "id": "1", "method": "system/ping"}
        self.assertEqual(request_sha256(request), hashlib.sha256(signing_input(request)).hexdigest())

    def test_no_signed_input_raises_no_signed_input(self) -> None:
        for name, request in (("list request", []), ("string request", "x"),
                              ("list params", {**REQUEST, "params": []}), ("string params", {**REQUEST, "params": "x"}),
                              ("int params", {**REQUEST, "params": 5}), ("null params", {**REQUEST, "params": None})):
            with self.subTest(name), self.assertRaises(NoSignedInput):
                request_sha256(request)

    def test_an_unencodable_request_raises_a_canonicalization_error(self) -> None:
        with self.assertRaises(CANONICALIZATION_ERRORS):
            request_sha256({**REQUEST, "params": {"request_id": "\ud800"}})

    def test_no_signed_input_is_not_a_canonicalization_error(self) -> None:
        self.assertFalse(issubclass(NoSignedInput, CANONICALIZATION_ERRORS))


if __name__ == "__main__":
    unittest.main()
