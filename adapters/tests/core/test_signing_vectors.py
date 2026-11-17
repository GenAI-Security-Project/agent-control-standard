"""Sign-side known answers for HMAC-SHA256, and the bytes every algorithm signs (issue #574, PREMORTEM P8).

These run without the pqc extra. The ML-DSA-65 known answers live in test_pqc_signing.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import unittest

from acs.core import sign_with_key, signing_input, verify_with_key

KEY = bytes(range(32))
REQUEST_ID = "5b0d7c3e-2f0a-4d4e-9a51-0c6f3c1e8a42"


def _request() -> dict:
    return {"jsonrpc": "2.0", "id": REQUEST_ID, "method": "steps/toolCallRequest",
            "params": {"acs_version": "0.1.0", "request_id": REQUEST_ID,
                       "metadata": {"agent_id": "finbot", "session_id": "0f8fad5b-d9cb-469f-a165-70867728950e"},
                       "payload": {"tool": {"name": "finmail__send_email"},
                                   "arguments": {"to": {"value": ["collector@exfil.example"]}}}}}


# RFC 8785 written out by hand, so the vector doesn't lean on the canonicalizer under test.
CANONICAL = (b'{"id":"5b0d7c3e-2f0a-4d4e-9a51-0c6f3c1e8a42","jsonrpc":"2.0","method":"steps/toolCallRequest",'
             b'"params":{"acs_version":"0.1.0","metadata":{"agent_id":"finbot",'
             b'"session_id":"0f8fad5b-d9cb-469f-a165-70867728950e"},"payload":{"arguments":{"to":{"value":'
             b'["collector@exfil.example"]}},"tool":{"name":"finmail__send_email"}},'
             b'"request_id":"5b0d7c3e-2f0a-4d4e-9a51-0c6f3c1e8a42"}}')
HMAC_VALUE = "JKeQYZNdfA3Qfu4AuzJjNZnHmnpULZlQ5rNGQF2KFxc="


class SigningInput(unittest.TestCase):
    def test_is_jcs_of_the_envelope_without_its_signature(self) -> None:
        self.assertEqual(signing_input(_request()), CANONICAL)
        signed = sign_with_key(_request(), KEY, key_id="lab")
        self.assertEqual(signing_input(signed), CANONICAL)

    def test_does_not_change_the_envelope(self) -> None:
        signed = sign_with_key(_request(), KEY, key_id="lab")
        before = repr(signed)
        signing_input(signed)
        self.assertEqual(repr(signed), before)

    def test_covers_a_result_and_an_error_container(self) -> None:
        result = {"jsonrpc": "2.0", "id": "1", "result": {"decision": "allow", "signature": {"value": "x"}}}
        error = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32000, "signature": {"value": "x"}}}
        self.assertEqual(signing_input(result), b'{"id":"1","jsonrpc":"2.0","result":{"decision":"allow"}}')
        self.assertEqual(signing_input(error), b'{"error":{"code":-32000},"id":"1","jsonrpc":"2.0"}')


class HmacSha256KnownAnswer(unittest.TestCase):
    def test_the_vector_is_hmac_sha256_over_the_canonical_bytes(self) -> None:
        self.assertEqual(base64.b64encode(hmac.new(KEY, CANONICAL, hashlib.sha256).digest()).decode(), HMAC_VALUE)

    def test_sign_with_key_produces_the_vector(self) -> None:
        signed = sign_with_key(_request(), KEY, key_id="lab")
        self.assertEqual(signed["params"]["signature"],
                         {"algorithm": "HMAC-SHA256", "value": HMAC_VALUE, "key_id": "lab"})
        self.assertTrue(verify_with_key(signed, KEY))


if __name__ == "__main__":
    unittest.main()
