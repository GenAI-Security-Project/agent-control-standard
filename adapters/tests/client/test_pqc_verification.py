"""acs.client verifies a response by keyring only when the caller passes one (issue #574)."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest import mock

from tests.pqc_extra import require_pqc

require_pqc()

from acs.client import verify_signature  # noqa: E402
from acs.core import Keyring, MLDSA65SigningKey, sign_with_key, sign_with_signing_key  # noqa: E402

KEY_ID = "lab-guardian-1"
REQUEST = {"jsonrpc": "2.0", "id": "1", "method": "steps/toolCallRequest", "params": {"request_id": "1"}}
SECRET = "keyring-test-secret-0123456789abcdef"


def _decision() -> dict:
    return {"jsonrpc": "2.0", "id": "1",
            "result": {"acs_version": "0.1.0", "request_id": "1", "decision": "deny"}}


class KeyringVerification(unittest.TestCase):
    def setUp(self) -> None:
        # The HMAC settings name the same key_id, so a test passes only if the keyring path ignores them.
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        patcher = mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": KEY_ID},
                                  clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.signer = MLDSA65SigningKey.generate(KEY_ID)
        self.keyring = Keyring([self.signer.verification_key()])

    def test_an_ml_dsa_response_verifies_by_keyring(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        self.assertTrue(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST))

    def test_without_a_keyring_the_hmac_rules_still_apply(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        self.assertFalse(verify_signature(envelope))

    def test_an_hmac_response_fails_by_keyring(self) -> None:
        envelope = sign_with_key(_decision(), SECRET.encode(), key_id=KEY_ID)
        self.assertFalse(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST))

    def test_a_response_from_another_keyring_key_is_rejected(self) -> None:
        # Review finding CR2: a keyring may hold several keys, and only the expected one answers.
        other = MLDSA65SigningKey.generate("lab-guardian-2")
        keyring = Keyring([self.signer.verification_key(), other.verification_key()])
        envelope = sign_with_signing_key(_decision(), other)
        self.assertTrue(verify_signature(envelope, keyring=keyring, expected_key_id="lab-guardian-2", request=REQUEST))
        self.assertFalse(verify_signature(envelope, keyring=keyring, expected_key_id=KEY_ID, request=REQUEST))

    def test_a_key_id_mismatch_is_rejected_before_any_crypto(self) -> None:
        import acs.core._mldsa as module
        other = MLDSA65SigningKey.generate("lab-guardian-2")
        keyring = Keyring([self.signer.verification_key(), other.verification_key()])
        envelope = sign_with_signing_key(_decision(), other)
        spy = mock.Mock(return_value=True)
        with mock.patch.dict(module._VERIFIERS, {"ML-DSA-65": spy}):
            self.assertFalse(verify_signature(envelope, keyring=keyring, expected_key_id=KEY_ID, request=REQUEST))
        spy.assert_not_called()

    def test_the_keyring_path_requires_an_expected_key_id(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        for expected in (None, ""):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                verify_signature(envelope, keyring=self.keyring, expected_key_id=expected, request=REQUEST)

    def test_a_response_replayed_under_another_request_is_rejected(self) -> None:
        # Round 4, D-029: the response must answer the request this caller sent.
        envelope = sign_with_signing_key(_decision(), self.signer)
        self.assertTrue(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST))
        other = {**REQUEST, "id": "2", "params": {"request_id": "2"}}
        self.assertFalse(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=other))

    def test_the_keyring_path_requires_the_request(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        for request in (None, {}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=request)

    def test_a_request_without_a_keyring_is_refused(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        with self.assertRaises(ValueError):
            verify_signature(envelope, request=REQUEST)

    def test_the_client_goes_through_the_public_export(self) -> None:
        # Review finding CR3-5: acs.client uses acs.core's lazy export, not the private module.
        import acs.core
        envelope = sign_with_signing_key(_decision(), self.signer)
        spy = mock.Mock(return_value=True)
        with mock.patch.object(acs.core, "verify_with_keyring", spy):
            self.assertTrue(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID,
                                             request=REQUEST))
        spy.assert_called_once_with(envelope, self.keyring, expected_key_id=KEY_ID, request=REQUEST)

    def test_without_the_extra_the_keyring_path_names_it(self) -> None:
        code = ("import sys\nsys.modules['cryptography'] = None\nfrom acs.client import verify_signature\n"
                "verify_signature({}, keyring=object(), expected_key_id='k', request={'id': '1'})\n")
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("AttributeError", proc.stderr)
        self.assertIn("pqc", proc.stderr)

    def test_an_expected_key_id_without_a_keyring_is_refused(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        with self.assertRaises(ValueError):
            verify_signature(envelope, expected_key_id=KEY_ID)

    def test_the_configured_hmac_key_id_does_not_reach_the_keyring(self) -> None:
        other = MLDSA65SigningKey.generate("lab-guardian-2")
        envelope = sign_with_signing_key(_decision(), other)
        self.assertFalse(verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST))

    def test_an_unsigned_response_fails_by_keyring(self) -> None:
        self.assertFalse(verify_signature(_decision(), keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST))

    def test_a_keyring_with_hmac_arguments_is_refused(self) -> None:
        envelope = sign_with_signing_key(_decision(), self.signer)
        for kwargs in ({"key": b"k" * 32}, {"key_id": KEY_ID}, {"session_id": "s"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                verify_signature(envelope, keyring=self.keyring, expected_key_id=KEY_ID, request=REQUEST, **kwargs)


if __name__ == "__main__":
    unittest.main()
