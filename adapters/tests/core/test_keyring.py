"""The keyring maps an opaque key_id to a key that carries its own algorithm (RFC 8725 section 3.1, D-026)."""
from __future__ import annotations

import hashlib
import unittest

from acs.core import ML_DSA_65, WIRE_ALGORITHMS, Keyring, VerificationKey
from acs.core._keyring import ECDSA_P256

PUBLIC = bytes(range(256)) * 7 + bytes(160)  # 1,952 bytes, the FIPS 204 ML-DSA-65 public key size


def _key(key_id: str = "lab-guardian-1", public: bytes = PUBLIC) -> VerificationKey:
    return VerificationKey(key_id=key_id, algorithm=ML_DSA_65, public_key=public)


class WireAlgorithms(unittest.TestCase):
    def test_only_ml_dsa_65_goes_on_the_wire(self) -> None:
        # PREMORTEM P7: no hybrid on the wire, and ECDSA-P256 is a benchmark primitive only.
        self.assertEqual(WIRE_ALGORITHMS, frozenset({"ML-DSA-65"}))
        self.assertEqual(ML_DSA_65, "ML-DSA-65")
        self.assertNotIn(ECDSA_P256, WIRE_ALGORITHMS)


class VerificationKeyRules(unittest.TestCase):
    def test_fingerprint_is_sha256_over_the_raw_public_key(self) -> None:
        self.assertEqual(_key().fingerprint, "sha256:" + hashlib.sha256(PUBLIC).hexdigest())

    def test_refuses_algorithms_off_the_wire(self) -> None:
        for algorithm in ("HMAC-SHA256", ECDSA_P256, "ML-DSA-65+ECDSA-P256", "ml-dsa-65", ""):
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                VerificationKey(key_id="k", algorithm=algorithm, public_key=PUBLIC)

    def test_refuses_a_public_key_of_the_wrong_size(self) -> None:
        for public in (b"", PUBLIC[:-1], PUBLIC + b"\x00"):
            with self.subTest(size=len(public)), self.assertRaises(ValueError):
                _key(public=public)

    def test_refuses_a_public_key_that_is_not_bytes(self) -> None:
        with self.assertRaises(ValueError):
            _key(public=PUBLIC.hex())  # type: ignore[arg-type]

    def test_refuses_an_empty_or_non_string_key_id(self) -> None:
        for key_id in ("", None, 7):
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                _key(key_id=key_id)  # type: ignore[arg-type]


class KeyringResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.key = _key()
        self.keyring = Keyring([self.key])

    def test_resolves_the_exact_key_id(self) -> None:
        self.assertIs(self.keyring.resolve("lab-guardian-1"), self.key)
        self.assertIn("lab-guardian-1", self.keyring)
        self.assertEqual(len(self.keyring), 1)
        self.assertEqual(self.keyring.key_ids, ("lab-guardian-1",))

    def test_an_unknown_key_id_resolves_to_nothing(self) -> None:
        self.assertIsNone(self.keyring.resolve("lab-guardian-2"))

    def test_key_id_is_opaque_so_near_spellings_resolve_to_nothing(self) -> None:
        # D-026: no case folding, trimming, or normalization, and no fallback to another key.
        for spelling in ("LAB-GUARDIAN-1", " lab-guardian-1", "lab-guardian-1 ", "lab-guardian-1\n"):
            with self.subTest(spelling=spelling):
                self.assertIsNone(self.keyring.resolve(spelling))

    def test_a_non_string_key_id_resolves_to_nothing(self) -> None:
        for key_id in (None, 1, ["lab-guardian-1"], {"key_id": "lab-guardian-1"}):
            with self.subTest(key_id=key_id):
                self.assertIsNone(self.keyring.resolve(key_id))

    def test_an_empty_keyring_resolves_nothing(self) -> None:
        self.assertIsNone(Keyring().resolve("lab-guardian-1"))
        self.assertEqual(len(Keyring()), 0)

    def test_a_duplicate_key_id_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            Keyring([_key(), _key(public=bytes(1952))])


if __name__ == "__main__":
    unittest.main()
