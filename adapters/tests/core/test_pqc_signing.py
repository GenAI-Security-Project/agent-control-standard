"""ML-DSA-65 envelope signing and keyring verification in acs.core (issue #574).

Signing is randomized in cryptography 50, so the known answers are verify-side (a Go-signed
vector) and keygen from a fixed seed (PREMORTEM P8). Sign-side tests round trip.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from tests.pqc_extra import require_pqc

require_pqc()

from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: E402

from acs.core import (  # noqa: E402
    ML_DSA_65,
    ML_DSA_CONTEXT,
    ML_DSA_MODE,
    Keyring,
    MLDSA65SigningKey,
    VerificationKey,
    sign_with_key,
    sign_with_signing_key,
    signing_input,
    verify_with_keyring,
)

VECTOR = json.loads((Path(__file__).parent / "vectors" / "ml_dsa_65_decision.json").read_text(encoding="utf-8"))
SEED = bytes(range(32))
# SHA-256 of the ML-DSA-65 public key for SEED. Go crypto/mldsa and pyca/cryptography agree on it.
SEED_PUBLIC_KEY_SHA256 = "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
KEY_ID = "lab-guardian-1"


def _decision() -> dict:
    return {"jsonrpc": "2.0", "id": "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60",
            "result": {"acs_version": "0.1.0", "request_id": "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60",
                       "decision": "allow", "chain_hash": "sha256:" + "cd" * 32}}


def _signer() -> MLDSA65SigningKey:
    return MLDSA65SigningKey.from_seed(SEED, KEY_ID)


def _keyring(signer: MLDSA65SigningKey | None = None) -> Keyring:
    return Keyring([(signer or _signer()).verification_key()])


class ModeAndContext(unittest.TestCase):
    """Issue #566: the registry fixes neither pure versus pre-hash nor the context, so the library says."""

    def test_pure_mode_with_an_empty_context(self) -> None:
        self.assertEqual(ML_DSA_MODE, "pure")
        self.assertEqual(ML_DSA_CONTEXT, b"")

    def test_a_signature_under_another_context_is_rejected(self) -> None:
        raw = mldsa.MLDSA65PrivateKey.from_seed_bytes(SEED)
        envelope = _decision()
        envelope["result"]["signature"] = {
            "algorithm": ML_DSA_65, "key_id": KEY_ID,
            "value": base64.b64encode(raw.sign(signing_input(envelope), b"acs")).decode()}
        self.assertFalse(verify_with_keyring(envelope, _keyring()))

    def test_the_signature_verifies_with_the_empty_context_directly(self) -> None:
        envelope = sign_with_signing_key(_decision(), _signer())
        sig = base64.b64decode(envelope["result"]["signature"]["value"])
        public = mldsa.MLDSA65PrivateKey.from_seed_bytes(SEED).public_key()
        public.verify(sig, signing_input(envelope), b"")  # raises InvalidSignature on failure


class KeygenFromSeedKnownAnswer(unittest.TestCase):
    def test_the_seed_gives_the_known_public_key(self) -> None:
        key = _signer().verification_key()
        self.assertEqual(hashlib.sha256(key.public_key).hexdigest(), SEED_PUBLIC_KEY_SHA256)
        self.assertEqual(key.public_key, base64.b64decode(VECTOR["public_key"]))
        self.assertEqual(key, VerificationKey(KEY_ID, ML_DSA_65, key.public_key))

    def test_the_seed_round_trips(self) -> None:
        self.assertEqual(_signer().seed(), SEED)
        generated = MLDSA65SigningKey.generate("k")
        self.assertEqual(MLDSA65SigningKey.from_seed(generated.seed(), "k").verification_key(),
                         generated.verification_key())

    def test_a_bad_seed_is_refused(self) -> None:
        for seed in (b"", SEED[:31], SEED + b"\x00", SEED.hex()):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                MLDSA65SigningKey.from_seed(seed, KEY_ID)  # type: ignore[arg-type]

    def test_a_bad_key_id_is_refused(self) -> None:
        for key_id in ("", None, 3):
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                MLDSA65SigningKey.from_seed(SEED, key_id)  # type: ignore[arg-type]

    def test_repr_and_str_never_show_the_seed(self) -> None:
        signer = _signer()
        for text in (repr(signer), str(signer)):
            with self.subTest(text=text):
                self.assertIn(KEY_ID, text)
                for leak in (SEED.hex(), base64.b64encode(SEED).decode(), repr(SEED)):
                    self.assertNotIn(leak, text)


class VerifySideKnownAnswer(unittest.TestCase):
    def test_the_go_signed_vector_verifies(self) -> None:
        public = base64.b64decode(VECTOR["public_key"])
        self.assertTrue(verify_with_keyring(VECTOR["envelope"], Keyring([VerificationKey(KEY_ID, ML_DSA_65, public)])))

    def test_the_go_signed_vector_fails_once_the_decision_changes(self) -> None:
        forged = copy.deepcopy(VECTOR["envelope"])
        forged["result"]["decision"] = "allow"
        self.assertFalse(verify_with_keyring(forged, _keyring()))


class SignAndVerify(unittest.TestCase):
    def test_round_trip(self) -> None:
        envelope = sign_with_signing_key(_decision(), _signer())
        sig = envelope["result"]["signature"]
        self.assertEqual(set(sig), {"algorithm", "value", "key_id"})
        self.assertEqual((sig["algorithm"], sig["key_id"]), (ML_DSA_65, KEY_ID))
        self.assertEqual(len(base64.b64decode(sig["value"], validate=True)), 3309)
        self.assertTrue(verify_with_keyring(envelope, _keyring()))

    def test_signing_is_randomized_and_both_signatures_verify(self) -> None:
        first = sign_with_signing_key(_decision(), _signer())
        second = sign_with_signing_key(_decision(), _signer())
        self.assertNotEqual(first["result"]["signature"]["value"], second["result"]["signature"]["value"])
        self.assertTrue(verify_with_keyring(second, _keyring()))

    def test_signs_the_same_bytes_hmac_signs(self) -> None:
        signer = _signer()
        envelope = sign_with_signing_key(_decision(), signer)
        hmac_signed = sign_with_key(_decision(), bytes(32), key_id="lab")
        self.assertEqual(signing_input(envelope), signing_input(hmac_signed))

    def test_resigning_replaces_the_old_signature(self) -> None:
        envelope = sign_with_key(_decision(), bytes(32), key_id="lab")
        sign_with_signing_key(envelope, _signer())
        self.assertEqual(envelope["result"]["signature"]["algorithm"], ML_DSA_65)
        self.assertTrue(verify_with_keyring(envelope, _keyring()))

    def test_a_request_envelope_signs_under_params(self) -> None:
        request = {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart", "params": {"acs_version": "0.1.0"}}
        sign_with_signing_key(request, _signer())
        self.assertEqual(request["params"]["signature"]["algorithm"], ML_DSA_65)
        self.assertTrue(verify_with_keyring(request, _keyring()))


class Rejections(unittest.TestCase):
    """Algorithm from the key, never from the envelope (RFC 8725 section 3.1, #308), and D-026 per key_id."""

    def setUp(self) -> None:
        self.keyring = _keyring()
        self.signed = sign_with_signing_key(_decision(), _signer())

    def _with_signature(self, **changes: object) -> dict:
        envelope = copy.deepcopy(self.signed)
        envelope["result"]["signature"].update(changes)
        return envelope

    def test_an_unknown_key_id_is_rejected(self) -> None:
        for key_id in ("lab-guardian-2", "LAB-GUARDIAN-1", "", None, 1):
            with self.subTest(key_id=key_id):
                self.assertFalse(verify_with_keyring(self._with_signature(key_id=key_id), self.keyring))

    def test_a_missing_key_id_is_rejected(self) -> None:
        envelope = copy.deepcopy(self.signed)
        del envelope["result"]["signature"]["key_id"]
        self.assertFalse(verify_with_keyring(envelope, self.keyring))

    def test_an_algorithm_the_key_does_not_carry_is_rejected(self) -> None:
        for algorithm in ("HMAC-SHA256", "ECDSA-P256", "ML-DSA-65+ECDSA-P256", "ml-dsa-65", "", None):
            with self.subTest(algorithm=algorithm):
                self.assertFalse(verify_with_keyring(self._with_signature(algorithm=algorithm), self.keyring))

    def test_an_hmac_signed_envelope_under_a_keyring_key_id_is_rejected(self) -> None:
        envelope = sign_with_key(_decision(), bytes(32), key_id=KEY_ID)
        self.assertFalse(verify_with_keyring(envelope, self.keyring))
        envelope["result"]["signature"]["algorithm"] = ML_DSA_65
        self.assertFalse(verify_with_keyring(envelope, self.keyring))

    def test_another_key_under_the_same_key_id_is_rejected(self) -> None:
        other = MLDSA65SigningKey.from_seed(bytes(32), KEY_ID)
        self.assertFalse(verify_with_keyring(self.signed, _keyring(other)))

    def test_an_empty_keyring_rejects_everything(self) -> None:
        self.assertFalse(verify_with_keyring(self.signed, Keyring()))

    def test_a_changed_envelope_is_rejected(self) -> None:
        for path, value in ((("result", "decision"), "deny"), (("id",), "other"), (("jsonrpc",), "3.0")):
            envelope = copy.deepcopy(self.signed)
            target = envelope
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(verify_with_keyring(envelope, self.keyring))
        added = copy.deepcopy(self.signed)
        added["result"]["reasoning"] = "added after signing"
        self.assertFalse(verify_with_keyring(added, self.keyring))

    def test_a_flipped_signature_byte_is_rejected(self) -> None:
        raw = bytearray(base64.b64decode(self.signed["result"]["signature"]["value"]))
        for index in (0, len(raw) // 2, len(raw) - 1):
            flipped = bytearray(raw)
            flipped[index] ^= 0x01
            with self.subTest(index=index):
                value = base64.b64encode(bytes(flipped)).decode()
                self.assertFalse(verify_with_keyring(self._with_signature(value=value), self.keyring))

    def test_a_malformed_value_is_rejected_without_raising(self) -> None:
        good = self.signed["result"]["signature"]["value"]
        for value in (None, 7, b"bytes", "", "not base64!", good[:-8], good + "AAAA", good + "=",
                      base64.urlsafe_b64encode(bytes(3309)).decode(), base64.b64encode(bytes(3309)).decode()):
            with self.subTest(value=str(value)[:24]):
                self.assertFalse(verify_with_keyring(self._with_signature(value=value), self.keyring))

    def test_an_unsigned_or_misshapen_envelope_is_rejected(self) -> None:
        unsigned = _decision()
        not_a_dict = {"jsonrpc": "2.0", "id": "1", "result": "allow"}
        signature_not_a_dict = copy.deepcopy(self.signed)
        signature_not_a_dict["result"]["signature"] = "sig"
        for name, envelope in (("unsigned", unsigned), ("container not a dict", not_a_dict),
                               ("signature not a dict", signature_not_a_dict), ("not an envelope", [])):
            with self.subTest(name):
                self.assertFalse(verify_with_keyring(envelope, self.keyring))  # type: ignore[arg-type]

    def test_an_envelope_without_a_canonical_form_is_rejected(self) -> None:
        envelope = copy.deepcopy(self.signed)
        envelope["result"]["big"] = 2 ** 60  # RFC 8785 has no form for an integer beyond 2**53
        self.assertFalse(verify_with_keyring(envelope, self.keyring))


class ImportTimeChecks(unittest.TestCase):
    """The module fails loudly at import when ML-DSA is unavailable, instead of at the first signature."""

    def _import_with(self, prelude: str) -> subprocess.CompletedProcess:
        code = prelude + "\nimport acs.core._mldsa\n"
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)

    def test_a_backend_without_ml_dsa_fails_loudly(self) -> None:
        prelude = ("from cryptography.exceptions import UnsupportedAlgorithm\n"
                   "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
                   "def refuse(*a, **k): raise UnsupportedAlgorithm('no ML-DSA here')\n"
                   "mldsa.MLDSA65PrivateKey.generate = staticmethod(refuse)\n")
        proc = self._import_with(prelude)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ImportError", proc.stderr)
        self.assertIn("ML-DSA-65", proc.stderr)
        self.assertIn("OpenSSL", proc.stderr)

    def test_missing_cryptography_names_the_pqc_extra(self) -> None:
        proc = self._import_with("import sys\nsys.modules['cryptography'] = None\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ImportError", proc.stderr)
        self.assertIn("pqc", proc.stderr)


if __name__ == "__main__":
    unittest.main()
