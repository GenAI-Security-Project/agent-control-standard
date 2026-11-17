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
from unittest import mock

from tests.pqc_extra import require_pqc

require_pqc()

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: E402

from acs.core import (  # noqa: E402
    ML_DSA_65,
    WIRE_ALGORITHMS,
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
from acs.core._keyring import ECDSA_P256  # noqa: E402

VECTOR = json.loads((Path(__file__).parent / "vectors" / "ml_dsa_65_decision.json").read_text(encoding="utf-8"))
SEED = bytes(range(32))
# SHA-256 of the ML-DSA-65 public key for SEED. Go crypto/mldsa and pyca/cryptography agree on it.
SEED_PUBLIC_KEY_SHA256 = "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
KEY_ID = "lab-guardian-1"
SESSION_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _decision() -> dict:
    return {"jsonrpc": "2.0", "id": "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60",
            "result": {"acs_version": "0.1.0", "request_id": "c9b0e0a2-6d1f-4a57-8f3e-2b7d9e4c1a60",
                       "decision": "allow", "chain_hash": "sha256:" + "cd" * 32,
                       "metadata": {"session_id": SESSION_ID}}}


def _signer() -> MLDSA65SigningKey:
    return MLDSA65SigningKey.from_seed(SEED, KEY_ID)


def _keyring(signer: MLDSA65SigningKey | None = None) -> Keyring:
    return Keyring([(signer or _signer()).verification_key()])


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

    def test_refuses_an_algorithm_that_is_not_a_string(self) -> None:
        # Review finding CR3-10: an unhashable value is a ValueError like any other bad field.
        for algorithm in (["ML-DSA-65"], {"ML-DSA-65": 1}, None, 65):
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                VerificationKey(key_id="k", algorithm=algorithm, public_key=PUBLIC)  # type: ignore[arg-type]

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



class KeysAreParsedOnce(unittest.TestCase):
    """Review finding CR7: the trusted key is parsed when its keyring entry is built, not per verification."""

    def test_verification_does_not_parse_the_public_key_again(self) -> None:
        signer = _signer()
        keyring = _keyring(signer)
        envelope = sign_with_signing_key(_decision(), signer)
        with mock.patch.object(mldsa.MLDSA65PublicKey, "from_public_bytes",
                               side_effect=AssertionError("parsed again")):
            self.assertTrue(verify_with_keyring(envelope, keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_building_a_key_without_the_extra_names_it(self) -> None:
        # The public name is gated (AttributeError), and the private module fails at build (ImportError).
        for route, error in (("import acs.core\nacs.core.VerificationKey", "AttributeError"),
                             ("from acs.core._keyring import VerificationKey\n"
                              "VerificationKey('k', 'ML-DSA-65', bytes(1952))", "ImportError")):
            code = "import sys\nsys.modules['cryptography'] = None\n" + route + "\n"
            proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
            with self.subTest(error=error):
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(error, proc.stderr)
                self.assertIn("pqc", proc.stderr)


class KeysSurviveCopyAndPickle(unittest.TestCase):
    """Re-review finding R-M2: a key holding a parsed backend object still copies and pickles."""

    def test_pickle_and_deepcopy_round_trip_and_still_verify(self) -> None:
        import pickle
        signer = _signer()
        key = signer.verification_key()
        envelope = sign_with_signing_key(_decision(), signer)
        for name, clone in (("pickle", lambda k: pickle.loads(pickle.dumps(k))), ("deepcopy", copy.deepcopy),
                            ("copy", copy.copy)):
            with self.subTest(name):
                copied = clone(key)
                self.assertEqual(copied, key)
                self.assertTrue(verify_with_keyring(envelope, Keyring([copied]), expected_key_id=KEY_ID,
                                                    expected_session_id=SESSION_ID))

    def test_a_keyring_deepcopies(self) -> None:
        keyring = _keyring()
        self.assertEqual(copy.deepcopy(keyring).key_ids, keyring.key_ids)


class SignatureLengthIsCheckedFirst(unittest.TestCase):
    """Review finding F-M1: any length but 3,309 bytes fails before cryptography sees it."""

    def test_a_wrong_length_never_reaches_the_verifier(self) -> None:
        import acs.core._mldsa as module
        envelope = sign_with_signing_key(_decision(), _signer())
        raw = base64.b64decode(envelope["result"]["signature"]["value"])
        spy = mock.Mock(return_value=True)
        with mock.patch.dict(module._VERIFIERS, {ML_DSA_65: spy}):
            for signature in (raw[:-1], raw + b"\x00", b"", raw[:3306]):
                with self.subTest(length=len(signature)):
                    envelope["result"]["signature"]["value"] = base64.b64encode(signature).decode()
                    self.assertFalse(verify_with_keyring(envelope, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))
            spy.assert_not_called()
            envelope["result"]["signature"]["value"] = base64.b64encode(raw).decode()
            self.assertTrue(verify_with_keyring(envelope, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))
            spy.assert_called_once()


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
        self.assertFalse(verify_with_keyring(envelope, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

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


ACVP = json.loads((Path(__file__).parent / "vectors" / "acvp_ml_dsa_65.json").read_text(encoding="utf-8"))


class NistAcvpKnownAnswers(unittest.TestCase):
    """Review finding F-M2: vectors from NIST's ACVP-Server, cited by file, commit and test case in the JSON.

    ACVP has no valid pure ML-DSA-65 case with an empty context, so none of these is a positive
    for the library's own empty-context verify path. The Go crypto/mldsa interop test in
    tests/interop/ is that positive, and VerifySideKnownAnswer pins a Go-signed vector here.
    """

    def test_keygen_from_the_acvp_seed_gives_the_acvp_public_key(self) -> None:
        case = ACVP["keyGen"]
        signer = MLDSA65SigningKey.from_seed(bytes.fromhex(case["seed"]), "acvp")
        self.assertEqual(signer.verification_key().public_key, bytes.fromhex(case["pk"]))

    def test_sigver_cases_give_the_acvp_verdict(self) -> None:
        for case in ACVP["sigVer"]:
            key = VerificationKey("acvp", ML_DSA_65, bytes.fromhex(case["pk"]))
            signature, message = bytes.fromhex(case["signature"]), bytes.fromhex(case["message"])
            with self.subTest(tcId=case["tcId"]):
                try:
                    key._parsed.verify(signature, message, bytes.fromhex(case["context"]))
                    verdict = True
                except InvalidSignature:
                    verdict = False
                self.assertEqual(verdict, case["testPassed"])

    def test_the_library_context_rejects_a_valid_acvp_signature_made_under_another_context(self) -> None:
        import acs.core._mldsa as module
        (valid,) = [c for c in ACVP["sigVer"] if c["testPassed"]]
        self.assertNotEqual(valid["context"], "")
        key = VerificationKey("acvp", ML_DSA_65, bytes.fromhex(valid["pk"]))
        self.assertFalse(module._verify_ml_dsa_65(key._parsed, bytes.fromhex(valid["signature"]),
                                                  bytes.fromhex(valid["message"])))


class VerifySideKnownAnswer(unittest.TestCase):
    def test_the_go_signed_vector_verifies(self) -> None:
        public = base64.b64decode(VECTOR["public_key"])
        self.assertTrue(verify_with_keyring(VECTOR["envelope"], Keyring([VerificationKey(KEY_ID, ML_DSA_65, public)]), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_the_go_signed_vector_fails_once_the_decision_changes(self) -> None:
        forged = copy.deepcopy(VECTOR["envelope"])
        forged["result"]["decision"] = "allow"
        self.assertFalse(verify_with_keyring(forged, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))


class SignAndVerify(unittest.TestCase):
    def test_round_trip(self) -> None:
        envelope = sign_with_signing_key(_decision(), _signer())
        sig = envelope["result"]["signature"]
        self.assertEqual(set(sig), {"algorithm", "value", "key_id"})
        self.assertEqual((sig["algorithm"], sig["key_id"]), (ML_DSA_65, KEY_ID))
        self.assertEqual(len(base64.b64decode(sig["value"], validate=True)), 3309)
        self.assertTrue(verify_with_keyring(envelope, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_signing_is_randomized_and_both_signatures_verify(self) -> None:
        first = sign_with_signing_key(_decision(), _signer())
        second = sign_with_signing_key(_decision(), _signer())
        self.assertNotEqual(first["result"]["signature"]["value"], second["result"]["signature"]["value"])
        self.assertTrue(verify_with_keyring(second, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_signs_the_same_bytes_hmac_signs(self) -> None:
        signer = _signer()
        envelope = sign_with_signing_key(_decision(), signer)
        hmac_signed = sign_with_key(_decision(), bytes(32), key_id="lab")
        self.assertEqual(signing_input(envelope), signing_input(hmac_signed))

    def test_resigning_replaces_the_old_signature(self) -> None:
        envelope = sign_with_key(_decision(), bytes(32), key_id="lab")
        sign_with_signing_key(envelope, _signer())
        self.assertEqual(envelope["result"]["signature"]["algorithm"], ML_DSA_65)
        self.assertTrue(verify_with_keyring(envelope, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_a_request_envelope_signs_under_params(self) -> None:
        request = {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart",
                   "params": {"acs_version": "0.1.0", "metadata": {"session_id": SESSION_ID}}}
        sign_with_signing_key(request, _signer())
        self.assertEqual(request["params"]["signature"]["algorithm"], ML_DSA_65)
        self.assertTrue(verify_with_keyring(request, _keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))


class SessionBinding(unittest.TestCase):
    """Review finding CR3-1: a response signed for one session never verifies in another.

    HMAC binds a response to its session through the per-session key. One ML-DSA key signs
    every session, so the verifier reads the session the signed envelope names.
    """

    def setUp(self) -> None:
        self.keyring = _keyring()
        self.signed = sign_with_signing_key(_decision(), _signer())

    def test_a_response_replayed_into_another_session_is_rejected(self) -> None:
        self.assertTrue(verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID,
                                            expected_session_id=SESSION_ID))
        self.assertFalse(verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID,
                                             expected_session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"))

    def test_session_id_is_matched_exactly(self) -> None:
        for spelling in (SESSION_ID.upper(), f"urn:uuid:{SESSION_ID}", SESSION_ID + " "):
            with self.subTest(spelling=spelling):
                self.assertFalse(verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID,
                                                     expected_session_id=spelling))

    def test_a_response_naming_no_session_is_rejected(self) -> None:
        for metadata in (None, {}, {"session_id": None}, {"session_id": 7}, "not a dict"):
            envelope = _decision()
            if metadata is None:
                del envelope["result"]["metadata"]
            else:
                envelope["result"]["metadata"] = metadata
            sign_with_signing_key(envelope, _signer())
            with self.subTest(metadata=metadata):
                self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID,
                                                     expected_session_id=SESSION_ID))

    def test_the_session_is_read_from_the_signed_bytes(self) -> None:
        # Rewriting the session after signing breaks the signature, so the check can't be steered.
        moved = copy.deepcopy(self.signed)
        moved["result"]["metadata"]["session_id"] = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
        self.assertFalse(verify_with_keyring(moved, self.keyring, expected_key_id=KEY_ID,
                                             expected_session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"))

    def test_a_session_mismatch_is_rejected_before_any_crypto(self) -> None:
        import acs.core._mldsa as module
        spy = mock.Mock(return_value=True)
        with mock.patch.dict(module._VERIFIERS, {ML_DSA_65: spy}):
            self.assertFalse(verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID,
                                                 expected_session_id="another-session"))
        spy.assert_not_called()

    def test_an_error_response_names_its_session_under_error_data(self) -> None:
        error = {"jsonrpc": "2.0", "id": "1",
                 "error": {"code": -32000, "message": "refused", "data": {"session_id": SESSION_ID}}}
        sign_with_signing_key(error, _signer())
        self.assertTrue(verify_with_keyring(error, self.keyring, expected_key_id=KEY_ID,
                                            expected_session_id=SESSION_ID))
        self.assertFalse(verify_with_keyring(error, self.keyring, expected_key_id=KEY_ID,
                                             expected_session_id="another-session"))

    def test_expected_session_id_is_required(self) -> None:
        for expected in (None, "", 7):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID,
                                    expected_session_id=expected)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_with_keyring(self.signed, self.keyring, expected_key_id=KEY_ID)  # type: ignore[call-arg]


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
                self.assertFalse(verify_with_keyring(self._with_signature(key_id=key_id), self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_an_expected_key_id_the_keyring_lacks_is_rejected(self) -> None:
        envelope = self._with_signature(key_id="lab-guardian-2")
        self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id="lab-guardian-2", expected_session_id=SESSION_ID))

    def test_a_response_from_another_keyring_key_is_rejected(self) -> None:
        # Review finding CR3-3: core enforces the pin, so no caller can skip it.
        other = MLDSA65SigningKey.from_seed(bytes(32), "lab-guardian-2")
        keyring = Keyring([_signer().verification_key(), other.verification_key()])
        envelope = sign_with_signing_key(_decision(), other)
        self.assertTrue(verify_with_keyring(envelope, keyring, expected_key_id="lab-guardian-2", expected_session_id=SESSION_ID))
        self.assertFalse(verify_with_keyring(envelope, keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_a_key_id_mismatch_is_rejected_before_any_crypto(self) -> None:
        import acs.core._mldsa as module
        spy = mock.Mock(return_value=True)
        with mock.patch.dict(module._VERIFIERS, {ML_DSA_65: spy}):
            self.assertFalse(verify_with_keyring(self.signed, self.keyring, expected_key_id="lab-guardian-2", expected_session_id=SESSION_ID))
        spy.assert_not_called()

    def test_expected_key_id_is_required(self) -> None:
        for expected in (None, "", 7):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                verify_with_keyring(self.signed, self.keyring, expected_key_id=expected, expected_session_id=SESSION_ID)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_with_keyring(self.signed, self.keyring, expected_session_id=SESSION_ID)  # type: ignore[call-arg]

    def test_a_missing_key_id_is_rejected(self) -> None:
        envelope = copy.deepcopy(self.signed)
        del envelope["result"]["signature"]["key_id"]
        self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_an_algorithm_the_key_does_not_carry_is_rejected(self) -> None:
        for algorithm in ("HMAC-SHA256", "ECDSA-P256", "ML-DSA-65+ECDSA-P256", "ml-dsa-65", "", None):
            with self.subTest(algorithm=algorithm):
                self.assertFalse(verify_with_keyring(self._with_signature(algorithm=algorithm), self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_an_hmac_signed_envelope_under_a_keyring_key_id_is_rejected(self) -> None:
        envelope = sign_with_key(_decision(), bytes(32), key_id=KEY_ID)
        self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))
        envelope["result"]["signature"]["algorithm"] = ML_DSA_65
        self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_another_key_under_the_same_key_id_is_rejected(self) -> None:
        other = MLDSA65SigningKey.from_seed(bytes(32), KEY_ID)
        self.assertFalse(verify_with_keyring(self.signed, _keyring(other), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_an_empty_keyring_rejects_everything(self) -> None:
        self.assertFalse(verify_with_keyring(self.signed, Keyring(), expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_a_changed_envelope_is_rejected(self) -> None:
        for path, value in ((("result", "decision"), "deny"), (("id",), "other"), (("jsonrpc",), "3.0")):
            envelope = copy.deepcopy(self.signed)
            target = envelope
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))
        added = copy.deepcopy(self.signed)
        added["result"]["reasoning"] = "added after signing"
        self.assertFalse(verify_with_keyring(added, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_a_flipped_signature_byte_is_rejected(self) -> None:
        raw = bytearray(base64.b64decode(self.signed["result"]["signature"]["value"]))
        for index in (0, len(raw) // 2, len(raw) - 1):
            flipped = bytearray(raw)
            flipped[index] ^= 0x01
            with self.subTest(index=index):
                value = base64.b64encode(bytes(flipped)).decode()
                self.assertFalse(verify_with_keyring(self._with_signature(value=value), self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_a_malformed_value_is_rejected_without_raising(self) -> None:
        good = self.signed["result"]["signature"]["value"]
        for value in (None, 7, b"bytes", "", "not base64!", good[:-8], good + "AAAA", good + "=",
                      base64.urlsafe_b64encode(bytes(3309)).decode(), base64.b64encode(bytes(3309)).decode()):
            with self.subTest(value=str(value)[:24]):
                self.assertFalse(verify_with_keyring(self._with_signature(value=value), self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))

    def test_an_unsigned_or_misshapen_envelope_is_rejected(self) -> None:
        unsigned = _decision()
        not_a_dict = {"jsonrpc": "2.0", "id": "1", "result": "allow"}
        signature_not_a_dict = copy.deepcopy(self.signed)
        signature_not_a_dict["result"]["signature"] = "sig"
        for name, envelope in (("unsigned", unsigned), ("container not a dict", not_a_dict),
                               ("signature not a dict", signature_not_a_dict), ("not an envelope", [])):
            with self.subTest(name):
                self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))  # type: ignore[arg-type]

    def test_an_envelope_without_a_canonical_form_is_rejected(self) -> None:
        envelope = copy.deepcopy(self.signed)
        envelope["result"]["big"] = 2 ** 60  # RFC 8785 has no form for an integer beyond 2**53
        self.assertFalse(verify_with_keyring(envelope, self.keyring, expected_key_id=KEY_ID, expected_session_id=SESSION_ID))


class VariantAndContextAreDocumented(unittest.TestCase):
    """Issue #574 done_when: the documentation names the ML-DSA variant and the context, and a test pins both."""

    DOC = Path(__file__).resolve().parents[2] / "docs" / "signing.md"

    def test_the_adapters_doc_names_pure_mode_and_the_empty_context(self) -> None:
        # The facts, not their formatting: pure mode, HashML-DSA ruled out, and an empty context.
        text = " ".join(self.DOC.read_text(encoding="utf-8").split())
        self.assertRegex(text, r"\bpure ML-DSA-65\b")
        self.assertRegex(text, r"not (use )?(the pre-hash )?HashML-DSA")
        self.assertRegex(text, r'context string is empty \(`b""`')
        self.assertNotIn("HashML-DSA-65 with", text)

    def test_the_module_docstring_names_pure_mode_and_the_empty_context(self) -> None:
        import acs.core._mldsa as module
        self.assertIn("Variant: pure ML-DSA, not the pre-hash HashML-DSA.", module.__doc__)
        self.assertIn('Context string: empty (b"").', module.__doc__)


# RFC 6979 Appendix A.2.5: ECDSA over P-256 with SHA-256. Values are written as the RFC prints them.
RFC6979_UX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
RFC6979_UY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # SEC 2, secp256r1 n
RFC6979_SIGNATURES = {
    b"sample": ("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
    b"test": ("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
              "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
}


class EcdsaP256BenchmarkPrimitive(unittest.TestCase):
    """ECDSA-P256 exists for the LAB-10 benchmark only. It isn't a wire algorithm (PREMORTEM P7)."""

    PUBLIC = b"\x04" + bytes.fromhex(RFC6979_UX) + bytes.fromhex(RFC6979_UY)

    def test_rfc_6979_vectors_verify_in_low_s_form(self) -> None:
        from acs.core._ecdsa import ecdsa_p256_verify
        for message, (r, s) in RFC6979_SIGNATURES.items():
            low_s = min(int(s, 16), P256_ORDER - int(s, 16))
            with self.subTest(message=message):
                self.assertTrue(ecdsa_p256_verify(self.PUBLIC, message, bytes.fromhex(r) + low_s.to_bytes(32, "big")))

    def test_a_high_s_signature_is_rejected(self) -> None:
        # Review finding CR6: (r, s) and (r, n - s) both satisfy ECDSA, so only low s is accepted.
        from acs.core._ecdsa import ecdsa_p256_verify
        r, s = RFC6979_SIGNATURES[b"sample"]
        self.assertGreater(int(s, 16), P256_ORDER // 2, "the RFC prints this vector with a high s")
        self.assertFalse(ecdsa_p256_verify(self.PUBLIC, b"sample", bytes.fromhex(r + s)))

    def test_only_a_65_byte_uncompressed_point_is_accepted(self) -> None:
        # Review finding CR3-9: the docstring promises uncompressed SEC1, so a compressed key fails.
        from acs.core._ecdsa import ecdsa_p256_verify
        r, s = RFC6979_SIGNATURES[b"test"]
        good = bytes.fromhex(r + s)
        y_parity = 0x03 if int(RFC6979_UY, 16) & 1 else 0x02
        compressed = bytes([y_parity]) + bytes.fromhex(RFC6979_UX)
        hybrid_form = bytes([0x06 | (y_parity & 1)]) + self.PUBLIC[1:]
        self.assertTrue(ecdsa_p256_verify(self.PUBLIC, b"test", good))
        for public in (compressed, hybrid_form, self.PUBLIC + b"\x00"):
            with self.subTest(length=len(public), prefix=public[0]):
                self.assertFalse(ecdsa_p256_verify(public, b"test", good))

    def test_non_bytes_inputs_return_false(self) -> None:
        from acs.core._ecdsa import ecdsa_p256_verify
        r, s = RFC6979_SIGNATURES[b"test"]
        good = bytes.fromhex(r + s)
        for public, message, signature in ((self.PUBLIC.hex(), b"test", good), (None, b"test", good),
                                           (self.PUBLIC, b"test", good.hex()), (self.PUBLIC, b"test", None),
                                           (self.PUBLIC, "test", good), (self.PUBLIC, None, good)):
            with self.subTest(public=type(public).__name__, message=type(message).__name__,
                              signature=type(signature).__name__):
                self.assertFalse(ecdsa_p256_verify(public, message, signature))  # type: ignore[arg-type]

    def test_a_changed_message_or_signature_fails(self) -> None:
        from acs.core._ecdsa import ecdsa_p256_verify
        r, s = RFC6979_SIGNATURES[b"test"]
        good = bytes.fromhex(r + s)
        flipped = bytes([good[0] ^ 1]) + good[1:]
        self.assertTrue(ecdsa_p256_verify(self.PUBLIC, b"test", good))
        self.assertFalse(ecdsa_p256_verify(self.PUBLIC, b"tesu", good))
        self.assertFalse(ecdsa_p256_verify(self.PUBLIC, b"test", flipped))

    def test_malformed_inputs_fail_without_raising(self) -> None:
        from acs.core._ecdsa import ecdsa_p256_verify
        r, s = RFC6979_SIGNATURES[b"test"]
        good = bytes.fromhex(r + s)
        for public, signature in ((self.PUBLIC, good[:-1]), (self.PUBLIC, good + b"\x00"), (self.PUBLIC, b""),
                                  (self.PUBLIC[:-1], good), (b"\x04" + bytes(64), good), (b"", good)):
            with self.subTest(public=len(public), signature=len(signature)):
                self.assertFalse(ecdsa_p256_verify(public, b"test", signature))

    def test_round_trip_with_a_fixed_width_signature(self) -> None:
        from acs.core._ecdsa import (
            ecdsa_p256_generate,
            ecdsa_p256_public_bytes,
            ecdsa_p256_sign,
            ecdsa_p256_verify,
        )
        private = ecdsa_p256_generate()
        public = ecdsa_p256_public_bytes(private)
        self.assertEqual((len(public), public[0]), (65, 4))
        for _ in range(20):  # r or s with leading zero bytes still encode to 32 bytes each
            signature = ecdsa_p256_sign(private, b"envelope bytes")
            self.assertEqual(len(signature), 64)
            self.assertLessEqual(int.from_bytes(signature[32:], "big"), P256_ORDER // 2)
            self.assertTrue(ecdsa_p256_verify(public, b"envelope bytes", signature))

    def test_not_exported_as_a_wire_algorithm(self) -> None:
        # Review finding CR3-8: no exclusion by name, so ECDSA_P256 itself entering any export fails.
        import acs.core
        exported = set(acs.core.__all__) | set(acs.core._EXPORTS) | set(acs.core._PQC_EXPORTS)
        self.assertEqual({n for n in exported if "ecdsa" in n.lower()}, set())
        self.assertFalse(hasattr(acs.core, "ECDSA_P256"))


class BackendChecks(unittest.TestCase):
    """Review finding CR3-7: the backend check runs once, on first use, and still fails loudly."""

    COUNTING = ("from cryptography.hazmat.primitives.asymmetric import mldsa\n"
                "real = mldsa.MLDSA65PrivateKey.generate\n"
                "calls = []\n"
                "def counted(*a, **k):\n    calls.append(1)\n    return real(*a, **k)\n"
                "mldsa.MLDSA65PrivateKey.generate = staticmethod(counted)\n")
    REFUSING = ("from cryptography.exceptions import UnsupportedAlgorithm\n"
                "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
                "def refuse(*a, **k): raise UnsupportedAlgorithm('no ML-DSA here')\n"
                "mldsa.MLDSA65PrivateKey.generate = staticmethod(refuse)\n")

    def _run(self, code: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)

    def test_importing_the_module_generates_no_key(self) -> None:
        proc = self._run(self.COUNTING + "import acs.core._mldsa\nprint(len(calls))\n")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "0"), proc.stderr)

    def test_the_check_runs_once_across_uses(self) -> None:
        code = (self.COUNTING + "from acs.core._mldsa import MLDSA65SigningKey, load_public_key\n"
                "a = MLDSA65SigningKey.from_seed(bytes(32), 'k')\n"
                "b = MLDSA65SigningKey.from_seed(bytes(range(32)), 'k')\n"
                "load_public_key(a.verification_key().public_key)\n"
                "print(len(calls))\n")
        proc = self._run(code)
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "1"), proc.stderr)

    def test_a_backend_without_ml_dsa_fails_loudly_on_first_use(self) -> None:
        proc = self._run(self.REFUSING + "import acs.core._mldsa as m\nprint('imported')\n"
                         "m.MLDSA65SigningKey.from_seed(bytes(32), 'k')\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("imported", proc.stdout)
        self.assertIn("MLDSAUnavailableError", proc.stderr)
        self.assertIn("ML-DSA-65", proc.stderr)
        self.assertIn("OpenSSL", proc.stderr)

    def test_missing_cryptography_names_the_pqc_extra(self) -> None:
        proc = self._run("import sys\nsys.modules['cryptography'] = None\nimport acs.core._mldsa\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ImportError", proc.stderr)
        self.assertIn("pqc", proc.stderr)


if __name__ == "__main__":
    unittest.main()
