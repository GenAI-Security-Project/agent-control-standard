"""acs.client parses a Guardian key document into a keyring pinned to one key (issue #576).

The key document is a lab convention until issue #460. The verifier takes the key from the
document by key_id (RFC 8725 section 3.1, issue #308), and D-026 applies per key_id.
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import tempfile
import unittest

from tests.pqc_extra import require_pqc

require_pqc()

from acs.client import KeyDocumentError, load_response_keys, parse_key_document, response_keys_from_env  # noqa: E402
from acs.core import MLDSA65SigningKey  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 12, 9, 12, tzinfo=UTC)
KEY_ID = "lab-guardian-1"


def _stamp(moment: datetime.datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _entry(signer: MLDSA65SigningKey, *, not_before: datetime.datetime | None = None,
           not_after: datetime.datetime | None = None, **overrides: object) -> dict:
    vk = signer.verification_key()
    entry = {"key_id": signer.key_id, "algorithm": "ML-DSA-65",
             "public_key": base64.b64encode(vk.public_key).decode("ascii"),
             "fingerprint": vk.fingerprint,
             "not_before": _stamp(not_before or NOW - datetime.timedelta(days=1)),
             "not_after": _stamp(not_after or NOW + datetime.timedelta(days=89))}
    entry.update(overrides)
    return entry


def _document(*entries: dict, revoked: list | tuple = ()) -> dict:
    return {"format": "acs-lab-keys/1", "guardian_id": "lab-guardian", "keys": list(entries),
            "revoked": list(revoked)}


class KeyDocument(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = MLDSA65SigningKey.generate(KEY_ID)
        cls.other = MLDSA65SigningKey.generate("lab-guardian-2")

    def _refused(self, document: object, key_id: str | None = None) -> None:
        with self.assertRaises(KeyDocumentError):
            parse_key_document(document, key_id=key_id, now=NOW)

    def test_a_valid_document_gives_the_pinned_key(self) -> None:
        vk = self.signer.verification_key()
        keys = parse_key_document(_document(_entry(self.signer)), key_id=KEY_ID, now=NOW)
        self.assertEqual(keys.key_id, KEY_ID)
        self.assertEqual(keys.algorithm, "ML-DSA-65")
        self.assertEqual(keys.keyring.key_ids, (KEY_ID,))
        self.assertEqual(keys.fingerprint, vk.fingerprint)
        self.assertEqual(keys.guardian_id, "lab-guardian")
        self.assertEqual(keys.document["keys"][0]["key_id"], KEY_ID)

    def test_key_id_matches_exactly(self) -> None:
        for pin in ("LAB-GUARDIAN-1", " lab-guardian-1", "lab-guardian-1 "):
            with self.subTest(pin=pin):
                self._refused(_document(_entry(self.signer)), pin)

    def test_two_live_keys_without_a_pin_are_refused(self) -> None:
        self._refused(_document(_entry(self.signer), _entry(self.other)))

    def test_a_pin_selects_one_of_two(self) -> None:
        keys = parse_key_document(_document(_entry(self.signer), _entry(self.other)),
                                  key_id="lab-guardian-2", now=NOW)
        self.assertEqual(keys.keyring.key_ids, ("lab-guardian-2",))
        self.assertEqual(keys.fingerprint, self.other.verification_key().fingerprint)

    def test_a_single_live_key_needs_no_pin(self) -> None:
        keys = parse_key_document(_document(_entry(self.signer)), key_id=None, now=NOW)
        self.assertEqual(keys.key_id, KEY_ID)

    def test_a_fingerprint_that_does_not_match_is_refused(self) -> None:
        swapped = _entry(self.signer, fingerprint=self.other.verification_key().fingerprint)
        self._refused(_document(swapped), KEY_ID)

    def test_a_bad_public_key_is_refused(self) -> None:
        raw = self.signer.verification_key().public_key
        cases = {"surplus padding": base64.b64encode(raw).decode() + "==",
                 "1,951 bytes": base64.b64encode(raw[:-1]).decode(),
                 "not a string": list(raw[:4]),
                 "not base64": "!" * 2604}
        for name, value in cases.items():
            with self.subTest(name):
                self._refused(_document(_entry(self.signer, public_key=value)), KEY_ID)

    def test_an_algorithm_off_the_wire_is_refused(self) -> None:
        for algorithm in ("ECDSA-P256", "ML-DSA-65+ECDSA-P256", "HMAC-SHA256"):
            with self.subTest(algorithm=algorithm):
                self._refused(_document(_entry(self.signer, algorithm=algorithm)), KEY_ID)

    def test_the_format_must_be_acs_lab_keys_1(self) -> None:
        for value in ("acs-lab-keys/2", None, 1):
            with self.subTest(format=value):
                self._refused({**_document(_entry(self.signer)), "format": value}, KEY_ID)

    def test_a_duplicate_key_id_is_refused(self) -> None:
        self._refused(_document(_entry(self.signer), _entry(self.signer)), KEY_ID)

    def test_a_document_that_is_not_an_object_is_refused(self) -> None:
        for value in ([], "doc", None, {"format": "acs-lab-keys/1", "guardian_id": "g", "keys": {}}):
            with self.subTest(value=value):
                self._refused(value, KEY_ID)

    def test_a_key_outside_its_window_is_not_live(self) -> None:
        early = _entry(self.signer, not_before=NOW + datetime.timedelta(seconds=1))
        ended = _entry(self.signer, not_after=NOW)
        for name, entry in (("before not_before", early), ("at not_after", ended)):
            with self.subTest(name):
                self._refused(_document(entry), KEY_ID)
                self._refused(_document(entry))

    def test_a_timestamp_must_be_rfc_3339_utc(self) -> None:
        for value in ("2026-12-08T12:00:00", "2026-12-08T12:00:00+01:00", "yesterday", 0):
            with self.subTest(value=value):
                entry = _entry(self.signer)
                entry["not_before"] = value
                self._refused(_document(entry), KEY_ID)

    def test_a_revoked_key_is_not_live(self) -> None:
        past = [{"key_id": KEY_ID, "revoked_at": _stamp(NOW - datetime.timedelta(hours=1))}]
        self._refused(_document(_entry(self.signer), revoked=past), KEY_ID)
        future = [{"key_id": KEY_ID, "revoked_at": _stamp(NOW + datetime.timedelta(hours=1))}]
        keys = parse_key_document(_document(_entry(self.signer), revoked=future), key_id=KEY_ID, now=NOW)
        self.assertEqual(keys.key_id, KEY_ID)

    def test_a_malformed_revocation_is_refused(self) -> None:
        for revoked in ([KEY_ID], [{"key_id": KEY_ID}], [{"key_id": KEY_ID, "revoked_at": "soon"}]):
            with self.subTest(revoked=revoked):
                self._refused(_document(_entry(self.signer), revoked=revoked), KEY_ID)


class FromEnvironment(unittest.TestCase):
    def test_env_off(self) -> None:
        for env in ({}, {"ACS_RESPONSE_ALGORITHMS": ""}, {"ACS_RESPONSE_ALGORITHMS": "HMAC-SHA256"},
                    {"ACS_RESPONSE_ALGORITHMS": "  "}):
            with self.subTest(env=env):
                self.assertIsNone(response_keys_from_env(env))

    def test_env_on_needs_the_document(self) -> None:
        with self.assertRaisesRegex(ValueError, "ACS_GUARDIAN_KEYS"):
            response_keys_from_env({"ACS_RESPONSE_ALGORITHMS": "ML-DSA-65"})

    def test_env_refuses_other_lists(self) -> None:
        for value in ("ML-DSA-65,HMAC-SHA256", "hybrid", "ml-dsa-65", "ML-DSA-65+ECDSA-P256"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "ACS_RESPONSE_ALGORITHMS"):
                response_keys_from_env({"ACS_RESPONSE_ALGORITHMS": value})

    def test_env_reads_the_document_and_pin(self) -> None:
        signer = MLDSA65SigningKey.generate(KEY_ID)
        other = MLDSA65SigningKey.generate("lab-guardian-2")
        now = datetime.datetime.now(UTC)
        window = {"not_before": now - datetime.timedelta(days=1), "not_after": now + datetime.timedelta(days=1)}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "guardian-keys.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(_document(_entry(signer, **window), _entry(other, **window)), f)
            keys = response_keys_from_env({"ACS_RESPONSE_ALGORITHMS": "ML-DSA-65", "ACS_GUARDIAN_KEYS": path,
                                           "ACS_GUARDIAN_KEY_ID": KEY_ID})
            self.assertEqual(keys.key_id, KEY_ID)
            loaded = load_response_keys(path, key_id="lab-guardian-2")
            self.assertEqual(loaded.key_id, "lab-guardian-2")

    def test_an_unreadable_document_is_a_key_document_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "absent.json")
            with self.assertRaises(KeyDocumentError):
                load_response_keys(missing)
            broken = os.path.join(directory, "broken.json")
            with open(broken, "w", encoding="utf-8") as f:
                f.write("{")
            with self.assertRaises(KeyDocumentError):
                load_response_keys(broken)


if __name__ == "__main__":
    unittest.main()
