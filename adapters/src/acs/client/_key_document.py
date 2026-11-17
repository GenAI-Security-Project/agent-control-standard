"""A Guardian's key document, parsed into a keyring that holds the one key this client trusts.

Lab convention until issue #460 settles how an asymmetric key_id is published, bound to an
identity, and revoked. The format is acs-lab-keys/1:

    {"format": "acs-lab-keys/1", "guardian_id": "...",
     "keys": [{"key_id", "algorithm", "public_key", "fingerprint", "not_before", "not_after"}],
     "revoked": [{"key_id", "revoked_at"}]}

The response key comes from the key document by key_id (issue #308, RFC 8725 section 3.1). The
envelope's algorithm never selects it, and D-026 applies per key_id: an exact match, no fallback.
A document with two live keys and no pin is refused, never resolved by order.

Only ML-DSA-65 is accepted, and cryptography loads only when a document is parsed, so importing
this module and reading a configuration that leaves response signing off need no pqc extra.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

KEY_DOCUMENT_FORMAT = "acs-lab-keys/1"
RESPONSE_ALGORITHMS_ENV = "ACS_RESPONSE_ALGORITHMS"
KEY_DOCUMENT_ENV = "ACS_GUARDIAN_KEYS"
KEY_ID_ENV = "ACS_GUARDIAN_KEY_ID"
ML_DSA_65 = "ML-DSA-65"
# Unset, blank, and the HMAC name all mean today's path: responses verified under the HMAC secret.
_OFF_VALUES = frozenset({"", "HMAC-SHA256"})


class KeyDocumentError(ValueError):
    """The key document is malformed, or holds no single live key this client may trust."""


@dataclass(frozen=True)
class ResponseKeys:
    """The pinned key a client verifies every Guardian response with, and the document it came from."""

    keyring: Any  # acs.core.Keyring, holding only the pinned key
    key_id: str
    algorithm: str
    fingerprint: str
    guardian_id: str
    document: Mapping[str, Any] = field(repr=False)
    # The pinned key's validity, checked again at every signature and every verification, so a key that expires
    # or is revoked while a process runs stops working then, not at the next restart (review R-I1).
    not_before: datetime.datetime = field(default=datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
    not_after: datetime.datetime = field(default=datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
    revoked_at: datetime.datetime | None = None

    def is_live(self, now: datetime.datetime) -> bool:
        """Whether the key may sign or verify at now: not_before <= now < not_after, and not revoked by now."""
        return self.not_before <= now < self.not_after and (self.revoked_at is None or now < self.revoked_at)


def _timestamp(value: object, where: str) -> datetime.datetime:
    # RFC 3339 in UTC with a Z suffix, the form the Guardian writes, so no local offset is guessed.
    if not isinstance(value, str) or not value.endswith("Z"):
        raise KeyDocumentError(f"{where} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        moment = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise KeyDocumentError(f"{where} must be an RFC 3339 UTC timestamp ending in Z") from exc
    return moment


def _public_key(value: object, where: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise KeyDocumentError(f"{where} must be standard base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyDocumentError(f"{where} must be standard base64") from exc
    # One spelling per key, so a document can't carry the same key under two encodings.
    if base64.b64encode(raw).decode("ascii") != value:
        raise KeyDocumentError(f"{where} is not canonical base64")
    return raw


def _revocations(document: Mapping[str, Any]) -> dict[str, datetime.datetime]:
    revoked = document.get("revoked", [])
    if not isinstance(revoked, list):
        raise KeyDocumentError("revoked must be a list")
    times: dict[str, datetime.datetime] = {}
    for i, entry in enumerate(revoked):
        where = f"revoked[{i}]"
        if not isinstance(entry, Mapping) or not isinstance(entry.get("key_id"), str) or not entry["key_id"]:
            raise KeyDocumentError(f"{where} must be an object with a key_id and a revoked_at")
        moment = _timestamp(entry.get("revoked_at"), f"{where}.revoked_at")
        # The earliest revocation of a key_id is the one that counts.
        times[entry["key_id"]] = min(moment, times.get(entry["key_id"], moment))
    return times


def parse_key_document(document: object, *, key_id: str | None, now: datetime.datetime) -> ResponseKeys:
    """The one key a client trusts from this document: the pinned key_id, or the only live key when unpinned.

    A key is live when not_before <= now < not_after and no revocation at or before now names it.
    Every entry is checked, live or not, so a broken entry can't hide behind a valid one.
    """
    from acs.core import Keyring, VerificationKey

    if not isinstance(document, Mapping):
        raise KeyDocumentError("the key document must be a JSON object")
    if document.get("format") != KEY_DOCUMENT_FORMAT:
        raise KeyDocumentError(f"format must be {KEY_DOCUMENT_FORMAT!r}")
    guardian_id = document.get("guardian_id")
    if not isinstance(guardian_id, str) or not guardian_id:
        raise KeyDocumentError("guardian_id must be a non-empty string")
    entries = document.get("keys")
    if not isinstance(entries, list) or not entries:
        raise KeyDocumentError("keys must be a non-empty list")
    if key_id is not None and (not isinstance(key_id, str) or not key_id):
        raise KeyDocumentError("the key_id pin must be a non-empty string")
    revoked = _revocations(document)

    live: dict[str, tuple[VerificationKey, datetime.datetime, datetime.datetime, datetime.datetime | None]] = {}
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        where = f"keys[{i}]"
        if not isinstance(entry, Mapping):
            raise KeyDocumentError(f"{where} must be an object")
        entry_id = entry.get("key_id")
        if not isinstance(entry_id, str) or not entry_id:
            raise KeyDocumentError(f"{where}.key_id must be a non-empty string")
        if entry_id in seen:
            raise KeyDocumentError(f"key_id {entry_id!r} appears more than once")
        seen.add(entry_id)
        if entry.get("algorithm") != ML_DSA_65:
            raise KeyDocumentError(f"{where}.algorithm must be {ML_DSA_65!r}")
        raw = _public_key(entry.get("public_key"), f"{where}.public_key")
        try:
            key = VerificationKey(entry_id, ML_DSA_65, raw)
        except ValueError as exc:
            raise KeyDocumentError(f"{where}.public_key: {exc}") from exc
        # The fingerprint is what an operator compares out of band, so it must name this exact key.
        if entry.get("fingerprint") != key.fingerprint:
            raise KeyDocumentError(f"{where}.fingerprint does not match its public_key")
        not_before = _timestamp(entry.get("not_before"), f"{where}.not_before")
        not_after = _timestamp(entry.get("not_after"), f"{where}.not_after")
        revoked_at = revoked.get(entry_id)
        if not_before <= now < not_after and (revoked_at is None or now < revoked_at):
            live[entry_id] = (key, not_before, not_after, revoked_at)

    if key_id is None:
        if len(live) != 1:
            raise KeyDocumentError(f"the key document holds {len(live)} live keys, so {KEY_ID_ENV} must name one")
        chosen = next(iter(live.values()))
    else:
        # D-026: the pin matches exactly, with no case folding, trimming, or fallback.
        chosen = live.get(key_id)
        if chosen is None:
            raise KeyDocumentError(f"key_id {key_id!r} is not a live key in the key document")
    key, not_before, not_after, revoked_at = chosen
    return ResponseKeys(keyring=Keyring([key]), key_id=key.key_id, algorithm=key.algorithm,
                        fingerprint=key.fingerprint, guardian_id=guardian_id, document=document,
                        not_before=not_before, not_after=not_after, revoked_at=revoked_at)


def load_response_keys(path: str | os.PathLike, *, key_id: str | None = None,
                       now: datetime.datetime | None = None) -> ResponseKeys:
    """Read the key document at path and pin one key, as parse_key_document does."""
    try:
        with open(path, encoding="utf-8") as f:
            document = json.load(f)
    except (OSError, ValueError, RecursionError) as exc:
        raise KeyDocumentError(f"{KEY_DOCUMENT_ENV} {os.fspath(path)!r} can't be read as JSON: {exc}") from exc
    moment = now if now is not None else datetime.datetime.now(datetime.timezone.utc)
    return parse_key_document(document, key_id=key_id, now=moment)


def response_keys_from_env(env: Mapping[str, str]) -> ResponseKeys | None:
    """The pinned response key the environment asks for, or None when response signing is off.

    ACS_RESPONSE_ALGORITHMS takes exactly one value until issue #316 settles verifier rules,
    because accepting HMAC beside ML-DSA-65 lets anyone holding the HMAC secret forge a decision.
    Config.from_env never reads these settings, so the three adapters are unchanged.
    """
    name = env.get(RESPONSE_ALGORITHMS_ENV, "").strip()
    if name in _OFF_VALUES:
        return None
    if name != ML_DSA_65:
        raise ValueError(f"{RESPONSE_ALGORITHMS_ENV} must be unset, HMAC-SHA256, or {ML_DSA_65}, got {name!r}. "
                         "It takes exactly one value (lab convention, issue #316)")
    path = env.get(KEY_DOCUMENT_ENV, "").strip()
    if not path:
        raise ValueError(f"{RESPONSE_ALGORITHMS_ENV}={ML_DSA_65} needs {KEY_DOCUMENT_ENV}, the Guardian's key document")
    pin = env.get(KEY_ID_ENV, "").strip() or None
    return load_response_keys(path, key_id=pin)
