"""The viewer's verify mark: acs-verify's verdict on every line the viewer has read from each session (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.12).

acs.testing.verify.verify_transcript runs over every line of a session file the viewer has read, with the key
document, keys only, each time the file grows or the key document changes. Everything it checks is its own: each
ML-DSA-65 signature under the key its key_id names, the JSON-RPC and request_id binding, the signed request hash,
the key's validity at the request's own time, a ServerHello's negotiation rules, a request_id seen twice, a request
from another session, a cause on a signed answer, and a discards line that doesn't follow its answer. The audit chain
is left to lab verify, which runs acs-verify with the chain over the finished transcript.

A session is judged only when its first signed answer names ML-DSA-65. The viewer holds no HMAC secret, and anyone
holding that secret can write an HMAC answer, the agent side included (specification section 8.6), so an HMAC
session reads not checked. Once a session's first signed answer is ML-DSA-65, acs-verify checks every answer in it
under the key document, so a later HMAC or unsigned answer fails.

Lab conventions: the key document format acs-lab-keys/1 (issue #460), the request hash x_acs_lab_request_sha256
(issue #13), and ML-DSA-65 response signing (issue #316).
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
from collections.abc import Mapping, Sequence
from typing import Any

VERIFY_MARKS = ("verified", "warning", "failed", "not_checked", "unsigned", "no_answer")
# The gateway's settings for the same key document, read the same way, so the viewer trusts exactly the key the
# gateway pins (acs.client KEY_DOCUMENT_ENV, KEY_ID_ENV, KEY_FINGERPRINT_ENV).
KEY_DOCUMENT_ENV = "ACS_GUARDIAN_KEYS"
KEY_ID_ENV = "ACS_GUARDIAN_KEY_ID"
KEY_FINGERPRINT_ENV = "ACS_GUARDIAN_KEY_FINGERPRINT"


@dataclasses.dataclass(frozen=True)
class Keys:
    """The key document and the pin the gateway's settings put on it."""

    document: Mapping[str, Any]
    key_id: str | None
    fingerprints: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class SessionVerdict:
    """acs-verify's verdict on one session: ok, or the first line it failed at, with its code and reason."""

    ok: bool
    failure_line: int | None = None
    failure_code: str | None = None
    failure_reason: str | None = None
    warnings: tuple[str, ...] = ()


class KeyDocumentUnavailable(Exception):
    """The settings name a key document that can't be read or used. The viewer pauses until it can (R6)."""


# The cap acs.client puts on a key document. The bytes are read and hashed on every poll, so they stay small.
MAX_KEY_DOCUMENT_BYTES = 1 << 20


def _read_document_bytes(path: str) -> bytes:
    """The key document's bytes, read once through acs.client's one reader for trusted files, with the rule
    acs-verify applies to a key document. It opens with O_NOFOLLOW and O_NONBLOCK, so neither a symlink nor a FIFO
    can redirect or hang it, refuses anything but a regular file and any group or other write, and reads at most
    MAX_KEY_DOCUMENT_BYTES (final review R9). Every refusal raises KeyDocumentUnavailable."""
    from acs.client import not_writable_by_others, read_trusted_file
    try:
        return read_trusted_file(path, setting=KEY_DOCUMENT_ENV, max_bytes=MAX_KEY_DOCUMENT_BYTES,
                                 mode_rule=not_writable_by_others, refused=KeyDocumentUnavailable,
                                 require_owner=False)
    except KeyDocumentUnavailable:
        raise
    except (OSError, RuntimeError) as e:
        raise KeyDocumentUnavailable(f"the key document can't be read: {e}") from e


def _keys_from_bytes(data: bytes, env: Mapping[str, str]) -> Keys:
    """The keys in these exact bytes, checked by acs-verify. Raises KeyDocumentUnavailable when they can't be used."""
    from acs.testing import verify as acs_verify
    key_id = env.get(KEY_ID_ENV, "").strip() or None
    fingerprint = env.get(KEY_FINGERPRINT_ENV, "").strip()
    try:
        # acs-verify's own strict JSON reader: a repeated key or a NaN is refused, as it refuses them on the file.
        document = acs_verify._strict_loads(data.decode("utf-8"))
        if not isinstance(document, Mapping):
            raise ValueError("the key document is not a JSON object")
        # An empty transcript runs every check on the document itself and stops before any line, so a document
        # acs-verify can't use is refused here once instead of failing every row later.
        acs_verify.verify_transcript([], key_document=document, hmac_secret=None, key_id=key_id, keys_only=True)
    except (acs_verify.UsageError, ImportError, UnicodeDecodeError, ValueError, RecursionError) as e:
        raise KeyDocumentUnavailable(f"the key document can't be used: {e}") from e
    return Keys(document=document, key_id=key_id, fingerprints=(fingerprint,) if fingerprint else ())


def load_keys(env: Mapping[str, str]) -> Keys | None:
    """The key document ACS_GUARDIAN_KEYS names, or None when it is unset or can't be used. One read, one parse."""
    path = env.get(KEY_DOCUMENT_ENV, "").strip()
    if not path:
        return None
    try:
        return _keys_from_bytes(_read_document_bytes(path), env)
    except KeyDocumentUnavailable:
        return None


class KeySource:
    """The key document the settings name, read again whenever its bytes change (fix round 1, I4).

    generation grows on every change, so the model knows to judge every session again under the new document.
    Each poll reads the document once, without blocking, and the same bytes give both the hash and the keys, so the
    keys in use always come from the bytes hashed (final review R9). A document that can't be read or used raises
    KeyDocumentUnavailable on every poll until it can, and no poll ever falls back to an older document (R6).
    """

    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = {name: env.get(name, "") for name in (KEY_DOCUMENT_ENV, KEY_ID_ENV, KEY_FINGERPRINT_ENV)}
        self._path = self._env[KEY_DOCUMENT_ENV].strip()
        self._digest: bytes | None = None
        self._keys: Keys | None = None
        self.generation = 0

    @property
    def configured(self) -> bool:
        return bool(self._path)

    def current(self) -> Keys | None:
        """The loaded document, or None when the settings name none. Raises while the named one can't be used."""
        if not self._path:
            return None
        data = _read_document_bytes(self._path)
        digest = hashlib.sha256(data).digest()
        if digest != self._digest:
            # Nothing is stored until these bytes parse, so a failed load is tried again on the next poll.
            self._keys, self._digest = _keys_from_bytes(data, self._env), digest
            self.generation += 1
        return self._keys


def verify_session(lines: Sequence[bytes], keys: Keys) -> SessionVerdict:
    """acs-verify over a session's lines, keys only. Any error inside it is a failure, never a pass."""
    from acs.testing.verify import verify_transcript
    try:
        report = verify_transcript(list(lines), key_document=keys.document, hmac_secret=None,
                                   expect_fingerprints=keys.fingerprints, key_id=keys.key_id, keys_only=True)
    except Exception as e:  # noqa: BLE001
        return SessionVerdict(ok=False, failure_code="verifier_error", failure_reason=type(e).__name__)
    if report.ok:
        return SessionVerdict(ok=True, warnings=tuple(report.warnings))
    failure = report.failure
    return SessionVerdict(ok=False, failure_line=failure.line or None if failure else None,
                          failure_code=failure.code if failure else "unknown",
                          failure_reason=failure.reason if failure else "")
