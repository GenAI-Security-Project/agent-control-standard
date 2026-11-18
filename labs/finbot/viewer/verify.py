"""The viewer's verify mark: whether each Guardian answer verifies, judged by acs-verify itself (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.12).

Each answer goes through acs.testing.verify.verify_transcript as a two-line transcript, its request and its answer,
with --keys-only. That is acs-verify's whole per-answer verdict, not a copy of it: the ML-DSA-65 signature under the
key its key_id names, the JSON-RPC and request_id binding, the signed request hash, the key's validity at the
request's own timestamp, and a ServerHello's negotiation rules. The audit chain spans a whole session, so the viewer
leaves it to acs-verify run over the transcript (lab verify).

Only ML-DSA-65 can read verified here. The viewer holds no HMAC secret, and anyone holding that secret can write an
HMAC answer, the agent side included (specification section 8.6), so an HMAC answer reads not_checked. In a session
whose ServerHello verified under ML-DSA-65 an HMAC answer is a downgrade and reads failed.

Lab conventions: the key document format acs-lab-keys/1 (issue #460), the request hash x_acs_lab_request_sha256
(issue #13), and ML-DSA-65 response signing (issue #316).
"""
from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Mapping
from typing import Any

from model import ML_DSA_65, signature_algorithm

VERIFY_MARKS = ("verified", "failed", "not_checked", "unsigned", "no_answer")
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


def load_keys(env: Mapping[str, str]) -> Keys | None:
    """The key document ACS_GUARDIAN_KEYS names, or None when it is unset or can't be used.

    None makes every ML-DSA-65 answer read not_checked, never verified. The document goes through acs-verify's own
    reader, with the rule acs.client applies to it: no symlink, no FIFO, no group or other write.
    """
    path = env.get(KEY_DOCUMENT_ENV, "").strip()
    if not path:
        return None
    from acs.testing import verify as acs_verify
    keys = Keys(document={}, key_id=env.get(KEY_ID_ENV, "").strip() or None,
                fingerprints=tuple(f for f in [env.get(KEY_FINGERPRINT_ENV, "").strip()] if f))
    try:
        document = acs_verify._read_key_document(path)
        keys = dataclasses.replace(keys, document=document)
        # An empty transcript runs every check on the document itself and stops before any line. A document
        # acs-verify can't use raises UsageError here, once, instead of failing every row later.
        acs_verify.verify_transcript([], key_document=document, hmac_secret=None, key_id=keys.key_id,
                                     keys_only=True)
    except (acs_verify.UsageError, ImportError, OSError, ValueError):
        return None
    return keys


def _line(direction: str, envelope: Mapping[str, Any]) -> str:
    return json.dumps({"dir": direction, "envelope": envelope}, separators=(",", ":"), ensure_ascii=True)


def verify_mark(request: Mapping[str, Any], response: Mapping[str, Any] | None, keys: Keys | None, *,
                mldsa_session: bool = False) -> tuple[str, str | None]:
    """(mark, algorithm) for one answer. Any error inside the check reads failed, never verified."""
    if response is None:
        return "no_answer", None
    algorithm = signature_algorithm(response)
    if algorithm is None:
        return "unsigned", None
    if algorithm != ML_DSA_65:
        return ("failed" if mldsa_session else "not_checked"), algorithm
    if keys is None:
        return "not_checked", algorithm
    from acs.testing.verify import verify_transcript
    try:
        report = verify_transcript([_line("req", request), _line("resp", response)], key_document=keys.document,
                                   hmac_secret=None, expect_fingerprints=keys.fingerprints, key_id=keys.key_id,
                                   keys_only=True)
    except Exception:  # noqa: BLE001
        return "failed", algorithm
    return ("verified" if report.ok else "failed"), algorithm


def make_verifier(keys: Keys | None) -> Callable[[Mapping[str, Any], Mapping[str, Any] | None, bool],
                                                 tuple[str, str | None]]:
    """The callable Model takes: verify_mark with these keys."""
    def verifier(request: Mapping[str, Any], response: Mapping[str, Any] | None,
                 mldsa_session: bool) -> tuple[str, str | None]:
        return verify_mark(request, response, keys, mldsa_session=mldsa_session)
    return verifier
