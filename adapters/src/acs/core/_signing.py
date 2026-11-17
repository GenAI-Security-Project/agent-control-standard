from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import Any

from acs.core._canonical import jcs_canonicalize


def derive_session_key(input_key_material: bytes, session_id: str) -> bytes:
    """HKDF-SHA256 with session_id as info and no salt (§10)."""
    # HKDF-Extract with empty salt
    prk = hmac.new(b"\x00" * 32, input_key_material, hashlib.sha256).digest()
    # HKDF-Expand to 32 bytes with info = session_id
    info = session_id.encode("utf-8")
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t  # one 32-byte block is enough for HMAC-SHA256


def container_key(envelope: dict) -> str:
    if "method" in envelope:
        return "params"
    if "error" in envelope:
        return "error"
    return "result"


def signing_input(envelope: dict) -> bytes:
    """The bytes every algorithm signs: JCS of the envelope without its signature (§10).

    Raises when RFC 8785 has no form for the envelope. A verifier treats that as a failed check.
    """
    ckey = container_key(envelope)
    container = envelope.get(ckey, {})
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    return jcs_canonicalize({**envelope, ckey: unsigned_container})


# Lab convention (issue #576): under one ML-DSA key for every session, a response names the request it answers by
# this hash, since specification section 10 gives a response no session_id. Issue #13 is the closest tracking
# issue. The HMAC path never reads it, because each session's key already separates sessions.
REQUEST_DIGEST_FIELD = "x_acs_lab_request_sha256"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def request_sha256(request: Mapping[str, Any]) -> str:
    """Lowercase hex SHA-256 of the request's section 10 signed input, which covers its session, ids, time and content.

    Raises when RFC 8785 has no form for the request, as signing_input does.
    """
    return hashlib.sha256(signing_input(request)).hexdigest()


def response_names_request(response: Mapping[str, Any], request: Mapping[str, Any]) -> bool:
    """Whether the response carries request_sha256(request): in result for a result, in error.data for an error."""
    if "result" in response:
        holder = response.get("result")
    else:
        error = response.get("error")
        holder = error.get("data") if isinstance(error, Mapping) else None
    claimed = holder.get(REQUEST_DIGEST_FIELD) if isinstance(holder, Mapping) else None
    # Only the one spelling request_sha256 gives. compare_digest raises on non-ASCII text, so the shape is checked
    # first and anything else simply fails.
    if not isinstance(claimed, str) or not _SHA256_HEX.fullmatch(claimed):
        return False
    try:
        expected = request_sha256(request)
    except Exception:  # noqa: BLE001
        # No canonical form, so no hash can name it.
        return False
    return hmac.compare_digest(claimed, expected)


def decode_signature_value(value: object) -> bytes | None:
    """The bytes a signature value encodes, or None unless it is the one canonical spelling.

    b64decode also accepts surplus padding and set unused trailing bits, so one signature
    would have several spellings. Compliant signers always emit the canonical form, so
    refusing the others costs a conformant peer nothing and keeps signed bytes unique.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _attach_signature(envelope: dict, *, algorithm: str, signature: bytes, key_id: str) -> dict:
    """Set the container's signature object in place, replacing any earlier one (§10)."""
    ckey = container_key(envelope)
    container = envelope.get(ckey, {})
    container["signature"] = {
        "algorithm": algorithm,
        "value": base64.b64encode(signature).decode("ascii"),
        "key_id": key_id,
    }
    envelope[ckey] = container
    return envelope


def sign_with_key(envelope: dict, key: bytes, *, key_id: str) -> dict:
    """Sign in place with HMAC-SHA256 over JCS(envelope without its signature), labelled key_id (§10)."""
    sig_bytes = hmac.new(key, signing_input(envelope), hashlib.sha256).digest()
    return _attach_signature(envelope, algorithm="HMAC-SHA256", signature=sig_bytes, key_id=key_id)


def verify_with_key(envelope: dict, key: bytes) -> bool:
    ckey = container_key(envelope)
    container = envelope.get(ckey) or {}
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if not isinstance(sig, dict) or sig.get("algorithm") != "HMAC-SHA256":
        return False
    provided_bytes = decode_signature_value(sig.get("value"))
    if provided_bytes is None:
        return False
    try:
        canonical = signing_input(envelope)
    except Exception:  # noqa: BLE001
        # RFC 8785 has no form for this envelope (an integer beyond 2**53, NaN, deep nesting), so no signature covers it.
        return False
    expected_bytes = hmac.new(key, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(expected_bytes, provided_bytes)
