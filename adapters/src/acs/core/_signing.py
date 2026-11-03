from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

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


def sign_with_key(envelope: dict, key: bytes, *, key_id: str) -> dict:
    """Sign in place with HMAC-SHA256 over JCS(envelope without its signature), labelled key_id (§10)."""
    ckey = container_key(envelope)
    container = envelope.get(ckey, {})
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, ckey: unsigned_container}

    sig_bytes = hmac.new(key, jcs_canonicalize(unsigned_envelope), hashlib.sha256).digest()
    container["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": base64.b64encode(sig_bytes).decode("ascii"),
        "key_id": key_id,
    }
    envelope[ckey] = container
    return envelope


def verify_with_key(envelope: dict, key: bytes) -> bool:
    ckey = container_key(envelope)
    container = envelope.get(ckey) or {}
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if not isinstance(sig, dict) or sig.get("algorithm") != "HMAC-SHA256":
        return False
    expected_b64 = sig.get("value")
    if not expected_b64:
        return False
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, ckey: unsigned_container}
    try:
        canonical = jcs_canonicalize(unsigned_envelope)
    except Exception:  # noqa: BLE001
        # RFC 8785 has no form for this envelope (an integer beyond 2**53, NaN, deep nesting), so no signature covers it.
        return False
    expected_bytes = hmac.new(key, canonical, hashlib.sha256).digest()
    # Malformed base64 is a failed verification, not an exception.
    try:
        provided_bytes = base64.b64decode(expected_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    return hmac.compare_digest(expected_bytes, provided_bytes)
