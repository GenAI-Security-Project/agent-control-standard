"""The HMAC-SHA256 baseline signature of §10: key derivation, signing and verification with a given key."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from acs.core._canonical import jcs_canonicalize


# ----- Signing (HMAC-SHA256 baseline per §10) -----

def derive_session_key(input_key_material: bytes, session_id: str) -> bytes:
    """HKDF-SHA256 with session_id as `info`, no salt.

    Spec §10: 'per-session HMAC key is HKDF-derived from deployment-provided
    input keying material (a pre-shared secret, or a transport channel
    binding such as a TLS exporter) together with the session_id.'
    """
    # HKDF-Extract with empty salt
    prk = hmac.new(b"\x00" * 32, input_key_material, hashlib.sha256).digest()
    # HKDF-Expand to 32 bytes with info = session_id
    info = session_id.encode("utf-8")
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t  # one 32-byte block is enough for HMAC-SHA256


def container_key(envelope: dict) -> str:
    """Where the signature lives: params for requests, result for
    decision responses, error for error responses (every response is
    signed under ACS-Core — including errors, since a spoofable
    unsigned error under a fail-open posture is an allow)."""
    if "method" in envelope:
        return "params"
    if "error" in envelope:
        return "error"
    return "result"


def sign_with_key(envelope: dict, key: bytes, *, key_id: str = "default") -> dict:
    """Add an HMAC-SHA256 signature made with `key` over JCS(envelope without its signature), in place."""
    ckey = container_key(envelope)
    container = envelope.get(ckey, {})
    # Strip any existing signature before signing
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
    """True when the envelope carries an HMAC-SHA256 signature that `key` reproduces."""
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
