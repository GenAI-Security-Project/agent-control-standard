"""Signing and verifying with the configured secret, and the one-time unsigned-mode warning."""
from __future__ import annotations

from acs.client._audit import audit_event
from acs.client._secrets import load_hmac_secret
from acs.core import container_key, derive_session_key, sign_with_key, verify_with_key


_warned_unsigned_mode = False


def _warn_unsigned_once() -> None:
    """One loud warning per process when operating without key material.

    Unsigned mode is an authentication failure, not just a
    confidentiality one: any local process that binds the Guardian port
    first becomes the Guardian and allows everything.
    Fine for a first local experiment; never fine silently."""
    global _warned_unsigned_mode
    if not _warned_unsigned_mode:
        _warned_unsigned_mode = True
        audit_event(
            "unsigned_mode",
            detail=(
                "no ACS_HMAC_SECRET / ACS_HMAC_SECRET_FILE configured — "
                "envelopes are UNSIGNED and any local process that binds "
                "the Guardian address is trusted"
            ),
        )


def sign_envelope(envelope: dict, *, key: bytes | None = None,
                  session_id: str | None = None, key_id: str = "default") -> dict:
    """Add a signature to the envelope. Returns the envelope unchanged
    (after a loud one-time audit event) if no key material is available."""
    if key is None:
        ikm = load_hmac_secret()
        if not ikm:
            _warn_unsigned_once()
            return envelope
        if not session_id:
            params = envelope.get("params") or envelope.get("result") or {}
            meta = params.get("metadata") or {}
            session_id = meta.get("session_id") or params.get("request_id") or ""
        key = derive_session_key(ikm, session_id)
    return sign_with_key(envelope, key, key_id=key_id)


def verify_signature(envelope: dict, *, key: bytes | None = None,
                     session_id: str | None = None) -> bool:
    """Verify a signed envelope (request, decision response, or error
    response). Returns True if valid (or if no signature present and no
    key material configured — local-dev mode)."""
    container = envelope.get(container_key(envelope)) or {}
    sig = container.get("signature")
    if sig is None:
        # No signature on the wire; valid only if local-dev (no key configured)
        return not bool(load_hmac_secret())

    if sig.get("algorithm") != "HMAC-SHA256":
        return False
    if not sig.get("value"):
        return False

    if key is None:
        ikm = load_hmac_secret()
        if not ikm:
            # Signature present but no key configured: cannot verify
            return False
        meta = container.get("metadata") or {}
        session_id = session_id or meta.get("session_id") or container.get("request_id") or ""
        key = derive_session_key(ikm, session_id)
    return verify_with_key(envelope, key)
