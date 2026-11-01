from __future__ import annotations

from acs.client._secrets import load_hmac_secret, load_key_id, load_signing_material
from acs.core import container_key, derive_session_key, sign_with_key, verify_with_key


def sign_envelope(envelope: dict, *, key: bytes | None = None,
                  session_id: str | None = None, key_id: str | None = None) -> dict:
    """Add a signature under key_id, the configured ACS_HMAC_KEY_ID unless given; raises SigningMaterialMissing without a usable secret and label."""
    if key is None:
        ikm, _ = load_signing_material()
        if not session_id:
            params = envelope.get("params") or envelope.get("result") or {}
            meta = params.get("metadata") or {}
            session_id = meta.get("session_id") or params.get("request_id") or ""
        key = derive_session_key(ikm, session_id)
    label = key_id if key_id is not None else load_key_id()
    if not label:
        raise ValueError("ACS_HMAC_KEY_ID is not set; it names the configured secret (§10)")
    return sign_with_key(envelope, key, key_id=label)


def verify_signature(envelope: dict, *, key: bytes | None = None,
                     session_id: str | None = None, key_id: str | None = None) -> bool:
    """Whether the envelope carries a valid signature under key_id (default ACS_HMAC_KEY_ID); an unsigned envelope is not valid."""
    container = envelope.get(container_key(envelope)) or {}
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if sig is None:
        return False

    if not isinstance(sig, dict) or sig.get("algorithm") != "HMAC-SHA256":
        return False
    if not sig.get("value"):
        return False
    # §10: an unknown key_id is rejected, with no fallback to another secret.
    label = key_id if key_id is not None else load_key_id()
    if not label or sig.get("key_id") != label:
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
