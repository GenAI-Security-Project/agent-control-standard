from __future__ import annotations

from typing import TYPE_CHECKING

from acs.client._secrets import load_hmac_secret, load_key_id, load_signing_material
from acs.core import container_key, derive_session_key, sign_with_key, verify_with_key

if TYPE_CHECKING:
    from acs.core import Keyring


def sign_envelope(envelope: dict, *, key: bytes | None = None,
                  session_id: str | None = None, key_id: str | None = None) -> dict:
    """Add a signature under key_id, the configured ACS_HMAC_KEY_ID unless given; raises SigningMaterialMissing without a usable secret and label."""
    if key is None:
        ikm, _ = load_signing_material()
        params = envelope.get("params") or envelope.get("result") or {}
        session_id = session_id or (params.get("metadata") or {}).get("session_id")
        if not session_id:
            raise ValueError("the envelope has no session_id, which the session key derives from (§10)")
        key = derive_session_key(ikm, session_id)
    label = key_id if key_id is not None else load_key_id()
    if not label:
        raise ValueError("ACS_HMAC_KEY_ID is not set; it names the configured secret (§10)")
    return sign_with_key(envelope, key, key_id=label)


def verify_signature(envelope: dict, *, key: bytes | None = None,
                     session_id: str | None = None, key_id: str | None = None,
                     keyring: Keyring | None = None, expected_key_id: str | None = None,
                     request: dict | None = None) -> bool:
    """Whether the envelope carries a valid signature under key_id (default ACS_HMAC_KEY_ID); an unsigned envelope is not valid.

    With a keyring, the signature must name expected_key_id, the key this caller trusts to
    answer, and the response must answer request, the envelope this caller sent (D-029).
    That key's algorithm decides (RFC 8725 section 3.1). Core verify_with_keyring enforces
    both. The ACS_HMAC_* settings play no part. Keyring verification needs the pqc extra
    (issue #574).
    """
    if keyring is None:
        if expected_key_id is not None or request is not None:
            raise ValueError("expected_key_id and request apply only to keyring verification")
    else:
        if key is not None or session_id is not None or key_id is not None:
            raise ValueError("keyring verification takes no HMAC key, session_id or key_id")
        # The lazy public export loads cryptography only here, never on the HMAC path, and
        # raises AttributeError naming the pqc extra when it is missing. Core checks the key_id
        # pin and the request binding.
        import acs.core
        return acs.core.verify_with_keyring(envelope, keyring, expected_key_id=expected_key_id,
                                            request=request)
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
            return False
        session_id = session_id or (container.get("metadata") or {}).get("session_id")
        if not session_id:
            return False
        key = derive_session_key(ikm, session_id)
    return verify_with_key(envelope, key)
