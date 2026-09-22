"""ACS §10 baseline cryptography: HKDF-SHA256 session keys, HMAC-SHA256 signatures.

ACS v0.1.0 requires the result but leaves part of the algorithm undefined
(§10 says "HKDF-derived" without fixing the hash, salt, ``info`` input, or
output length). Two implementations must make the same choice to
interoperate, so this module makes the same choices the Go reference
implementation documents in its "Behavior that ACS v0.1.0 leaves undefined"
table (open PR #169, not merged at the time of writing): HKDF-SHA256, no
salt, the UTF-8 bytes of ``session_id`` as the ``info`` input, and a 32-byte
key. ``tests/test_crypto_vectors.py`` pins the agreement against that
implementation's vectors.

Everything here is stdlib: HKDF over HMAC is a few lines, and pulling a crypto
dependency for it would widen the supply chain for no correctness gain.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

ALGORITHM = "HMAC-SHA256"
SESSION_KEY_BYTES = 32


def derive_session_key(ikm: bytes, session_id: str) -> bytes:
    """HKDF-SHA256(ikm, salt=HashLen zeros, info=session_id, L=32).

    An absent salt is a HashLen string of zeros per RFC 5869 §2.2; the
    ``cryptography``-style "no salt" reading is the same bytes, which is why
    this matches both the Node harness's empty-buffer call and the Go
    implementation's vectors.
    """
    salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # T(1) is the whole OKM when L <= HashLen (32 bytes here).
    return hmac.new(prk, session_id.encode("utf-8") + b"\x01", hashlib.sha256).digest()[:SESSION_KEY_BYTES]


def sign(key: bytes, signing_input: bytes) -> str:
    """Base64 HMAC-SHA256 over the §10 canonical input."""
    return base64.b64encode(hmac.new(key, signing_input, hashlib.sha256).digest()).decode("ascii")


def verify(key: bytes, signing_input: bytes, signature_b64: object) -> bool:
    """Constant-time verification. A malformed signature is a failed one, never a raise."""
    if not isinstance(signature_b64, str):
        return False
    try:
        received = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(received, expected)
