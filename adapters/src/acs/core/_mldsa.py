"""ML-DSA-65 (FIPS 204) envelope signing, and verification through a keyring (issue #574).

Variant: pure ML-DSA, not the pre-hash HashML-DSA. Context string: empty (b"").
The signature registry fixes neither (issue #566), so this library states both, and
adapters/docs/signing.md repeats them. A verifier on another stack must use the same pair,
since a context mismatch fails verification with no other sign.

The signed bytes are the ones HMAC-SHA256 signs: JCS of the envelope without its signature.
Signing is randomized (the FIPS 204 hedged variant that cryptography 50 uses), so two signatures
of one envelope differ and both verify.

Nothing on the default path imports this module. It needs the pqc extra (cryptography 50),
and it fails at import, not at the first signature, when ML-DSA is unavailable.
"""
from __future__ import annotations

import base64
import binascii

try:
    import cryptography
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError as exc:
    raise ImportError(
        "ML-DSA-65 signing needs the pqc extra, which installs cryptography 50: "
        "pip install 'acs-adapters[pqc]' or uv sync --extra pqc. The pqc and nat extras "
        "can't be installed together (see adapters/README.md).") from exc

from acs.core._keyring import ML_DSA_65, Keyring, VerificationKey, check_key_id
from acs.core._signing import _attach_signature, container_key, signing_input

ML_DSA_MODE = "pure"
ML_DSA_CONTEXT = b""
SEED_BYTES = 32


def _check_backend() -> None:
    # cryptography exposes the ML-DSA classes even when its OpenSSL lacks the algorithm, and then
    # raises UnsupportedAlgorithm on first use. Generating one throwaway key surfaces that here.
    try:
        mldsa.MLDSA65PrivateKey.generate()
    except UnsupportedAlgorithm as exc:
        from cryptography.hazmat.backends.openssl.backend import backend
        raise ImportError(
            f"the OpenSSL backend of cryptography {cryptography.__version__} "
            f"({backend.openssl_version_text()}) does not support ML-DSA-65. "
            "Install the cryptography 50 wheel, which bundles an OpenSSL with ML-DSA.") from exc


_check_backend()


class MLDSA65SigningKey:
    """An ML-DSA-65 private key and the opaque key_id its signatures carry (D-026)."""

    __slots__ = ("_key_id", "_private")

    def __init__(self, private: mldsa.MLDSA65PrivateKey, key_id: str) -> None:
        if not isinstance(private, mldsa.MLDSA65PrivateKey):
            raise ValueError("private must be an MLDSA65PrivateKey")
        self._key_id = check_key_id(key_id)
        self._private = private

    @classmethod
    def generate(cls, key_id: str) -> MLDSA65SigningKey:
        return cls(mldsa.MLDSA65PrivateKey.generate(), key_id)

    @classmethod
    def from_seed(cls, seed: bytes, key_id: str) -> MLDSA65SigningKey:
        """Rebuild the key from its 32 byte FIPS 204 seed, the form a key file stores."""
        if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
            raise ValueError(f"an ML-DSA-65 seed is {SEED_BYTES} bytes")
        return cls(mldsa.MLDSA65PrivateKey.from_seed_bytes(seed), key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return ML_DSA_65

    def seed(self) -> bytes:
        return self._private.private_bytes_raw()

    def verification_key(self) -> VerificationKey:
        return VerificationKey(self._key_id, ML_DSA_65, self._private.public_key().public_bytes_raw())

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message, ML_DSA_CONTEXT)

    def __repr__(self) -> str:
        # The seed is the whole private key, so it never reaches a log line through repr.
        return f"MLDSA65SigningKey(key_id={self._key_id!r})"


def sign_with_signing_key(envelope: dict, signing_key: MLDSA65SigningKey) -> dict:
    """Sign in place over JCS(envelope without its signature), replacing any earlier signature."""
    if not isinstance(signing_key, MLDSA65SigningKey):
        raise ValueError("signing_key must be an MLDSA65SigningKey")
    signature = signing_key.sign(signing_input(envelope))
    return _attach_signature(envelope, algorithm=signing_key.algorithm, signature=signature,
                             key_id=signing_key.key_id)


def _verify_ml_dsa_65(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message, ML_DSA_CONTEXT)
    except (InvalidSignature, ValueError):
        return False
    return True


_VERIFIERS = {ML_DSA_65: _verify_ml_dsa_65}


def verify_with_keyring(envelope: dict, keyring: Keyring) -> bool:
    """Whether the envelope's signature verifies under the key its key_id names.

    The algorithm comes from the resolved key, never from the envelope (RFC 8725 section 3.1,
    issue #308). An unknown key_id, an envelope algorithm that disagrees with the key's, an
    unsigned or malformed envelope, and a bad signature all return False (D-026).
    """
    if not isinstance(envelope, dict):
        return False
    container = envelope.get(container_key(envelope))
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if not isinstance(sig, dict):
        return False
    key = keyring.resolve(sig.get("key_id"))
    if key is None:
        return False
    if sig.get("algorithm") != key.algorithm:
        return False
    verify = _VERIFIERS.get(key.algorithm)
    value = sig.get("value")
    if verify is None or not isinstance(value, str) or not value:
        return False
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    # b64decode accepts surplus trailing padding, so one signature would have many spellings.
    # Only the canonical encoding verifies, which keeps a signed envelope's bytes unique.
    if base64.b64encode(signature).decode("ascii") != value:
        return False
    try:
        message = signing_input(envelope)
    except Exception:  # noqa: BLE001
        # RFC 8785 has no form for this envelope, so no signature covers it.
        return False
    return verify(key.public_key, signature, message)
