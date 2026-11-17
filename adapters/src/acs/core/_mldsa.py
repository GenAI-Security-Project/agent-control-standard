"""ML-DSA-65 (FIPS 204) envelope signing, and verification through a keyring (issue #574).

Variant: pure ML-DSA, not the pre-hash HashML-DSA. Context string: empty (b"").
The signature registry fixes neither (issue #566), so this library states both, and
adapters/docs/signing.md repeats them. A verifier on another stack must use the same pair,
since a context mismatch fails verification with no other sign.

The signed bytes are the ones HMAC-SHA256 signs: JCS of the envelope without its signature.
Signing is randomized (the FIPS 204 hedged variant that cryptography 50 uses), so two signatures
of one envelope differ and both verify.

Nothing on the default path imports this module. It needs the pqc extra (cryptography 50)
and fails at import without it. A backend that lacks ML-DSA fails loudly on first use.
"""
from __future__ import annotations

import functools

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
from acs.core._envelope import response_matches_request
from acs.core._signing import _attach_signature, container_key, decode_signature_value, signing_input

ML_DSA_MODE = "pure"
ML_DSA_CONTEXT = b""
SEED_BYTES = 32
SIGNATURE_BYTES = 3309  # FIPS 204 Table 2, ML-DSA-65


class MLDSAUnavailableError(RuntimeError):
    """The installed cryptography's OpenSSL backend has no ML-DSA-65."""


@functools.cache
def _backend_problem() -> str | None:
    # cryptography exposes the ML-DSA classes even when its OpenSSL lacks the algorithm, and then
    # raises UnsupportedAlgorithm on first use. One throwaway key per process finds out, and the
    # answer is cached, since the backend can't change while the process runs.
    try:
        mldsa.MLDSA65PrivateKey.generate()
    except UnsupportedAlgorithm:
        from cryptography.hazmat.backends.openssl.backend import backend
        return (f"the OpenSSL backend of cryptography {cryptography.__version__} "
                f"({backend.openssl_version_text()}) does not support ML-DSA-65. "
                "Install the cryptography 50 wheel, which bundles an OpenSSL with ML-DSA.")
    return None


def ml_dsa_available() -> bool:
    """Whether this process's OpenSSL backend can do ML-DSA-65. Probes once and keeps the answer."""
    return _backend_problem() is None


def _require_backend() -> None:
    problem = _backend_problem()
    if problem is not None:
        raise MLDSAUnavailableError(problem)


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
        _require_backend()
        return cls(mldsa.MLDSA65PrivateKey.generate(), key_id)

    @classmethod
    def from_seed(cls, seed: bytes, key_id: str) -> MLDSA65SigningKey:
        """Rebuild the key from its 32 byte FIPS 204 seed, the form a key file stores."""
        if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
            raise ValueError(f"an ML-DSA-65 seed is {SEED_BYTES} bytes")
        _require_backend()
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


def load_public_key(public_key: bytes) -> mldsa.MLDSA65PublicKey:
    """Parse a raw FIPS 204 public key. A VerificationKey calls this once, when it is built."""
    _require_backend()
    return mldsa.MLDSA65PublicKey.from_public_bytes(public_key)


def _verify_ml_dsa_65(public_key: mldsa.MLDSA65PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ML_DSA_CONTEXT)
    except (InvalidSignature, ValueError):
        return False
    return True


_VERIFIERS = {ML_DSA_65: _verify_ml_dsa_65}

def verify_with_keyring(envelope: dict, keyring: Keyring, *, expected_key_id: str, request: dict) -> bool:
    """Whether the response's signature verifies under expected_key_id, as the answer to request.

    A keyring can hold several keys, so the caller names the one it trusts here, and a
    signature naming any other key_id fails before any crypto runs. One key signs every
    session, so the key alone can't stop a response from one exchange being replayed onto
    another. The response must answer request (D-029): the same JSON-RPC id and, when the
    result carries one, the same request_id. A mismatch fails before any crypto, and a binding
    rewritten after signing fails the signature. This stops replay only as far as the caller's
    ids are unique, which this function doesn't check. request_envelope gives every request a
    fresh UUID4 JSON-RPC id. A request envelope answers nothing and fails. The algorithm comes from the
    resolved key, never from the envelope (RFC 8725 section 3.1, issue #308). An unknown
    key_id, an envelope algorithm that disagrees with the key's, an unsigned or malformed
    envelope, and a bad signature all return False (D-026). A missing expected_key_id, a
    request that isn't an envelope with a JSON-RPC id, or a request whose params is present
    but not an object, is a caller error and raises ValueError.
    """
    check_key_id(expected_key_id)
    if not isinstance(request, dict) or request.get("id") is None:
        raise ValueError("request must be the request envelope this response answers, with its JSON-RPC id")
    if not isinstance(request.get("params", {}), (dict, type(None))):
        raise ValueError("request params must be an object when present")
    if not isinstance(envelope, dict) or "method" in envelope:
        return False
    container = envelope.get(container_key(envelope))
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if not isinstance(sig, dict):
        return False
    if sig.get("key_id") != expected_key_id:
        return False
    if not response_matches_request(request, envelope):
        return False
    key = keyring.resolve(expected_key_id)
    if key is None:
        return False
    if sig.get("algorithm") != key.algorithm:
        return False
    verify = _VERIFIERS.get(key.algorithm)
    signature = decode_signature_value(sig.get("value"))
    if verify is None or signature is None:
        return False
    # Any other length is malformed, so it never reaches the library.
    if len(signature) != SIGNATURE_BYTES:
        return False
    try:
        message = signing_input(envelope)
    except Exception:  # noqa: BLE001
        # RFC 8785 has no form for this envelope, so no signature covers it.
        return False
    return verify(key._parsed, signature, message)
