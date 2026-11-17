"""ECDSA-P256 with SHA-256, as a benchmark primitive (issue #574, LAB-10).

Lab convention: this is not a wire algorithm. No keyring accepts an ECDSA-P256 key and no
envelope function signs with it, because the hybrid it would pair with is unsettled.
PR #564 (spec(crypto): call HMAC a MAC, take the algorithm from the key, and adopt composite
ML-DSA) and issue #532 would settle it (PREMORTEM P7). It exists so the signature benchmark
can measure the classical algorithm next to ML-DSA-65.

Signatures are the 64 byte fixed-width r || s form (IEEE P1363, as JOSE and COSE use), not
DER. Public keys are 65 byte uncompressed SEC1 points. Signing is randomized.

Only low-s signatures verify, and signing always produces one. (r, s) and (r, n - s) both
satisfy ECDSA, so accepting both would give one signature two encodings.

Nothing on the default path imports this module. It needs the pqc extra.
"""
from __future__ import annotations

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError as exc:
    raise ImportError(
        "the ECDSA-P256 benchmark primitive needs the pqc extra: pip install 'acs-adapters[pqc]' "
        "or uv sync --extra pqc") from exc

_SCALAR_BYTES = 32
_POINT_BYTES = 1 + 2 * _SCALAR_BYTES
# The order n of the P-256 group (SEC 2, secp256r1).
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def ecdsa_p256_generate() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def ecdsa_p256_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def ecdsa_p256_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = decode_dss_signature(private_key.sign(message, ec.ECDSA(hashes.SHA256())))
    s = min(s, _ORDER - s)
    return r.to_bytes(_SCALAR_BYTES, "big") + s.to_bytes(_SCALAR_BYTES, "big")


def ecdsa_p256_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if not all(isinstance(v, bytes) for v in (public_key, message, signature)):
        return False
    # Uncompressed SEC1 only: from_encoded_point would also take a compressed point, which
    # gives one key two encodings and contradicts the documented form.
    if len(public_key) != _POINT_BYTES or public_key[0] != 0x04:
        return False
    if len(signature) != 2 * _SCALAR_BYTES:
        return False
    r = int.from_bytes(signature[:_SCALAR_BYTES], "big")
    s = int.from_bytes(signature[_SCALAR_BYTES:], "big")
    if s > _ORDER // 2:
        return False
    try:
        point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        point.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
