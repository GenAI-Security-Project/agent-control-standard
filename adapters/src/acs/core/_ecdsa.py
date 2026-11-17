"""ECDSA-P256 with SHA-256, as a benchmark primitive (issue #574, LAB-10).

Lab convention: this is not a wire algorithm. No keyring accepts an ECDSA-P256 key and no
envelope function signs with it, because the hybrid it would pair with is unsettled.
PR #564 (spec(crypto): call HMAC a MAC, take the algorithm from the key, and adopt composite
ML-DSA) and issue #532 would settle it (PREMORTEM P7). It exists so the signature benchmark
can measure the classical algorithm next to ML-DSA-65.

Signatures are the 64 byte fixed-width r || s form (IEEE P1363, as JOSE and COSE use), not
DER. Public keys are 65 byte uncompressed SEC1 points. Signing is randomized.

Nothing on the default path imports this module. It needs the pqc extra.
"""
from __future__ import annotations

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError as exc:
    raise ImportError(
        "the ECDSA-P256 benchmark primitive needs the pqc extra: pip install 'acs-adapters[pqc]' "
        "or uv sync --extra pqc") from exc

_SCALAR_BYTES = 32


def ecdsa_p256_generate() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def ecdsa_p256_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def ecdsa_p256_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = decode_dss_signature(private_key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(_SCALAR_BYTES, "big") + s.to_bytes(_SCALAR_BYTES, "big")


def ecdsa_p256_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 2 * _SCALAR_BYTES:
        return False
    try:
        point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        der = encode_dss_signature(int.from_bytes(signature[:_SCALAR_BYTES], "big"),
                                   int.from_bytes(signature[_SCALAR_BYTES:], "big"))
        point.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
