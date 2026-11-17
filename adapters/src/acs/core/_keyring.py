"""Public keys a verifier trusts, each bound to one opaque key_id and one algorithm.

The verifier takes the algorithm from the key it resolves, never from the envelope's
signature.algorithm field (RFC 8725 section 3.1, issue #308). key_id is an opaque label
(D-026): the keyring matches it exactly, never derives it from key material, and never
falls back to another key.

This module imports only the standard library, so building a keyring needs no extra.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

ML_DSA_65 = "ML-DSA-65"
ECDSA_P256 = "ECDSA-P256"

# PREMORTEM P7: PR #564's composite construction and the v1.1 length-prefixed one disagree, so
# no hybrid goes on the wire. ECDSA-P256 is a benchmark primitive (acs.core._ecdsa), not a wire
# algorithm. A key for anything outside this set never enters a keyring.
WIRE_ALGORITHMS = frozenset({ML_DSA_65})

# FIPS 204 Table 2. A wrong size is a broken key document, caught when the keyring is built.
PUBLIC_KEY_SIZES = {ML_DSA_65: 1952}


@dataclass(frozen=True)
class VerificationKey:
    """One public key, the algorithm it verifies, and the key_id that names it."""

    key_id: str
    algorithm: str
    public_key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise ValueError("key_id must be a non-empty string")
        if self.algorithm not in WIRE_ALGORITHMS:
            raise ValueError(f"algorithm {self.algorithm!r} is not accepted on the wire; "
                             f"accepted: {sorted(WIRE_ALGORITHMS)}")
        if not isinstance(self.public_key, bytes):
            raise ValueError("public_key must be the raw public key bytes")
        expected = PUBLIC_KEY_SIZES[self.algorithm]
        if len(self.public_key) != expected:
            raise ValueError(f"a {self.algorithm} public key is {expected} bytes, "
                             f"got {len(self.public_key)}")

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key).hexdigest()


class Keyring:
    """Resolves a key_id to the one key it names, or to nothing."""

    def __init__(self, keys: Iterable[VerificationKey] = ()) -> None:
        self._keys: dict[str, VerificationKey] = {}
        for key in keys:
            if not isinstance(key, VerificationKey):
                raise ValueError("a keyring holds VerificationKey entries only")
            # Two keys under one key_id would make resolution depend on load order.
            if key.key_id in self._keys:
                raise ValueError(f"key_id {key.key_id!r} appears more than once")
            self._keys[key.key_id] = key

    def resolve(self, key_id: object) -> VerificationKey | None:
        if not isinstance(key_id, str):
            return None
        return self._keys.get(key_id)

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(self._keys)

    def __contains__(self, key_id: object) -> bool:
        return self.resolve(key_id) is not None

    def __len__(self) -> int:
        return len(self._keys)
