"""Public keys a verifier trusts, each bound to one opaque key_id and one algorithm.

The verifier takes the algorithm from the key it resolves, never from the envelope's
signature.algorithm field (RFC 8725 section 3.1, issue #308). key_id is an opaque label
(D-026): the keyring matches it exactly, never derives it from key material, and never
falls back to another key.

This module imports only the standard library. Building a key parses it once, which needs
the pqc extra for ML-DSA-65, so a malformed key fails when the keyring is built and no
verification parses it again.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

ML_DSA_65 = "ML-DSA-65"
ECDSA_P256 = "ECDSA-P256"

# PREMORTEM P7: PR #564's composite construction and the v1.1 length-prefixed one disagree, so
# no hybrid goes on the wire. ECDSA-P256 is a benchmark primitive (acs.core._ecdsa), not a wire
# algorithm. A key for anything outside this set never enters a keyring.
WIRE_ALGORITHMS = frozenset({ML_DSA_65})

# FIPS 204 Table 2. A wrong size is a broken key document, caught when the keyring is built.
PUBLIC_KEY_SIZES = {ML_DSA_65: 1952}


def check_key_id(key_id: object) -> str:
    """The one key_id rule for signing and verifying keys: a non-empty string, used as given."""
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id must be a non-empty string")
    return key_id


@dataclass(frozen=True)
class VerificationKey:
    """One public key, the algorithm it verifies, and the key_id that names it."""

    key_id: str
    algorithm: str
    public_key: bytes
    # The parsed key, kept so verification never re-parses trusted key material.
    _parsed: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        check_key_id(self.key_id)
        if self.algorithm not in WIRE_ALGORITHMS:
            raise ValueError(f"algorithm {self.algorithm!r} is not accepted on the wire. "
                             f"Accepted: {sorted(WIRE_ALGORITHMS)}")
        if not isinstance(self.public_key, bytes):
            raise ValueError("public_key must be the raw public key bytes")
        expected = PUBLIC_KEY_SIZES[self.algorithm]
        if len(self.public_key) != expected:
            raise ValueError(f"a {self.algorithm} public key is {expected} bytes, "
                             f"got {len(self.public_key)}")
        object.__setattr__(self, "_parsed", _parse_public_key(self.public_key))

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key).hexdigest()


def _parse_public_key(public_key: bytes) -> Any:
    # Imported here so this module, and the HMAC path that imports acs.core, need no extra.
    from acs.core._mldsa import load_public_key
    return load_public_key(public_key)


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
