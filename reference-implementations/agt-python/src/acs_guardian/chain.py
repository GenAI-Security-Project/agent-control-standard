"""SessionContext audit chain (Specification §8.1, §8.2).

``entry_hash = lowercase-hex(SHA-256(content_bytes || prev_hash_bytes))`` where
``content_bytes`` is the UTF-8 encoding of the JCS canonicalization of the
entry with ``entry_hash`` and ``previous_hash`` REMOVED, and
``prev_hash_bytes`` is the raw 32-byte decoding of ``previous_hash`` or the
empty byte string for the first entry.

The chain is cross-implementation verifiable: any conformant Guardian must
produce the same ``entry_hash`` for the same entry content, or chain-mismatch
detection between implementations breaks. That is why this module hashes the
canonical form rather than the stored dict, and why a test pins the vector.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_bytes

ZERO_HASH_LENGTH = 64


@dataclass
class ChainEntry:
    """One append-only ContextEntry, stored with its hash."""

    entry_id: str
    step_id: str
    step_type: str
    request_hash: str | None
    timestamp: str | None
    previous_hash: str | None
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "entry_id": self.entry_id,
            "step_id": self.step_id,
            "step_type": self.step_type,
            "entry_hash": self.entry_hash,
        }
        if self.request_hash is not None:
            entry["request_hash"] = self.request_hash
        if self.timestamp is not None:
            entry["timestamp"] = self.timestamp
        if self.previous_hash is not None:
            entry["previous_hash"] = self.previous_hash
        return entry


def request_hash(params: dict[str, Any]) -> str:
    """Lowercase-hex SHA-256 of the JCS-canonicalized request ``params`` object (§8.1)."""
    return hashlib.sha256(canonical_bytes(params)).hexdigest()


def compute_entry_hash(entry: dict[str, Any], previous_hash: str | None) -> str:
    """The §8.2 rule, over the entry as stored (minus the two hash fields)."""
    content = {key: value for key, value in entry.items() if key not in ("entry_hash", "previous_hash")}
    prev_bytes = bytes.fromhex(previous_hash) if previous_hash else b""
    return hashlib.sha256(canonical_bytes(content) + prev_bytes).hexdigest()


@dataclass
class AuditChain:
    """The append-only ContextEntry chain for one session."""

    entries: list[ChainEntry] = field(default_factory=list)

    @property
    def head(self) -> str | None:
        return self.entries[-1].entry_hash if self.entries else None

    def append(
        self,
        *,
        step_id: str,
        step_type: str,
        params: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> ChainEntry:
        previous = self.head
        # Optional members are omitted from the hashed content when absent,
        # never written as null: the spec's rule is "included in the entry's
        # content when present", and a null placeholder would make two
        # implementations hash different bytes for the same entry.
        entry: dict[str, Any] = {
            "entry_id": str(uuid.uuid4()),
            "step_id": step_id,
            "step_type": step_type,
        }
        if params is not None:
            entry["request_hash"] = request_hash(params)
        if timestamp is not None:
            entry["timestamp"] = timestamp
        entry_hash = compute_entry_hash(entry, previous)
        appended = ChainEntry(
            entry_id=entry["entry_id"],
            step_id=entry["step_id"],
            step_type=entry["step_type"],
            request_hash=entry.get("request_hash"),
            timestamp=entry.get("timestamp"),
            previous_hash=previous,
            entry_hash=entry_hash,
        )
        self.entries.append(appended)
        return appended


def verify_chain(entries: list[dict[str, Any]]) -> bool:
    """Recompute a serialized chain's hashes; used by tests and external auditors."""
    previous: str | None = None
    for entry in entries:
        expected = compute_entry_hash(entry, previous)
        if entry.get("entry_hash") != expected:
            return False
        previous = expected
    return True
