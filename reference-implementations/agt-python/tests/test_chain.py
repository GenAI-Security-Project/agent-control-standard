"""The §8.2 chain rule, checked independently of the implementation that computes it."""

from __future__ import annotations

import hashlib

from acs_guardian.canonical import canonical_bytes
from acs_guardian.chain import AuditChain, verify_chain


def _independent_entry_hash(entry: dict, previous_hash: str | None) -> str:
    """The §8.2 rule written out again, from the prose, not via chain.py."""
    content = {key: value for key, value in entry.items() if key not in ("entry_hash", "previous_hash")}
    prev_bytes = bytes.fromhex(previous_hash) if previous_hash else b""
    return hashlib.sha256(canonical_bytes(content) + prev_bytes).hexdigest()


def test_first_entry_hashes_over_the_empty_previous_hash() -> None:
    chain = AuditChain()
    entry = chain.append(step_id="s-1", step_type="steps/sessionStart", params={"a": 1}, timestamp="2026-09-22T00:00:00Z")
    assert entry.previous_hash is None
    assert entry.entry_hash == _independent_entry_hash(entry.to_dict(), None)
    assert verify_chain([e.to_dict() for e in chain.entries])


def test_chain_links_entries_and_verifies() -> None:
    chain = AuditChain()
    first = chain.append(step_id="s-1", step_type="steps/sessionStart", params={"a": 1})
    second = chain.append(step_id="s-2", step_type="steps/toolCallRequest", params={"b": 2})
    assert second.previous_hash == first.entry_hash
    assert chain.head == second.entry_hash
    assert second.entry_hash == _independent_entry_hash(second.to_dict(), first.entry_hash)
    assert verify_chain([e.to_dict() for e in chain.entries])


def test_request_hash_commits_to_the_params_object() -> None:
    chain = AuditChain()
    params = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}}
    entry = chain.append(step_id="s-1", step_type="steps/toolCallRequest", params=params)
    assert entry.request_hash == hashlib.sha256(canonical_bytes(params)).hexdigest()


def test_tampering_with_a_stored_entry_breaks_verification() -> None:
    chain = AuditChain()
    chain.append(step_id="s-1", step_type="steps/sessionStart")
    chain.append(step_id="s-2", step_type="steps/toolCallRequest")
    serialized = [entry.to_dict() for entry in chain.entries]
    serialized[0]["step_id"] = "s-forged"
    assert not verify_chain(serialized)
