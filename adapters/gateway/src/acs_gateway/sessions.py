"""ACS sessions for model conversations, and the outcome cache that keeps a resend from being governed twice (A.4)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)


def conversation_key(body: dict[str, Any]) -> str:
    """SHA-256 of the system text and the first user message, which every resend of one agent run repeats.

    The system text is the instructions field when present, otherwise the first system or developer item.
    """
    items = body.get("input")
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    items = items if isinstance(items, list) else []
    system = body.get("instructions") if isinstance(body.get("instructions"), str) else None
    user = None
    for item in items:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        if system is None and role in ("system", "developer"):
            system = _text(item.get("content"))
        elif user is None and role == "user":
            user = _text(item.get("content"))
    joined = json.dumps([system or "", user or ""], separators=(",", ":"))
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass
class CachedOutcome:
    """How a gated item left the gateway, reapplied verbatim whenever the client resends it."""
    # "delivered", "removed" or "rewritten"
    outcome: str
    name: str
    # The item as delivered (rewritten arguments or output included), or None when it was removed.
    item: dict[str, Any] | None
    request_id: str | None = None
    # What the gated item first said, so a reused call_id carrying something else is caught, never served from here.
    fingerprint: str = ""


def fingerprint(item: dict[str, Any]) -> str:
    """SHA-256 over what a function_call asks for (name, arguments) or what an output says (output)."""
    content = [item.get("name"), item.get("arguments")] if item.get("type") == "function_call" else item.get("output")
    try:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    except (ValueError, RecursionError):
        encoded = repr(content)
    return hashlib.sha256(encoded.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass
class Session:
    session_id: str
    epoch: int
    # One lock per ACS session keeps its steps, and so its chain, in send order (PREMORTEM P20).
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    handshake: Any = None
    posture: Any = None
    # Keyed on call_id within this session, so the cache key is (session_id, call_id) (PREMORTEM P3).
    calls: dict[str, CachedOutcome] = field(default_factory=dict)
    results: dict[str, CachedOutcome] = field(default_factory=dict)


class SessionMap:
    """Conversation key to ACS session, for the current epoch only."""

    def __init__(self) -> None:
        self.epoch = 0
        self._sessions: dict[str, Session] = {}

    def get(self, key: str) -> Session:
        session = self._sessions.get(key)
        if session is None:
            session = Session(session_id=str(uuid.uuid4()), epoch=self.epoch)
            self._sessions[key] = session
        return session

    def bump_epoch(self) -> int:
        """Forget every session and cached outcome, so a call_id seen before is gated afresh under a new session."""
        self.epoch += 1
        self._sessions = {}
        return self.epoch
