"""ACS sessions for model conversations, and the outcome cache that keeps a resend from being governed twice (A.4)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acs.core import jcs_canonicalize

from acs_gateway.strict import loads_strict


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
    # What the gated item first said, raw and as a canonical fingerprint, so a reused call_id carrying something else
    # is caught. The raw form is compared first, so an unchanged resend never pays for canonicalization.
    fingerprint: str = ""
    raw: Any = None
    # The delivered call's arguments in canonical form, computed once.
    canonical_arguments: Any = None
    # For a call, how many input items the request that produced it forwarded. Replay's branch tokens put a removed
    # call there, since the client never resends it (issue #579).
    position: int | None = None


def canonical_value(value: Any, raw: Any) -> Any:
    """The RFC 8785 form of an already parsed JSON value, so a caller that parsed it doesn't parse it again. raw
    stands in when RFC 8785 can't encode the value."""
    try:
        return jcs_canonicalize(value).decode("utf-8")
    except Exception:  # noqa: BLE001
        return raw


def canonical(value: Any) -> Any:
    """A JSON string in RFC 8785 form, so key order and whitespace don't change what it says. Any other value, and a
    string that isn't JSON, repeats a key, or that RFC 8785 can't encode, stays as it is."""
    if not isinstance(value, str):
        return value
    try:
        parsed = loads_strict(value)
    except Exception:  # noqa: BLE001
        return value
    return canonical_value(parsed, value)


def content(item: dict[str, Any]) -> Any:
    """What a function_call asks for (name, arguments) or what an output says (output), as sent."""
    if item.get("type") == "function_call":
        return [item.get("name"), item.get("arguments")]
    return item.get("output")


def same_content(item: dict[str, Any], cached: CachedOutcome) -> bool:
    """Whether a resent item says what the cached one first said: raw equality first, canonical only on a mismatch."""
    return content(item) == cached.raw or fingerprint(item) == cached.fingerprint


_UNSET = object()


def fingerprint(item: dict[str, Any], canonical_arguments: Any = _UNSET) -> str:
    """SHA-256 over what a function_call asks for (name, arguments) or what an output says (output). A caller that
    already canonicalized a call's arguments passes them in, so they aren't canonicalized twice."""
    if item.get("type") == "function_call":
        arguments = canonical(item.get("arguments")) if canonical_arguments is _UNSET else canonical_arguments
        content: Any = [item.get("name"), arguments]
    else:
        content = canonical(item.get("output"))
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
    # Requests between their input and output phases. A session with any, or with its lock held, is never evicted.
    active: int = 0
    # time.monotonic() when opening last failed, so a retry waits out the backoff.
    open_failed_at: float | None = None
    # A step of this session hung past its bounded wait, so the session left the map and takes no more steps.
    retired: bool = False

    @property
    def busy(self) -> bool:
        return self.active > 0 or self.lock.locked()


class SessionsBusy(Exception):
    """Every session is busy, so a new conversation can't get one without evicting a turn in progress."""


class SessionMap:
    """Conversation key to ACS session, for the current epoch only, holding at most max_sessions."""

    def __init__(self, max_sessions: int = 256, on_evict: Callable[[Session], None] | None = None) -> None:
        self.epoch = 0
        self._max = max_sessions
        self._on_evict = on_evict
        self._sessions: OrderedDict[str, Session] = OrderedDict()

    def get(self, key: str) -> Session:
        session = self._sessions.get(key)
        if session is not None:
            self._sessions.move_to_end(key)
            return session
        while len(self._sessions) >= self._max:
            # The least recently used idle run is the one most likely over. Its next resend opens a new session.
            idle = next((k for k, s in self._sessions.items() if not s.busy), None)
            if idle is None:
                raise SessionsBusy()
            evicted = self._sessions.pop(idle)
            if self._on_evict is not None:
                self._on_evict(evicted)
        session = Session(session_id=str(uuid.uuid4()), epoch=self.epoch)
        self._sessions[key] = session
        return session

    def peek(self, key: str) -> Session | None:
        """The key's session if one exists, without creating one, evicting or touching the LRU order."""
        return self._sessions.get(key)

    def retire(self, session: Session) -> None:
        """Take a session out of the map, so the next request for its conversation opens a fresh one."""
        session.retired = True
        for key in [k for k, s in self._sessions.items() if s is session]:
            del self._sessions[key]

    def bump_epoch(self) -> int:
        """Forget every session and cached outcome, so a call_id seen before is gated afresh under a new session."""
        self.epoch += 1
        self._sessions = OrderedDict()
        return self.epoch
