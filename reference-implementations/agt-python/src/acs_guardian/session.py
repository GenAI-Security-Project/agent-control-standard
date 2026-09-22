"""Per-session state: negotiated terms, replay bookkeeping, audit chain.

One ``Session`` per ``session_id``, created by a successful handshake. The
replay bookkeeping is deliberately part of the session (Specification §10.3:
"duplicate ``request_id`` values within the session"), not a process-wide set,
so two sessions cannot collide on an id and a session's history is dropped
with it.

``seen_request_ids`` records ids on arrival -- including ids of requests the
Guardian then refuses for a capability reason -- because a replay of a refused
request is still a replay, and the conformance probes assert exactly that
(-32003 on first sight, -32005 on the second).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .chain import AuditChain


@dataclass
class Session:
    session_id: str
    agent_id: str
    key_id: str
    negotiated_version: str
    methods_evaluated: tuple[str, ...]
    selected_transport: str
    timeout_config: dict[str, Any]
    on_decision_failure: str
    skew_window_ms: int
    profiles_accepted: tuple[str, ...]
    chain: AuditChain = field(default_factory=AuditChain)
    seen_request_ids: set[str] = field(default_factory=set)
    seen_nonces: set[str] = field(default_factory=set)
    # steps/sessionEnd closes the session: no later step is evaluated (the Go
    # reference answers one with a session_closed denial), while replay
    # history survives so a replayed step is still REPLAY_DETECTED.
    closed: bool = False
    # Guards the session's mutable state against the HTTP server's threads.
    # The store's own lock protects the session table, not session contents:
    # without this, two concurrent copies of one request both pass the
    # check-then-act replay test and both append to the chain.
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


class SessionStore:
    """Thread-safe in-memory session table (the reference deployment's store)."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def create_if_absent(self, session: Session) -> bool:
        """Create the session unless one already exists; False means it raced.

        The handshake path checks for an existing session before negotiation
        and calls this after it, so two concurrent handshakes for one
        ``session_id`` cannot both install a session.
        """
        with self._lock:
            if session.session_id in self._sessions:
                return False
            self._sessions[session.session_id] = session
            return True

    def drop(self, session_id: str) -> None:
        """Eviction hook for a deployment that owns the store; see README non-goals."""
        with self._lock:
            self._sessions.pop(session_id, None)
