"""Per-session adapter state persisted across hook processes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


# ----- Per-session adapter state (cross-invocation) -----
#
# Shell-stdin adapters (claude-code, cursor) spawn one process per hook
# event. To accumulate state across events in the same session (last
# step_id, step_ids seen, subagent registry, etc.) the adapter persists
# a small JSON file in the cache directory.

_SESSION_STATE_DIR = Path(
    os.environ.get(
        "ACS_SESSION_STATE_DIR",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-session"),
    )
)


def _session_state_path(session_id: str, *, workspace: str | None = None) -> Path:
    """Path to the per-session state file.

    Hash key is full 64-char SHA-256 (not [:16]) to eliminate birthday
    collisions over the lifetime of a deployment. When `workspace` is
    given, it is folded into the hash so two clients with the same
    session_id but different workspaces (e.g., two Cursor windows
    using `conv-default` as conversation_id) get distinct state files.
    """
    if not session_id:
        # Empty session_id — return a path that won't collide with anything real
        digest = hashlib.sha256(b"empty").hexdigest()
        return _SESSION_STATE_DIR / f"{digest}.json"
    if workspace:
        digest = hashlib.sha256(
            (workspace + "\x00" + session_id).encode()
        ).hexdigest()
    else:
        digest = hashlib.sha256(session_id.encode()).hexdigest()
    return _SESSION_STATE_DIR / f"{digest}.json"


def load_session_state(session_id: str, *, workspace: str | None = None) -> dict:
    """Return the session-state dict for `session_id`, or an empty dict.

    See `_session_state_path` for the workspace-namespacing rationale.
    """
    if not session_id:
        return {}
    path = _session_state_path(session_id, workspace=workspace)
    try:
        with open(path) as f:
            state = json.load(f)
    except Exception:  # noqa: BLE001
        # Any parse failure counts, including RecursionError from deep nesting.
        return {}
    return state if isinstance(state, dict) else {}


def save_session_state(session_id: str, state: dict, *, workspace: str | None = None) -> None:
    """Persist the session-state dict atomically. No-op on session_id empty.

    The directory is created with mode 0700 and the file with mode 0600
    so other local users cannot read or poison adapter state. State
    files contain step_id histories that an attacker could use to spoof
    `parent_step_id` in subagentStart payloads — a security boundary
    for the chain integrity properties of §8.
    """
    if not session_id:
        return
    try:
        _SESSION_STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(exist_ok=True) does not chmod an existing dir — enforce explicitly
        try:
            os.chmod(_SESSION_STATE_DIR, 0o700)
        except OSError:
            pass
        path = _session_state_path(session_id, workspace=workspace)
        tmp = path.with_suffix(".json.tmp")
        # Open with 0o600 from the start so the file is never group/world-readable
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def record_step(session_id: str, step_id: str, *, workspace: str | None = None) -> None:
    """Append step_id to the session's seen-list and update last_step_id."""
    if not session_id or not step_id:
        return
    st = load_session_state(session_id, workspace=workspace)
    seen = st.setdefault("seen_step_ids", [])
    if step_id not in seen:
        seen.append(step_id)
        # Bound the list so it doesn't grow unbounded across long sessions
        if len(seen) > 1000:
            del seen[: len(seen) - 1000]
    st["last_step_id"] = step_id
    save_session_state(session_id, st, workspace=workspace)
