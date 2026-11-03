from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt

T = TypeVar("T")


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
            (workspace + "\x00" + session_id).encode("utf-8", "surrogatepass")
        ).hexdigest()
    else:
        digest = hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()
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
    """Replace the session's state; the file is owner-only because its step history backs parent_step_id (§8)."""
    update_session_state(session_id, lambda current: (current.clear(), current.update(state)),
                         workspace=workspace)


def discard_session_state(session_id: str, *, workspace: str | None = None) -> None:
    if not session_id:
        return
    path = _session_state_path(session_id, workspace=workspace)
    for record in (path, Path(f"{path}.lock")):
        with contextlib.suppress(OSError):
            record.unlink()


def update_session_state(session_id: str, change: Callable[[dict], T], *,
                         workspace: str | None = None) -> T | None:
    """Apply change as one locked read-modify-write, since a session's hooks run concurrently; returns its result, or None when the state cannot be stored."""
    if not session_id:
        return None
    path = _session_state_path(session_id, workspace=workspace)
    try:
        _SESSION_STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(exist_ok=True) does not chmod an existing dir — enforce explicitly
        try:
            os.chmod(_SESSION_STATE_DIR, 0o700)
        except OSError:
            pass
        with _locked(path):
            state = load_session_state(session_id, workspace=workspace)
            result = change(state)
            _write(path, state)
            return result
    except OSError:
        return None


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    fd = os.open(f"{path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        else:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def _write(path: Path, state: dict[str, Any]) -> None:
    """Publish the state atomically through a temp file of its own, so concurrent writers never share one."""
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def record_step(session_id: str, step_id: str, *, workspace: str | None = None) -> None:
    """Append step_id to the session's seen-list and update last_step_id."""
    if not session_id or not step_id:
        return

    def change(state: dict) -> None:
        seen = state.get("seen_step_ids")
        seen = seen if isinstance(seen, list) else []
        if step_id not in seen:
            seen.append(step_id)
            del seen[:-1000]
        state["seen_step_ids"] = seen
        state["last_step_id"] = step_id

    update_session_state(session_id, change, workspace=workspace)


def mark_once(session_id: str, flag: str, *, workspace: str | None = None) -> bool:
    """True the first time `flag` is marked for the session, False after; True also when the state cannot be stored, so a record is never lost."""
    def change(state: dict) -> bool:
        marked = state.get("marked")
        marked = marked if isinstance(marked, dict) else {}
        state["marked"] = {**marked, flag: True}
        return not marked.get(flag)

    first = update_session_state(session_id, change, workspace=workspace)
    return first is not False


def count_decision_failure(session_id: str | None, failure: str, *, workspace: str | None = None) -> None:
    """Count one decision failure for sessionEnd's summary; never raises, so a count cannot stop a deny."""
    if not session_id:
        return

    def change(state: dict) -> None:
        counts = state.get("decision_failures")
        counts = counts if isinstance(counts, dict) else {}
        counts[failure] = int(counts.get(failure, 0)) + 1
        state["decision_failures"] = counts

    try:
        update_session_state(session_id, change, workspace=workspace)
    except Exception:  # noqa: BLE001
        # The failure itself is already audited; sessionEnd's count is a lower bound (trace/events.md).
        pass


def decision_failure_counts(session_id: str | None, *, workspace: str | None = None) -> dict[str, int]:
    counts = load_session_state(session_id, workspace=workspace).get("decision_failures") if session_id else None
    if not isinstance(counts, dict):
        return {}
    return {k: v for k, v in counts.items() if isinstance(k, str) and isinstance(v, int) and v >= 0}


def current_turn(session_id: str | None, *, workspace: str | None = None) -> str | None:
    if not session_id:
        return None
    turn_id = load_session_state(session_id, workspace=workspace).get("turn_id")
    return turn_id if isinstance(turn_id, str) else None


def open_turn(session_id: str, turn_id: str, *, workspace: str | None = None) -> None:
    update_session_state(session_id, lambda state: state.update(turn_id=turn_id), workspace=workspace)


def close_turn(session_id: str, *, workspace: str | None = None) -> None:
    update_session_state(session_id, lambda state: state.pop("turn_id", None), workspace=workspace)
