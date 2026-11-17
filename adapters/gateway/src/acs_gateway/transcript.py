"""Append-only records the lab reads back: the per-session transcript (A.7) and the model input log."""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

DIRECTIONS = ("req", "resp")


def _append_line(path: Path, record: Any) -> None:
    # O_APPEND keeps each line whole when two writers share the file, and 0600 keeps signed envelopes private.
    # ensure_ascii escapes every non-ASCII character as \uXXXX, so a lone surrogate, which UTF-8 can't encode, is
    # written as its escape and the line can never fail to encode. Reading it back with json.loads gives the same text.
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)


class Transcript:
    """ACS_TRANSCRIPT_DIR/<session_id>.jsonl, one {"dir", "envelope"} line per envelope, verbatim, in send order."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._lock = threading.Lock()

    def append(self, session_id: str, direction: str, envelope: dict[str, Any] | None, *,
               cause: str | None = None) -> None:
        """envelope None with a cause marks a request that got no usable answer, so the gap is explicit.

        acs.client doesn't hand back a refused, malformed or tampered answer, so the line can't carry it yet.
        LAB-03 (issue #576) adds that hook (PREMORTEM P6).
        """
        if direction not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}, got {direction!r}")
        if envelope is None and (direction != "resp" or not cause):
            raise ValueError("only a response line may omit its envelope, and it must name the cause")
        # The session_id names the file, so only the gateway's own UUIDs are accepted.
        name = str(uuid.UUID(session_id))
        record: dict[str, Any] = {"dir": direction, "envelope": envelope}
        if envelope is None:
            record["cause"] = cause
        with self._lock:
            self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            _append_line(self._directory / f"{name}.jsonl", record)


class ModelInputLog:
    """Every request body the gateway forwards upstream, in every mode, so the lab can show what the model saw."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._path is not None

    def append(self, body: Any) -> None:
        if self._path is None:
            return
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _append_line(self._path, body)
