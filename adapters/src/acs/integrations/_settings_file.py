from __future__ import annotations

import datetime
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

_INLINE_SECRET = "ACS_HMAC_SECRET="
# Characters that end an unquoted shell word.
_WORD_END = frozenset(" \t\n;&|<>()")


def _redact_command(command: str) -> str:
    out, i = [], 0
    while (start := command.find(_INLINE_SECRET, i)) >= 0:
        j = start + len(_INLINE_SECRET)
        out.append(command[i:j])
        # The value is one shell word, which shlex.quote may build from several quoted fragments.
        while j < len(command) and command[j] not in _WORD_END:
            if command[j] == "'":
                close = command.find("'", j + 1)
                j = len(command) if close < 0 else close + 1
            elif command[j] == '"':
                j += 1
                while j < len(command) and command[j] != '"':
                    j += 2 if command[j] == "\\" else 1
                j += 1
            else:
                j += 2 if command[j] == "\\" else 1
        out.append("<redacted>")
        i = j
    out.append(command[i:])
    return "".join(out)


def _redacted(text: str) -> str:
    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return _redact_command(value)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value
    try:
        return json.dumps(walk(json.loads(text)), indent=2) + "\n"
    except ValueError:
        return _redact_command(text)


def write_atomically(path: Path, content: str) -> Path | None:
    """Replace the file atomically and return the 0600 backup, which holds no inline secret, or None; a symlink stays a symlink, and the mode stays unless an inline secret makes it 0600."""
    target = Path(os.path.realpath(path))
    backup = None
    mode = 0o600
    if target.exists():
        mode = stat.S_IMODE(target.stat().st_mode)
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = target.with_suffix(target.suffix + f".bak.{ts}")
        _write(backup, _redacted(target.read_text()), 0o600)
    if _INLINE_SECRET in content:
        mode = 0o600
    target.parent.mkdir(parents=True, exist_ok=True)
    _write(target, content, mode)
    return backup


def _write(target: Path, content: str, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    except BaseException:
        os.unlink(temporary)
        raise
