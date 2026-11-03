from __future__ import annotations

import datetime
import os
import re
import stat
import tempfile
from pathlib import Path

_INLINE_SECRET = re.compile(r"(ACS_HMAC_SECRET=)('[^']*'|[^\s\"\\]+)")


def write_atomically(path: Path, content: str) -> Path | None:
    """Replace the file atomically and return the 0600 backup, which holds no inline secret, or None; a symlink stays a symlink, and the mode stays unless an inline secret makes it 0600."""
    target = Path(os.path.realpath(path))
    backup = None
    mode = 0o600
    if target.exists():
        mode = stat.S_IMODE(target.stat().st_mode)
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = target.with_suffix(target.suffix + f".bak.{ts}")
        _write(backup, _INLINE_SECRET.sub(r"\1<redacted>", target.read_text()), 0o600)
    if _INLINE_SECRET.search(content):
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
