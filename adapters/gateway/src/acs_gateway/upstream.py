"""Where model answers come from: live, capture or replay (issue #579, BUILD_PLAN A.8 and WP15).

Each mode is an httpx transport under the gateway's one upstream client, so gating never knows which mode answered.
Live with no key file passes no transport at all, which is the gateway's behavior before upstream modes existed.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


def _inside_git_work_tree(path: Path) -> bool:
    """True when any parent holds .git, so a key file there could be committed (PREMORTEM P24)."""
    for parent in path.resolve(strict=False).parents:
        if (parent / ".git").exists():
            return True
    return False


def read_key_file(path: Path) -> str:
    """The model key, from a file the lab writes outside the repository. No message ever carries the key itself.

    Held to the gateway's other secret files: not a symlink, a regular file, mode 0600 or 0400, owned by the gateway's
    uid. The checks and the read share one descriptor opened with O_NOFOLLOW, so the file can't be swapped between
    them, and O_NONBLOCK keeps a FIFO from stalling startup.
    """
    name = "ACS_UPSTREAM_KEY_FILE"
    if _inside_git_work_tree(path):
        raise ValueError(f"{name} {path} is inside a git work tree, and the key must live outside the repository")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        if path.is_symlink():
            raise ValueError(f"{name} {path} is a symlink") from None
        raise ValueError(f"{name} {path} can't be opened: {e.strerror}") from None
    info = os.fstat(fd)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{name} {path} is not a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"{name} {path} must be mode 0600 or 0400")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ValueError(f"{name} {path} is owned by uid {info.st_uid}, not the gateway's uid {os.geteuid()}")
        raw = f.read()
    try:
        key = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ValueError(f"{name} {path} is not UTF-8 text") from None
    if not key:
        raise ValueError(f"{name} {path} is empty")
    if any(c.isspace() or not c.isprintable() for c in key):
        # The key becomes one header value, so anything that could split or extend the header is refused.
        raise ValueError(f"{name} {path} must hold one key on one line with no spaces")
    return key
