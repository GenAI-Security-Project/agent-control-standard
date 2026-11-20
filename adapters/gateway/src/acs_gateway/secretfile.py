"""One reader for the gateway's secret files: the admin token and the model key (issue #579, fix round 2 CR9)."""
from __future__ import annotations

import os
import stat
from pathlib import Path


def load_secret_file(path: Path, name: str) -> str:
    """The file's text, stripped, held to acs.client's HMAC secret rules: no symlink, a regular file, mode 0600 or
    0400, owned by the gateway's own uid. name is the setting that named the file, for the error messages, which
    never carry the contents.

    The checks and the read use one descriptor opened with O_NOFOLLOW, so the file can't be swapped between them, and
    O_NONBLOCK keeps a FIFO from stalling startup. Callers add their own length and format rules.
    """
    return read_secret_text(path, name).strip()


def read_secret_text(path: Path, name: str, max_bytes: int | None = None) -> str:
    """The file's text exactly as written, under load_secret_file's rules. With max_bytes, a larger file is refused
    before it is read, so a mistaken path to a large file can't exhaust memory at startup."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        if path.is_symlink():
            raise ValueError(f"{name} {path} is a symlink") from None
        raise ValueError(f"{name} {path} can't be opened: {e.strerror}") from None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        # Checked before fdopen, which refuses a directory with its own error.
        os.close(fd)
        raise ValueError(f"{name} {path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"{name} {path} must be mode 0600 or 0400")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ValueError(f"{name} {path} is owned by uid {info.st_uid}, not the gateway's uid {os.geteuid()}")
        if max_bytes is not None and info.st_size > max_bytes:
            raise ValueError(f"{name} {path} must hold at most {max_bytes} bytes")
        # Read one byte past the cap, so a file that grew after fstat is still caught.
        raw = f.read() if max_bytes is None else f.read(max_bytes + 1)
    if max_bytes is not None and len(raw) > max_bytes:
        raise ValueError(f"{name} {path} must hold at most {max_bytes} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{name} {path} is not UTF-8 text") from None
