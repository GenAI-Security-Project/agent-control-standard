from __future__ import annotations

import datetime
import os
import shutil
import stat
import tempfile
from pathlib import Path


def write_atomically(path: Path, content: str) -> Path | None:
    """Replace the settings file's content atomically and return the timestamped backup of the old one, or None.

    A symlinked settings file stays a symlink and its target is rewritten. The file keeps its
    mode; a new file is created 0600, since --secret-env-inline puts the secret in it.
    """
    target = Path(os.path.realpath(path))
    backup = None
    mode = 0o600
    if target.exists():
        mode = stat.S_IMODE(target.stat().st_mode)
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = target.with_suffix(target.suffix + f".bak.{ts}")
        shutil.copy2(target, backup)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    except BaseException:
        os.unlink(temporary)
        raise
    return backup
