from __future__ import annotations

import os
import shutil


def resolve_hook_command(script: str, override: str | None = None) -> str:
    """Return the absolute path a hook entry should run, or raise ValueError saying why it cannot be wired."""
    candidate = override or script
    if os.sep in candidate or (os.altsep and os.altsep in candidate):
        if not os.path.isabs(candidate):
            raise ValueError(f"--hook-command must be an absolute path, got {candidate!r}")
        path = candidate
    else:
        found = shutil.which(candidate)
        if found is None:
            raise ValueError(f"{candidate} is not on PATH; install acs-adapters, "
                             "or pass --hook-command with an absolute path")
        path = os.path.abspath(found)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        raise ValueError(f"hook command is not an executable file: {path}")
    return path
