"""Loading the HMAC input keying material from ACS_HMAC_SECRET_FILE or ACS_HMAC_SECRET."""
from __future__ import annotations

import os
import stat

from acs.client._audit import audit_event


class SecretFilePermissionsError(RuntimeError):
    """ACS_HMAC_SECRET_FILE exists but its permissions / ownership leak the secret."""


class SecretFileUnreadableError(RuntimeError):
    """ACS_HMAC_SECRET_FILE is configured but cannot be read.

    Raised loudly: silently downgrading to unsigned mode would turn
    off the only integrity control ACS-Core mandates."""


def _check_secret_file_perms(path: str) -> None:
    """Refuse to read the secret file if anything about its mode or
    ownership would expose the key to another local user."""
    # Reject symlinks — a symlink is an attack vector (replace target
    # without changing the visible path).
    if os.path.islink(path):
        raise SecretFilePermissionsError(
            f"ACS_HMAC_SECRET_FILE {path!r} is a symlink; refusing to follow")
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SecretFilePermissionsError(
            f"ACS_HMAC_SECRET_FILE {path!r} mode {oct(mode)} is too permissive; "
            f"must be 0600 or 0400 (no group/other access). "
            f"Fix: chmod 600 {path}")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise SecretFilePermissionsError(
            f"ACS_HMAC_SECRET_FILE {path!r} owned by uid {st.st_uid}, "
            f"adapter is running as uid {os.geteuid()}; refusing")


def load_hmac_secret() -> bytes:
    """Read the HMAC input keying material.

    Resolution order (first hit wins):
    1. `ACS_HMAC_SECRET_FILE` — path to a file containing the secret.
       Preferred for production. Permissions MUST be 0600 (or 0400) and
       the file MUST be owned by the running user. The file's content
       (stripped of trailing whitespace) is the secret. Symlinks are
       rejected. Insecure permissions raise SecretFilePermissionsError —
       the adapter refuses to use a leaked secret rather than silently
       proceed.
    2. `ACS_HMAC_SECRET` — env-var fallback. Quick for dev, less secure
       (visible in `ps eauxw`, child-process envs, core dumps).
    3. Empty bytes — caller decides whether that means dev-mode or fail.

    Generate a secret: `openssl rand -hex 32 > /etc/acs/hmac.key && chmod 600 /etc/acs/hmac.key`
    """
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            _check_secret_file_perms(path)
            with open(path, "rb") as f:
                return f.read().rstrip(b"\r\n\t ")
        except SecretFilePermissionsError:
            raise
        except OSError as e:
            # Configured-but-unreadable is an incident, not dev mode.
            audit_event("hmac_secret_file_unreadable", path=path, error=str(e))
            raise SecretFileUnreadableError(
                f"ACS_HMAC_SECRET_FILE {path!r} is configured but cannot "
                f"be read ({e}); refusing to continue unsigned"
            ) from e
    env_val = os.environ.get("ACS_HMAC_SECRET", "")
    return env_val.encode("utf-8") if env_val else b""


def load_key_id() -> str:
    """ACS_HMAC_KEY_ID, the deployment's label for the secret (§10); "" when unset."""
    return os.environ.get("ACS_HMAC_KEY_ID", "").strip()
