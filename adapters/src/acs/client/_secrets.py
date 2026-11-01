"""Loading the HMAC input keying material from ACS_HMAC_SECRET_FILE or ACS_HMAC_SECRET."""
from __future__ import annotations

import os
import stat

from acs.client._audit import audit_event


class SecretFilePermissionsError(RuntimeError):
    """ACS_HMAC_SECRET_FILE exists but its permissions / ownership leak the secret."""


class SecretFileUnreadableError(RuntimeError):
    """ACS_HMAC_SECRET_FILE is configured but cannot be read, or is empty."""


class SigningMaterialMissing(RuntimeError):
    """No usable secret or label, so nothing may be sent: ACS-Core signs every request (§10)."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause


# §10: the secret MUST be at least 32 bytes from a cryptographically secure random source.
MIN_SECRET_BYTES = 32


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
    """The input keying material from ACS_HMAC_SECRET_FILE (owner-only, no symlink) or ACS_HMAC_SECRET; b"" when neither is set."""
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            _check_secret_file_perms(path)
            with open(path, "rb") as f:
                secret = f.read().rstrip(b"\r\n\t ")
            if not secret:
                raise OSError(f"{path} is empty")
            return secret
        except SecretFilePermissionsError:
            raise
        except OSError as e:
            # Configured-but-unreadable is an incident, not dev mode.
            audit_event("hmac_secret_file_unreadable", path=path, error=str(e))
            raise SecretFileUnreadableError(
                f"ACS_HMAC_SECRET_FILE {path!r} is configured but cannot "
                f"be read ({e})"
            ) from e
    env_val = os.environ.get("ACS_HMAC_SECRET", "")
    return env_val.encode("utf-8") if env_val else b""


def load_key_id() -> str:
    """ACS_HMAC_KEY_ID, the deployment's label for the secret (§10); "" when unset."""
    return os.environ.get("ACS_HMAC_KEY_ID", "").strip()


def load_signing_material() -> tuple[bytes, str]:
    """The secret and the label that names it; raises SigningMaterialMissing when either is missing or the secret is under 32 bytes (§10)."""
    secret = load_hmac_secret()
    if not secret:
        raise SigningMaterialMissing("secret_missing", "no ACS_HMAC_SECRET_FILE or ACS_HMAC_SECRET is configured; "
                                                       "ACS-Core signs every request (§10)")
    if len(secret) < MIN_SECRET_BYTES:
        raise SigningMaterialMissing("secret_too_short", f"the secret is {len(secret)} bytes; "
                                                         f"§10 requires at least {MIN_SECRET_BYTES}")
    label = load_key_id()
    if not label:
        raise SigningMaterialMissing("key_id_missing", "ACS_HMAC_KEY_ID is not set; it names the configured secret (§10)")
    return secret, label
