from __future__ import annotations

import os
import stat
import sys

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

# Windows carries no owner/group/other bits: stat() reports 0o666 for every ordinary file, so the
# 0600 rule below cannot be evaluated there. The equivalent control is the file's NTFS ACL.
_IS_WINDOWS = os.name == "nt"
_ALLOW_UNCHECKED_ENV = "ACS_ALLOW_UNCHECKED_KEY_PERMS"


def _check_secret_file_perms(path: str) -> None:
    # A symlink is refused: its target can change behind the visible path.
    if os.path.islink(path):
        raise SecretFilePermissionsError(
            f"ACS_HMAC_SECRET_FILE {path!r} is a symlink; refusing to follow")
    st = os.stat(path)
    _refuse_loose_secret(path, st.st_mode, st.st_uid, "ACS_HMAC_SECRET_FILE")


def _refuse_loose_secret(path: str, st_mode: int, st_uid: int, setting: str) -> None:
    """The owner-only rule for a secret file, given its mode and owner, with setting naming it in every message."""
    mode = stat.S_IMODE(st_mode)
    if _IS_WINDOWS:
        # Refuse by default: an unchecked secret is an unknown quantity, not a permitted one.
        # Starting anyway takes an explicit opt-in and says so on stderr, which is where the
        # Guardian's operator looks.
        if os.environ.get(_ALLOW_UNCHECKED_ENV) != "1":
            raise SecretFilePermissionsError(
                f"{setting} {path!r}: Windows has no owner/group/other mode bits "
                f"(stat reports {oct(mode)} for every file), so the 0600 check cannot run. "
                f"Restrict the file first:  cmd.exe:  icacls \"{path}\" /inheritance:r "
                f"/grant:r \"%USERNAME%:R\"   PowerShell:  icacls \"{path}\" /inheritance:r "
                f"/grant:r \"${{env:USERNAME}}:R\"   then set {_ALLOW_UNCHECKED_ENV}=1 to confirm that "
                f"this check is skipped on Windows.")
        print(
            f"[acs] WARNING: {_ALLOW_UNCHECKED_ENV}=1 — {path} was not checked for group/other "
            f"access; verify its ACL yourself",
            file=sys.stderr,
        )
    elif mode & 0o077:
        raise SecretFilePermissionsError(
            f"{setting} {path!r} mode {oct(mode)} is too permissive; "
            f"must be 0600 or 0400 (no group/other access). "
            f"Fix: chmod 600 {path}")
    if hasattr(os, "geteuid") and st_uid != os.geteuid():
        raise SecretFilePermissionsError(
            f"{setting} {path!r} owned by uid {st_uid}, "
            f"adapter is running as uid {os.geteuid()}; refusing")


def read_secret_file(path: str, *, setting: str, max_bytes: int) -> bytes:
    """An owner-only secret file's bytes, checked through the descriptor that reads them (issue #576, review R-M2).

    The file is opened without following a symlink, and fstat on that descriptor decides, so nothing can swap the
    file between the check and the read. The rules are the ones ACS_HMAC_SECRET_FILE meets, named by setting.
    Raises SecretFilePermissionsError for a symlink, a non-regular file, loose permissions, another owner, or more
    than max_bytes, and OSError when the file can't be opened.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    symlink = SecretFilePermissionsError(f"{setting} {path!r} is a symlink; refusing to follow")
    if not nofollow and os.path.islink(path):
        raise symlink
    try:
        fd = os.open(path, os.O_RDONLY | nofollow)
    except OSError:
        if os.path.islink(path):
            raise symlink from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecretFilePermissionsError(f"{setting} {path!r} is not a regular file")
        _refuse_loose_secret(path, st.st_mode, st.st_uid, setting)
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise SecretFilePermissionsError(f"{setting} {path!r} is larger than {max_bytes} bytes")
    return data


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
            # Configured-but-unreadable is an incident, not a missing secret.
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
