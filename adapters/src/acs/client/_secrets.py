from __future__ import annotations

import errno
import os
import stat
import sys
from collections.abc import Callable

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


# A mode rule takes (setting, path, mode) and returns why the file can't be trusted, or None.
ModeRule = Callable[[str, str, int], "str | None"]


def owner_only(setting: str, path: str, mode: int) -> str | None:
    """The rule for a secret: no group or other access at all, 0600 or 0400.

    Windows reports 0o666 for every file, so the rule can't run there. It refuses unless the operator sets
    ACS_ALLOW_UNCHECKED_KEY_PERMS=1, and then it says on stderr that the file went unchecked.
    """
    if _IS_WINDOWS:
        if os.environ.get(_ALLOW_UNCHECKED_ENV) != "1":
            return (f"{setting} {path!r}: Windows has no owner/group/other mode bits "
                    f"(stat reports {oct(mode)} for every file), so the 0600 check cannot run. "
                    f"Restrict the file first:  cmd.exe:  icacls \"{path}\" /inheritance:r "
                    f"/grant:r \"%USERNAME%:R\"   PowerShell:  icacls \"{path}\" /inheritance:r "
                    f"/grant:r \"${{env:USERNAME}}:R\"   then set {_ALLOW_UNCHECKED_ENV}=1 to confirm that "
                    f"this check is skipped on Windows.")
        print(f"[acs] WARNING: {_ALLOW_UNCHECKED_ENV}=1, so {path} was not checked for group/other "
              f"access. Verify its ACL yourself.", file=sys.stderr)
        return None
    if mode & 0o077:
        return (f"{setting} {path!r} mode {oct(mode)} is too permissive. It must be 0600 or 0400, "
                f"with no group or other access. Fix: chmod 600 {path}")
    return None


def not_writable_by_others(setting: str, path: str, mode: int) -> str | None:
    """The rule for a public but trusted file, such as a key document: anyone may read it, only its owner may write.

    Windows has no group or other bits, so nothing is checked there.
    """
    if not _IS_WINDOWS and mode & 0o022:
        return f"{setting} {path!r} mode {oct(mode)} is writable by group or other. Fix: chmod 644 {path}"
    return None


def _directory_problem(setting: str, path: str) -> str | None:
    # Whoever can write the directory can replace the file. A sticky directory such as /tmp lets nobody but the
    # owner rename or remove it, so it is allowed.
    directory = os.path.dirname(os.path.abspath(path))
    mode = os.stat(directory).st_mode
    if mode & 0o022 and not mode & stat.S_ISVTX:
        return (f"{setting} {path!r} sits in directory {directory!r}, which is writable by group or other "
                f"(mode {oct(stat.S_IMODE(mode))}). Move the file or chmod go-w {directory}")
    return None


def read_trusted_file(path: str, *, setting: str, max_bytes: int, mode_rule: ModeRule,
                      refused: type[Exception], unreadable: type[Exception] | None = None) -> bytes:
    """The bytes of a secret or trusted file, read once and checked through the descriptor that reads them.

    The one reader for the HMAC secret, the Guardian's ML-DSA-65 seed, and the key document (issue #576). It opens
    with O_NOFOLLOW so a symlink is refused, O_NONBLOCK so a FIFO can't hang it, and O_BINARY where defined, and it
    never checks a path and then opens it again. On the open descriptor it requires a regular file, an owner that
    is this user or root, a directory no group or other can write unless it is sticky, and the caller's mode rule.
    It reads at most max_bytes. A problem with the file raises refused, and any OSError raises unreadable, which
    defaults to refused, each with a message that names setting.
    """
    unreadable = unreadable or refused
    if not hasattr(os, "O_NOFOLLOW") and os.path.islink(path):
        raise refused(f"{setting} {path!r} is a symlink. Refusing to follow it")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno == errno.ELOOP or os.path.islink(path):
            raise refused(f"{setting} {path!r} is a symlink. Refusing to follow it") from None
        raise unreadable(f"{setting} {path!r} is configured but cannot be read ({e})") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise refused(f"{setting} {path!r} is not a regular file")
        if hasattr(os, "geteuid") and st.st_uid not in (os.geteuid(), 0):
            raise refused(f"{setting} {path!r} is owned by uid {st.st_uid}, but this process runs as uid "
                          f"{os.geteuid()}. Refusing it")
        problem = (_directory_problem(setting, path) if not _IS_WINDOWS else None) \
            or mode_rule(setting, path, stat.S_IMODE(st.st_mode))
        if problem:
            raise refused(problem)
        chunks, remaining = [], max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as e:
        raise unreadable(f"{setting} {path!r} is configured but cannot be read ({e})") from e
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise refused(f"{setting} {path!r} is larger than {max_bytes} bytes")
    return data


# Far more than any secret needs, and small enough that a wrong path can't fill memory.
MAX_SECRET_FILE_BYTES = 64 * 1024


def load_hmac_secret() -> bytes:
    """The input keying material from ACS_HMAC_SECRET_FILE (owner-only, no symlink) or ACS_HMAC_SECRET. b"" when neither is set."""
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            raw = read_trusted_file(path, setting="ACS_HMAC_SECRET_FILE", max_bytes=MAX_SECRET_FILE_BYTES,
                                    mode_rule=owner_only, refused=SecretFilePermissionsError,
                                    unreadable=SecretFileUnreadableError)
            secret = raw.rstrip(b"\r\n\t ")
            if not secret:
                raise SecretFileUnreadableError(f"ACS_HMAC_SECRET_FILE {path!r} is configured but cannot be read "
                                                "(it is empty)")
            return secret
        except SecretFileUnreadableError as e:
            # Configured-but-unreadable is an incident, not a missing secret.
            audit_event("hmac_secret_file_unreadable", path=path, error=str(e))
            raise
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
