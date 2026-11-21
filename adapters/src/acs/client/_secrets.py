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


def _owner_problem(setting: str, path: str, uid: int, what: str, remedy: str = "") -> str | None:
    if hasattr(os, "geteuid") and uid not in (os.geteuid(), 0):
        return (f"{setting} {path!r}: {what} is owned by uid {uid}, but this process runs as uid {os.geteuid()}. "
                f"Refusing it{remedy}")
    return None


def _directory_problem(setting: str, path: str, directory: str, st: os.stat_result,
                       require_owner: bool, owner_remedy: str = "") -> str | None:
    """Whoever can replace a file in the directory can replace the file. Read from the directory's own descriptor.

    Group write is allowed, since mkdir under the common umask 002 gives 0775 and the group is the user's own. A
    world-writable directory is refused unless it is sticky, as /tmp is, where only a file's owner can rename it.
    For a secret, the directory's owner must also be this user or root (review round 4).
    """
    mode = st.st_mode
    if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
        return (f"{setting} {path!r} sits in directory {directory!r}, which is world-writable without the sticky "
                f"bit (mode {oct(stat.S_IMODE(mode))}). Move the file or chmod o-w {directory}")
    if require_owner:
        return _owner_problem(setting, path, st.st_uid, f"its directory {directory!r}", owner_remedy)
    return None


# Whether os.open takes dir_fd here. Windows doesn't, and falls back to the round 3 open by path.
_OPENS_IN_DIRECTORY = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")


def _open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def _open_in_directory(path: str, *, setting: str, require_owner: bool, refused: type[Exception],
                       unreadable: type[Exception], owner_remedy: str = "") -> int:
    """Open the file through one descriptor on its directory, so every path component is resolved once.

    The directory is opened with O_DIRECTORY, so the kernel resolves "link/.." the way it will for the file, and its
    fstat is the one every directory check reads. The file is then opened by name relative to it with O_NOFOLLOW.
    A loop or a missing component in the directory fails the directory open with its own message, so an ELOOP from
    the file open can only mean the last component is a symlink. Ancestors above the directory aren't checked.
    """
    directory, name = os.path.split(path)
    directory = directory or "."
    if name in ("", ".", ".."):
        raise refused(f"{setting} {path!r} is not a regular file")
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as e:
        raise unreadable(f"{setting} {path!r}: its directory {directory!r} cannot be opened ({e})") from e
    try:
        try:
            problem = _directory_problem(setting, path, directory, os.fstat(dfd), require_owner, owner_remedy)
        except OSError as e:
            raise unreadable(f"{setting} {path!r}: its directory {directory!r} cannot be read ({e})") from e
        if problem:
            raise refused(problem)
        try:
            return os.open(name, _open_flags(), dir_fd=dfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise refused(f"{setting} {path!r} is a symlink. Refusing to follow it") from None
            raise unreadable(f"{setting} {path!r} is configured but cannot be read ({e})") from e
    finally:
        os.close(dfd)


def _open_by_path(path: str, *, setting: str, refused: type[Exception], unreadable: type[Exception]) -> int:
    """Where os.open takes no dir_fd (Windows), the round 3 open: the file by path, with no directory checks."""
    if not hasattr(os, "O_NOFOLLOW") and os.path.islink(path):
        raise refused(f"{setting} {path!r} is a symlink. Refusing to follow it")
    try:
        return os.open(path, _open_flags())
    except OSError as e:
        if e.errno == errno.ELOOP or os.path.islink(path):
            raise refused(f"{setting} {path!r} is a symlink. Refusing to follow it") from None
        raise unreadable(f"{setting} {path!r} is configured but cannot be read ({e})") from e


def read_trusted_file(path: str, *, setting: str, max_bytes: int, mode_rule: ModeRule,
                      refused: type[Exception], unreadable: type[Exception] | None = None,
                      require_owner: bool = True, owner_remedy: str = "") -> bytes:
    """The bytes of a secret or trusted file, read once and checked through descriptors, never through the path again.

    The one reader for the HMAC secret, the Guardian's ML-DSA-65 seed, and the key document (issue #576). It opens
    the file's directory once and the file inside it with O_NOFOLLOW so a symlink is refused, O_NONBLOCK so a FIFO
    can't hang it, and O_BINARY where defined. It requires a directory that is not world-writable unless sticky, a
    regular file, and the caller's mode rule. With require_owner, which secrets pass, the file and its directory
    must belong to this user or root. A key document passes False only when a fingerprint pin covers an owner swap.
    owner_remedy is appended to an owner refusal, so the message can name the caller's other way out. It reads at
    most max_bytes. A problem with the file raises refused. Any OSError and a
    file past max_bytes raise unreadable, which defaults to refused. Every message names setting.
    """
    unreadable = unreadable or refused
    if _OPENS_IN_DIRECTORY:
        fd = _open_in_directory(path, setting=setting, require_owner=require_owner, refused=refused,
                                unreadable=unreadable, owner_remedy=owner_remedy)
    else:
        fd = _open_by_path(path, setting=setting, refused=refused, unreadable=unreadable)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise refused(f"{setting} {path!r} is not a regular file")
        problem = (_owner_problem(setting, path, st.st_uid, "the file", owner_remedy) if require_owner else None) \
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
        raise unreadable(f"{setting} {path!r} is larger than {max_bytes} bytes")
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
