#!/usr/bin/env python3
"""Example Guardian for testing the reference adapters, not a production Guardian; docs/guardian/README.md describes it."""
from __future__ import annotations

import argparse
import copy
import errno
try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt
import hashlib
import http.server
import json
import math
import os
import posixpath
import re
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, NamedTuple

from acs.guardian._limits import depth_exceeds
from acs.guardian._policy_backend import POLICY_BACKEND_ENV, policy_backend_name
from acs.client import load_key_id, load_signing_material, sign_envelope, verify_signature
from acs.examples.destructive_bash import DESTRUCTIVE_SCAN_MAX_LEN, matches_destructive_bash
from acs.core._canonical import CANONICALIZATION_ERRORS
from acs.core import (
    ACS_VERSION,
    DEFAULT_SKEW_WINDOW_MS,
    MAX_REQUEST_BODY_BYTES,
    derive_session_key,
    iso8601_now,
    jcs_canonicalize,
    parse_iso8601,
)

import datetime

# With jsonschema available, every incoming envelope is validated against request-envelope.json before policy runs.
_SPEC_VALIDATION_AVAILABLE = False
_REQUEST_ENVELOPE_VALIDATOR = None
try:
    from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    from jsonschema.validators import RefResolver  # type: ignore[import-not-found]
    from acs.core import schemas_dir
    try:
        _spec_dir = schemas_dir(os.environ.get("ACS_SPEC_DIR"))
    except FileNotFoundError:
        _spec_dir = Path("<no bundled or in-repo schemas>")
    _envelope_schema_path = _spec_dir / "request-envelope.json"
    if _envelope_schema_path.exists():
        with open(_envelope_schema_path, encoding="utf-8") as _f:
            _schema_obj = json.load(_f)
        _REQUEST_ENVELOPE_VALIDATOR = Draft202012Validator(
            _schema_obj,
            resolver=RefResolver(
                base_uri=(_spec_dir.as_uri() + "/request-envelope.json"),
                referrer=_schema_obj,
            ),
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        _SPEC_VALIDATION_AVAILABLE = True
    else:
        _spec_validation_unavailable_reason = (
            f"canonical schemas not found at {_spec_dir} "
            "(set ACS_SPEC_DIR to your spec checkout)"
        )
except ImportError:
    _spec_validation_unavailable_reason = (
        "jsonschema is not installed (pip install jsonschema)"
    )


def _flock(fd: int, how: str) -> None:
    """flock(2) on POSIX, msvcrt byte-range locks on Windows (the idiom client/_store.py uses).

    On Windows "sh" is really an exclusive lock: msvcrt's LK_RLCK behaves like LK_LOCK, and
    msvcrt gives up after about 10 seconds of retries. Safe for the Guardian state file,
    just stronger than the shared-lock name suggests.
    """
    if fcntl is not None:
        fcntl.flock(fd, {"sh": fcntl.LOCK_SH, "ex": fcntl.LOCK_EX, "un": fcntl.LOCK_UN}[how])
        return
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, {"sh": msvcrt.LK_RLCK, "ex": msvcrt.LK_LOCK, "un": msvcrt.LK_UNLCK}[how], 1)


if not _SPEC_VALIDATION_AVAILABLE:
    # Without validation, malformed envelopes reach policy unchecked.
    print(
        "[guardian] WARNING: envelope schema validation DISABLED — "
        + _spec_validation_unavailable_reason
        + ". Malformed envelopes will NOT be rejected before policy "
        "evaluation.",
        file=sys.stderr,
    )


SKEW_WINDOW_MS = int(os.environ.get("ACS_SKEW_WINDOW_MS", str(DEFAULT_SKEW_WINDOW_MS)))
ALLOW_SUBAGENT = os.environ.get("ACS_ALLOW_SUBAGENT", "0") == "1"
ON_DECISION_FAILURE = "proceed" if os.environ.get("ACS_ON_DECISION_FAILURE", "").strip().lower() == "proceed" else "deny"


# /proc/ is here because /proc/self/root/ reaches the whole filesystem on Linux.
PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/proc/")
# macOS reaches the whole root again under its Data volume.
DATA_VOLUME_PREFIX = "/system/volumes/data/"
# macOS links /etc to /private/etc, so that spelling is compared as /etc. /var and /tmp have the same links but
# aren't protected, so they need none.
PATH_ALIASES: tuple[tuple[str, str], ...] = (("/private/etc/", "/etc/"),)
# Case-folded tool names that change a file, and the argument names that can name the file. This is a fixed list:
# a tool under any other name, an MCP file tool included, meets no path deny here, and a policy has to cover it.
WRITE_CAPABLE_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit", "delete", "remove", "move", "rename"})
# Path arguments read for every file tool. paths may hold a list, and each string in it is checked.
# Every name is read on every file tool. A move or rename names its source and destination with these, and so can
# a delete that names its target. On Edit, target can be ordinary text, so text that names a protected path is
# over-denied. That fails closed, and the README says so.
PATH_ARGUMENTS: tuple[str, ...] = ("file_path", "notebook_path", "path", "target_file", "paths",
                                   "destination", "new_path", "target", "to", "source", "from", "old_path", "src")

# Lab convention (issue #531): ACS_POLICY_BACKEND=opa hands these two methods to OPA. main() loads the settings
# once into OPA_CONFIG, and acs.guardian.opa_backend is imported only on that path.
OPA_CONFIG: Any = None


# Read once, at import, and never again: a later change to the environment can't switch a running Guardian's
# policy backend on or off. main() loads the settings for this name into OPA_CONFIG, or refuses to start.
POLICY_BACKEND_NAME = policy_backend_name()


def _policy_backend_named() -> bool:
    return OPA_CONFIG is not None or bool(POLICY_BACKEND_NAME)


def _policy_backend_decision(method: str, params: dict, base: dict) -> dict:
    from acs.guardian import opa_backend
    if OPA_CONFIG is None:
        # Named at import, but main() never loaded it, as when a caller serves handle_request on its own.
        return opa_backend.misconfigured(base)
    return opa_backend.evaluate(method, params, base, OPA_CONFIG)


# Acknowledged with an unconditional allow; subagentStart is absent because it is the confused-deputy gate.
INFORMATIONAL_METHODS = {
    "steps/sessionStart", "steps/sessionEnd", "steps/userMessage",
    "steps/toolCallResult", "steps/agentResponse",
    "steps/preCompact", "steps/postCompact",
    "steps/subagentStop",
    "steps/knowledgeRetrieval", "steps/memoryStore", "steps/memoryContextRetrieval",
    "steps/turnStart", "steps/turnEnd", "steps/agentTrigger",
}


# Replay and chain state persist per session under ACS_GUARDIAN_STATE_DIR, so §10.3 replay rejection survives a restart.

_STATE_DIR_ENV = os.environ.get(
    "ACS_GUARDIAN_STATE_DIR",
    os.path.join(os.path.expanduser("~"), ".cache", "acs-guardian-state"),
)
PERSIST_ENABLED = bool(_STATE_DIR_ENV)
STATE_DIR = Path(_STATE_DIR_ENV) if PERSIST_ENABLED else None


def _state_path(session_id: str) -> Path | None:
    if not PERSIST_ENABLED:
        return None
    key = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    return STATE_DIR / f"{key}.json"


class SessionState:
    """A session's chain head and seen request_ids, persisted as 0600 JSON; a corrupt file loads as a fresh session."""

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self.previous_hash: str | None = None  # None for the first entry (§8.1)
        self.seen_request_ids: dict[str, float] = {}
        self.seen_nonces: dict[str, float] = {}
        self.lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        path = _state_path(self.session_id)
        if path is None or not path.exists():
            return
        try:
            # Shared flock: never read a file mid-write by another instance.
            with open(path, encoding="utf-8") as f:
                try:
                    _flock(f.fileno(), "sh")
                except OSError:
                    pass
                try:
                    data = json.load(f)
                finally:
                    try:
                        _flock(f.fileno(), "un")
                    except OSError:
                        pass
            self.previous_hash = data.get("previous_hash")
            sr = data.get("seen_request_ids", {})
            self.seen_request_ids = sr if isinstance(sr, dict) else {x: time.time() for x in sr}  # legacy list: stamped now, so the entries live a full window
            sn = data.get("seen_nonces", {})
            self.seen_nonces = sn if isinstance(sn, dict) else {x: time.time() for x in sn}  # legacy list: stamped now, so the entries live a full window
        except (OSError, json.JSONDecodeError):
            pass

    def persist(self) -> None:
        """Write atomically, merging with the on-disk state under an exclusive lock for Guardians sharing STATE_DIR; call with self.lock held."""
        path = _state_path(self.session_id)
        if path is None:
            return
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(STATE_DIR, 0o700)
            except OSError:
                pass
            lock_path = path.with_suffix(".lock")
            lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                try:
                    _flock(lock_fd, "ex")
                except OSError as e:
                    if e.errno != errno.ENOLCK:
                        raise

                merged_seen = dict(self.seen_request_ids)
                merged_nonces = dict(self.seen_nonces)
                merged_prev = self.previous_hash
                if path.exists():
                    try:
                        with open(path, encoding="utf-8") as rf:
                            disk = json.load(rf)
                        disk_seen = disk.get("seen_request_ids") or {}
                        if isinstance(disk_seen, list):
                            disk_seen = {x: time.time() for x in disk_seen}  # legacy list: stamped now, so the entries live a full window
                        for k, v in disk_seen.items():
                            # The earliest timestamp wins, so eviction keeps the full window.
                            if k not in merged_seen or merged_seen[k] > v:
                                merged_seen[k] = v
                        disk_nonces = disk.get("seen_nonces") or {}
                        if isinstance(disk_nonces, list):
                            disk_nonces = {x: time.time() for x in disk_nonces}  # legacy list: stamped now, so the entries live a full window
                        for k, v in disk_nonces.items():
                            if k not in merged_nonces or merged_nonces[k] > v:
                                merged_nonces[k] = v
                        # Either head will do: one Guardian keeps them identical, and HA mode is best-effort.
                        if not merged_prev and disk.get("previous_hash"):
                            merged_prev = disk["previous_hash"]
                    except (OSError, json.JSONDecodeError):
                        pass

                # Evict from the merged result, or dropped entries return from disk; the skew check already rejects anything older.
                cutoff = time.time() - 2 * (SKEW_WINDOW_MS / 1000.0)
                merged_seen = {k: v for k, v in merged_seen.items()
                               if v >= cutoff}
                merged_nonces = {k: v for k, v in merged_nonces.items()
                                 if v >= cutoff}

                self.seen_request_ids = merged_seen
                self.seen_nonces = merged_nonces
                self.previous_hash = merged_prev

                tmp = path.with_suffix(".json.tmp")
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump({
                        "previous_hash": self.previous_hash,
                        "seen_request_ids": self.seen_request_ids,
                        "seen_nonces": self.seen_nonces,
                    }, f)
                os.replace(tmp, path)
            finally:
                try:
                    _flock(lock_fd, "un")
                except OSError:
                    pass
                os.close(lock_fd)
        except OSError:
            pass


def evict_old_request_ids(st: "SessionState") -> int:
    """Drop request_ids older than twice the skew window, which -32006 already rejects; call with st.lock held."""
    cutoff = time.time() - 2 * (SKEW_WINDOW_MS / 1000.0)
    old = [k for k, ts in st.seen_request_ids.items() if ts < cutoff]
    for k in old:
        del st.seen_request_ids[k]
    return len(old)


class GuardianState:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionState] = {}
        self.lock = threading.Lock()

    def get(self, session_id: str) -> SessionState:
        with self.lock:
            st = self.sessions.get(session_id)
            if st is None:
                st = SessionState(session_id=session_id)
                self.sessions[session_id] = st
            return st


STATE = GuardianState()


def _unwrap_arguments(wrapped: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (wrapped or {}).items():
        out[k] = v["value"] if isinstance(v, dict) and "value" in v else v
    return out


def compute_entry_hash(entry: dict, previous_hash: str | None) -> str:
    """§8.2: lowercase hex SHA-256 of JCS(entry without its hashes) followed by the previous hash's 32 raw bytes."""
    entry_for_hash = {k: v for k, v in entry.items() if k not in ("entry_hash", "previous_hash")}
    content_bytes = jcs_canonicalize(entry_for_hash)
    prev_bytes = bytes.fromhex(previous_hash) if previous_hash else b""
    return hashlib.sha256(content_bytes + prev_bytes).hexdigest()


def append_to_chain(session_id: str, method: str, request_id: str,
                    payload_canonical: str, client_timestamp: str) -> str:
    """Append a ContextEntry and return the chain head; the request's timestamp is used, so an observer can recompute the hash."""
    st = STATE.get(session_id)
    with st.lock:
        entry = {
            "entry_id": request_id,
            "step_id": request_id,
            "step_type": method,
            "request_hash": hashlib.sha256(payload_canonical.encode()).hexdigest(),
            "timestamp": client_timestamp or iso8601_now(),
        }
        if st.previous_hash is not None:
            entry["previous_hash"] = st.previous_hash
        new_head = compute_entry_hash(entry, st.previous_hash)
        st.previous_hash = new_head
        st.persist()
        return new_head


class GuardianError(Exception):
    def __init__(self, code: int, message: str, *, signed: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        # §10: the error for a key_id no configured secret matches is unsigned.
        self.signed = signed


def check_replay(session_id: str, request_id: str) -> None:
    if not request_id:
        return
    st = STATE.get(session_id)
    with st.lock:
        # Re-read, so this sees what other Guardian instances accepted.
        st._load()
        if request_id in st.seen_request_ids:
            raise GuardianError(-32005, f"REPLAY_DETECTED: request_id {request_id} already seen in session")
        if len(st.seen_request_ids) % 100 == 0:
            evict_old_request_ids(st)
        st.seen_request_ids[request_id] = time.time()
        st.persist()


def check_nonce(session_id: str, nonce: str) -> None:
    """§10.3: reject a duplicate `nonce` in a sliding window (a SHOULD, not a MUST).

    The window is twice the skew window, the same span the persisted state is evicted over, so an
    entry this check relies on cannot be dropped between the read and the write. Deployments that
    configure a different window change SKEW_WINDOW_MS; there is no second knob.
    """
    if not nonce:
        return
    st = STATE.get(session_id)
    with st.lock:
        # Re-read, so this sees what other Guardian instances accepted.
        st._load()
        cutoff = time.time() - 2 * (SKEW_WINDOW_MS / 1000.0)
        for seen in [k for k, ts in st.seen_nonces.items() if ts < cutoff]:
            del st.seen_nonces[seen]
        if nonce in st.seen_nonces:
            raise GuardianError(-32005, f"REPLAY_DETECTED: nonce {nonce[:8]}... already seen in session")
        st.seen_nonces[nonce] = time.time()
        st.persist()


def check_skew(timestamp: str) -> None:
    if not timestamp:
        return
    try:
        ts = parse_iso8601(timestamp)
    except (ValueError, AttributeError):
        raise GuardianError(-32006, f"TIMESTAMP_OUT_OF_WINDOW: cannot parse timestamp {timestamp!r}")
    now = datetime.datetime.now(datetime.timezone.utc)
    delta_ms = abs((now - ts).total_seconds() * 1000)
    if delta_ms > SKEW_WINDOW_MS:
        raise GuardianError(-32006, f"TIMESTAMP_OUT_OF_WINDOW: {int(delta_ms)}ms > {SKEW_WINDOW_MS}ms")


def check_signature(envelope: dict, session_id: str) -> None:
    # Signed, unlike every error before it: §10 exempts only an unknown key_id, and acs.client reads a signed -32004
    # as signature_invalid_response, the cause the conformance suite requires (Core08). An unknown key_id gets its
    # unsigned -32004 earlier, in _handle_request.
    if not verify_signature(envelope, session_id=session_id):
        raise GuardianError(-32004, "SIGNATURE_INVALID")


def _major(version: str) -> str | None:
    parts = str(version).split(".")
    return parts[0] if parts and parts[0].isdigit() else None


def evaluate_handshake(params: dict, request_id: str) -> dict:
    client_hello = params.get("payload") or {}

    # handshake.json requires these ClientHello fields; unknown fields are ignored.
    missing = [f for f in ("acs_versions_supported", "methods_implemented",
                           "transports_supported", "provenance_producer")
               if f not in client_hello]
    if missing:
        raise GuardianError(-32600,
            f"Invalid Request: ClientHello missing required field(s): {missing}")

    # §3: accept a client sharing the Guardian's major version, and negotiate the Guardian's own version.
    client_versions = client_hello.get("acs_versions_supported") or []
    our_major = _major(ACS_VERSION)
    if not any(_major(v) == our_major for v in client_versions):
        raise GuardianError(-32001,
            f"UNSUPPORTED_VERSION: client majors "
            f"{[_major(v) for v in client_versions]}, Guardian major {our_major}")

    # Answer only with what the client offered: a transport this Guardian serves, and the profiles it implements.
    offered = client_hello.get("transports_supported") or []
    transport = next((t for t in ("http", "https") if t in offered), None)
    if transport is None:
        raise GuardianError(-32602, f"Invalid params: no offered transport this Guardian serves in {offered}")
    server_hello = {
        "negotiated_version": ACS_VERSION,
        "methods_evaluated": client_hello.get("methods_implemented") or [],
        "selected_transport": transport,
        "signature_algorithms_supported": ["HMAC-SHA256"],
        "timeout_config": {"default_ms": 5000},
        "skew_window_ms": SKEW_WINDOW_MS,
        "on_decision_failure": ON_DECISION_FAILURE,
        "policy_requires_provenance": False,
        "profiles_accepted": [p for p in client_hello.get("profiles_supported") or [] if p == "acs-core"],
    }
    # handle_request wraps and signs this direct ServerHello as result.
    return server_hello


def evaluate_ping(params: dict, request_id: str) -> dict:
    echo = (params.get("payload") or {}).get("echo", "")
    return {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "decision": "allow",
        "payload": {
            "status": "ok",
            "echo": echo,
            "server_timestamp": iso8601_now(),
        },
    }


def _argument_type_deny(base: dict, tool_name: str, name: str, value: Any) -> dict:
    return {**base, "decision": "deny",
            "reasoning": f"{tool_name} {name} has the wrong type ({type(value).__name__})",
            "reason_codes": ["argument_type_invalid"]}


def _normalize_path(path: str) -> str:
    """POSIX normalization, with the leading // that normpath keeps collapsed to /, since Linux treats both alike."""
    if not path:
        return path
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/") if normalized.startswith("//") else normalized


def _comparable_path(normalized: str) -> str:
    """The normalized path case-folded, with a trailing / and macOS aliases resolved, for the prefix check.

    Case-folded because the default macOS and Windows filesystems ignore case, so /ETC/passwd is /etc/passwd there.
    """
    folded = normalized.casefold() + "/"
    # The same files are reachable through the macOS Data volume, so that prefix comes off before the aliases.
    if folded.startswith(DATA_VOLUME_PREFIX):
        folded = folded[len(DATA_VOLUME_PREFIX) - 1:]
    for alias, target in PATH_ALIASES:
        if folded.startswith(alias):
            return target + folded[len(alias):]
    return folded


def _path_deny(base: dict, tool_name: str, name: str, path: Any) -> dict | None:
    """The type, traversal, and protected-path denies for one path argument value, or None."""
    if not isinstance(path, str):
        return _argument_type_deny(base, tool_name, name, path)
    # Compared after normalizing, so /tmp/../etc/passwd and //etc/passwd can't step around the prefixes.
    normalized = _normalize_path(path)
    if normalized == ".." or normalized.startswith("../"):
        return {**base, "decision": "deny",
                "reasoning": f"relative path leaves its starting directory: {path}",
                "reason_codes": ["path_traversal"]}
    comparable = _comparable_path(normalized)
    if any(comparable.startswith(p) for p in PROTECTED_PATH_PREFIXES):
        return {**base, "decision": "deny",
                "reasoning": f"write to protected system path: {path}",
                "reason_codes": ["protected_path"]}
    return None


def _hard_deny(base: dict, tool_name: str, args: dict) -> dict | None:
    """The built-in denies for a tool call, or None. They hold under every policy backend."""
    if tool_name == "task" and not ALLOW_SUBAGENT:
        return {**base, "decision": "deny",
                "reasoning": "Task tool (in-process subagent) is gated by default. Set ACS_ALLOW_SUBAGENT=1 to allow.",
                "reason_codes": ["subagent_gated"]}

    if tool_name in ("bash", "shell"):
        # None reads as absent for every argument a hard deny reads, the same answer as a missing one.
        cmd = args.get("command", "")
        cmd = "" if cmd is None else cmd
        # The pattern scan reads a string. Anything else is denied here instead of crashing the request handler.
        if not isinstance(cmd, str):
            return _argument_type_deny(base, tool_name, "command", cmd)
        match = matches_destructive_bash(cmd)
        if match == "too_large":
            return {**base, "decision": "deny",
                    "reasoning": f"command length {len(cmd)} exceeds safe-scan cap "
                                 f"({DESTRUCTIVE_SCAN_MAX_LEN}); cannot evaluate destructive patterns",
                    "reason_codes": ["input_too_large"]}
        if match is not None:
            return {**base, "decision": "deny",
                    "reasoning": f"destructive Bash pattern in: {cmd[:120]}",
                    "reason_codes": ["destructive_command"]}

    if tool_name in WRITE_CAPABLE_TOOLS:
        # Each tool on the list meets the same path denies, on every path argument it carries.
        for name in PATH_ARGUMENTS:
            value = args.get(name)
            if value is None:
                continue  # absent, or null, which reads as absent
            # Only paths takes a list, and a non-empty one. Every other path argument is a single string.
            if name == "paths":
                if not isinstance(value, list) or not value:
                    return _argument_type_deny(base, tool_name, name, value)
                values = value
            else:
                values = [value]
            for path in values:
                denied = _path_deny(base, tool_name, name, path)
                if denied is not None:
                    return denied
    return None


def _recheck_rewritten_call(base: dict, tool_name: str, payload: dict, result: dict) -> dict:
    """The hard denies run on the arguments as a modify would leave them. A deny there replaces the modify."""
    modifications = result.get("modifications") or {}
    try:
        from acs.guardian import opa_backend
        # The modify allowlist keeps every edit under /arguments, so only that subtree is copied.
        rewritten = {"arguments": copy.deepcopy(payload.get("arguments") or {})}
        for redaction in modifications.get("redactions") or []:
            opa_backend.replace_at(rewritten, redaction["path"],
                                   redaction.get("replacement", "[REDACTED]"))
        arguments = _unwrap_arguments(rewritten["arguments"])
        # Overrides replace the tool's own argument values, exactly as the Claude Code and Cursor adapters merge
        # them into the tool input, so they are never unwrapped.
        arguments.update(modifications.get("parameter_overrides") or {})
        return _hard_deny(base, tool_name, arguments) or result
    except Exception:  # noqa: BLE001
        # The verdict already validated, so this is unexpected. It still ends in a deny, never an unchecked modify.
        return {**base, "decision": "deny",
                "reasoning": "The rewritten tool call could not be checked, so the step is denied.",
                "reason_codes": ["opa_verdict_invalid"]}


def evaluate_step(method: str, params: dict, request_id: str, chain_hash: str) -> dict:
    base = {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "chain_hash": chain_hash,
    }

    # Absent means empty. On the HTTP path read_request has already refused any other non-object with -32600, but
    # direct callers such as acs.testing's real_policy_handler reach this function without it.
    payload = params.get("payload", {})
    if not isinstance(payload, dict):
        return _argument_type_deny(base, method, "payload", payload)

    if method == "steps/toolCallRequest":
        # Absent means empty. A present value is checked as it is, so [], "", 0, false, and null can't pass as {}.
        tool = payload.get("tool", {})
        wrapped = payload.get("arguments", {})
        # The checks below read a string name and an argument object. Any other shape denies before they run,
        # instead of crashing the request handler.
        if not isinstance(tool, dict) or not isinstance(tool.get("name", ""), str):
            return _argument_type_deny(base, "tool", "name", tool.get("name") if isinstance(tool, dict) else tool)
        if not isinstance(wrapped, dict):
            return _argument_type_deny(base, str(tool.get("name", "")), "arguments", wrapped)
        # Case-folded, so Claude Code's Bash, Cursor's Shell and NAT's shell meet one policy.
        tool_name = tool.get("name", "").lower()
        args = _unwrap_arguments(wrapped)

        hard_deny = _hard_deny(base, tool_name, args)
        if hard_deny is not None:
            return hard_deny

        # The hard denies hold under every backend. A policy backend decides only what they allow, and a modify
        # that rewrites the arguments is checked again, so a policy cannot turn ls into rm -rf /.
        if _policy_backend_named():
            result = _policy_backend_decision(method, params, base)
            if result.get("decision") == "modify":
                return _recheck_rewritten_call(base, tool_name, payload, result)
            return result
        return {**base, "decision": "allow"}

    if method == "steps/subagentStart":
        # Spawns are gated as strictly as the Task tool, and a fresh intent_derivation gets its own reason code.
        # None reads as absent. Any other non-string denies, instead of crashing on .lower().
        derivation = payload.get("intent_derivation")
        derivation = "" if derivation is None else derivation
        if not isinstance(derivation, str):
            return _argument_type_deny(base, method, "intent_derivation", derivation)
        derivation = derivation.lower()
        if not ALLOW_SUBAGENT:
            code = ("subagent_fresh_intent_gated" if derivation == "fresh"
                    else "subagent_gated")
            return {**base, "decision": "deny",
                    "reasoning": (
                        "subagent spawns are gated by default"
                        + (" — and intent_derivation 'fresh' claims "
                           "authority not derived from the parent"
                           if derivation == "fresh" else "")
                        + ". Set ACS_ALLOW_SUBAGENT=1 to allow."),
                    "reason_codes": [code]}
        return {**base, "decision": "allow"}

    if method == "steps/toolCallResult" and _policy_backend_named():
        # Under a policy backend a tool result is judged, so it can be denied or redacted.
        return _policy_backend_decision(method, params, base)

    if method in INFORMATIONAL_METHODS:
        return {**base, "decision": "allow"}

    return {**base, "decision": "deny",
            "reasoning": f"unknown method: {method}",
            "reason_codes": ["unknown_method"]}


def _error_envelope(request_id, session_id: str, code: int, message: str, *, signed: bool = True) -> dict:
    """A JSON-RPC error, signed whenever the session key is derivable, since Baseline integrity covers errors."""
    envelope = {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}
    if signed and session_id:
        sign_envelope(envelope, session_id=session_id)
    return envelope


# Deeper requests are refused right after parsing, before replay or chain state changes. Well inside the parser's
# and the canonicalizer's recursion limits, and far deeper than any tool call the reference adapters send.
MAX_REQUEST_DEPTH = 128


def _log_value(value: Any, width: int = 8) -> str:
    """A field for the log line: a string cut to width, anything else only its type name, never a full repr."""
    return value[:width] if isinstance(value, str) else f"<{type(value).__name__}>"


class RequestFields(NamedTuple):
    """The request fields every later step reads, each one checked for type once, here."""
    method: str
    id: Any
    params: dict
    request_id: str
    session_id: str


MAX_SAFE_ID = 2**53 - 1


def _valid_id(value: Any) -> bool:
    """A JSON-RPC id: a string, an int within 2^53 - 1 or a finite float (never a bool), or null."""
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        # JCS (RFC 8785) signs only integers within 2^53 - 1, so a larger one could never get a signed answer.
        return -MAX_SAFE_ID <= value <= MAX_SAFE_ID
    return isinstance(value, float) and math.isfinite(value)


class ReadResult(NamedTuple):
    """read_request's answer: the fields, or the problem with the id and session an error answer can use."""
    fields: RequestFields | None
    problem: str | None
    id: Any
    session_id: str


def read_request(request: Any) -> ReadResult:
    """The request's fields, each checked for type once, or the structural problem that stops the request.

    The id is one an answer can carry: the request's own when it has a valid type, else None. The session_id is
    the request's own when it was readable before the problem, else "", so an error is signed whenever it can be.
    """
    if not isinstance(request, dict):
        kind = "batch" if isinstance(request, list) else type(request).__name__
        return ReadResult(None, f"expected a JSON-RPC object, got {kind} (batches unsupported in v0.1)", None, "")
    # Null reads as absent for params, metadata, request_id, and session_id, as it always has.
    params = request.get("params")
    params = {} if params is None else params
    metadata = params.get("metadata") if isinstance(params, dict) else None
    metadata = {} if metadata is None and isinstance(params, dict) else metadata
    session_id = metadata.get("session_id") if isinstance(metadata, dict) else None
    session_id = "" if session_id is None else session_id
    signing_session = session_id if isinstance(session_id, str) else ""

    raw_id = request.get("id")
    if not _valid_id(raw_id):
        # Read after the session, so this refusal is signed whenever the session is readable, with id null.
        return ReadResult(None, "id must be a string, an int within 2^53 - 1, a finite float, or null", None,
                          signing_session)

    def refuse(problem: str) -> ReadResult:
        return ReadResult(None, problem, raw_id, signing_session)

    method = request.get("method", "")
    if not isinstance(method, str):
        return refuse("method must be a string")
    if not isinstance(params, dict):
        return refuse("params must be an object")
    if not isinstance(metadata, dict):
        return refuse("params.metadata must be an object")
    # Every method reads its payload as an object, ping and handshake included, so any other value is refused here.
    if "payload" in params and not isinstance(params["payload"], dict):
        return refuse("params.payload must be an object")
    request_id = "" if params.get("request_id") is None else params["request_id"]
    for name, value in (("params.request_id", request_id), ("params.metadata.session_id", session_id)):
        if not isinstance(value, str):
            return refuse(f"{name} must be a string")
    return ReadResult(RequestFields(method, raw_id, params, request_id, session_id), None, raw_id, session_id)


def handle_request(request: dict, read: "ReadResult | None" = None) -> dict:
    """Answer one JSON-RPC request. A request the Guardian can't read or canonicalize gets an error answer."""
    # Errors are signed whenever the session key is derivable, as spec section 10 requires. The two unsigned
    # answers are the -32004 for an unknown key_id (the section 10 exemption) and do_POST's floor, which answers
    # when signing itself fails. Signing an error before the sender is verified gives that sender an HMAC under a
    # session key it chose, over an error envelope with an id it chose. A client accepts a response only for its
    # own UUID request ids, so it can't use one.
    # do_POST reads the request once and passes the result in. Other callers let it be read here.
    read = read if read is not None else read_request(request)
    try:
        return _answer(request, read)
    except CANONICALIZATION_ERRORS:
        # Signing itself failed, as for a session_id JCS can't encode. A direct caller gets the same unsigned floor
        # envelope do_POST sends, so handle_request never raises for one.
        return internal_error_envelope(read.id)


def _foreign_key_id(request: Any) -> bool:
    """Whether a non-ping request carries a readable signature object under a key_id this Guardian doesn't hold."""
    if not isinstance(request, dict) or request.get("method") == "system/ping":
        return False
    params = request.get("params")
    signature = params.get("signature") if isinstance(params, dict) else None
    return isinstance(signature, dict) and signature.get("key_id") != load_key_id()


def internal_error_envelope(request_id: Any) -> dict:
    """The unsigned -32603 floor: a fixed message, and the id only when it passed the id rule."""
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": INTERNAL_ERROR_MESSAGE}}


def _answer(request: dict, read: "ReadResult") -> dict:
    # §10: a key_id this Guardian holds no secret for gets an unsigned -32004 before any other check, whenever the
    # signature object is readable, so key_id_rejected is never hidden behind an error signed with this Guardian's
    # key. system/ping is exempt: it is unsigned and answers whatever it carries (§13).
    if _foreign_key_id(request):
        return _error_envelope(read.id, "", -32004, "SIGNATURE_INVALID: unknown key_id", signed=False)
    if read.problem:
        return _error_envelope(read.id, read.session_id, -32600, f"Invalid Request: {read.problem}")
    if depth_exceeds(request, MAX_REQUEST_DEPTH):
        return _error_envelope(read.id, read.session_id, -32600,
                               f"Invalid Request: the envelope nests deeper than {MAX_REQUEST_DEPTH} levels")
    try:
        return _handle_request(request, read.fields)
    except CANONICALIZATION_ERRORS as e:
        # Last resort, after the depth bound. If even this error can't be signed, do_POST's floor answers.
        cause = " (it exceeds the recursion limit)" if isinstance(e, RecursionError) else ""
        return _error_envelope(read.id, read.session_id, -32600,
                               f"Invalid Request: the envelope could not be canonicalized{cause}")


def _handle_request(request: dict, fields: RequestFields) -> dict:
    method, request_id, params = fields.method, fields.id, fields.params
    session_id, acs_request_id = fields.session_id, fields.request_id
    timestamp = params.get("timestamp", "")

    # system/ping is the only unsigned method (§13), so liveness probes survive a key outage.
    if method == "system/ping":
        result = evaluate_ping(params, acs_request_id)
        envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
        return envelope


    # Validated before policy; ping and handshake have their own payload shapes.
    if (_SPEC_VALIDATION_AVAILABLE
            and method not in ("system/ping", "handshake/hello")):
        errors = list(_REQUEST_ENVELOPE_VALIDATOR.iter_errors(request))
        if errors:
            paths = "; ".join(
                f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                for e in errors[:5]
            )
            return _error_envelope(request_id, session_id, -32600, f"Invalid Request: envelope failed schema: {paths}")

    if method == "handshake/hello":
        # The handshake is signed too (§10): the session key is known before negotiation, and the chain roots at sessionStart.
        try:
            check_signature(request, session_id)
            result = evaluate_handshake(params, acs_request_id)
        except GuardianError as e:
            return _error_envelope(request_id, session_id, e.code, e.message, signed=e.signed)
        envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
        sign_envelope(envelope, session_id=session_id)
        return envelope

    try:
        check_signature(request, session_id)
        check_skew(timestamp)
        check_replay(session_id, acs_request_id)
        check_nonce(session_id, params.get("nonce", ""))
    except GuardianError as e:
        return _error_envelope(request_id, session_id, e.code, e.message, signed=e.signed)

    payload_canonical = jcs_canonicalize(params).decode("utf-8")
    chain_hash = append_to_chain(session_id, method, acs_request_id, payload_canonical, timestamp)

    try:
        result = evaluate_step(method, params, acs_request_id, chain_hash)
    except GuardianError as e:
        return _error_envelope(request_id, session_id, e.code, e.message)

    return _signed_step_response(request_id, session_id, result)


# Fixed ASCII. The fallback holds only this, constants, and the request_id and chain_hash the Guardian already
# canonicalized for the request, so JCS can encode it. A missing signing key would still fail it, and propagate.
UNSIGNABLE_REASONING = "The Guardian could not sign its decision for this step, so the step is denied."


def _signed_step_response(request_id: Any, session_id: str, result: dict) -> dict:
    """Sign a step's decision. One JCS can't canonicalize (a lone surrogate, an integer beyond 2^53, a non-finite
    float, or nesting past the recursion limit) is answered with a signed deny instead of a dropped connection,
    which a proceed posture would run."""
    envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
    try:
        sign_envelope(envelope, session_id=session_id)
        return envelope
    except CANONICALIZATION_ERRORS:
        # Only a canonicalization failure is relabeled, recursion depth included. Any other error is a bug and
        # propagates as before.
        fallback = {key: result[key] for key in ("type", "acs_version", "request_id", "chain_hash") if key in result}
        envelope = {"jsonrpc": "2.0", "id": request_id,
                    "result": {**fallback, "decision": "deny", "reasoning": UNSIGNABLE_REASONING,
                               "reason_codes": ["response_not_signable"]}}
        sign_envelope(envelope, session_id=session_id)
        return envelope


_CONTENT_LENGTH = re.compile(r"[0-9]+")
# One deadline for reading a whole request body. The per-recv socket timeout alone lets a slow drip run for days.
BODY_READ_SECONDS = 30.0

# The one answer for anything that escapes every specific check. Fixed text, so nothing internal reaches the agent.
INTERNAL_ERROR_MESSAGE = "Internal error: the Guardian could not process this request"


class GuardianHandler(http.server.BaseHTTPRequestHandler):
    # A socket timeout, so a client that never sends the body its Content-Length promised can't hold a handler
    # thread forever. Generous next to the 5 s decision timeout a client waits for.
    timeout = 30

    def do_POST(self) -> None:  # noqa: N802
        """Answer every request. The specific checks give specific codes. This guard is the floor beneath them."""
        self._answered = False
        self._answer_id = None
        try:
            self._serve()
        except TimeoutError:
            # The client stopped sending. The socket is probably gone, so close without writing to it.
            sys.stderr.write("[guardian] request body read timed out, closing the connection\n")
            sys.stderr.flush()
            self.close_connection = True
        except Exception as e:  # noqa: BLE001
            # A dropped connection reads as transport_failure, which a proceed posture runs ungoverned.
            sys.stderr.write(f"[guardian] internal error: {type(e).__name__}\n")
            sys.stderr.flush()
            if not self._answered:
                # The request's own id when it parsed and passed the id rule, else null.
                self._respond(500, internal_error_envelope(self._answer_id))

    def _serve(self) -> None:
        # Oversized requests are rejected before the body is read.
        # A missing, negative, or non-integer length is refused before any read: a negative one would make the
        # read wait for EOF, and a missing one gives nothing to bound the read with.
        raw_length = self.headers.get("Content-Length")
        # 1*DIGIT in ASCII only (RFC 9110). int() would also take +10, " 10 ", 1_0, and non-ASCII digits.
        # More digits than the body cap has is refused before int(), which raises past 4,300 digits.
        length = (int(raw_length) if raw_length is not None and _CONTENT_LENGTH.fullmatch(raw_length)
                  and len(raw_length) <= len(str(MAX_REQUEST_BODY_BYTES)) else -1)
        if length < 0:
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "Invalid Request: missing or invalid Content-Length"}})
            return
        if length > MAX_REQUEST_BODY_BYTES:
            self._respond(413, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600,
                                          "message": f"Request body {length} bytes exceeds {MAX_REQUEST_BODY_BYTES} cap"}})
            return
        body = self._read_body(length)
        try:
            request = json.loads(body.decode("utf-8"))
        except (ValueError, RecursionError):
            # ValueError covers a body that isn't UTF-8 or JSON and an integer too long to parse. RecursionError is a
            # body nested past the parser's limit. Each is a parse error, never a dropped connection.
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "Parse error"}})
            return

        # One extraction for the log line too. A request whose structure is wrong logs as invalid, and
        # handle_request answers it.
        read = read_request(request)
        self._answer_id = read.id
        fields = read.fields
        if fields is None:
            method = request.get("method") if isinstance(request, dict) else None
            sys.stderr.write(f"[guardian] invalid request {_log_value(method, 40)}: {read.problem}\n")
        else:
            sys.stderr.write(f"[guardian] {_log_value(fields.method, 40)} session={_log_value(fields.session_id)} "
                             f"req={_log_value(fields.request_id)}\n")
        sys.stderr.flush()

        response = handle_request(request, read)
        result = (response or {}).get("result") or {}
        decision = result.get("decision")
        if decision:
            tail = ""
            if decision == "deny":
                tail = f" — {result.get('reasoning', '')[:80]}"
            sys.stderr.write(
                f"[guardian] → {decision}{tail}\n"
            )
            sys.stderr.flush()
        self._respond(200, response)

    def _read_body(self, length: int) -> bytes:
        """Read the body within one deadline for the whole read, so a client dripping one byte per interval
        can't hold this thread past BODY_READ_SECONDS. A short body ends at EOF and fails to parse later."""
        deadline = time.monotonic() + BODY_READ_SECONDS
        chunks, remaining = [], length
        while remaining > 0:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("the request body passed its read deadline")
            self.connection.settimeout(min(left, self.timeout) if self.timeout else left)
            chunk = self.rfile.read1(min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self._answered = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    # §10: every request and response is signed, so the Guardian starts only with a usable secret and label.
    try:
        load_signing_material()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(
            f"[guardian] REFUSING TO START: {e}\n"
            "  Configure a secret of at least 32 bytes and the label that names it:\n"
            "    ACS_HMAC_SECRET_FILE=/path/to/key   (preferred; chmod 600)\n"
            "    ACS_HMAC_KEY_ID=<label>             (the same label the adapters use)\n"
            "  Generate a key:\n"
            "    openssl rand -hex 32 > /etc/acs/hmac.key && chmod 600 /etc/acs/hmac.key\n"
        )
        return 1

    global OPA_CONFIG
    if policy_backend_name() != POLICY_BACKEND_NAME:
        # The name is read once, at import. A different value now would be silently ignored, so startup stops.
        sys.stderr.write(f"[guardian] REFUSING TO START: {POLICY_BACKEND_ENV} changed after import "
                         f"(was {POLICY_BACKEND_NAME!r}, now {policy_backend_name()!r}). Restart the process "
                         "with the setting you want.\n")
        return 1
    if POLICY_BACKEND_NAME:
        from acs.guardian import opa_backend
        backend_problem = opa_backend.backend_problem(POLICY_BACKEND_NAME)
        if backend_problem:
            sys.stderr.write(f"[guardian] REFUSING TO START: {backend_problem}\n")
            return 1
        OPA_CONFIG = opa_backend.load_config()

    class ReusableServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ReusableServer((args.host, args.port), GuardianHandler) as httpd:
        # --port 0 binds an OS-assigned port; announce the real one on
        # stdout so a parent process can read it (no pre-pick bind race).
        port = httpd.server_address[1]
        sys.stdout.write(f"ACS_GUARDIAN_LISTENING port={port}\n")
        sys.stdout.flush()
        sys.stderr.write(f"[guardian] listening on {args.host}:{port} (case-insensitive-tool-policy)\n")
        if OPA_CONFIG is not None:
            opa_url = opa_backend.redact_url(OPA_CONFIG.url)
            sys.stderr.write(f"[guardian] tool calls and tool results go to OPA at {opa_url} "
                             "(lab convention, issue #531)\n")
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
