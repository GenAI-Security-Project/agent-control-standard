#!/usr/bin/env python3
"""Example Guardian for testing the reference adapters, not a production Guardian; docs/guardian/README.md describes it."""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import http.server
import json
import os
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any

from acs.client import load_key_id, load_signing_material, sign_envelope, verify_signature
from acs.examples.destructive_bash import DESTRUCTIVE_SCAN_MAX_LEN, matches_destructive_bash
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
        with open(_envelope_schema_path) as _f:
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


PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/etc/", "/usr/", "/bin/", "/sbin/", "/boot/")

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
            with open(path) as f:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                except OSError:
                    pass
                try:
                    data = json.load(f)
                finally:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
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
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except OSError as e:
                    if e.errno != errno.ENOLCK:
                        raise

                merged_seen = dict(self.seen_request_ids)
                merged_nonces = dict(self.seen_nonces)
                merged_prev = self.previous_hash
                if path.exists():
                    try:
                        with open(path) as rf:
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
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
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


def evaluate_step(method: str, params: dict, request_id: str, chain_hash: str) -> dict:
    payload = params.get("payload") or {}

    base = {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "chain_hash": chain_hash,
    }

    if method == "steps/toolCallRequest":
        tool = payload.get("tool") or {}
        # Case-folded, so Claude Code's Bash, Cursor's Shell and NAT's shell meet one policy.
        tool_name_raw = tool.get("name", "")
        tool_name = tool_name_raw.lower()
        args = _unwrap_arguments(payload.get("arguments") or {})

        if tool_name == "task" and not ALLOW_SUBAGENT:
            return {**base, "decision": "deny",
                    "reasoning": "Task tool (in-process subagent) is gated by default. Set ACS_ALLOW_SUBAGENT=1 to allow.",
                    "reason_codes": ["subagent_gated"]}

        if tool_name in ("bash", "shell"):
            cmd = args.get("command", "") or ""
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

        if tool_name == "write":
            path = args.get("file_path", "")
            if any(path.startswith(p) for p in PROTECTED_PATH_PREFIXES):
                return {**base, "decision": "deny",
                        "reasoning": f"write to protected system path: {path}",
                        "reason_codes": ["protected_path"]}

        return {**base, "decision": "allow"}

    if method == "steps/subagentStart":
        # Spawns are gated as strictly as the Task tool, and a fresh intent_derivation gets its own reason code.
        derivation = (payload.get("intent_derivation") or "").lower()
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


def handle_request(request: dict) -> dict:
    method = request.get("method", "")
    request_id = request.get("id")
    params = request.get("params") or {}
    meta = params.get("metadata") or {}
    session_id = meta.get("session_id") or ""
    acs_request_id = params.get("request_id", "")
    timestamp = params.get("timestamp", "")

    # system/ping is the only unsigned method (§13), so liveness probes survive a key outage.
    if method == "system/ping":
        result = evaluate_ping(params, acs_request_id)
        envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
        return envelope

    # §10: a request under a key_id this Guardian holds no secret for gets an unsigned
    # SIGNATURE_INVALID before any other check, since no response to it can be signed.
    signature = params.get("signature")
    if isinstance(signature, dict) and signature.get("key_id") != load_key_id():
        return _error_envelope(request_id, session_id, -32004, "SIGNATURE_INVALID: unknown key_id", signed=False)

    # Validated before policy; ping and handshake have their own payload shapes.
    if (_SPEC_VALIDATION_AVAILABLE
            and method not in ("system/ping", "handshake/hello")):
        errors = list(_REQUEST_ENVELOPE_VALIDATOR.iter_errors(request))
        if errors:
            paths = "; ".join(
                f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                for e in errors[:5]
            )
            return _error_envelope(request_id, session_id, -32600,
                                   f"Invalid Request: envelope failed schema: {paths}")

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
    except GuardianError as e:
        return _error_envelope(request_id, session_id, e.code, e.message, signed=e.signed)

    payload_canonical = jcs_canonicalize(params).decode("utf-8")
    chain_hash = append_to_chain(session_id, method, acs_request_id, payload_canonical, timestamp)

    try:
        result = evaluate_step(method, params, acs_request_id, chain_hash)
    except GuardianError as e:
        return _error_envelope(request_id, session_id, e.code, e.message)

    envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
    sign_envelope(envelope, session_id=session_id)
    return envelope


class GuardianHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        # Oversized requests are rejected before the body is read.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "Invalid Content-Length"}})
            return
        if length > MAX_REQUEST_BODY_BYTES:
            self._respond(413, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600,
                                          "message": f"Request body {length} bytes exceeds {MAX_REQUEST_BODY_BYTES} cap"}})
            return
        body = self.rfile.read(length).decode("utf-8")
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "Parse error"}})
            return

        # A non-object, or a batch array, is not a v0.1 request: -32600.
        if not isinstance(request, dict):
            kind = "batch" if isinstance(request, list) else type(request).__name__
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600,
                                          "message": f"Invalid Request: expected a JSON-RPC "
                                                     f"object, got {kind} (batches unsupported in v0.1)"}})
            return

        method = request.get("method", "")
        params = request.get("params") or {}
        meta = params.get("metadata") or {}
        sys.stderr.write(
            f"[guardian] {method} session={meta.get('session_id', '?')[:8]} "
            f"req={params.get('request_id', '?')[:8]}\n"
        )
        sys.stderr.flush()

        response = handle_request(request)
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

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
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
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
