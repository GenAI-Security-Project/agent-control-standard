"""
Shared test harness for ACS adapter tests.

Test files across `adapters/` (and `adapters/<adapter>/tests/`) have
historically duplicated ~50 lines of boilerplate each: free-port
allocation, Guardian-spawn waiting, envelope construction, schema
validation, ref-resolver setup. This module is the single home for
those helpers — import what you need rather than redefining.

Usage from any test file:

    from acs.testing.harness import (
        launch_guardian, wait_port,
        make_envelope, validate_request_envelope, validate_response_envelope,
        ProgrammableGuardian,
    )

The harness has no opinion on `unittest.TestCase` vs other runners —
it's pure functions and a context manager. Plug it into whatever
framework you're using.

"""
from __future__ import annotations

import datetime
import json
import os
import re
import select
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from acs import client
from acs import core
from acs.core import schemas_dir

_HERE = Path(__file__).resolve().parent
# The ACS_HMAC_KEY_ID the test setups configure, and the label the test Guardian signs with by default.
TEST_KEY_ID = "test-key"


# ────────────────────────────────────────────────────────────────────
# Port + readiness
# ────────────────────────────────────────────────────────────────────

def wait_port(host: str, port: int, *, timeout: float = 5.0) -> None:
    """Block until something is listening on host:port, or raise.

    NOTE: this cannot tell OUR process from a port thief — Guardian
    spawns must use launch_guardian(), whose child binds its own port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server not up on {host}:{port} after {timeout}s")


def launch_guardian(*, env: dict | None = None,
                    timeout: float = 5.0) -> tuple[subprocess.Popen, int]:
    """Start example_guardian on an OS-assigned port it binds itself.

    The child binds --port 0 and announces the assigned port on stdout, so
    the returned port is owned by the spawned process by construction — a
    pre-picked port could be bound by anything, including another Guardian.
    Returns (process, port); caller terminates the process.
    """
    proc = subprocess.Popen(
        [sys.executable, str(GUARDIAN_SCRIPT), "--port", "0"],
        env=env if env is not None else os.environ.copy(),
        stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )

    line = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        readable, _, _ = select.select([proc.stdout], [], [], 0.2)
        if readable:
            line = proc.stdout.readline()
            break
        if proc.poll() is not None:
            break
    m = re.match(r"ACS_GUARDIAN_LISTENING port=(\d+)", line)
    if m and proc.poll() is None:
        return proc, int(m.group(1))
    stderr_tail = ""
    if proc.poll() is not None:
        stderr_tail = proc.stderr.read()[-500:]
    else:
        proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
    raise RuntimeError(
        "example_guardian did not announce its port "
        f"(exit={proc.poll()!r}, line={line!r}) {stderr_tail}")


# ────────────────────────────────────────────────────────────────────
# Envelope construction
# ────────────────────────────────────────────────────────────────────

def make_envelope(
    method: str,
    payload: dict | None = None,
    *,
    session_id: str | None = None,
    request_id: str | None = None,
    timestamp: str | None = None,
    agent_id: str = "test",
    platform: str = "test",
    sign_with_secret: str | bytes | None = None,
    key_id: str = TEST_KEY_ID,
) -> dict:
    """Build a canonical request envelope ready for the wire.

    Pass `sign_with_secret` to attach an HMAC-SHA256 signature using
    the same HKDF-per-session-key derivation the real adapters use.
    Pass None to leave the envelope unsigned (used for handshake/hello,
    system/ping, or to test the unsigned-rejection path).
    """
    sid = session_id or str(uuid.uuid4())
    env = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id or str(uuid.uuid4()),
            "timestamp": timestamp or core.iso8601_now(),
            "metadata": {
                "agent_id": agent_id,
                "session_id": sid,
                "platform": platform,
            },
            "payload": payload or {},
        },
    }
    if sign_with_secret is not None:
        secret = sign_with_secret.encode() if isinstance(sign_with_secret, str) else sign_with_secret
        key = core.derive_session_key(secret, sid)
        client.sign_envelope(env, key=key, session_id=sid, key_id=key_id)
    return env


def claude_code_event(hook_event_name: str, *, session_id: str | None = None,
                       **extra: Any) -> dict:
    """Build a Claude Code hook event matching the framework's stdin schema.

    Use this for `subprocess`-spawning adapter tests so every fixture
    has the same shape.
    """
    base = {
        "session_id": session_id or str(uuid.uuid4()),
        "transcript_path": "/tmp/test_transcript.jsonl",
        "cwd": "/tmp/test_work",
        "hook_event_name": hook_event_name,
    }
    if hook_event_name in ("PreToolUse", "PostToolUse", "Stop"):
        base["permission_mode"] = "default"
    base.update(extra)
    return base


# ────────────────────────────────────────────────────────────────────
# Schema validation
# ────────────────────────────────────────────────────────────────────

def _default_spec_dir() -> Path:
    return schemas_dir(os.environ.get("ACS_SPEC_DIR"))


def build_local_resolver(schema_name: str, *, spec_dir: Path | None = None):
    """Return (schema_dict, RefResolver) for `schema_name` under spec_dir.

    Populates the resolver's `store` so `$ref` to sibling schemas
    resolves locally (no network round-trip to acs.org).
    """
    from jsonschema.validators import RefResolver
    spec_dir = spec_dir or _default_spec_dir()
    store: dict[str, dict] = {}
    for path in spec_dir.glob("*.json"):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if "$id" in doc:
            store[doc["$id"]] = doc
        store[path.as_uri()] = doc
    hooks_dir = spec_dir / "hooks"
    if hooks_dir.exists():
        for path in hooks_dir.glob("*.json"):
            try:
                doc = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if "$id" in doc:
                store[doc["$id"]] = doc
            store[path.as_uri()] = doc

    schema_path = spec_dir / schema_name
    schema = json.loads(schema_path.read_text())
    resolver = RefResolver(
        base_uri=schema_path.as_uri(),
        referrer=schema,
        store=store,
    )
    return schema, resolver


def _validate(envelope: dict, schema_name: str,
              spec_dir: Path | None = None) -> list[str]:
    from jsonschema import Draft202012Validator
    schema, resolver = build_local_resolver(schema_name, spec_dir=spec_dir)
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(envelope)
    ]


def validate_request_envelope(envelope: dict, *,
                               spec_dir: Path | None = None) -> list[str]:
    """Validate against request-envelope.json. Returns list of error
    messages; empty list means valid."""
    return _validate(envelope, "request-envelope.json", spec_dir=spec_dir)


def validate_response_envelope(envelope: dict, *,
                                spec_dir: Path | None = None) -> list[str]:
    """Validate against response-envelope.json. Returns list of error
    messages; empty list means valid."""
    return _validate(envelope, "response-envelope.json", spec_dir=spec_dir)


def validate_hook_payload(payload: dict, hook_schema: str, *,
                           spec_dir: Path | None = None) -> list[str]:
    """Validate a hook payload (e.g., `hooks/tool-call-request.json`).
    Returns list of error messages; empty list means valid."""
    return _validate(payload, f"hooks/{hook_schema}", spec_dir=spec_dir)


# ────────────────────────────────────────────────────────────────────
# HTTP helpers
# ────────────────────────────────────────────────────────────────────

def post_envelope(url: str, envelope: dict, *, timeout: float = 5.0) -> dict:
    """POST an envelope to a Guardian URL and return the parsed response.

    Raises urllib errors if the Guardian is unreachable — callers can
    catch to test fail-posture behavior.
    """
    body = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ────────────────────────────────────────────────────────────────────
# Guardian lifecycle
# ────────────────────────────────────────────────────────────────────

GUARDIAN_SCRIPT = _HERE.parent / "guardian" / "example_guardian.py"


# A ServerHello for a session whose handshake already happened, evaluating every method the reference adapters send.
NEGOTIATED_HELLO = {
    "negotiated_version": "0.1.0",
    "methods_evaluated": ["steps/sessionStart", "steps/sessionEnd", "steps/userMessage", "steps/agentResponse",
                          "steps/turnStart", "steps/turnEnd", "steps/toolCallRequest", "steps/toolCallResult",
                          "steps/subagentStart", "steps/preCompact"],
    "selected_transport": "http",
    "timeout_config": {"default_ms": 5000},
    "on_decision_failure": "proceed",
}


def signing_env() -> dict[str, str]:
    """The test secret and the label that names it, as the adapters and the example Guardian read them (§10)."""
    return {"ACS_HMAC_SECRET": ProgrammableGuardian.DEFAULT_TEST_HMAC_SECRET, "ACS_HMAC_KEY_ID": TEST_KEY_ID}


def sign_for_test(envelope: dict) -> dict:
    """Sign a hand-built request with the test secret under its label, as an adapter would (§10)."""
    session_id = envelope["params"]["metadata"]["session_id"]
    key = core.derive_session_key(ProgrammableGuardian.DEFAULT_TEST_HMAC_SECRET.encode(), session_id)
    return core.sign_with_key(envelope, key, key_id=TEST_KEY_ID)


def seed_negotiated_session(cache_dir: str | Path, *, session_id: str, guardian_url: str,
                            hmac_secret: str | None = None,
                            server_hello: dict | None = None) -> None:
    """Store a negotiated decision for a session, as its first handshake would, so a test can exercise its steps."""
    from acs.client._handshake import store_session_decision
    decision = client.Negotiated(dict(server_hello or NEGOTIATED_HELLO))
    store_session_decision(Path(cache_dir), session_id, guardian_url, decision,
                           (hmac_secret or "").encode())


class ProgrammableGuardian:
    """Test Guardian whose response can be programmed per method.

    Records every received request and every sent response so tests
    can assert on the wire-level exchange. By default verifies HMAC
    signatures (using TEST_HMAC_SECRET) and returns allow for every
    method. Replace `handlers[method]` with a callable returning a
    result dict (or an error dict with `code` + `message`) to customize.
    """

    DEFAULT_TEST_HMAC_SECRET = "shared-test-harness-secret-not-for-production"

    def __init__(self, *, hmac_secret: str | None = None,
                  sign_responses: bool = True, port: int = 0, threaded: bool = False,
                  key_id: str = TEST_KEY_ID) -> None:
        import http.server
        self.hmac_secret = hmac_secret or self.DEFAULT_TEST_HMAC_SECRET
        # The label of hmac_secret (§10): requests under another label get an unsigned SIGNATURE_INVALID.
        self.key_id = key_id
        self.sign_responses = sign_responses
        self.received: list[dict] = []
        self.sent: list[dict] = []
        self.lock = threading.Lock()
        self.handlers: dict[str, Callable[[dict], dict]] = {
            "handshake/hello": self._default_handshake,
            "__default__":     self._default_allow,
        }
        self.delay_s: float = 0.0
        # Optional callback(raw_bytes, parsed_dict) run on every received
        # request before the response is built. CaptureGuardian uses it
        # as the schema-validation oracle. None = no-op. Any exception it
        # raises is recorded here (not swallowed) so a validator bug is
        # loud, not silent.
        self.on_request = None
        self.on_request_errors: list[str] = []
        self._http = http.server
        # Port 0 takes an OS-assigned port; a fixed port brings a stopped Guardian back at the same URL.
        # threaded serves requests concurrently, as a deployed Guardian does.
        server = self._http.ThreadingHTTPServer if threaded else self._http.HTTPServer
        self._server = server(("127.0.0.1", port), self._make_handler_cls())
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/acs"

    def start(self) -> None:
        self._thread.start()
        wait_port("127.0.0.1", self.port)

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def reset(self) -> None:
        with self.lock:
            self.received.clear()
            self.sent.clear()

    def methods_seen(self) -> list[str]:
        with self.lock:
            return [r.get("method", "") for r in self.received]

    def last_envelope(self) -> dict | None:
        with self.lock:
            return self.received[-1] if self.received else None

    def envelopes_for(self, method: str) -> list[dict]:
        with self.lock:
            return [r for r in self.received if r.get("method") == method]

    # ─── Default handlers ───

    def _default_handshake(self, req: dict) -> dict:
        # The HTTP handler wraps this ServerHello in result and signs the envelope.
        offered = req["params"]["payload"]
        return {
            "negotiated_version": "0.1.0",
            "methods_evaluated": offered.get("methods_implemented", []),
            "selected_transport": next((t for t in offered.get("transports_supported", []) if t != "stdio"),
                                       "http"),
            "signature_algorithms_supported": ["HMAC-SHA256"],
            "timeout_config": {"default_ms": 5000},
            "skew_window_ms": 300000,
            "on_decision_failure": "proceed",
            "profiles_accepted": [p for p in offered.get("profiles_supported", []) if p == "acs-core"],
        }

    def _default_allow(self, req: dict) -> dict:
        return {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "decision": "allow",
            "chain_hash": "0" * 64,
        }

    def _make_handler_cls(self):
        guardian = self

        class Handler(self._http.BaseHTTPRequestHandler):
            def do_POST(self_h):  # noqa: N802
                length = int(self_h.headers.get("Content-Length", "0"))
                raw = self_h.rfile.read(length)
                req = json.loads(raw.decode())
                with guardian.lock:
                    guardian.received.append(req)
                # Raw-capture hook (CaptureGuardian) validates the
                # unmodified bytes against the canonical schemas; a hook
                # exception is recorded so assert_all_valid() fails while
                # the wire stays alive.
                if guardian.on_request is not None:
                    try:
                        guardian.on_request(raw, req)
                    except Exception as e:  # noqa: BLE001
                        with guardian.lock:
                            guardian.on_request_errors.append(repr(e))
                if guardian.delay_s > 0:
                    time.sleep(guardian.delay_s)

                method = req.get("method", "")
                # system/ping is the only signature-exempt method (§13);
                # the handshake key derives from secret + session_id, both
                # known pre-handshake.
                if method != "system/ping":
                    sid = req.get("params", {}).get("metadata", {}).get("session_id", "")
                    key = core.derive_session_key(
                        guardian.hmac_secret.encode(), sid)
                    if not client.verify_signature(req, key=key, session_id=sid, key_id=guardian.key_id):
                        self_h._reply({
                            "jsonrpc": "2.0", "id": req.get("id"),
                            "error": {"code": -32004, "message": "SIGNATURE_INVALID"},
                        })
                        return

                handler = guardian.handlers.get(method, guardian.handlers["__default__"])
                result_or_error = handler(req)
                container = ("error" if "code" in result_or_error and "message" in result_or_error
                             else "result")
                resp = {"jsonrpc": "2.0", "id": req.get("id"), container: result_or_error}
                # Errors are signed too under ACS-Core (§10).
                if guardian.sign_responses:
                    sid = req["params"]["metadata"]["session_id"]
                    key = core.derive_session_key(
                        guardian.hmac_secret.encode(), sid)
                    client.sign_envelope(resp, key=key, session_id=sid, key_id=guardian.key_id)
                self_h._reply(resp)

            def _reply(self_h, resp: dict):
                with guardian.lock:
                    guardian.sent.append(resp)
                body = json.dumps(resp).encode()
                self_h.send_response(200)
                self_h.send_header("Content-Type", "application/json")
                self_h.send_header("Content-Length", str(len(body)))
                self_h.end_headers()
                try:
                    self_h.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    # A negotiated-timeout test intentionally closes the
                    # client socket before the delayed Guardian response.
                    # That is the behavior under test, not a server failure;
                    # keep the harness from printing a misleading traceback.
                    pass

            def log_message(self_h, *a, **kw):
                return

        return Handler
