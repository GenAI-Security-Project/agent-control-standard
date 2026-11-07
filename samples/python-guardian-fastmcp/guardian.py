# SPDX-License-Identifier: Apache-2.0
"""Minimal ACS Guardian Agent sample (Python, stdlib only).

Speaks specification/v0.1.0 over POST /acs:
  handshake/hello      -> ServerHello (fail-closed posture declared)
  system/ping          -> allow (never advances the chain, per spec)
  steps/toolCallRequest -> allow | deny via a pluggable policy fn

Every envelope is hash-chained per session into a JSONL log. Policy
exceptions deny (fail-closed). Unknown methods and version mismatches
are JSON-RPC errors, never silent allows.

Run:  python guardian.py [--port 8787] [--log .acs/envelopes.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

ACS_VERSION = "0.1.0"

# method -> namespace allowlist (v0.1 surface of this sample)
_KNOWN_METHODS = {"handshake/hello", "system/ping", "steps/toolCallRequest"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _chain(prev: Optional[str], envelope: dict) -> str:
    return hashlib.sha256((prev or "GENESIS").encode() + _canonical(envelope)).hexdigest()


PolicyFn = Callable[[str, dict, dict], tuple]
"""policy(tool_name, arguments, context) -> (decision, reasoning[, reason_codes]).

decision: "allow" | "deny". Anything else is treated as deny. ``arguments``
arrives unwrapped (plain values), so a policy author never has to think about
the ACS ``{"value": ...}`` envelope form. Returning a third element is
optional; when present it becomes ``result.reason_codes``, whose vocabulary
is free in v0.1."""


def arguments_conform(arguments: Any) -> bool:
    """True when every argument is an object carrying a ``value`` key.

    ACS v0.1 requires this shape so provenance can attach per argument
    (specification/v0.1.0/hooks/tool-call-request.json). A Guardian that
    accepted raw scalars here would be validating something the standard
    does not describe.
    """
    return isinstance(arguments, dict) and all(
        isinstance(v, dict) and "value" in v for v in arguments.values())


def unwrap_arguments(arguments: dict) -> dict:
    """Strip the ACS ``{"value": ...}`` wrapper for the policy layer."""
    return {k: v.get("value") for k, v in arguments.items()}


def sample_policy(tool_name: str, arguments: dict, context: dict) -> tuple:
    """Demo policy: deny destructive tool names and path escapes."""
    lowered = tool_name.lower()
    if any(p in lowered for p in ("delete", "drop", "destroy", "rmtree", "format", "wipe")):
        return ("deny",
                f"tool {tool_name!r} matches the destructive-name blocklist",
                ["destructive_tool"])
    blob = json.dumps(arguments, default=str)
    if ".." in blob or re.search(r"ssh-rsa\s+[A-Za-z0-9+/=]+", blob):
        return ("deny", "arguments carry path-escape or key material",
                ["path_escape_or_key_material"])
    return "allow", f"tool {tool_name!r} not on any deny rule"


def _error(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _result(req_id: Any, request_id: str, decision: str,
            reasoning: str = "", reason_codes: Optional[list] = None) -> dict:
    res: dict[str, Any] = {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "decision": decision,
    }
    if reasoning:
        res["reasoning"] = reasoning
    if reason_codes:
        res["reason_codes"] = reason_codes
    return {"jsonrpc": "2.0", "id": req_id, "result": res}


class Guardian:
    """Stateful Guardian: handshake, chain log, policy dispatch."""

    def __init__(self, policy: PolicyFn = sample_policy,
                 log_path: str = ".acs/envelopes.jsonl") -> None:
        self.policy = policy
        self.log_path = log_path
        self._chains: dict[str, str] = {}

    def _record(self, session_id: str, envelope: dict, advance: bool) -> str:
        head = self._chains.get(session_id)
        digest = _chain(head, envelope)
        if advance:
            self._chains[session_id] = digest
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"chain_hash": digest, "envelope": envelope}) + "\n")
        except OSError:
            pass  # logging must never break enforcement
        return digest

    def handle(self, envelope: Any) -> dict:
        """Dispatch one decoded JSON-RPC envelope. Never raises."""
        try:
            return self._dispatch(envelope)
        except Exception as exc:  # fail-closed on Guardian bugs too
            req_id = envelope.get("id") if isinstance(envelope, dict) else None
            return _error(req_id, -32603, "guardian internal error (fail-closed)",
                          {"detail": str(exc)[:200]})

    def _dispatch(self, envelope: Any) -> dict:
        if not isinstance(envelope, dict):
            return _error(None, -32700, "parse error: envelope must be an object")
        req_id = envelope.get("id")
        if envelope.get("jsonrpc") != "2.0" or not isinstance(envelope.get("method"), str):
            return _error(req_id, -32600, "invalid request envelope")
        method = envelope["method"]
        params = envelope.get("params")
        if not isinstance(params, dict):
            return _error(req_id, -32600, "params must be an object")
        if params.get("acs_version") != ACS_VERSION:
            return _error(req_id, -32001, "UNSUPPORTED_VERSION",
                          {"supported": [ACS_VERSION]})
        metadata = params.get("metadata")
        if not isinstance(metadata, dict) or "agent_id" not in metadata \
                or "session_id" not in metadata:
            return _error(req_id, -32600, "metadata.agent_id/session_id required")
        session_id = str(metadata["session_id"])
        request_id = str(params.get("request_id", "") or uuid.uuid4())

        if method == "handshake/hello":
            hello = {
                "negotiated_version": ACS_VERSION,
                "methods_evaluated": sorted(_KNOWN_METHODS),
                "selected_transport": "http",
                "timeout_config": {"default_ms": 5000},
                "on_decision_failure": "deny",
            }
            self._record(session_id, envelope, advance=True)
            return {"jsonrpc": "2.0", "id": req_id, "result": hello}

        if method == "system/ping":
            # Spec: always allow, never advance the chain.
            self._record(session_id, envelope, advance=False)
            payload: dict[str, Any] = {"echo": params.get("payload", {}).get("echo")}
            out = _result(req_id, request_id, "allow")
            out["result"]["payload"] = payload
            return out

        if method != "steps/toolCallRequest":
            return _error(req_id, -32601, f"method not implemented: {method}")

        payload = params.get("payload")
        if not isinstance(payload, dict):
            return _error(req_id, -32600, "payload must be an object")
        tool = payload.get("tool", {})
        tool_name = tool.get("name") if isinstance(tool, dict) else None
        arguments = payload.get("arguments")
        if not tool_name:
            return _error(req_id, -32600, "payload.tool.name required")
        if not arguments_conform(arguments):
            return _error(
                req_id, -32600,
                "payload.arguments must map each name to an object carrying a "
                "'value' key (specification/v0.1.0/hooks/tool-call-request.json)")

        self._record(session_id, envelope, advance=True)
        codes: Optional[list] = None
        try:
            verdict = self.policy(
                tool_name, unwrap_arguments(arguments),
                {"agent_id": metadata.get("agent_id"), "session_id": session_id})
            decision, reasoning = verdict[0], verdict[1]
            if len(verdict) > 2:
                codes = list(verdict[2]) or None
        except Exception as exc:
            decision = "deny"
            reasoning = f"policy error (fail-closed): {exc}"[:300]
            codes = ["policy_error"]
        if decision not in ("allow", "deny"):
            reasoning = f"unknown policy verdict {decision!r} treated as deny"
            decision, codes = "deny", ["unknown_verdict"]
        return _result(req_id, request_id, decision, reasoning, codes)


class _Handler(BaseHTTPRequestHandler):
    guardian: Guardian = Guardian()  # replaced per serve()

    def log_message(self, *args: Any) -> None:  # quiet stdlib server
        pass

    def do_POST(self) -> None:
        if self.path != "/acs":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        try:
            envelope = json.loads(self.rfile.read(length) or b"null")
        except (ValueError, OSError):
            envelope = None
        body = _canonical(self.guardian.handle(envelope))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port: int = 8787, host: str = "127.0.0.1",
          policy: PolicyFn = sample_policy,
          log_path: str = ".acs/envelopes.jsonl") -> ThreadingHTTPServer:
    """Start the Guardian. Binds loopback by default (never 0.0.0.0 blindly)."""
    _Handler.guardian = Guardian(policy=policy, log_path=log_path)
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"Guardian listening at http://{host}:{port}/acs "
          f"(fail-closed posture, log {log_path})", flush=True)
    return server


def main(argv: Optional[list] = None) -> None:
    parser = argparse.ArgumentParser(description="Minimal ACS Guardian sample")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--log", default=".acs/envelopes.jsonl")
    args = parser.parse_args(argv)
    serve(args.port, args.host, log_path=args.log).serve_forever()


if __name__ == "__main__":
    main()
