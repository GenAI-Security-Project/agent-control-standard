"""
Mock ACS Guardians — real servers speaking the ACS v0.1.0 wire, used so the conformance
suite can self-demonstrate before it is pointed at the reference AGT Guardian.

Each Guardian is PROTOCOL-conformant (well-formed ACS envelopes, handshake, ping,
decision shapes). They differ only in their *policy* for a shared cumulative grant, which
is what the invariant layer measures:

  stateless     - checks only confirmed consumption; no reservation. The naive baseline.
  reserve-only  - atomic reservation, but on a lost acknowledgement it auto-releases the
                  pending reservation (the subtle bug: passes concurrency, leaks later).
  holding       - atomic reservation + binds consumption to a stable operation_id + holds
                  a pending reservation on a lost ack (never auto-releases). The correct one.

Grant model: a session+grant has a cumulative limit (default 100). A budget.consume tool
call draws `amount`. The point of the suite is that all three speak ACS perfectly, yet
only `holding` actually keeps the committed total at or under the limit.

Run one:  python3 guardian.py --policy holding --port 8801
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root, for acs_sig
import acs_sig  # noqa: E402  (§10 message authentication: JCS + HKDF + HMAC)

ACS_VERSION = "0.1.0"
DEFAULT_LIMIT = 100
RESERVED, CONSUMED, RELEASED = "reserved", "consumed", "released"

# §10 message authentication (this mock supports the HMAC-SHA256 baseline). One configured
# secret under a key_id, the ACS §10 replay window, and a per-session replay memory.
SKEW_MS = 300000                                       # ServerHello skew_window_ms (spec default, 5 min)
SECRETS = {acs_sig.TEST_KEY_ID: acs_sig.TEST_SECRET}   # key_id -> shared secret


def _within_skew(timestamp: str, skew_ms: int) -> bool:
    """§10.3: is `timestamp` within skew_ms of now, in either direction? A malformed or
    missing timestamp cannot be shown fresh, so it is treated as outside the window."""
    try:
        ts = datetime.fromisoformat(timestamp)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    delta_ms = abs((datetime.now(timezone.utc) - ts).total_seconds()) * 1000.0
    return delta_ms <= skew_ms


class Policy:
    """Per-(session, grant) authorization state and the decision logic for one policy."""

    def __init__(self, name: str, limit: int = DEFAULT_LIMIT):
        self.name = name
        self.limit = limit
        self.lock = threading.Lock()
        # keyed by (session_id, grant_id)
        self.reservations: dict[tuple, dict] = {}   # -> {operation_id: {"amount","state"}}
        self.confirmed: dict[tuple, dict] = {}       # stateless: {operation_id: amount}
        self.pending_amt: dict[tuple, dict] = {}     # requested amount per op (all policies)
        self.seen_rids: dict[str, set] = {}          # §10.3: request_ids seen per session
        self.seen_nonces: dict[str, set] = {}        # §10.3: nonces seen per session

    def _key(self, session_id, grant_id):
        return (session_id, grant_id)

    def check_signature(self, envelope: dict) -> tuple | None:
        """§10 / §10.3 verification for a signed request. Returns None if it passes, else an
        (error_code, message, data) triple. Order: signature validity, then timestamp window,
        then replay — so a request isolating one failure gets that failure's code. Only called
        when a signature is present; v0.1 leaves unsigned requests to the baseline flow."""
        params = envelope.get("params") or {}
        sig = params.get("signature") or {}
        secret = SECRETS.get(sig.get("key_id"))
        if secret is None:
            return (acs_sig.SIGNATURE_INVALID, "unknown key_id", None)   # MUST NOT fall back (§10)
        if not acs_sig.verify_envelope(envelope, secret):
            return (acs_sig.SIGNATURE_INVALID, "signature does not verify over the canonical envelope", None)
        if not _within_skew(params.get("timestamp"), SKEW_MS):
            return (acs_sig.TIMESTAMP_OUT_OF_WINDOW, "timestamp outside the skew window",
                    {"skew_window_ms": SKEW_MS})
        session = (params.get("metadata") or {}).get("session_id", "default")
        rid, nonce = params.get("request_id"), params.get("nonce")
        with self.lock:
            rids = self.seen_rids.setdefault(session, set())
            nonces = self.seen_nonces.setdefault(session, set())
            if rid in rids:
                return (acs_sig.REPLAY_DETECTED, "duplicate request_id within session", None)
            if nonce is not None and nonce in nonces:
                return (acs_sig.REPLAY_DETECTED, "duplicate nonce within session", None)
            rids.add(rid)
            if nonce is not None:
                nonces.add(nonce)
        return None

    def decide_consume(self, session_id, grant_id, operation_id, amount):
        """Return (decision, reasoning, reason_codes) for a budget.consume request."""
        k = self._key(session_id, grant_id)
        with self.lock:
            self.pending_amt.setdefault(k, {})[operation_id] = amount

            if self.name == "stateless":
                committed = sum(self.confirmed.get(k, {}).values())
                if committed + amount > self.limit:
                    return "deny", "cumulative limit would be exceeded", ["cumulative_limit_exceeded"]
                return "allow", "within confirmed budget", []

            # reserving policies (reserve-only, holding)
            res = self.reservations.setdefault(k, {})
            existing = res.get(operation_id)
            if existing and existing["state"] in (RESERVED, CONSUMED):
                # bound to a stable operation_id: a retry of a live operation is a duplicate
                return "deny", "operation already reserved/consumed", ["duplicate_operation"]
            live = sum(r["amount"] for r in res.values() if r["state"] in (RESERVED, CONSUMED))
            if live + amount > self.limit:
                return "deny", "reservation would exceed the grant", ["cumulative_limit_exceeded"]
            res[operation_id] = {"amount": amount, "state": RESERVED}
            return "allow", "reserved against the grant", []

    def on_result(self, session_id, grant_id, operation_id, status):
        """Apply a toolCallResult. status: committed | failed | unresolved (lost ack)."""
        k = self._key(session_id, grant_id)
        with self.lock:
            if self.name == "stateless":
                if status == "committed":
                    amt = self.pending_amt.get(k, {}).get(operation_id, 0)
                    self.confirmed.setdefault(k, {})[operation_id] = amt
                return
            res = self.reservations.get(k, {})
            r = res.get(operation_id)
            if not r:
                return
            if status == "committed":
                r["state"] = CONSUMED
            elif status == "failed":
                r["state"] = RELEASED
            elif status == "unresolved":
                # the ONLY difference that matters between the two reserving policies
                if self.name == "reserve-only":
                    r["state"] = RELEASED          # auto-release: frees budget already spent
                # holding: leave it RESERVED (hold the pending reservation)


class GuardianHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _result(self, req_id, acs_request_id, decision, reasoning, reason_codes):
        result = {"type": "final", "acs_version": ACS_VERSION, "request_id": acs_request_id,
                  "decision": decision}
        if reasoning:
            result["reasoning"] = reasoning
        if reason_codes:
            result["reason_codes"] = reason_codes
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _error(self, req_id, code, message, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            env = json.loads(self.rfile.read(n).decode())
        except Exception as e:
            return self._send(self._error(None, -32700, f"parse error: {e}"), 400)

        req_id = env.get("id")
        method = env.get("method", "")
        params = env.get("params", {}) or {}
        acs_rid = params.get("request_id")
        meta = params.get("metadata", {}) or {}
        session_id = meta.get("session_id", "default")
        payload = params.get("payload", {}) or {}
        pol: Policy = self.server.policy  # type: ignore[attr-defined]

        # §10 message authentication: verify any signed request before acting on it.
        # system/ping is signature-exempt (§13); the handshake carries none; unsigned
        # requests fall through to the baseline flow (v0.1 signatures are optional).
        if params.get("signature") is not None and method not in ("handshake/hello", "system/ping"):
            err = pol.check_signature(env)
            if err:
                return self._send(self._error(req_id, err[0], err[1], err[2]), 400)

        if method == "handshake/hello":
            # A schema-valid ServerHello: the four fields handshake.json's $def requires,
            # plus a fail-closed posture, the HMAC-SHA256 baseline this mock verifies (§10),
            # and the advertised replay window (§10.3).
            return self._send({"jsonrpc": "2.0", "id": req_id,
                               "result": {"negotiated_version": ACS_VERSION,
                                          "methods_evaluated": ["steps/toolCallRequest",
                                                                "steps/toolCallResult"],
                                          "selected_transport": "http",
                                          "timeout_config": {"default_ms": 5000},
                                          "on_decision_failure": "deny",
                                          "signature_algorithms_supported": ["HMAC-SHA256"],
                                          "skew_window_ms": SKEW_MS,
                                          "profiles_accepted": ["ACS-Core"]}})
        if method == "system/ping":
            return self._send({"jsonrpc": "2.0", "id": req_id, "result": {"status": "ok"}})

        if method == "steps/toolCallRequest":
            tool = (payload.get("tool") or {}).get("name")
            args = {k: v.get("value") for k, v in (payload.get("arguments") or {}).items()}
            if tool == "budget.consume":
                d, why, codes = pol.decide_consume(session_id, args.get("grant_id"),
                                                    args.get("operation_id"), args.get("amount"))
                return self._send(self._result(req_id, acs_rid, d, why, codes))
            # unknown tool: default-deny is the safe posture
            return self._send(self._result(req_id, acs_rid, "deny", "unknown tool", ["unknown_tool"]))

        if method == "steps/toolCallResult":
            pol.on_result(session_id, payload.get("grant_id"),
                          payload.get("operation_id"), payload.get("status"))
            return self._send(self._result(req_id, acs_rid, "allow", "result recorded", []))

        # ACS-Core: an undeclared method must be refused
        return self._send(self._error(req_id, -32601, f"method not found: {method}"), 404)


def make_server(policy_name: str, port: int, limit: int = DEFAULT_LIMIT) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), GuardianHandler)
    srv.policy = Policy(policy_name, limit)  # type: ignore[attr-defined]
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", choices=["stateless", "reserve-only", "holding"], required=True)
    ap.add_argument("--port", type=int, default=8801)
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = ap.parse_args()
    srv = make_server(args.policy, args.port, args.limit)
    print(f"ACS mock Guardian '{args.policy}' listening at http://127.0.0.1:{args.port}/acs (limit {args.limit})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
