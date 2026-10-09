"""
Validating capture Guardian — the emission-conformance oracle.

Proves that each production adapter emits ACS-Core traffic passing the
canonical schemas: builder unit tests prove the builder, only the exact
bytes actually sent prove emission.

This server:
  1. Receives the adapter's real HTTP request (via ProgrammableGuardian's
     transport) and records the UNMODIFIED body bytes.
  2. Validates the envelope against request-envelope.json.
  3. Selects the payload schema from the method and validates
     params.payload against it.
  4. Independently verifies signature, timestamp, UUIDs, and metadata.
  5. Returns a valid (optionally programmable) response so the adapter
     completes its round-trip.

The schema files — NOT this server's own leniency — are the oracle. A
CaptureRecord carries every validation error found, so a test asserts
`guardian.assert_all_valid()` rather than trusting a 200 response.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import rfc8785
from test_harness import (
    ProgrammableGuardian,
    build_local_resolver,
    validate_request_envelope,
    validate_hook_payload,
)

try:
    from rfc3339_validator import validate_rfc3339
except ImportError:  # pragma: no cover
    validate_rfc3339 = None  # type: ignore[assignment]


# ---- INDEPENDENT signature verification ----
#
# Deliberately NOT acs_common's implementation — a shared bug would
# pass both sides. From-scratch HKDF-SHA256 + HMAC-SHA256 over RFC 8785,
# pinned by a known-answer vector in tests/test_capture_guardian.py.

def independent_session_key(secret: bytes, session_id: str) -> bytes:
    """HKDF-SHA256(ikm=secret, salt=0, info=session_id), 32-byte output."""
    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    return hmac.new(prk, session_id.encode("utf-8") + b"\x01",
                    hashlib.sha256).digest()


def independent_verify(envelope: dict, secret: bytes, session_id: str) -> bool:
    """Recompute the HMAC-SHA256 over JCS(envelope minus signature) and
    constant-time compare against the wire value. Container is params
    (requests), result, or error — matching §10 placement."""
    if "method" in envelope:
        container_key = "params"
    elif "error" in envelope:
        container_key = "error"
    else:
        container_key = "result"
    container = envelope.get(container_key) or {}
    sig = container.get("signature")
    if not isinstance(sig, dict):
        return False
    if sig.get("algorithm") != "HMAC-SHA256":
        return False
    provided_b64 = sig.get("value")
    if not isinstance(provided_b64, str):
        return False
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned = {**envelope, container_key: unsigned_container}
    key = independent_session_key(secret, session_id)
    expected = hmac.new(key, rfc8785.dumps(unsigned), hashlib.sha256).digest()
    try:
        provided = base64.b64decode(provided_b64, validate=True)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, provided)


# ACS method → canonical payload schema under specification/v0.1.0/hooks/.
# Methods absent here (handshake/hello, system/ping, protocols/MCP/*) get
# envelope-only validation plus their own special-casing below.
METHOD_PAYLOAD_SCHEMA: dict[str, str] = {
    "steps/sessionStart":           "session-start.json",
    "steps/sessionEnd":             "session-end.json",
    "steps/userMessage":            "user-message.json",
    "steps/agentTrigger":           "agent-trigger.json",
    "steps/toolCallRequest":        "tool-call-request.json",
    "steps/toolCallResult":         "tool-call-result.json",
    "steps/agentResponse":          "agent-response.json",
    "steps/subagentStart":          "subagent-start.json",
    "steps/subagentStop":           "subagent-stop.json",
    "steps/preCompact":             "pre-compact.json",
    "steps/postCompact":            "post-compact.json",
    "steps/knowledgeRetrieval":     "knowledge-retrieval.json",
    "steps/memoryStore":            "memory-store.json",
    "steps/memoryContextRetrieval": "memory-context-retrieval.json",
    "steps/turnStart":              "turn-start.json",
    "steps/turnEnd":                "turn-end.json",
    "steps/skillRegister":          "skill-register.json",
    "steps/skillLoad":              "skill-load.json",
    "steps/skillUnload":            "skill-unload.json",
}


@dataclass
class CaptureRecord:
    method: str
    raw: bytes
    parsed: dict
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class CaptureGuardian(ProgrammableGuardian):
    """ProgrammableGuardian + schema/invariant validation of raw bytes.

    Use:
        with CaptureGuardian() as g:
            <run the real adapter pointed at g.url() with
             ACS_HMAC_SECRET=g.hmac_secret>
        g.assert_all_valid(testcase)
        rec = g.only("steps/toolCallRequest")
    """

    def __init__(self, *, hmac_secret: str | None = None,
                 sign_responses: bool = True) -> None:
        super().__init__(hmac_secret=hmac_secret, sign_responses=sign_responses)
        self.captures: list[CaptureRecord] = []
        self.on_request = self._capture

    # ----- the oracle -----

    def _capture(self, raw: bytes, parsed: dict) -> None:
        method = parsed.get("method", "")
        rec = CaptureRecord(method=method, raw=raw, parsed=parsed)
        self.captures.append(rec)
        # A validator bug must surface as an error on this record,
        # never a silently-clean capture.
        try:
            self._validate_envelope(rec)
            self._validate_payload(rec)
            self._validate_invariants(rec)
        except Exception as e:  # noqa: BLE001
            rec.errors.append(f"validator raised (treat as INVALID): {e!r}")

    def _validate_envelope(self, rec: CaptureRecord) -> None:
        for e in validate_request_envelope(rec.parsed):
            rec.errors.append(f"envelope: {e}")

    def _validate_payload(self, rec: CaptureRecord) -> None:
        method = rec.method
        payload = (rec.parsed.get("params") or {}).get("payload")
        if method == "handshake/hello":
            # Validate the ClientHello subschema explicitly.
            self._validate_against_subschema(
                rec, payload, "handshake.json", "ClientHello")
            return
        if method == "system/ping" or method.startswith("protocols/"):
            # system/ping: payload is a liveness echo; protocols/MCP/*:
            # wrapped form has no canonical hooks/ payload schema in v0.1.
            # Envelope validation already covered the shape.
            return
        schema = METHOD_PAYLOAD_SCHEMA.get(method)
        if schema is None:
            rec.errors.append(
                f"payload: no canonical schema known for method {method!r} "
                "(unmapped Core method or a typo in the emitted method)")
            return
        if payload is None:
            rec.errors.append("payload: params.payload is missing")
            return
        for e in validate_hook_payload(payload, schema):
            rec.errors.append(f"payload({schema}): {e}")

    def _validate_against_subschema(self, rec: CaptureRecord, payload: Any,
                                    schema_file: str, defs_key: str) -> None:
        if payload is None:
            rec.errors.append(f"payload: missing (expected {defs_key})")
            return
        try:
            from jsonschema import Draft202012Validator
            schema, resolver = build_local_resolver(schema_file)
            subschema = schema.get("$defs", {}).get(defs_key)
            if subschema is None:
                rec.errors.append(
                    f"payload: {schema_file} has no $defs/{defs_key}")
                return
            validator = Draft202012Validator(
                subschema, resolver=resolver,
                format_checker=Draft202012Validator.FORMAT_CHECKER)
            for err in validator.iter_errors(payload):
                path = ".".join(str(p) for p in err.absolute_path) or "<root>"
                rec.errors.append(f"payload({defs_key}): {path}: {err.message}")
        except ImportError:
            rec.errors.append("payload: jsonschema not installed")

    def _validate_invariants(self, rec: CaptureRecord) -> None:
        params = rec.parsed.get("params") or {}
        meta = params.get("metadata") or {}

        # request_id: a real UUID
        rid = params.get("request_id")
        try:
            uuid.UUID(str(rid))
        except (ValueError, AttributeError, TypeError):
            rec.errors.append(f"invariant: request_id {rid!r} is not a UUID")

        # timestamp: RFC 3339
        ts = params.get("timestamp")
        if validate_rfc3339 is not None:
            if not (isinstance(ts, str) and validate_rfc3339(ts)):
                rec.errors.append(f"invariant: timestamp {ts!r} not RFC 3339")

        # metadata: agent_id, session_id (uuid), platform
        for f in ("agent_id", "session_id", "platform"):
            if not meta.get(f):
                rec.errors.append(f"invariant: metadata.{f} missing/empty")
        try:
            uuid.UUID(str(meta.get("session_id")))
        except (ValueError, AttributeError, TypeError):
            rec.errors.append(
                f"invariant: metadata.session_id {meta.get('session_id')!r} not a UUID")

        # signature: INDEPENDENTLY recompute (system/ping exempt, §13).
        # Uses independent_verify() — a from-scratch HMAC/HKDF/JCS
        # implementation, NOT the adapter's own acs_common code, so a
        # shared signing+verifying bug cannot pass both sides.
        if rec.method != "system/ping":
            sid = meta.get("session_id") or ""
            if not independent_verify(rec.parsed, self.hmac_secret.encode(), sid):
                rec.errors.append(
                    "invariant: signature does not independently verify "
                    "(recomputed HMAC-SHA256 over JCS with a from-scratch "
                    "verifier)")

        # toolCallRequest: arguments use the {value: ...} wrapper
        if rec.method == "steps/toolCallRequest":
            args = (params.get("payload") or {}).get("arguments") or {}
            for k, v in args.items():
                if not (isinstance(v, dict) and "value" in v):
                    rec.errors.append(
                        f"invariant: argument {k!r} is not wrapped as "
                        f"{{value: ...}} (got {type(v).__name__})")

    # ----- assertions / accessors for tests -----

    def methods(self) -> list[str]:
        return [r.method for r in self.captures]

    def records_for(self, method: str) -> list[CaptureRecord]:
        return [r for r in self.captures if r.method == method]

    def only(self, method: str) -> CaptureRecord:
        recs = self.records_for(method)
        assert len(recs) == 1, (
            f"expected exactly one {method!r} capture, got {len(recs)}: "
            f"{self.methods()}")
        return recs[0]

    def assert_all_valid(self, testcase) -> None:
        # A validator crash (recorded on the guardian, not a record)
        # must fail the test too — else a schema-load bug reads as clean.
        if self.on_request_errors:
            testcase.fail("capture validator raised (would have hidden a "
                          f"defect): {self.on_request_errors}")
        bad = [r for r in self.captures if not r.ok]
        if bad:
            lines = []
            for r in bad:
                lines.append(f"  {r.method}:")
                lines.extend(f"    - {e}" for e in r.errors)
            testcase.fail(
                "captured envelopes failed canonical validation:\n"
                + "\n".join(lines))

    # ----- session-level invariants (need a shared Guardian across a
    #       sequence, not a fresh one per event) -----

    def duplicate_request_ids(self) -> list[str]:
        """request_ids seen more than once across the whole session —
        each MUST be unique (§10.3 replay protection keys on it)."""
        seen: dict[str, int] = {}
        for r in self.captures:
            rid = (r.parsed.get("params") or {}).get("request_id")
            if rid is not None:
                seen[rid] = seen.get(rid, 0) + 1
        return [rid for rid, n in seen.items() if n > 1]

    def request_id_for(self, method: str) -> str | None:
        recs = self.records_for(method)
        if not recs:
            return None
        return (recs[0].parsed.get("params") or {}).get("request_id")

    def payload_of(self, method: str) -> dict:
        recs = self.records_for(method)
        return (recs[0].parsed.get("params") or {}).get("payload") or {} if recs else {}

    def handshake_methods_implemented(self) -> list[str]:
        """The methods_implemented the adapter advertised in its
        ClientHello — for the advertise-vs-emit honesty check."""
        for r in self.records_for("handshake/hello"):
            payload = (r.parsed.get("params") or {}).get("payload") or {}
            return list(payload.get("methods_implemented") or [])
        return []
