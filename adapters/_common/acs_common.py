"""
Shared ACS v0.1.0 helpers used by the three reference adapters and the
example Guardian.

Lives in `adapters/_common/`. Each adapter prepends this directory to
`sys.path` and imports the symbols it needs.

What's in here:

- `jcs_canonicalize` — RFC 8785 (JCS) canonicalization via the
  `rfc8785` PyPI package; a hard dependency with no fallback, since
  §10 permits no alternative canonicalization.
- `derive_session_key` — HKDF-SHA256 per-session key derivation per §10.
- `sign_envelope` / `verify_signature` — HMAC-SHA256 baseline signature
  over JCS(envelope with signature field removed), per §10.
- `load_hmac_secret` — read the HMAC secret from `ACS_HMAC_SECRET_FILE`
  (preferred: file mode 0600) or `ACS_HMAC_SECRET` (env). File path
  beats env var so secrets don't sit in `ps aux` output.
- `iso8601_now` / `coerce_uuid` / `parse_iso8601` — time + ID helpers.
- `audit_event` — structured `ACS_AUDIT` line for §6.4 fail-open bypass.
- `ensure_session_handshake` / `ping` — protocol helpers (§4, §13).
  `ensure_session_handshake` is idempotent per session via disk cache;
  see its docstring. The old name `do_handshake` is kept as an alias.
- `session_state` — per-session JSON file used by adapters to track
  last_step_id, seen_step_ids, etc. across separate hook-process
  invocations (shell-stdin adapters spawn one process per hook).
"""
from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ACS_VERSION = "0.1.0"
DEFAULT_SKEW_WINDOW_MS = 300_000

# Maximum bytes the Guardian will read from a single HTTP POST body.
# Matches the handshake's max_payload_size_bytes default. Defends against
# memory exhaustion via a huge Content-Length.
MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB

# Maximum command string length to scan with destructive-pattern regexes.
# Real shell commands are tiny; longer inputs are either non-shell data
# routed through the wrong tool or a regex-DoS attempt.
DESTRUCTIVE_SCAN_MAX_LEN = 8 * 1024  # 8 KiB


# ----- Canonicalization -----

try:
    import rfc8785 as _rfc8785  # type: ignore[import-not-found]
except ImportError as _rfc8785_import_error:
    # HARD dependency, deliberately. Spec §10: "Alternative
    # canonicalization is not permitted in v0.1." A sorted-keys
    # json.dumps fallback diverges from RFC 8785 on floats (1.0 vs 1),
    # -0.0, large exponents, and non-BMP key ordering. The failure mode
    # is a silent policy bypass (divergent canonicalization →
    # SIGNATURE_INVALID → fail posture), so refuse to import instead.
    raise ImportError(
        "ACS adapters require the `rfc8785` package for RFC 8785 (JCS) "
        "canonical signing — spec §10 permits no alternative "
        "canonicalization. Install it: pip install rfc8785"
    ) from _rfc8785_import_error


def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme) via the `rfc8785` package.

    A hard dependency — see the import block above for why there is
    deliberately no fallback."""
    return _rfc8785.dumps(obj)


# ----- Signing (HMAC-SHA256 baseline per §10) -----

def derive_session_key(input_key_material: bytes, session_id: str) -> bytes:
    """HKDF-SHA256 with session_id as `info`, no salt.

    Spec §10: 'per-session HMAC key is HKDF-derived from deployment-provided
    input keying material (a pre-shared secret, or a transport channel
    binding such as a TLS exporter) together with the session_id.'
    """
    # HKDF-Extract with empty salt
    prk = hmac.new(b"\x00" * 32, input_key_material, hashlib.sha256).digest()
    # HKDF-Expand to 32 bytes with info = session_id
    info = session_id.encode("utf-8")
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t  # one 32-byte block is enough for HMAC-SHA256


class SecretFilePermissionsError(RuntimeError):
    """ACS_HMAC_SECRET_FILE exists but its permissions / ownership leak the secret."""


class SecretFileUnreadableError(RuntimeError):
    """ACS_HMAC_SECRET_FILE is configured but cannot be read.

    Raised loudly: silently downgrading to unsigned mode would turn
    off the only integrity control ACS-Core mandates."""


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
    """Read the HMAC input keying material.

    Resolution order (first hit wins):
    1. `ACS_HMAC_SECRET_FILE` — path to a file containing the secret.
       Preferred for production. Permissions MUST be 0600 (or 0400) and
       the file MUST be owned by the running user. The file's content
       (stripped of trailing whitespace) is the secret. Symlinks are
       rejected. Insecure permissions raise SecretFilePermissionsError —
       the adapter refuses to use a leaked secret rather than silently
       proceed.
    2. `ACS_HMAC_SECRET` — env-var fallback. Quick for dev, less secure
       (visible in `ps eauxw`, child-process envs, core dumps).
    3. Empty bytes — caller decides whether that means dev-mode or fail.

    Generate a secret: `openssl rand -hex 32 > /etc/acs/hmac.key && chmod 600 /etc/acs/hmac.key`
    """
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            _check_secret_file_perms(path)
            with open(path, "rb") as f:
                return f.read().rstrip(b"\r\n\t ")
        except SecretFilePermissionsError:
            raise
        except OSError as e:
            # Configured-but-unreadable is an incident, not dev mode.
            audit_event("hmac_secret_file_unreadable", path=path, error=str(e))
            raise SecretFileUnreadableError(
                f"ACS_HMAC_SECRET_FILE {path!r} is configured but cannot "
                f"be read ({e}); refusing to continue unsigned"
            ) from e
    env_val = os.environ.get("ACS_HMAC_SECRET", "")
    return env_val.encode("utf-8") if env_val else b""


# Back-compat alias for internal callers.
_signing_secret = load_hmac_secret


# ----- URL scheme allowlist (defends against SSRF / file:// disclosure) -----

_ALLOWED_GUARDIAN_SCHEMES = frozenset({"http", "https"})


def validate_guardian_url(url: str) -> None:
    """Reject Guardian URLs whose scheme is not http/https.

    urllib.request.urlopen happily accepts file://, ftp://, data://, etc.
    An attacker who controls ACS_GUARDIAN_URL could use file:// to read
    arbitrary files the adapter user has access to, or data:// to feed
    a crafted response. The adapter and any other code POSTing to the
    Guardian MUST call this before urlopen.

    Optionally also restricts the hostname against an operator-provided
    `ACS_GUARDIAN_HOST_ALLOWLIST` (comma-separated). Defense in depth
    against env-var attacks that smuggle a real http:// URL to an
    internal service the adapter shouldn't reach.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_GUARDIAN_SCHEMES:
        raise ValueError(
            f"Guardian URL scheme {parsed.scheme!r} not allowed; "
            f"only {sorted(_ALLOWED_GUARDIAN_SCHEMES)} permitted")
    allow = os.environ.get("ACS_GUARDIAN_HOST_ALLOWLIST", "").strip()
    if allow:
        allowed_hosts = {h.strip().lower() for h in allow.split(",") if h.strip()}
        host = (parsed.hostname or "").lower()
        if host not in allowed_hosts:
            raise ValueError(
                f"Guardian host {host!r} not in ACS_GUARDIAN_HOST_ALLOWLIST "
                f"({sorted(allowed_hosts)})")


# ----- Bounded regex scanning (defends against regex DoS / input bombing) -----

def scan_destructive_bash_safely(cmd: str, *, max_len: int = DESTRUCTIVE_SCAN_MAX_LEN):
    """Run destructive-pattern regex scanning ONLY if cmd is below max_len.

    Returns:
      None — command is short and matched no destructive pattern
      a re.Pattern — command matched (caller decides what to do)
      "input_too_large" — command exceeds max_len; caller MUST treat as
        suspicious and MUST NOT silently allow (skipping the scan is
        not the same as the scan returning "safe").

    Caller pattern set is loaded lazily from example_guardian.DESTRUCTIVE_BASH_PATTERNS
    to keep the canonical pattern set in one place.
    """
    if len(cmd) > max_len:
        audit_event("destructive_scan_skipped_oversized",
                    cmd_length=len(cmd), max_len=max_len)
        return "input_too_large"
    # Lazy import — _common doesn't directly own the pattern set, the
    # Guardian does. Adapters that want to run the scan themselves can
    # call this; the Guardian uses its own DESTRUCTIVE_BASH_PATTERNS
    # directly. We import here so this function is callable without
    # forcing example-guardian onto every adapter's path.
    try:
        eg_path = str(Path(__file__).resolve().parent.parent / "example-guardian")
        if eg_path not in sys.path:
            sys.path.insert(0, eg_path)
        import example_guardian  # type: ignore[import-not-found]
        for pat in example_guardian.DESTRUCTIVE_BASH_PATTERNS:
            if pat.search(cmd):
                return pat
        return None
    except ImportError:
        return None


_warned_unsigned_mode = False


def _warn_unsigned_once() -> None:
    """One loud warning per process when operating without key material.

    Unsigned mode is an authentication failure, not just a
    confidentiality one: any local process that binds the Guardian port
    first becomes the Guardian and allows everything.
    Fine for a first local experiment; never fine silently."""
    global _warned_unsigned_mode
    if not _warned_unsigned_mode:
        _warned_unsigned_mode = True
        audit_event(
            "unsigned_mode",
            detail=(
                "no ACS_HMAC_SECRET / ACS_HMAC_SECRET_FILE configured — "
                "envelopes are UNSIGNED and any local process that binds "
                "the Guardian address is trusted"
            ),
        )


def _envelope_container_key(envelope: dict) -> str:
    """Where the signature lives: params for requests, result for
    decision responses, error for error responses (every response is
    signed under ACS-Core — including errors, since a spoofable
    unsigned error under a fail-open posture is an allow)."""
    if "method" in envelope:
        return "params"
    if "error" in envelope:
        return "error"
    return "result"


def sign_envelope(envelope: dict, *, key: bytes | None = None,
                  session_id: str | None = None, key_id: str = "default") -> dict:
    """Add a signature to the envelope. Returns the envelope unchanged
    (after a loud one-time audit event) if no key material is available."""
    if key is None:
        ikm = _signing_secret()
        if not ikm:
            _warn_unsigned_once()
            return envelope
        if not session_id:
            params = envelope.get("params") or envelope.get("result") or {}
            meta = params.get("metadata") or {}
            session_id = meta.get("session_id") or params.get("request_id") or ""
        key = derive_session_key(ikm, session_id)

    container_key = _envelope_container_key(envelope)
    container = envelope.get(container_key, {})
    # Strip any existing signature before signing
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, container_key: unsigned_container}

    sig_bytes = hmac.new(key, jcs_canonicalize(unsigned_envelope), hashlib.sha256).digest()
    container["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": base64.b64encode(sig_bytes).decode("ascii"),
        "key_id": key_id,
    }
    envelope[container_key] = container
    return envelope


def verify_signature(envelope: dict, *, key: bytes | None = None,
                     session_id: str | None = None) -> bool:
    """Verify a signed envelope (request, decision response, or error
    response). Returns True if valid (or if no signature present and no
    key material configured — local-dev mode)."""
    container_key = _envelope_container_key(envelope)
    container = envelope.get(container_key) or {}
    sig = container.get("signature")
    if sig is None:
        # No signature on the wire; valid only if local-dev (no key configured)
        return not bool(_signing_secret())

    if sig.get("algorithm") != "HMAC-SHA256":
        return False
    expected_b64 = sig.get("value")
    if not expected_b64:
        return False

    if key is None:
        ikm = _signing_secret()
        if not ikm:
            # Signature present but no key configured: cannot verify
            return False
        meta = container.get("metadata") or {}
        session_id = session_id or meta.get("session_id") or container.get("request_id") or ""
        key = derive_session_key(ikm, session_id)

    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, container_key: unsigned_container}
    expected_bytes = hmac.new(key, jcs_canonicalize(unsigned_envelope), hashlib.sha256).digest()
    # Malformed base64 (truncation, garbage chars, non-string) must NOT
    # crash the request path — that turns a bad signature into a 500 /
    # uncaught exception instead of the spec's SIGNATURE_INVALID
    # (-32004) response. Return False so the caller emits the right
    # error code and the audit event carries cause=signature_invalid_*.
    try:
        provided_bytes = base64.b64decode(expected_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    return hmac.compare_digest(expected_bytes, provided_bytes)


# ----- Safe decision normalization -----

# The five ACS dispositions (§6.3). Shared so every adapter classifies an
# arrived verdict against the same set.
KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def normalize_decision(result: Any) -> tuple[str, str, dict]:
    """Coerce a Guardian result's decision fields to safe types, never
    raising.

    Reading `decision`/`reasoning`/`modifications` must never throw:
    §6.3:146 requires failing closed on an undeterminable Guardian
    intent, and an uncaught AttributeError exits 1, which the shell
    hosts treat as proceed (fail-open).

    Returns (decision, reasoning, modifications):
      - decision: stripped, lower-cased str; "" when the field is not a
        usable string, which routes the caller to its unusable→DENY branch.
      - reasoning: always a str (JSON repr if the Guardian sent a
        non-string, so it can go into a `reason` field unchanged).
      - modifications: always a dict ({} when the Guardian sent a
        non-object, which makes a MODIFY with no usable mutation
        substitute to DENY per §6.3:146).
    """
    if not isinstance(result, dict):
        return "", "", {}
    raw_decision = result.get("decision")
    decision = raw_decision.strip().lower() if isinstance(raw_decision, str) else ""
    raw_reason = result.get("reasoning", "")
    reasoning = (raw_reason if isinstance(raw_reason, str)
                 else json.dumps(raw_reason, default=str))
    raw_mods = result.get("modifications", {})
    modifications = raw_mods if isinstance(raw_mods, dict) else {}
    return decision, reasoning, modifications


def modify_composition_violation(modifications: dict) -> str | None:
    """Return a reason string if a MODIFY's `modifications` object violates
    the §6.3 / modifications.json composition rules, else None.

    The two shapes are mutually exclusive (modifications.json `oneOf`):
    wholesale `modified_content`, OR structured edits (`redactions` and/or
    `parameter_overrides`) whose targets are DISJOINT — never both shapes,
    never overlapping structured targets. Per §6.3:146 the receiver MUST
    fail closed (DENY) rather than half-apply one branch."""
    if not isinstance(modifications, dict):
        return None  # caller treats empty/absent as no-usable-mutation
    has_content = "modified_content" in modifications
    has_redactions = "redactions" in modifications
    has_overrides = "parameter_overrides" in modifications
    redactions = modifications.get("redactions")
    overrides = modifications.get("parameter_overrides")
    if has_content and (has_redactions or has_overrides):
        return ("modifications combines wholesale modified_content with "
                "structured edits — the two shapes are mutually exclusive "
                "(§6.3)")
    if has_content and not isinstance(modifications.get("modified_content"), str):
        return "modified_content is not a string — Guardian intent is unusable (§6.3)"
    if has_redactions and not isinstance(redactions, list):
        return "redactions is not an array — Guardian intent is unusable (§6.3)"
    if has_overrides and not isinstance(overrides, dict):
        return ("parameter_overrides is not an object — Guardian intent is "
                "unusable (§6.3)")

    def _pointer_token(value: str) -> str:
        """Encode one object-member name as an RFC 6901 token."""
        return value.replace("~", "~0").replace("/", "~1")

    def _paths_overlap(left: str, right: str) -> bool:
        """True when equal paths or one JSON Pointer contains the other."""
        return (left == right or left == "" or right == ""
                or left.startswith(right + "/")
                or right.startswith(left + "/"))

    override_paths = {
        f"/{_pointer_token(key)}": key
        for key in (overrides or {})
        if isinstance(key, str)
    }
    if has_redactions:
        for r in redactions:
            if not isinstance(r, dict):
                return ("redactions contains a non-object item — Guardian "
                        "intent is unusable (§6.3)")
            path = r.get("path")
            if not isinstance(path, str) or (path and not path.startswith("/")):
                return (f"redaction path {path!r} is not an RFC 6901 JSON "
                        "Pointer — Guardian intent is unusable (§6.3)")
            # JSON Pointer permits only ~0 and ~1 escape sequences.  Reject a
            # malformed pointer rather than compare a different path from the
            # one the Guardian intended.
            if re.search(r"~(?:[^01]|$)", path):
                return (f"redaction path '{path}' has an invalid JSON Pointer "
                        "escape — Guardian intent is unusable (§6.3)")
            if has_overrides:
                for override_path, key in override_paths.items():
                    if _paths_overlap(path, override_path):
                        return (f"redaction path '{path}' overlaps "
                                f"parameter_override '{key}' — structured "
                                "targets MUST be disjoint (§6.3)")
    return None


# ----- JSON-RPC error code → audit cause label -----
#
# Adapters use this when the Guardian returns a JSON-RPC `error` response
# (as opposed to a transport failure). Separating "Guardian rejected this
# envelope" from "I couldn't reach the Guardian" is load-bearing for
# operator triage — same fail-posture under §6.4, completely different
# remediation. Codes are the §17.1 / JSON-RPC reserved set.
GUARDIAN_ERROR_CAUSE: dict[int, str] = {
    -32001: "unsupported_version_response",
    -32002: "provenance_required_response",
    -32004: "signature_invalid_response",         # adapter or operator bug
    -32005: "replay_detected_response",            # duplicate request_id
    -32006: "timestamp_out_of_window_response",    # clock skew
    -32600: "malformed_envelope_response",         # non-conformant envelope
    -32700: "parse_error_response",
}


def guardian_error_cause(code: int | None) -> str:
    """Resolve a JSON-RPC error code to a stable audit cause label.

    Returns the generic 'guardian_error_response' for unrecognized codes
    so audit consumers always have a non-empty cause string."""
    if code is None:
        return "guardian_error_response"
    return GUARDIAN_ERROR_CAUSE.get(code, "guardian_error_response")


# ----- Guardian refusals fail closed -----
#
# DELIBERATELY STRICTER THAN v0.1 SPEC TEXT (tracked as spec issue #32).
# §6.4:156 as written routes ANY "error response instead of a decision"
# to the fail posture (default proceed). We do NOT do that for the codes
# below: the Guardian is ALIVE and REFUSED the envelope, and every one of
# them is attacker-reachable — oversize the body past the Guardian's cap
# (-32600 before policy runs), replay a request_id the adapter derives
# deterministically (-32005), strip or corrupt the signature (-32004),
# present a stale captured envelope (-32006). Routing those through a
# fail-OPEN posture turns each into a policy-bypass primitive. So we fail
# CLOSED on them regardless of ACS_DEFAULT_DENY / on_decision_failure.
# This is deliberate hardening ahead of the spec, NOT a claim that v0.1
# mandates it — #32 proposes the normative text; until it lands, treat
# this as adapter behavior, not a conformance requirement.
GUARDIAN_REFUSAL_CODES = frozenset({
    -32000,  # SESSION_REFUSED — policy refuses this session
    -32004,  # SIGNATURE_INVALID
    -32005,  # REPLAY_DETECTED
    -32006,  # TIMESTAMP_OUT_OF_WINDOW
    -32600,  # Invalid Request (malformed / oversized envelope)
    -32700,  # Parse error
})


def is_guardian_refusal(code: int | None) -> bool:
    """True when the error code means 'Guardian alive and refused this
    envelope' — the adapter must fail closed, not apply the §6.4 posture."""
    return code in GUARDIAN_REFUSAL_CODES


# ----- Response↔request binding -----

def response_matches_request(request: dict, response: dict) -> bool:
    """Bind a Guardian response to the request that elicited it.

    The per-session HMAC proves a response came from the Guardian, not
    that it answers *this* request — a captured signed ALLOW replays
    fine against a different call. Binding is two spec-carried checks:

      1. JSON-RPC `id` on the response equals the request's `id`.
      2. `result.request_id` equals the request's `params.request_id`
         (required on every result per response-envelope.json).

    Error responses carry no result; for those only check 1 applies.
    Adapters MUST fail closed when this returns False."""
    if response.get("id") != request.get("id"):
        return False
    result = response.get("result")
    if result is not None:
        want = (request.get("params") or {}).get("request_id")
        if result.get("request_id") != want:
            return False
    return True


# ----- Time + IDs -----

def iso8601_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def coerce_uuid(raw: str | None, *, namespace_prefix: str = "acs") -> str:
    if not raw:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{namespace_prefix}:{raw}"))


def parse_iso8601(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ----- Audit events (§6.4 fail-open recording) -----

def audit_event(event_type: str, **fields: Any) -> None:
    """Emit a structured audit-event line to stderr and, when
    `ACS_AUDIT_FILE` is set, append it to that file (created 0600).

    §6.4 requires every undecided proceed to be recorded; stderr alone
    is not durable, so deployments SHOULD set ACS_AUDIT_FILE. Single-line
    JSON for line-oriented ingestion.
    """
    payload = {
        "acs_audit_event": event_type,
        "timestamp": iso8601_now(),
        **fields,
    }
    line = "ACS_AUDIT " + json.dumps(payload, sort_keys=True) + "\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    audit_file = os.environ.get("ACS_AUDIT_FILE", "").strip()
    if audit_file:
        try:
            fd = os.open(audit_file,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(line)
        except OSError as e:
            # Never crash the hook path over the audit sink, but say so.
            sys.stderr.write(
                f"ACS_AUDIT_SINK_ERROR cannot append to {audit_file!r}: {e}\n")
            sys.stderr.flush()


# ----- Handshake (§4) -----

_HANDSHAKE_CACHE_DIR = Path(
    os.environ.get(
        "ACS_HANDSHAKE_CACHE",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-handshake"),
    )
)


def _handshake_cache_path(session_id: str, guardian_url: str) -> Path:
    # Full SHA-256 (no truncation) for the same reason as state files —
    # avoid birthday collisions across the deployment's lifetime.
    key = hashlib.sha256((session_id + "|" + guardian_url).encode()).hexdigest()
    return _HANDSHAKE_CACHE_DIR / f"{key}.json"


# Cache TTL — default 1 hour. A Guardian config change (new
# skew_window_ms, new accepted profiles) propagates to adapters within
# this window. Override with ACS_HANDSHAKE_CACHE_TTL_SECONDS.
_HANDSHAKE_CACHE_TTL_S = int(os.environ.get("ACS_HANDSHAKE_CACHE_TTL_SECONDS", "3600"))

# Failure cache TTL — default 30s: the first event against a dead
# Guardian pays the handshake timeout, later ones fail fast to the
# startup posture; short so a recovering Guardian is picked up quickly.
_HANDSHAKE_FAILURE_TTL_S = int(
    os.environ.get("ACS_HANDSHAKE_FAILURE_CACHE_TTL_SECONDS", "30"))

# Handshake network timeout — default 5s, configurable per deployment.
_HANDSHAKE_TIMEOUT_S = float(os.environ.get("ACS_HANDSHAKE_TIMEOUT_SECONDS", "5"))


def ensure_session_handshake(
    *,
    guardian_url: str,
    session_id: str,
    agent_id: str,
    platform: str,
    methods_implemented: list[str],
    wrapped_protocols: list[str] | None = None,
    timeout: float | None = None,
) -> dict | None:
    """Idempotently ensure a handshake/hello has happened for this session.

    Spec contract (§4): handshake is REQUIRED at session start, ONCE
    per session, not per event. The shell-stdin adapters
    (claude-code, cursor) spawn a fresh process per hook event, so we
    persist the negotiated ServerHello in a small JSON file under
    `~/.cache/acs-adapter-handshake/<sha256(session_id+url)>.json`:

      - First event of a session: cache miss → POSTs ClientHello,
        receives ServerHello, writes cache file, returns ServerHello.
      - Subsequent events same session: cache hit (file fresh, < 1h
        old by default) → reads file, returns cached ServerHello.
        NO network call.
      - Cache files older than the TTL are ignored so operator
        Guardian-config changes propagate.

    Returns the ServerHello (cached or freshly fetched), or None on
    failure (Guardian unreachable, etc.) — adapters fall to their
    startup posture in that case (§4.1).

    Hardening:
      - The ServerHello signature is verified before caching or return.
      - The whole signed envelope is cached and re-verified on every
        read — the cache path is writable by the observed agent.
      - The response is bound to the ClientHello by JSON-RPC id.
      - Failures are negative-cached for a short TTL; every
        negative-cache hit is audited (§4.1:77).
    """
    if timeout is None:
        timeout = _HANDSHAKE_TIMEOUT_S
    cache = _handshake_cache_path(session_id, guardian_url)
    failure_marker = cache.with_suffix(".failed")
    if cache.exists():
        try:
            mtime = cache.stat().st_mtime
            if (time.time() - mtime) <= _HANDSHAKE_CACHE_TTL_S:
                with open(cache) as f:
                    cached = json.load(f)
                # Verify a cached envelope exactly like a fresh one:
                # the file is writable by the observed agent, and an
                # unverified read lets it flip its own fail posture (§10).
                if not isinstance(cached, dict) or "result" not in cached:
                    # Pre-0.1.2 cache held the bare payload, with no
                    # signature to check. Treat as a miss and re-handshake.
                    raise ValueError("legacy unsigned handshake cache entry")
                if not verify_signature(cached, session_id=session_id):
                    audit_event("handshake_cache_signature_invalid",
                                guardian_url=guardian_url, session_id=session_id,
                                detail="cached ServerHello failed verification; "
                                       "re-handshaking")
                    raise ValueError("cached ServerHello signature invalid")
                return (cached.get("result") or {}).get("payload")
            # Else: cache is stale, fall through to re-handshake
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    if failure_marker.exists():
        try:
            if (time.time() - failure_marker.stat().st_mtime) <= _HANDSHAKE_FAILURE_TTL_S:
                # Recent failure: fail fast, audited per §4.1:77 (an
                # unguarded session must be recorded).
                audit_event("handshake_negative_cache_hit",
                            guardian_url=guardian_url, session_id=session_id)
                return None
        except OSError:
            pass

    client_hello = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "handshake/hello",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": agent_id, "session_id": session_id, "platform": platform},
            "payload": {
                "acs_versions_supported": [ACS_VERSION],
                "methods_implemented": methods_implemented,
                "transports_supported": ["http", "stdio"],
                "max_payload_size_bytes": 1_000_000,
                "provenance_producer": "none",
                "wrapped_protocols": wrapped_protocols or [],
                # An unsigned session does not meet acs-core's signed-
                # envelope floor (§10), so it must not advertise the profile.
                "profiles_supported": (
                    ["acs-core"] if _signing_secret() else []
                ),
                "signature_algorithms_supported": (
                    ["HMAC-SHA256"] if _signing_secret() else []
                ),
            },
        },
    }
    sign_envelope(client_hello, session_id=session_id)
    try:
        validate_guardian_url(guardian_url)
    except ValueError:
        return None
    def _record_failure(cause: str, **fields: Any) -> None:
        audit_event("handshake_failed", cause=cause,
                    guardian_url=guardian_url, session_id=session_id,
                    **fields)
        try:
            _HANDSHAKE_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(failure_marker),
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
        except OSError:
            pass

    try:
        body = json.dumps(client_hello).encode("utf-8")
        req = urllib.request.Request(
            guardian_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
        _record_failure("transport_failure", error=str(e))
        return None

    # Bind the response to OUR ClientHello — a stray or replayed
    # response envelope must not establish a session.
    if response.get("id") != client_hello["id"]:
        _record_failure("response_id_mismatch")
        return None

    # An unverifiable ServerHello is a failure, not a Guardian: caching
    # it would let a port squatter hand out its own negotiated config.
    if not verify_signature(response, session_id=session_id):
        _record_failure("server_hello_signature_invalid")
        return None

    result = response.get("result") or {}
    server_hello = result.get("payload")
    if server_hello:
        try:
            _HANDSHAKE_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(_HANDSHAKE_CACHE_DIR, 0o700)
            except OSError:
                pass
            fd = os.open(str(cache), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                # Store the whole signed response, not result.payload, so the
                # read path can re-verify it (§10 binds the signature to the
                # envelope, so a bare payload cannot be checked at all).
                json.dump(response, f)
            # A fresh success clears any lingering failure marker.
            try:
                failure_marker.unlink()
            except OSError:
                pass
        except OSError:
            pass
    else:
        _record_failure("no_server_hello_payload")
    return server_hello


# ----- system/ping (§13) -----

def ping(guardian_url: str, *, echo: str = "ping", timeout: float = 2.0) -> dict | None:
    """Send a system/ping and return the result, or None on failure.

    Per §13: Guardian MUST always return allow; ping does not participate
    in the chain; no signature required.
    """
    request = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "system/ping",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": "ping-client", "session_id": str(uuid.uuid4())},
            "payload": {"echo": echo},
        },
    }
    try:
        validate_guardian_url(guardian_url)
    except ValueError:
        return None
    try:
        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            guardian_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("result")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return None


# ----- Per-session adapter state (cross-invocation) -----
#
# Shell-stdin adapters (claude-code, cursor) spawn one process per hook
# event. To accumulate state across events in the same session (last
# step_id, step_ids seen, subagent registry, etc.) the adapter persists
# a small JSON file in the cache directory.

_SESSION_STATE_DIR = Path(
    os.environ.get(
        "ACS_SESSION_STATE_DIR",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-session"),
    )
)


def _session_state_path(session_id: str, *, workspace: str | None = None) -> Path:
    """Path to the per-session state file.

    Hash key is full 64-char SHA-256 (not [:16]) to eliminate birthday
    collisions over the lifetime of a deployment. When `workspace` is
    given, it is folded into the hash so two clients with the same
    session_id but different workspaces (e.g., two Cursor windows
    using `conv-default` as conversation_id) get distinct state files.
    """
    if not session_id:
        # Empty session_id — return a path that won't collide with anything real
        digest = hashlib.sha256(b"empty").hexdigest()
        return _SESSION_STATE_DIR / f"{digest}.json"
    if workspace:
        digest = hashlib.sha256(
            (workspace + "\x00" + session_id).encode()
        ).hexdigest()
    else:
        digest = hashlib.sha256(session_id.encode()).hexdigest()
    return _SESSION_STATE_DIR / f"{digest}.json"


def load_session_state(session_id: str, *, workspace: str | None = None) -> dict:
    """Return the session-state dict for `session_id`, or an empty dict.

    See `_session_state_path` for the workspace-namespacing rationale.
    """
    if not session_id:
        return {}
    path = _session_state_path(session_id, workspace=workspace)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_session_state(session_id: str, state: dict, *, workspace: str | None = None) -> None:
    """Persist the session-state dict atomically. No-op on session_id empty.

    The directory is created with mode 0700 and the file with mode 0600
    so other local users cannot read or poison adapter state. State
    files contain step_id histories that an attacker could use to spoof
    `parent_step_id` in subagentStart payloads — a security boundary
    for the chain integrity properties of §8.
    """
    if not session_id:
        return
    try:
        _SESSION_STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(exist_ok=True) does not chmod an existing dir — enforce explicitly
        try:
            os.chmod(_SESSION_STATE_DIR, 0o700)
        except OSError:
            pass
        path = _session_state_path(session_id, workspace=workspace)
        tmp = path.with_suffix(".json.tmp")
        # Open with 0o600 from the start so the file is never group/world-readable
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def record_step(session_id: str, step_id: str, *, workspace: str | None = None) -> None:
    """Append step_id to the session's seen-list and update last_step_id."""
    if not session_id or not step_id:
        return
    st = load_session_state(session_id, workspace=workspace)
    seen = st.setdefault("seen_step_ids", [])
    if step_id not in seen:
        seen.append(step_id)
        # Bound the list so it doesn't grow unbounded across long sessions
        if len(seen) > 1000:
            del seen[: len(seen) - 1000]
    st["last_step_id"] = step_id
    save_session_state(session_id, st, workspace=workspace)


# ----- Sys-path bootstrap for adapters in sibling directories -----

def install_path_for_sibling() -> None:
    """Convenience: ensures the _common dir is on sys.path so adapters in
    sibling directories can `from acs_common import ...`. No-op if
    already on path."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)


# ----- Back-compat alias -----
# `do_handshake` was the original name. Renamed to make the cache
# short-circuit visible at call sites. Old name kept so out-of-tree
# adapter forks aren't broken by the rename.
do_handshake = ensure_session_handshake
