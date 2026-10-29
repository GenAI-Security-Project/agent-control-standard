"""The §4 handshake: ClientHello, a verified ServerHello, and its per-session disk cache."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from acs.client._audit import audit_event
from acs.client._secrets import load_hmac_secret
from acs.client._signing import sign_envelope, verify_signature
from acs.client._urls import validate_guardian_url
from acs.core import ACS_VERSION, iso8601_now


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
    profiles_supported: list[str] | None = None,
    transports_supported: list[str] | None = None,
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

    Partial adapters can explicitly advertise no profiles and only their
    implemented transports. None preserves the existing adapter defaults.

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
                # handshake/hello returns ServerHello directly in result.
                # A signed legacy AcsResult wrapper is still the wrong shape:
                # treat it as a cache miss and negotiate again.
                server_hello = cached.get("result")
                if not isinstance(server_hello, dict) or "negotiated_version" not in server_hello:
                    raise ValueError("legacy or invalid cached ServerHello")
                return server_hello
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
                "transports_supported": (transports_supported if transports_supported
                                         is not None else ["http", "stdio"]),
                "max_payload_size_bytes": 1_000_000,
                "provenance_producer": "none",
                "wrapped_protocols": wrapped_protocols or [],
                # An unsigned session does not meet acs-core's signed-
                # envelope floor (§10), so it must not advertise the profile.
                "profiles_supported": (
                    (profiles_supported if profiles_supported is not None
                     else ["acs-core"]) if load_hmac_secret() else []
                ),
                "signature_algorithms_supported": (
                    ["HMAC-SHA256"] if load_hmac_secret() else []
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

    # ServerHello is the handshake result, not an AcsResult payload.
    # Leave capability/posture validation to the adapter as before; this
    # discriminator prevents an old wrapper from becoming a cached hello.
    server_hello = response.get("result")
    if isinstance(server_hello, dict) and "negotiated_version" in server_hello:
        try:
            _HANDSHAKE_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(_HANDSHAKE_CACHE_DIR, 0o700)
            except OSError:
                pass
            fd = os.open(str(cache), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                # Store the whole signed response, not the bare result, so the
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
        _record_failure("invalid_server_hello")
        return None
    return server_hello
