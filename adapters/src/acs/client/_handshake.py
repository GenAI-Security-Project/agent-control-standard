from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import urllib.error
import urllib.parse
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from acs.client._audit import audit_event
from acs.client._config import Config
from acs.client._exchange import GuardianHTTPError, is_jsonrpc_response, post
from acs.client._outcome import Handshake, Negotiated, NoAnswer, SessionRefused
from acs.client._secrets import load_hmac_secret
from acs.client._signing import sign_envelope, verify_signature
from acs.client._urls import validate_guardian_url
from acs.core import (
    ACS_VERSION,
    derive_session_key,
    guardian_error_cause,
    is_guardian_refusal,
    is_session_refusal,
    iso8601_now,
    jcs_canonicalize,
    server_hello_problem,
)


_HANDSHAKE_CACHE_DIR = Path(
    os.environ.get(
        "ACS_HANDSHAKE_CACHE",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-handshake"),
    )
)

# Handshake network timeout — default 5s, configurable per deployment.
_HANDSHAKE_TIMEOUT_S = float(os.environ.get("ACS_HANDSHAKE_TIMEOUT_SECONDS", "5"))

_RECORD_VERSION = 1


def _handshake_cache_path(session_id: str, guardian_url: str, directory: Path | None = None) -> Path:
    # Full SHA-256 (no truncation) avoids birthday collisions across the deployment's lifetime.
    key = hashlib.sha256((session_id + "|" + guardian_url).encode()).hexdigest()
    return (directory or _HANDSHAKE_CACHE_DIR) / f"{key}.json"


def open_session(*, config: Config, session_id: str | None, agent_id: str, platform: str,
                 methods_implemented: list[str], wrapped_protocols: list[str] | None = None,
                 timeout: float | None = None, profiles_supported: list[str] | None = None,
                 transports_supported: list[str] | None = None) -> Handshake:
    """Return the session's decision: the stored one, or the result of one handshake, stored for the session's lifetime; never raises.

    The record sits where the observed agent can write, so it carries an
    HMAC under the session key over the decision, the session and the
    Guardian URL: a record that is modified, corrupted, copied from another
    endpoint, or cannot be stored refuses the session.
    """
    if not session_id:
        return NoAnswer("missing_session_id")
    try:
        ikm = load_hmac_secret()
    except Exception as e:  # noqa: BLE001
        return SessionRefused("secret_unavailable", {"error": str(e)})
    path = _handshake_cache_path(session_id, config.guardian_url)
    stored = _read_record(path, ikm, session_id, config.guardian_url)
    if stored is not None:
        return _required_profiles(stored, config)
    # An unsigned session does not meet acs-core's signed-envelope floor (§10), so it claims no profile.
    claimed = (profiles_supported if profiles_supported is not None else ["acs-core"]) if ikm else []
    if not config.handshake_enabled:
        decision: Handshake = NoAnswer("handshake_disabled")
    else:
        decision = _hello(
            guardian_url=config.guardian_url, session_id=session_id, agent_id=agent_id,
            platform=platform, methods_implemented=methods_implemented,
            wrapped_protocols=wrapped_protocols, profiles_supported=claimed,
            transports_supported=transports_supported, signed=bool(ikm),
            timeout=_HANDSHAKE_TIMEOUT_S if timeout is None else timeout,
        )
    decision, ours = _store_first(path, decision, ikm, session_id, config.guardian_url)
    if ours:
        _audit_start(decision, config, session_id, claimed)
    return _required_profiles(decision, config)


def _required_profiles(decision: Handshake, config: Config) -> Handshake:
    """This hook's ACS_REQUIRE_PROFILES applied to the session's negotiation; the stored record keeps what the Guardian answered."""
    if not isinstance(decision, Negotiated):
        return decision
    missing = sorted(config.require_profiles - set(decision.server_hello.get("profiles_accepted") or []))
    if missing:
        return SessionRefused("required_profile_not_accepted", {"profiles": missing})
    return decision


def store_session_decision(directory: Path, session_id: str, guardian_url: str,
                           decision: Handshake, ikm: bytes) -> Handshake:
    """Store a decision for a session unless one is already stored; return the one that holds."""
    return _store_first(_handshake_cache_path(session_id, guardian_url, directory),
                        decision, ikm, session_id, guardian_url)[0]


def _hello(*, guardian_url: str, session_id: str, agent_id: str, platform: str,
           methods_implemented: list[str], wrapped_protocols: list[str] | None,
           profiles_supported: list[str], transports_supported: list[str] | None,
           signed: bool, timeout: float) -> Handshake:
    # The client POSTs to the Guardian URL, so that URL's scheme is the one transport it offers.
    scheme = urllib.parse.urlsplit(guardian_url).scheme
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
                "transports_supported": (transports_supported if transports_supported is not None
                                         else [scheme]),
                "max_payload_size_bytes": 1_000_000,
                "provenance_producer": "none",
                "wrapped_protocols": wrapped_protocols or [],
                "profiles_supported": profiles_supported,
                "signature_algorithms_supported": ["HMAC-SHA256"] if signed else [],
            },
        },
    }
    try:
        validate_guardian_url(guardian_url)
        sign_envelope(client_hello, session_id=session_id)
    except Exception as e:  # noqa: BLE001
        return NoAnswer("guardian_url_rejected" if isinstance(e, ValueError) else "adapter_exception",
                        {"error": str(e)})
    try:
        response = post(client_hello, guardian_url=guardian_url, timeout_s=timeout)
    except GuardianHTTPError as e:
        if not is_jsonrpc_response(e.body):
            return NoAnswer(f"http_{e.status}_error", {"http_status": e.status})
        response = e.body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        timed_out = isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError)
        return NoAnswer("handshake_timeout" if timed_out else "transport_failure", {"error": str(e)})
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return NoAnswer("malformed_response", {"error": str(e)})
    except Exception as e:  # noqa: BLE001
        return NoAnswer("adapter_exception", {"error": str(e)})
    try:
        return _classify_hello(client_hello, response, session_id)
    except Exception as e:  # noqa: BLE001
        return SessionRefused("response_unverifiable", {"error": str(e)})


def _classify_hello(client_hello: Mapping[str, Any], response: Any, session_id: str) -> Handshake:
    """An answer that fails its checks refuses the session; a verified error that is not a refusal, or a ServerHello that does not answer the ClientHello, is no answer (§4.1)."""
    if not is_jsonrpc_response(response):
        return NoAnswer("malformed_response")
    error = response.get("error")
    code = error.get("code") if error is not None else None
    if response.get("id") != client_hello["id"]:
        return SessionRefused("response_binding_mismatch",
                              {"claimed_error_code": code} if code is not None else {})
    verified = verify_signature(response, session_id=session_id)
    if error is not None:
        if not verified:
            return SessionRefused("error_signature_invalid",
                                  {"claimed_error_code": code, "claimed_cause": guardian_error_cause(code)})
        fields = {"error_code": code, "error_message": error.get("message")}
        # §4.1 names three session refusals; the step-level refusal codes are refused too.
        if is_session_refusal(code) or is_guardian_refusal(code):
            return SessionRefused(guardian_error_cause(code), fields)
        return NoAnswer(guardian_error_cause(code), fields)
    if not verified:
        return SessionRefused("server_hello_signature_invalid")
    server_hello = response["result"]
    if "negotiated_version" not in server_hello:
        return NoAnswer("invalid_server_hello")
    problem = server_hello_problem(server_hello, client_hello["params"]["payload"])
    if problem is not None:
        return NoAnswer("invalid_server_hello", {"problem": problem})
    return Negotiated(server_hello)


def _audit_start(decision: Handshake, config: Config, session_id: str, claimed: list[str]) -> None:
    common = {"cause": getattr(decision, "cause", None), "session_id": session_id,
              "guardian_url": config.guardian_url}
    if isinstance(decision, Negotiated):
        accepted = decision.server_hello.get("profiles_accepted")
        declined = sorted(set(claimed) - set(accepted)) if isinstance(accepted, list) else []
        if declined:
            audit_event("profile_not_accepted", profiles=declined, session_id=session_id,
                        guardian_url=config.guardian_url)
    elif isinstance(decision, SessionRefused):
        audit_event("session_refused", **{**decision.fields, **common})
    elif isinstance(decision, NoAnswer):
        audit_event("session_without_negotiated_guardian",
                    **{**decision.fields, **common, "failure_class": "handshake_failure",
                       "posture": "fail_open" if config.startup_proceeds else "fail_closed"})


def _record_key(ikm: bytes, session_id: str) -> bytes:
    return hmac.new(derive_session_key(ikm, session_id), b"acs-adapter session record",
                    hashlib.sha256).digest()


def _encode(decision: Handshake, session_id: str, guardian_url: str) -> dict[str, Any]:
    body: dict[str, Any] = {"acs_session_record": _RECORD_VERSION, "session_id": session_id,
                            "guardian_url": guardian_url}
    if isinstance(decision, Negotiated):
        return {**body, "decision": "negotiated", "server_hello": dict(decision.server_hello)}
    kind = "refused" if isinstance(decision, SessionRefused) else "no_answer"
    return {**body, "decision": kind, "cause": decision.cause, "fields": dict(decision.fields)}


def _decode(body: Mapping[str, Any]) -> Handshake | None:
    kind = body.get("decision")
    if kind == "negotiated" and isinstance(body.get("server_hello"), dict):
        return Negotiated(body["server_hello"])
    if kind in ("refused", "no_answer") and isinstance(body.get("cause"), str) \
            and isinstance(body.get("fields"), dict):
        cls = SessionRefused if kind == "refused" else NoAnswer
        return cls(body["cause"], body["fields"])
    return None


def _mac(body: Mapping[str, Any], ikm: bytes, session_id: str) -> str:
    digest = hmac.new(_record_key(ikm, session_id), jcs_canonicalize(body), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _is_legacy(record: Any) -> bool:
    """The cache an earlier adapter wrote: a ServerHello, bare or in its JSON-RPC envelope, bound to no Guardian URL."""
    if not isinstance(record, dict) or "acs_session_record" in record:
        return False
    hello = record.get("result") if "jsonrpc" in record else record
    return isinstance(hello, dict) and "negotiated_version" in hello


def _read_record(path: Path, ikm: bytes, session_id: str, guardian_url: str) -> Handshake | None:
    """The stored decision, None only when no record exists, and a refusal for any record that fails its checks."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        return SessionRefused("session_record_unreadable", {"record": str(path), "error": str(e)})
    try:
        record = json.loads(raw)
    except Exception:  # noqa: BLE001
        # Any parse failure counts, including RecursionError from deep nesting.
        record = None
    if _is_legacy(record):
        # Its signature covers the session but not the Guardian URL, so it cannot vouch for this endpoint.
        return SessionRefused("session_record_legacy", {"record": str(path)})
    if not isinstance(record, dict) or record.get("acs_session_record") != _RECORD_VERSION:
        return SessionRefused("session_record_invalid", {"record": str(path)})
    body = {k: v for k, v in record.items() if k != "mac"}
    try:
        authentic = not ikm or hmac.compare_digest(str(record.get("mac")), _mac(body, ikm, session_id))
    except Exception:  # noqa: BLE001
        authentic = False
    bound = body.get("session_id") == session_id and body.get("guardian_url") == guardian_url
    decision = _decode(body) if authentic and bound else None
    if decision is None:
        return SessionRefused("session_record_invalid", {"record": str(path)})
    return decision


def _store_first(path: Path, decision: Handshake, ikm: bytes, session_id: str,
                 guardian_url: str) -> tuple[Handshake, bool]:
    """Store the decision first-wins; return the one that holds and whether it is ours. A decision that cannot be stored refuses the session."""
    temporary = None
    try:
        body = _encode(decision, session_id, guardian_url)
        record = {**body, "mac": _mac(body, ikm, session_id) if ikm else None}
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".record-")
        with os.fdopen(fd, "w") as f:
            json.dump(record, f)
        for _ in range(2):
            try:
                # link() publishes the complete file atomically and fails if a decision is already stored.
                os.link(temporary, path)
                return decision, True
            except FileExistsError:
                existing = _read_record(path, ikm, session_id, guardian_url)
                if existing is not None:
                    return existing, False
        raise OSError("the stored record kept disappearing")
    except Exception as e:  # noqa: BLE001
        audit_event("session_record_unwritable", session_id=session_id, guardian_url=guardian_url,
                    record=str(path), decision=type(decision).__name__, error=str(e))
        return SessionRefused("session_record_unwritable", {"error": str(e)}), True
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
