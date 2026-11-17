from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import math
import os
import tempfile
import urllib.error
import urllib.parse
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from acs.client._audit import audit_event
from acs.client._config import Config, Resolution
from acs.client._exchange import (
    GuardianHTTPError,
    OnWire,
    claims_json_rpc_answer,
    key_id_rejected,
    post,
    ON_WIRE_FAILED,
    OnWireFailed,
    report_on_wire,
    response_verified,
    wire_body,
)
from acs.client._outcome import Decided, Handshake, Negotiated, NoAnswer, SessionRefused, Undecided
from acs.client._secrets import SigningMaterialMissing, load_signing_material
from acs.client._signing import sign_envelope
from acs.client._store import _locked
from acs.client._urls import validate_guardian_url
from acs.core import (
    ACS_VERSION,
    BINDING_ID,
    BINDING_REQUEST,
    BINDING_SHAPE,
    HANDSHAKE_METHOD,
    MAX_REQUEST_BODY_BYTES,
    derive_session_key,
    guardian_error_cause,
    is_guardian_refusal,
    is_session_refusal,
    iso8601_now,
    jcs_canonicalize,
    normalize_decision,
    request_binding_problem,
    response_binding_problem,
    response_shape_problem,
    server_hello_problem,
)

if TYPE_CHECKING:
    from acs.client._key_document import ResponseKeys


_HANDSHAKE_CACHE_DIR = Path(
    os.environ.get(
        "ACS_HANDSHAKE_CACHE",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-handshake"),
    )
)

_DEFAULT_HANDSHAKE_TIMEOUT_S = 5.0

_RECORD_VERSION = 1
_STARTUP_VERSION = 1
# A startup record whose sessionStart was claimed but whose outcome was never recorded.
_PENDING = "pending"


def _handshake_cache_path(session_id: str, guardian_url: str, directory: Path | None = None) -> Path:
    key = hashlib.sha256((session_id + "|" + guardian_url).encode("utf-8", "surrogatepass")).hexdigest()
    return (directory or _HANDSHAKE_CACHE_DIR) / f"{key}.json"


def current_session_id(host_session_id: str, guardian_url: str) -> str:
    """The ACS session a host session's hooks belong to: the host's id until a sessionEnd ends it, then a new one each time."""
    session_id, generation = host_session_id, 0
    while _ended(session_id, guardian_url).exists():
        generation += 1
        session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"acs-session:{host_session_id}:{generation}"))
    return session_id


def mark_session_ended(session_id: str, guardian_url: str) -> bool:
    """Mark a session ended, so a later hook of the same host session opens a new one; False when it cannot be marked."""
    marker = _ended(session_id, guardian_url)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker.touch(mode=0o600)
    except OSError as e:
        audit_event("session_record_unwritable", session_id=session_id, guardian_url=guardian_url,
                    record=str(marker), error=str(e))
        return False
    return True


def _ended(session_id: str, guardian_url: str) -> Path:
    return Path(f"{_handshake_cache_path(session_id, guardian_url)}.ended")


def discard_session(session_id: str, guardian_url: str) -> None:
    path = _handshake_cache_path(session_id, guardian_url)
    for record in (path, Path(f"{path}.started"), Path(f"{path}.lock")):
        with contextlib.suppress(OSError):
            record.unlink()


def open_session(*, config: Config, session_id: str | None, agent_id: str, platform: str,
                 methods_implemented: list[str], wrapped_protocols: list[str] | None = None,
                 timeout: float | None = None, profiles_supported: list[str] | None = None,
                 transports_supported: list[str] | None = None,
                 start: Callable[[Negotiated], Decided | Resolution | None] | None = None,
                 count_start_failure: Callable[[str], None] | None = None,
                 response_keys: ResponseKeys | None = None, on_wire: OnWire | None = None) -> Handshake:
    """The session's decision, stored once under an HMAC. With start, the opening process also sends sessionStart under the startup lock. Never raises.

    on_wire sees the ClientHello before it is sent and the Guardian's answer before it is
    classified. A stored decision is reused with no on_wire call, since nothing crosses the wire.
    response_keys turns on response verification by key document (issue #576). start sends its
    own request, so the caller passes both to the round_trip inside it.
    """
    if not session_id:
        return NoAnswer("missing_session_id")
    # §10: every request is signed, so a session with no usable secret and label is refused before any stored one is read.
    try:
        ikm, _ = load_signing_material()
    except SigningMaterialMissing as e:
        return SessionRefused(e.cause, {"error": str(e)})
    except Exception as e:  # noqa: BLE001
        return SessionRefused("secret_unavailable", {"error": str(e)})
    path = _handshake_cache_path(session_id, config.guardian_url)
    hello = dict(config=config, session_id=session_id, agent_id=agent_id, platform=platform,
                 methods_implemented=methods_implemented, wrapped_protocols=wrapped_protocols, timeout=timeout,
                 profiles_supported=profiles_supported, transports_supported=transports_supported,
                 response_keys=response_keys, on_wire=on_wire)
    if start is None:
        return _required_profiles(_decide(path, ikm, **hello), config)
    started = Path(f"{path}.started")
    stored = _read_record(path, ikm, session_id, config.guardian_url)
    if stored is not None and not isinstance(stored, Negotiated):
        return stored
    if stored is not None:
        recorded = _read_startup(started, ikm, session_id, config.guardian_url)
        if recorded is not None and recorded != _PENDING:
            return _required_profiles(recorded, config)
    with contextlib.ExitStack() as startup:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            startup.enter_context(_locked(path))
        except OSError as e:
            audit_event("session_record_unwritable", session_id=session_id, guardian_url=config.guardian_url,
                        record=f"{path}.lock", error=str(e))
            return SessionRefused("session_startup_lock_unavailable", {"error": str(e)})
        decision = _decide(path, ikm, **hello)
        own = _required_profiles(decision, config)
        if not isinstance(own, Negotiated):
            return own
        recorded = _read_startup(started, ikm, session_id, config.guardian_url)
        if recorded == _PENDING:
            failure = config.posture.negotiated(decision.server_hello).resolve(Undecided(
                "session_start_incomplete", {"record": str(started)},
                "the hook that sent sessionStart ended before its decision arrived"))
            if count_start_failure is not None:
                count_start_failure(failure.fields["failure_class"])
            outcome = session_start_outcome(decision, failure, session_id=session_id, guardian_url=config.guardian_url)
            unrecorded = _write_startup(started, outcome, ikm, session_id, config.guardian_url)
            return _required_profiles(unrecorded or outcome, config)
        if recorded is not None:
            return _required_profiles(recorded, config)
        claim = _write_startup(started, None, ikm, session_id, config.guardian_url)
        if claim is not None:
            return claim
        outcome = _start_session(decision, start, config, session_id)
        unrecorded = _write_startup(started, outcome, ikm, session_id, config.guardian_url)
        return _required_profiles(unrecorded or outcome, config)


def _start_session(decision: Negotiated, start: Callable[[Negotiated], Decided | Resolution | None],
                   config: Config, session_id: str) -> Handshake:
    try:
        result = start(decision)
    except Exception as e:  # noqa: BLE001
        result = config.posture.negotiated(decision.server_hello).resolve(
            Undecided("adapter_exception", {"error": str(e)}, f"adapter error: {e}"))
    return session_start_outcome(decision, result, session_id=session_id, guardian_url=config.guardian_url)


def session_start_outcome(decision: Negotiated, result: Decided | Resolution | None, *, session_id: str,
                          guardian_url: str) -> Handshake:
    """The session's decision after its sessionStart answered with result, audited (hooks.md sessionStart: ALLOW / DENY)."""
    if result is None:
        # The Guardian does not evaluate sessionStart.
        return decision
    common = {"method": "steps/sessionStart", "session_id": session_id, "guardian_url": guardian_url}
    if isinstance(result, Resolution):
        audit_event(result.audit_type, **{**result.fields, "cause": result.cause, **common})
        if result.audit_type == "guardian_refusal_fail_closed":
            refusal = SessionRefused("session_start_refused", {**result.fields, "refusal": result.cause})
            audit_event("session_refused", **{**refusal.fields, "cause": refusal.cause, **common})
            return refusal
        # No decision arrived: recorded once, and each hook's fail posture settles its own steps.
        return Negotiated(decision.server_hello, {"cause": result.cause, "fields": dict(result.fields)})
    verdict = normalize_decision((result.response or {}).get("result"))
    if verdict.disposition == "allow":
        return Negotiated(decision.server_hello, start_context=verdict.reasoning) if verdict.reasoning else decision
    refusal = SessionRefused("session_start_denied", {"decision": verdict.disposition, "reasoning": verdict.reasoning})
    audit_event("session_refused", **{**refusal.fields, "cause": refusal.cause, **common})
    return refusal


def _decide(path: Path, ikm: bytes, *, config: Config, session_id: str, agent_id: str, platform: str,
            methods_implemented: list[str], wrapped_protocols: list[str] | None, timeout: float | None,
            profiles_supported: list[str] | None, transports_supported: list[str] | None,
            response_keys: ResponseKeys | None = None, on_wire: OnWire | None = None) -> Handshake:
    stored = _read_record(path, ikm, session_id, config.guardian_url)
    if stored is not None:
        return stored
    claimed = profiles_supported if profiles_supported is not None else ["acs-core"]
    if not config.handshake_enabled:
        decision: Handshake = NoAnswer("handshake_disabled")
    else:
        decision = _hello(
            guardian_url=config.guardian_url, session_id=session_id, agent_id=agent_id,
            platform=platform, methods_implemented=methods_implemented,
            wrapped_protocols=wrapped_protocols, profiles_supported=claimed,
            transports_supported=transports_supported,
            timeout=_handshake_timeout_s() if timeout is None else timeout,
            response_keys=response_keys, on_wire=on_wire,
        )
        if isinstance(decision, SessionRefused) and decision.cause == ON_WIRE_FAILED:
            # A local transcript failure, not the Guardian's decision: refuse this attempt only and store nothing,
            # so the next hook retries the handshake (review CR1). report_on_wire already audited it.
            return decision
    decision, ours = _store_first(path, decision, ikm, session_id, config.guardian_url)
    if ours:
        _audit_start(decision, config, session_id, claimed)
    return decision


def _handshake_timeout_s() -> float:
    raw = os.environ.get("ACS_HANDSHAKE_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_HANDSHAKE_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if math.isfinite(value) and value > 0:
        return value
    audit_event("invalid_setting", setting="ACS_HANDSHAKE_TIMEOUT_SECONDS", value=raw,
                used=_DEFAULT_HANDSHAKE_TIMEOUT_S)
    return _DEFAULT_HANDSHAKE_TIMEOUT_S


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
    return _store_first(_handshake_cache_path(session_id, guardian_url, directory),
                        decision, ikm, session_id, guardian_url)[0]


def _hello(*, guardian_url: str, session_id: str, agent_id: str, platform: str,
           methods_implemented: list[str], wrapped_protocols: list[str] | None,
           profiles_supported: list[str], transports_supported: list[str] | None,
           timeout: float, response_keys: ResponseKeys | None = None, on_wire: OnWire | None = None) -> Handshake:
    # The client POSTs to the Guardian URL, so that URL's scheme is the one transport it offers.
    scheme = urllib.parse.urlsplit(guardian_url).scheme
    client_hello = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": HANDSHAKE_METHOD,
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
                "max_payload_size_bytes": MAX_REQUEST_BODY_BYTES,
                "provenance_producer": "none",
                "wrapped_protocols": wrapped_protocols or [],
                "profiles_supported": profiles_supported,
                "signature_algorithms_supported": ["HMAC-SHA256"],
            },
        },
    }
    if response_keys is not None:
        # Lab convention until issue #316: the algorithm the Guardian signs responses with. Requests stay
        # on HMAC, so signature_algorithms_supported, which governs requests, is unchanged.
        client_hello["params"]["payload"]["x_acs_lab_response_algorithms"] = [response_keys.algorithm]
    try:
        validate_guardian_url(guardian_url)
        sign_envelope(client_hello, session_id=session_id)
    except Exception as e:  # noqa: BLE001
        return NoAnswer("guardian_url_rejected" if isinstance(e, ValueError) else "adapter_exception",
                        {"error": str(e)})
    try:
        body = wire_body(client_hello, on_wire, HANDSHAKE_METHOD)
    except OnWireFailed as e:
        return SessionRefused(ON_WIRE_FAILED, {"dir": "req", "error": e.fields["error"]})
    except Exception as e:  # noqa: BLE001
        # post() used to raise these from inside its own call, which ended the same way.
        return NoAnswer("adapter_exception", {"error": str(e)})
    reported = False
    try:
        response = post(client_hello, guardian_url=guardian_url, timeout_s=timeout, body=body)
    except GuardianHTTPError as e:
        # Any decoded body is an answer that arrived, so on_wire sees it whatever its shape.
        if e.body is not None:
            reported = True
            failed = report_on_wire(on_wire, "resp", e.body, HANDSHAKE_METHOD)
            if failed is not None:
                return SessionRefused(ON_WIRE_FAILED, {"dir": "resp", "error": failed["error"]})
        if response_shape_problem(e.body) is not None:
            return NoAnswer(f"http_{e.status}_error", {"http_status": e.status})
        response = e.body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        timed_out = isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError)
        return NoAnswer("handshake_timeout" if timed_out else "transport_failure", {"error": str(e)})
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return NoAnswer("malformed_response", {"error": str(e)})
    except Exception as e:  # noqa: BLE001
        return NoAnswer("adapter_exception", {"error": str(e)})
    if not reported:
        failed = report_on_wire(on_wire, "resp", response, HANDSHAKE_METHOD)
        if failed is not None:
            return SessionRefused(ON_WIRE_FAILED, {"dir": "resp", "error": failed["error"]})
    try:
        return _classify_hello(client_hello, response, session_id, response_keys)
    except Exception as e:  # noqa: BLE001
        return SessionRefused("response_unverifiable", {"error": str(e)})


def _classify_hello(client_hello: Mapping[str, Any], response: Any, session_id: str,
                    response_keys: ResponseKeys | None = None) -> Handshake:
    """An answer that fails its checks refuses the session; a verified error that is not a refusal, or a ServerHello that does not answer the ClientHello, is no answer (§4.1)."""
    # The one binding rule decides. A malformed response is no answer, so the fail posture
    # applies, as for a transport failure. A request or id problem refuses the session.
    binding = response_binding_problem(client_hello, response)
    if binding == BINDING_SHAPE:
        # As in a step: a JSON-RPC answer rejected only for its members may be a signed answer someone altered.
        if claims_json_rpc_answer(response):
            return SessionRefused("response_shape_invalid")
        return NoAnswer("malformed_response")
    # A request problem can come with any response at all, so read the claimed code defensively.
    error = response.get("error") if isinstance(response, Mapping) else None
    code = error.get("code") if isinstance(error, Mapping) else None
    if binding == BINDING_REQUEST:
        # The ClientHello is the caller's own error, not the Guardian's.
        return SessionRefused("request_envelope_invalid")
    if binding == BINDING_ID:
        return SessionRefused("response_binding_mismatch",
                              {"claimed_error_code": code} if code is not None else {})
    # A request that isn't a real ClientHello is the caller's error. For a handshake/hello request,
    # request_binding_problem says whether its params and payload are objects, as the checks below
    # need. A real ClientHello's result then binds by id alone, and server_hello_problem's
    # required fields decide whether it is a ServerHello, as the legacy-wrapper contract asks.
    if "result" in response and (client_hello.get("method") != HANDSHAKE_METHOD
                                 or request_binding_problem(client_hello) is not None):
        return SessionRefused("request_envelope_invalid")
    verified = response_verified(response, client_hello, session_id, response_keys)
    if error is not None:
        if not verified:
            if key_id_rejected(error):
                return SessionRefused("key_id_rejected", {"claimed_error_code": code})
            return SessionRefused("error_signature_invalid",
                                  {"claimed_error_code": code, "claimed_cause": guardian_error_cause(code)})
        fields = {"error_code": code, "error_message": error.get("message")}
        reason = error.get("data", {}).get("reason") if isinstance(error.get("data"), Mapping) else None
        if response_keys is not None and isinstance(reason, str):
            # Verified under the key document, so the Guardian's stated reason is trusted (issue #316).
            fields["reason"] = reason
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
    if response_keys is not None:
        # Lab convention until issue #316. A Guardian that verified but didn't select the offered algorithm
        # would sign this session's decisions some other way, so the session is refused before any step.
        selected = server_hello.get("x_acs_lab_response_algorithm")
        if selected != response_keys.algorithm:
            return SessionRefused("response_algorithm_not_negotiated",
                                  {"offered": [response_keys.algorithm], "selected": selected})
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
        negotiated = {**body, "decision": "negotiated", "server_hello": dict(decision.server_hello)}
        if decision.start_failure is not None:
            negotiated["start_failure"] = dict(decision.start_failure)
        if decision.start_context:
            negotiated["start_context"] = decision.start_context
        return negotiated
    kind = "refused" if isinstance(decision, SessionRefused) else "no_answer"
    return {**body, "decision": kind, "cause": decision.cause, "fields": dict(decision.fields)}


def _decode(body: Mapping[str, Any]) -> Handshake | None:
    kind = body.get("decision")
    if kind == "negotiated" and isinstance(body.get("server_hello"), dict):
        failure, context = body.get("start_failure"), body.get("start_context", "")
        if not isinstance(context, str):
            return None
        if failure is None:
            return Negotiated(body["server_hello"], start_context=context)
        if isinstance(failure, dict) and isinstance(failure.get("cause"), str) and isinstance(failure.get("fields"), dict):
            return Negotiated(body["server_hello"], failure, context)
        return None
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
    body = _verified(path, ikm, session_id, guardian_url, "acs_session_record", _RECORD_VERSION)
    if body is None or isinstance(body, SessionRefused):
        return body
    decision = _decode(body)
    # Only the startup record says how a sessionStart went.
    if decision is None or isinstance(decision, Negotiated) and (decision.start_failure is not None or decision.start_context):
        return SessionRefused("session_record_invalid", {"record": str(path)})
    return decision


def _read_startup(path: Path, ikm: bytes, session_id: str, guardian_url: str) -> Handshake | str | None:
    """The session's decision after its sessionStart, None when none is recorded, _PENDING while it is claimed, and a refusal for a record that fails its checks."""
    body = _verified(path, ikm, session_id, guardian_url, "acs_session_startup", _STARTUP_VERSION)
    if body is None or isinstance(body, SessionRefused):
        return body
    if body.get("state") == _PENDING:
        return _PENDING
    decision = _decode(body)
    return decision if decision is not None else SessionRefused("session_record_invalid", {"record": str(path)})


def _verified(path: Path, ikm: bytes, session_id: str, guardian_url: str, marker: str,
              version: int) -> Mapping[str, Any] | SessionRefused | None:
    """A record's body once its MAC, session and Guardian URL check out; None when no record exists, a refusal otherwise."""
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
    if marker == "acs_session_record" and _is_legacy(record):
        # Its signature covers the session but not the Guardian URL, so it cannot vouch for this endpoint.
        return SessionRefused("session_record_legacy", {"record": str(path)})
    # The marker keeps one kind of record from standing in for the other under the same session key.
    if not isinstance(record, dict) or record.get(marker) != version:
        return SessionRefused("session_record_invalid", {"record": str(path)})
    body = {k: v for k, v in record.items() if k != "mac"}
    try:
        authentic = hmac.compare_digest(str(record.get("mac")), _mac(body, ikm, session_id))
    except Exception:  # noqa: BLE001
        authentic = False
    if not (authentic and body.get("session_id") == session_id and body.get("guardian_url") == guardian_url):
        return SessionRefused("session_record_invalid", {"record": str(path)})
    return body


def _write_startup(path: Path, outcome: Handshake | None, ikm: bytes, session_id: str,
                   guardian_url: str) -> SessionRefused | None:
    """Claim the session's sessionStart (outcome None), or record its outcome; a refusal, audited, when the record cannot be written."""
    temporary = None
    try:
        body: dict[str, Any] = {"acs_session_startup": _STARTUP_VERSION, "session_id": session_id,
                                "guardian_url": guardian_url}
        if outcome is None:
            body["state"] = _PENDING
        else:
            decision = _encode(outcome, session_id, guardian_url)
            body.update({k: v for k, v in decision.items() if k not in body and k != "acs_session_record"},
                        state="done")
        record = {**body, "mac": _mac(body, ikm, session_id)}
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".startup-")
        with os.fdopen(fd, "w") as f:
            json.dump(record, f)
        if outcome is None:
            # link() fails if any startup record already exists.
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
            temporary = None
        return None
    except Exception as e:  # noqa: BLE001
        audit_event("session_record_unwritable", session_id=session_id, guardian_url=guardian_url,
                    record=str(path), stage="claim" if outcome is None else "outcome", error=str(e))
        return SessionRefused("session_record_unwritable", {"error": str(e)})
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _store_first(path: Path, decision: Handshake, ikm: bytes, session_id: str,
                 guardian_url: str) -> tuple[Handshake, bool]:
    """Store the decision first-wins; return the one that holds and whether it is ours. A decision that cannot be stored refuses the session."""
    temporary = None
    try:
        body = _encode(decision, session_id, guardian_url)
        record = {**body, "mac": _mac(body, ikm, session_id)}
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
