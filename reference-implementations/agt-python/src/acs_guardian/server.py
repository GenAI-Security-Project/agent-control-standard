"""The ACS wire boundary: one JSON-RPC 2.0 endpoint, POST /acs.

The spec mandates no URL path convention -- ``/acs`` is this implementation's
choice -- so dispatch is by the JSON-RPC ``method`` field, never by path.

Dispatch order, and why it is this order (each step is asserted by the
conformance probes in ``tests/test_external_probes.py``):

1. JSON-RPC envelope shape -> ``-32600``.
2. Signature verification -> ``-32004`` (unsigned answer: the request
   established no key).
3. Session lookup -> ``-32003`` when no handshake negotiated the session.
4. Replay -> ``-32005``, *before* the capability and payload checks, so a
   replay of a refused request is still reported as a replay.
5. Negotiated-method check -> ``-32003``.
6. Timestamp skew -> ``-32006``.
7. Hook payload schema -> ``-32602``.
8. Evaluation, audit-chain append, signed decision.

Every response to an authenticated request is signed with the session key at
``result.signature`` / ``error.signature``, including error responses: the
conformance harness verifies the signature on every signed request it sends,
refusals included. A request that did not authenticate gets an unsigned
answer, because signing it would claim a key relationship that does not exist.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .canonical import request_signing_input, response_signing_input
from .chain import AuditChain
from .crypto import ALGORITHM, derive_session_key, sign, verify
from .engine import ALLOW, DENY, Evaluation, EvaluationRequest, PolicyEngine
from .errors import (
    CAPABILITY_NOT_NEGOTIATED,
    INVALID_PARAMS,
    INVALID_REQUEST,
    PARSE_ERROR,
    REPLAY_DETECTED,
    SESSION_REFUSED,
    SIGNATURE_INVALID,
    TIMESTAMP_OUT_OF_WINDOW,
    AcsError,
)
from .handshake import IMPLEMENTED_METHODS, negotiate, server_hello
from .schemas import SchemaRegistry
from .session import Session, SessionStore

ACS_PATH = "/acs"
MAX_REQUEST_BODY_BYTES = 1_048_576
ACS_VERSION = "0.1.0"


@dataclass
class GuardianConfig:
    """Deployment configuration. The secret is deployment-provided key material (§10)."""

    secret: bytes
    key_id: str = "conformance"
    on_decision_failure: str = "proceed"
    timeout_ms: int = 5000
    skew_window_ms: int = 300_000
    policy_requires_provenance: bool = False
    spec_root: Path | None = None
    engine: PolicyEngine | None = None
    # A deployment that needs eviction (TTL, capacity) supplies its own store;
    # the default keeps sessions for the process lifetime.
    session_store: SessionStore | None = None
    host: str = "127.0.0.1"
    port: int = 8787


class Guardian:
    """The protocol logic, transport-independent so tests can drive it directly."""

    def __init__(self, config: GuardianConfig) -> None:
        if config.on_decision_failure not in ("proceed", "deny"):
            raise ValueError(f"on_decision_failure must be proceed or deny, got {config.on_decision_failure!r}")
        if len(config.secret) < 32:
            raise ValueError("the HMAC secret must be at least 32 bytes")
        self.config = config
        self.schemas = SchemaRegistry(config.spec_root)
        self.store = config.session_store if config.session_store is not None else SessionStore()
        if config.engine is None:
            from .engine import BuiltinEngine

            self.engine: PolicyEngine = BuiltinEngine()
        else:
            self.engine = config.engine

    # -- transport-independent entry point ---------------------------------

    def handle(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, list):
            return self._error(None, INVALID_REQUEST, "batching is not supported; send one request per POST")
        try:
            # The authoritative envelope check: request-envelope.json, required
            # fields included (acs_version, request_id, timestamp, metadata).
            self.schemas.validate_request(raw)
        except AcsError as error:
            return self._error(_best_effort_id(raw), error.code, error.message, error.data)
        rpc_id = raw.get("id")
        if not isinstance(rpc_id, (str, int)) or isinstance(rpc_id, bool):
            rpc_id = None
        method = raw.get("method")
        if not isinstance(method, str):
            return self._error(rpc_id, INVALID_REQUEST, "method must be a string")

        key: bytes | None = None
        key_id: str | None = None
        params = raw.get("params")
        if isinstance(params, dict):
            metadata = params.get("metadata")
            if isinstance(metadata, dict) and isinstance(metadata.get("session_id"), str):
                key = derive_session_key(self.config.secret, metadata["session_id"])
            signature = params.get("signature")
            if isinstance(signature, dict) and isinstance(signature.get("key_id"), str):
                key_id = signature["key_id"]

        try:
            if method == "handshake/hello":
                return self._handshake(raw, rpc_id, params, key, key_id)
            return self._step(raw, rpc_id, method, params, key, key_id)
        except AcsError as error:
            if error.signable and key is not None:
                return self._error(rpc_id, error.code, error.message, error.data, key=key, key_id=key_id)
            return self._error(rpc_id, error.code, error.message, error.data)
        except Exception as error:  # noqa: BLE001 - nothing may escape as a non-JSON-RPC answer
            from .errors import INTERNAL_ERROR

            # Details go to the operator's log, not the wire: an exception
            # message can carry filesystem paths and schema internals.
            #
            # Deliberately unsigned: this route is a bug in the Guardian, and
            # the request may not have authenticated (the key is derived from
            # metadata.session_id, not from a verified signature), so signing
            # would claim a key relationship that may not exist.
            print(f"guardian failed to handle a request: {error!r}", file=sys.stderr)
            return self._error(rpc_id, INTERNAL_ERROR, "guardian failed to handle the request")

    # -- handshake ---------------------------------------------------------

    def _handshake(
        self,
        raw: dict[str, Any],
        rpc_id: str | int | None,
        params: Any,
        key: bytes | None,
        key_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise AcsError(INVALID_PARAMS, "params must be an object", signable=False)
        session_id, request_id = self._session_and_request_id(params, signable=False)
        if key is None or not self._signature_ok(raw, params, key):
            raise AcsError(SIGNATURE_INVALID, "handshake request signature is missing or invalid", signable=False)
        client_hello = params.get("payload")
        if not isinstance(client_hello, dict):
            raise AcsError(INVALID_PARAMS, "handshake payload must be a ClientHello object")
        self.schemas.validate_client_hello(client_hello)

        existing = self.store.get(session_id)
        if existing is not None:
            with existing.lock:
                if isinstance(request_id, str) and request_id in existing.seen_request_ids:
                    raise AcsError(REPLAY_DETECTED, "request_id was already seen in this session")
                # Recorded before the refusal, like a step's id: a replay of a
                # refused handshake is still a replay (the probes assert the
                # same rule for refused steps).
                if isinstance(request_id, str):
                    existing.seen_request_ids.add(request_id)
            raise AcsError(
                SESSION_REFUSED,
                "session is already negotiated; v0.1 defines no renegotiation",
                data={"reason": "renegotiation_not_supported"},
            )

        terms = negotiate(
            client_hello,
            on_decision_failure=self.config.on_decision_failure,
            timeout_ms=self.config.timeout_ms,
            skew_window_ms=self.config.skew_window_ms,
            policy_requires_provenance=self.config.policy_requires_provenance,
        )
        session = self._new_session(params, session_id, request_id, key_id, terms)
        if not self.store.create_if_absent(session):
            # Lost a race with a concurrent handshake for the same session_id.
            raced = self.store.get(session_id)
            if raced is not None:
                with raced.lock:
                    if isinstance(request_id, str) and request_id not in raced.seen_request_ids:
                        raced.seen_request_ids.add(request_id)
            raise AcsError(
                SESSION_REFUSED,
                "session is already negotiated; v0.1 defines no renegotiation",
                data={"reason": "renegotiation_not_supported"},
            )

        response = {"jsonrpc": "2.0", "id": rpc_id, "result": server_hello(terms)}
        return self._sign(response, key, session.key_id)

    def _new_session(
        self,
        params: dict[str, Any],
        session_id: str,
        request_id: Any,
        key_id: str | None,
        terms: Any,
    ) -> Session:
        return Session(
            session_id=session_id,
            agent_id=str((params.get("metadata") or {}).get("agent_id", "")),
            key_id=key_id or self.config.key_id,
            negotiated_version=terms.negotiated_version,
            methods_evaluated=terms.methods_evaluated,
            selected_transport=terms.selected_transport,
            timeout_config={"default_ms": terms.timeout_ms},
            on_decision_failure=terms.on_decision_failure,
            skew_window_ms=terms.skew_window_ms,
            profiles_accepted=terms.profiles_accepted,
            chain=AuditChain(),
            seen_request_ids={request_id} if isinstance(request_id, str) else set(),
            seen_nonces=set(),
        )

    # -- steps/*, system/*, and anything else ------------------------------

    def _step(
        self,
        raw: dict[str, Any],
        rpc_id: str | int | None,
        method: str,
        params: Any,
        key: bytes | None,
        key_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise AcsError(INVALID_PARAMS, "params must be an object", signable=False)
        session_id, request_id = self._session_and_request_id(params, signable=False)

        # Every request but system/ping must be signed (§10, §13). Ping is
        # exempt so liveness probing survives key-resolution failures.
        if method != "system/ping":
            if key is None or not self._signature_ok(raw, params, key):
                raise AcsError(SIGNATURE_INVALID, "request signature is missing or invalid", signable=False)

        if method == "system/ping":
            return self._ping(rpc_id, params, key, key_id)

        session = self.store.get(session_id)
        if session is None:
            raise AcsError(
                CAPABILITY_NOT_NEGOTIATED,
                f"no negotiated session for {session_id}; handshake/hello is required first",
                data={"method": method},
            )
        if key_id != session.key_id:
            raise AcsError(SIGNATURE_INVALID, "signature key_id does not match the negotiated session", signable=False)

        # One session's steps are serialized: the replay check, the chain
        # append, and the decision must be one atomic step, or two concurrent
        # copies of a request both pass the check and both append.
        with session.lock:
            if isinstance(request_id, str):
                if request_id in session.seen_request_ids:
                    raise AcsError(REPLAY_DETECTED, "request_id was already seen in this session")
                session.seen_request_ids.add(request_id)
            nonce = params.get("nonce")
            if isinstance(nonce, str):
                if nonce in session.seen_nonces:
                    raise AcsError(REPLAY_DETECTED, "nonce was already seen in this session")
                session.seen_nonces.add(nonce)

            if method not in session.methods_evaluated:
                raise AcsError(
                    CAPABILITY_NOT_NEGOTIATED,
                    f"method {method} was not negotiated for this session",
                    data={"method": method},
                )

            self._check_timestamp(params.get("timestamp"), session.skew_window_ms)
            self.schemas.validate_payload(method, params.get("payload"))

            evaluation = self._evaluate(method, params, session, request_id)

            # The chain entry is appended on arrival of an evaluated step,
            # before the verdict is delivered: a denied step is still a step
            # the session took (§8.6).
            session.chain.append(
                step_id=str(request_id),
                step_type=method,
                params=params,
                timestamp=params.get("timestamp"),
            )

            result = self._decision_result(session, request_id, evaluation)

        response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        return self._sign(response, key, session.key_id)

    def _evaluate(
        self,
        method: str,
        params: dict[str, Any],
        session: Session,
        request_id: Any,
    ) -> Evaluation:
        try:
            evaluation = self.engine.evaluate(
                EvaluationRequest(
                    method=method,
                    payload=params.get("payload") or {},
                    session_id=session.session_id,
                    agent_id=session.agent_id,
                    request_id=str(request_id),
                )
            )
        except Exception as error:  # noqa: BLE001 - an engine failure is a deny, never a crash
            print(f"policy engine failed on {method}: {error!r}", file=sys.stderr)
            return _evaluation_failed()
        # A decision that cannot be expressed conformantly is not sent as one
        # (response-envelope.json requires reasoning on deny/modify/ask/defer,
        # and the disposition's own details object): it fails closed instead.
        if not _disposition_complete(evaluation):
            print(f"policy engine returned an incomplete {evaluation.decision} decision on {method}", file=sys.stderr)
            return _evaluation_failed()
        return evaluation

    @staticmethod
    def _decision_result(session: Session, request_id: Any, evaluation: Evaluation) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "final",
            "acs_version": session.negotiated_version,
            "request_id": request_id,
            "decision": evaluation.decision,
            "chain_hash": session.chain.head,
        }
        if evaluation.reasoning is not None:
            result["reasoning"] = evaluation.reasoning
        if evaluation.reason_codes:
            result["reason_codes"] = evaluation.reason_codes
        if evaluation.policy_references:
            result["policy_references"] = evaluation.policy_references
        if evaluation.modifications is not None:
            result["modifications"] = evaluation.modifications
        if evaluation.ask_details is not None:
            result["ask_details"] = evaluation.ask_details
        if evaluation.defer_details is not None:
            result["defer_details"] = evaluation.defer_details
        return result

    def _ping(
        self,
        rpc_id: str | int | None,
        params: dict[str, Any],
        key: bytes | None,
        key_id: str | None,
    ) -> dict[str, Any]:
        payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
        result = {
            "type": "final",
            "acs_version": str(params.get("acs_version", ACS_VERSION)),
            "request_id": params.get("request_id"),
            "decision": ALLOW,
            "payload": {
                "status": "ok",
                "echo": payload.get("echo"),
                "server_timestamp": _now_iso(),
            },
        }
        response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        # Ping never requires a signature; if one authenticated, answering
        # signed costs nothing and keeps the harness's verification uniform.
        session_id = (params.get("metadata") or {}).get("session_id") if isinstance(params.get("metadata"), dict) else None
        if key is not None and isinstance(session_id, str):
            return self._sign(response, key, key_id or self.config.key_id)
        return response

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _session_and_request_id(params: dict[str, Any], *, signable: bool) -> tuple[str, Any]:
        metadata = params.get("metadata")
        session_id = metadata.get("session_id") if isinstance(metadata, dict) else None
        if not isinstance(session_id, str):
            raise AcsError(INVALID_PARAMS, "params.metadata.session_id is required", signable=signable)
        request_id = params.get("request_id")
        if not isinstance(request_id, str):
            raise AcsError(INVALID_PARAMS, "params.request_id is required", signable=signable)
        return session_id, request_id

    @staticmethod
    def _signature_ok(raw: dict[str, Any], params: dict[str, Any], key: bytes) -> bool:
        signature = params.get("signature")
        if not isinstance(signature, dict) or signature.get("algorithm") != ALGORITHM:
            return False
        return verify(key, request_signing_input(raw), signature.get("value"))

    @staticmethod
    def _check_timestamp(timestamp: Any, skew_window_ms: int) -> None:
        if not isinstance(timestamp, str):
            raise AcsError(TIMESTAMP_OUT_OF_WINDOW, "params.timestamp is required", data={"skew_window_ms": skew_window_ms})
        try:
            moment = datetime.fromisoformat(timestamp)
        except ValueError:
            raise AcsError(
                TIMESTAMP_OUT_OF_WINDOW,
                "params.timestamp is not an ISO 8601 date-time",
                data={"skew_window_ms": skew_window_ms},
            ) from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        window = timedelta(milliseconds=skew_window_ms)
        if abs(datetime.now(timezone.utc) - moment) > window:
            raise AcsError(
                TIMESTAMP_OUT_OF_WINDOW,
                "params.timestamp is outside the negotiated skew window",
                data={"skew_window_ms": skew_window_ms},
            )

    def _sign(self, response: dict[str, Any], key: bytes, key_id: str) -> dict[str, Any]:
        holder = response["result"] if "result" in response else response["error"]
        holder["signature"] = {
            "algorithm": ALGORITHM,
            "key_id": key_id,
            "value": sign(key, response_signing_input(response)),
        }
        finding = self.schemas.validate_response(response)
        if finding is not None:
            print(f"guardian sent a response that fails response-envelope.json: {finding}", file=sys.stderr)
        return response

    def _error(
        self,
        rpc_id: str | int | None,
        code: int,
        message: str,
        data: dict[str, Any] | None = None,
        *,
        key: bytes | None = None,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        response = {"jsonrpc": "2.0", "id": rpc_id, "error": error}
        if key is not None:
            return self._sign(response, key, key_id or self.config.key_id)
        return response


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_non_finite(token: str) -> Any:
    raise ValueError(f"non-finite JSON number is not permitted: {token}")


def _best_effort_id(raw: Any) -> str | int | None:
    """The JSON-RPC id for an error response, when one can be determined (§ response-envelope)."""
    if isinstance(raw, dict):
        rpc_id = raw.get("id")
        if isinstance(rpc_id, (str, int)) and not isinstance(rpc_id, bool):
            return rpc_id
    return None


def _disposition_complete(evaluation: Evaluation) -> bool:
    """Whether the decision carries every field response-envelope.json requires for it."""
    from .engine import DISPOSITIONS

    if evaluation.decision not in DISPOSITIONS:
        return False
    if evaluation.decision in (DENY, "modify", "ask", "defer") and not evaluation.reasoning:
        return False
    if evaluation.decision == "modify" and evaluation.modifications is None:
        return False
    if evaluation.decision == "ask" and evaluation.ask_details is None:
        return False
    if evaluation.decision == "defer" and evaluation.defer_details is None:
        return False
    return True


def _evaluation_failed() -> Evaluation:
    return Evaluation(
        decision=DENY,
        reasoning="the Guardian could not produce a conformant decision for this step; failing closed",
        reason_codes=["evaluation_failed"],
    )


# -- HTTP transport --------------------------------------------------------


class _AcsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "acs-guardian/0.1.0"
    # Bounds how long a client can hold a worker thread mid-request (a
    # Content-Length larger than the body, say). The body cap bounds memory;
    # this bounds time.
    timeout = 10

    @property
    def guardian(self) -> Guardian:
        return self.server.guardian  # type: ignore[attr-defined]

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's own naming
        if self.path != ACS_PATH:
            self._respond_text(404, "Not Found")
            return
        length_header = self.headers.get("Content-Length")
        try:
            declared = int(length_header) if length_header is not None else 0
        except ValueError:
            declared = 0
        if declared > MAX_REQUEST_BODY_BYTES:
            # Refused before the body is read; the connection closes so the
            # unread body cannot be misread as the next request on keep-alive.
            self.close_connection = True
            self._respond_json(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": INVALID_REQUEST,
                        "message": f"request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit",
                    },
                }
            )
            return
        body = self.rfile.read(declared)
        try:
            # parse_constant: JSON.parse accepts NaN/Infinity, JCS (RFC 8785)
            # does not, and a non-finite number that reached signature
            # verification would raise out of canonicalization rather than
            # fail it.
            raw = json.loads(body.decode("utf-8"), parse_constant=_reject_non_finite)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._respond_json({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Parse error"}})
            return
        self._respond_json(self.guardian.handle(raw))

    def _respond_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature fixed upstream
        print(f"{self.address_string()} {format % args}", file=sys.stderr)


class GuardianServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, guardian: Guardian) -> None:
        super().__init__((guardian.config.host, guardian.config.port), _AcsHandler)
        self.guardian = guardian
        self.url = f"http://{guardian.config.host}:{self.server_address[1]}{ACS_PATH}"


def serve(guardian: Guardian) -> GuardianServer:
    """Start the HTTP server; the caller owns shutdown."""
    return GuardianServer(guardian)
