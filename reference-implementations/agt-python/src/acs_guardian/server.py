"""The ACS wire boundary: one JSON-RPC 2.0 endpoint, POST /acs.

The spec mandates no URL path convention -- ``/acs`` is this implementation's
choice -- so dispatch is by the JSON-RPC ``method`` field, never by path.

Dispatch order, and why it is this order (the probes in
``tests/test_external_probes.py`` assert the parts of it that are on their
wire; the rest is asserted by ``tests/test_server.py`` and
``tests/test_wrapped_mcp.py``):

1. JSON-RPC envelope shape -> ``-32600``, and JCS canonicalizability ->
   ``-32600`` (a number outside the JCS domain cannot be signed by anyone).
2. Signature verification -> ``-32004`` (unsigned answer: the request
   established no key).
3. Method routing: an undefined method -> ``-32601``; a method the standard
   defines and this Guardian never negotiates (``agbom/*``) -> ``-32003``.
4. Session lookup -> ``-32003`` when no handshake negotiated the session.
5. Under the session lock: replay -> ``-32005`` (before everything below, so
   a replay of a refused request is still a replay), then the session
   bindings and the closed check, answered as signed DENYs, then the
   negotiated-method check -> ``-32003``, then timestamp skew -> ``-32006``.
6. Payload: a wrapped MCP message read and checked -> ``-32602``; a native
   hook's payload validated against its schema -> ``-32602``.
7. Evaluation, the hook's permitted dispositions, §6's required fields and
   §6.3's composition, the audit-chain append, a signed decision.

Every response to an authenticated request is signed with the session key at
``result.signature`` / ``error.signature``, including error responses: the
conformance harness verifies the signature on every signed request it sends,
refusals included. A request that did not authenticate gets an unsigned
answer, because signing it would claim a key relationship that does not exist.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import mcp, methods
from .canonical import canonical_bytes, request_signing_input, response_signing_input
from .chain import AuditChain
from .crypto import ALGORITHM, derive_session_key, sign, verify
from .engine import ALLOW, DENY, Evaluation, EvaluationRequest, PolicyEngine
from .errors import (
    CAPABILITY_NOT_NEGOTIATED,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REPLAY_DETECTED,
    SESSION_REFUSED,
    SIGNATURE_INVALID,
    TIMESTAMP_OUT_OF_WINDOW,
    AcsError,
)
from .handshake import negotiate, server_hello
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
        try:
            # ACS pins JCS (§10): an envelope whose numbers fall outside the
            # JCS domain (1e400, an integer past 2^53) cannot be signed or
            # verified by anyone, so it is invalid here rather than an
            # internal error later when canonicalization raises.
            canonical_bytes(raw)
        except ValueError as error:
            return self._error(
                _best_effort_id(raw),
                INVALID_REQUEST,
                f"request envelope is not JCS-canonicalizable: {error}",
            )
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
                # Signed under the deployment's key_id, like every response:
                # an error answered before a session exists has no session
                # key to name.
                return self._error(rpc_id, error.code, error.message, error.data, key=key)
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
        # §10.3 applies to every request, the handshake included: a recorded
        # ClientHello must not be replayable after the in-memory session (and
        # with it the replay history) is gone.
        self._check_timestamp(params.get("timestamp"), self.config.skew_window_ms)
        client_hello = params.get("payload")
        if not isinstance(client_hello, dict):
            raise AcsError(INVALID_PARAMS, "handshake payload must be a ClientHello object")
        self.schemas.validate_client_hello(client_hello)

        nonce = params.get("nonce")
        existing = self.store.get(session_id)
        if existing is not None:
            with existing.lock:
                if isinstance(request_id, str) and request_id in existing.seen_request_ids:
                    raise AcsError(REPLAY_DETECTED, "request_id was already seen in this session")
                if isinstance(nonce, str) and nonce in existing.seen_nonces:
                    raise AcsError(REPLAY_DETECTED, "nonce was already seen in this session")
                # Recorded before the refusal, like a step's id: a replay of a
                # refused handshake is still a replay (the probes assert the
                # same rule for refused steps).
                if isinstance(request_id, str):
                    existing.seen_request_ids.add(request_id)
                if isinstance(nonce, str):
                    existing.seen_nonces.add(nonce)
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
        session = self._new_session(params, session_id, request_id, key_id, terms, nonce)
        if not self.store.create_if_absent(session):
            # Lost a race with a concurrent handshake for the same session_id.
            raced = self.store.get(session_id)
            if raced is not None:
                with raced.lock:
                    if isinstance(request_id, str) and request_id not in raced.seen_request_ids:
                        raced.seen_request_ids.add(request_id)
                    if isinstance(nonce, str) and nonce not in raced.seen_nonces:
                        raced.seen_nonces.add(nonce)
            raise AcsError(
                SESSION_REFUSED,
                "session is already negotiated; v0.1 defines no renegotiation",
                data={"reason": "renegotiation_not_supported"},
            )

        response = {"jsonrpc": "2.0", "id": rpc_id, "result": server_hello(terms)}
        return self._sign(response, key, self.config.key_id)

    def _new_session(
        self,
        params: dict[str, Any],
        session_id: str,
        request_id: Any,
        key_id: str | None,
        terms: Any,
        nonce: Any = None,
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
            seen_nonces={nonce} if isinstance(nonce, str) else set(),
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

        # The method table decides the route before the session is read
        # (the order the Go port in open PR #169 routes by): a method the
        # standard does not define is
        # METHOD_NOT_FOUND, one it defines and this Guardian never negotiates
        # (agbom/*) is CAPABILITY_NOT_NEGOTIATED.
        route = methods.route(method)
        if route == methods.ROUTE_UNDEFINED:
            raise AcsError(METHOD_NOT_FOUND, f"ACS v0.1 defines no method {method}", data={"method": method})
        if route == methods.ROUTE_UNSUPPORTED:
            raise AcsError(
                CAPABILITY_NOT_NEGOTIATED, f"this Guardian does not negotiate {method}", data={"method": method}
            )

        session = self.store.get(session_id)
        if session is None:
            raise AcsError(
                CAPABILITY_NOT_NEGOTIATED,
                f"no negotiated session for {session_id}; handshake/hello is required first",
                data={"method": method},
            )

        # One session's steps are serialized: the replay check, the binding
        # checks, the chain append, and the decision must be one atomic step,
        # or two concurrent copies of a request both pass the check and both
        # append.
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

            # A session answers only the key and the agent that opened it.
            # Both are answered as a signed DENY, not an error: an error would
            # leave the Observed Agent to its failure posture, which by
            # default proceeds.
            if key_id != session.key_id:
                return self._answer_denial(
                    rpc_id, session, request_id, key, key_id, method,
                    "key_not_bound",
                    "the request is signed with a key_id other than the one that opened this session",
                )
            if params.get("metadata", {}).get("agent_id") != session.agent_id:
                return self._answer_denial(
                    rpc_id, session, request_id, key, key_id, method,
                    "agent_id_not_bound",
                    "the request names an agent other than the agent that opened this session",
                )
            if session.closed:
                return self._answer_denial(
                    rpc_id, session, request_id, key, key_id, method,
                    "session_closed",
                    "the session has ended; no step enters after steps/sessionEnd",
                )
            if method not in session.methods_evaluated:
                raise AcsError(
                    CAPABILITY_NOT_NEGOTIATED,
                    f"method {method} was not negotiated for this session",
                    data={"method": method},
                )

            self._check_timestamp(params.get("timestamp"), session.skew_window_ms)
            evaluation = self._evaluate(method, params, session, request_id, route)

            # The chain entry is appended on arrival of an evaluated step,
            # before the verdict is delivered: a denied step is still a step
            # the session took (§8.6).
            session.chain.append(
                step_id=str(request_id),
                step_type=method,
                params=params,
                timestamp=params.get("timestamp"),
            )
            if method == "steps/sessionEnd":
                session.closed = True

            result = self._decision_result(session, request_id, evaluation)

        response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        return self._sign(response, key, self.config.key_id)

    def _answer_denial(
        self,
        rpc_id: str | int | None,
        session: Session,
        request_id: Any,
        key: bytes | None,
        key_id: str | None,
        method: str,
        reason_code: str,
        reasoning: str,
    ) -> dict[str, Any]:
        """A Guardian-authored DENY that is not an evaluated step: no chain entry.

        The step never reached the chain, so the answer carries no
        ``chain_hash`` at all — not the previous step's head, which is what
        the field would name if it were sent, and not a null, which fails
        response-envelope.json. The denial still passes through the hook's
        permitted dispositions: a hook that permits no DENY is answered with
        an ALLOW carrying the reason code instead.
        """
        evaluation = _substitute_permitted(
            method, Evaluation(decision=DENY, reasoning=reasoning, reason_codes=[reason_code])
        )
        response = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": self._decision_result(session, request_id, evaluation, include_chain_hash=False),
        }
        # Signed under the deployment's key_id, like every other response:
        # key_id names the key a verifier resolves, and that is the one this
        # Guardian holds. The session's key_id is a binding the request is
        # checked against, not a second label for the same key.
        return self._sign(response, key, self.config.key_id)

    def _evaluate(
        self,
        method: str,
        params: dict[str, Any],
        session: Session,
        request_id: Any,
        route: str,
    ) -> Evaluation:
        if route == methods.ROUTE_WRAPPED:
            split = methods.split_wrapped(method)
            assert split is not None  # route() returned Wrapped, so this parses
            # The wrapped MCP message reaches the engine intact; a malformed
            # one is INVALID_PARAMS (-32602).
            engine_payload = mcp.read(split[2], params.get("payload"))
        else:
            self.schemas.validate_payload(method, params.get("payload"))
            engine_payload = params.get("payload") or {}

        try:
            evaluation = self.engine.evaluate(
                EvaluationRequest(
                    method=method,
                    payload=engine_payload,
                    session_id=session.session_id,
                    agent_id=session.agent_id,
                    request_id=str(request_id),
                )
            )
        except Exception as error:  # noqa: BLE001 - an engine failure is a deny, never a crash
            print(f"policy engine failed on {method}: {error!r}", file=sys.stderr)
            return _evaluation_failed(method)

        # A disposition the hook does not permit is not sent as one: the hook
        # cannot carry it (hooks.md "Decision").
        evaluation = _substitute_permitted(method, evaluation)

        # A decision that cannot be expressed conformantly is not sent as one
        # (response-envelope.json requires reasoning on deny/modify/ask/defer,
        # the disposition's own details object, and §6.3's modification
        # composition): it fails closed instead.
        if not _decision_fit(self.schemas, method, evaluation):
            print(f"policy engine returned an unfit {evaluation.decision} decision on {method}", file=sys.stderr)
            return _evaluation_failed(method)
        return evaluation

    @staticmethod
    def _decision_result(
        session: Session, request_id: Any, evaluation: Evaluation, *, include_chain_hash: bool = True
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "final",
            "acs_version": session.negotiated_version,
            "request_id": request_id,
            "decision": evaluation.decision,
        }
        # The head "after this step's ContextEntry was appended"
        # (response-envelope.json): omitted, never the previous step's head and
        # never null, when this step wrote no entry.
        if include_chain_hash and session.chain.head is not None:
            result["chain_hash"] = session.chain.head
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
            return self._sign(response, key, self.config.key_id)
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
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        response = {"jsonrpc": "2.0", "id": rpc_id, "error": error}
        if key is not None:
            return self._sign(response, key, self.config.key_id)
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


def _decision_fit(schemas: SchemaRegistry, method: str, evaluation: Evaluation) -> bool:
    """Whether the decision satisfies §6's required fields and §6.3's composition rules.

    The disposition-specific objects are validated against their own schemas
    (modifications.json, ask-details.json, defer-details.json) rather than
    field-by-field: the schemas are the contract, and they express rules a
    hand-written check would miss (an empty ``redactions`` array beside
    ``modified_content`` is still "carrying" it).
    """
    from .engine import DISPOSITIONS

    if evaluation.decision not in DISPOSITIONS:
        return False
    if evaluation.decision != ALLOW and not evaluation.reasoning:
        return False
    if evaluation.decision == "modify":
        if schemas.check("modifications.json", evaluation.modifications) is not None:
            return False
        return _modification_targets_disjoint(method, evaluation.modifications)
    if evaluation.decision == "ask":
        return schemas.check("ask-details.json", evaluation.ask_details) is None
    if evaluation.decision == "defer":
        return schemas.check("defer-details.json", evaluation.defer_details) is None
    return True


def _modification_targets_disjoint(method: str, modifications: Any) -> bool:
    """§6.3: no redaction path addresses the same field as an override key, or an ancestor/descendant.

    The only §6.3 rule a JSON Schema cannot express; the exclusivity of
    ``modified_content`` and the presence rules are the schema's.
    """
    if not isinstance(modifications, dict):
        return False
    # Absent keys are the empty containers; the schema has already refused a
    # present-but-empty one beside modified_content ("carrying" is presence).
    redactions = modifications.get("redactions", [])
    overrides = modifications.get("parameter_overrides", {})
    if not isinstance(redactions, list) or not isinstance(overrides, dict):
        return False
    for redaction in redactions:
        path = redaction.get("path") if isinstance(redaction, dict) else None
        if not isinstance(path, str):
            return False
        for argument in overrides:
            if _pointers_overlap(path, methods.override_pointer(method, str(argument))):
                return False
    return True


def _pointers_overlap(a: str, b: str) -> bool:
    """Whether one JSON pointer addresses the same field as the other, or an ancestor/descendant."""
    return a == b or b.startswith(a + "/") or a.startswith(b + "/") or a == "" or b == ""


def _substitute_permitted(method: str, evaluation: Evaluation) -> Evaluation:
    """Coerce a decision the hook does not permit into one it can carry (hooks.md "Decision").

    DENY when the hook permits a denial; ALLOW otherwise, because the action
    has already happened and the step stands with an audit reason. The
    original reason codes are kept beside ``disposition_not_permitted``.
    """
    permitted = methods.permitted_dispositions(method)
    if evaluation.decision in permitted:
        return evaluation
    detail = f"{evaluation.decision} is not permitted at {method}, which permits {'/'.join(permitted)}"
    print(f"{detail}; substituting", file=sys.stderr)
    codes = [*evaluation.reason_codes, "disposition_not_permitted"]
    reasoning = f"{detail}. {evaluation.reasoning or ''}".strip()
    if DENY in permitted:
        return Evaluation(decision=DENY, reasoning=reasoning, reason_codes=codes)
    return Evaluation(
        decision=ALLOW,
        reasoning=f"{reasoning} The action has already happened, so the step stands.",
        reason_codes=codes,
    )


def _evaluation_failed(method: str) -> Evaluation:
    return _substitute_permitted(
        method,
        Evaluation(
            decision=DENY,
            reasoning="the Guardian could not produce a conformant decision for this step; failing closed",
            reason_codes=["evaluation_failed"],
        ),
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
            # Closing, not reading: an unread body on a keep-alive connection
            # would be parsed as the next request.
            self.close_connection = True
            self._respond_text(404, "Not Found")
            return
        length_header = self.headers.get("Content-Length")
        declared = 0
        # RFC 9110's Content-Length is 1*DIGIT: no sign, no whitespace, no
        # underscores, no Unicode digits. `int()` would accept all of those,
        # and a proxy that frames the body differently than this server reads
        # it is exactly the desync this refusal prevents. Duplicate headers
        # are refused for the same reason.
        declared_values = self.headers.get_all("Content-Length") or []
        if length_header is None or len(declared_values) != 1 or not re.fullmatch(r"[0-9]+", length_header):
            # No body framing this server supports (chunked is not read):
            # refusing and closing beats reading nothing and letting the
            # unread body desync the next keep-alive request.
            self.close_connection = True
            self._respond_json(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": INVALID_REQUEST,
                        "message": "a single, non-negative integer Content-Length header is required",
                    },
                }
            )
            return
        declared = int(length_header)
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
            # parse_constant rejects the literal NaN/Infinity tokens JSON.parse
            # accepts; numeric overflow (1e400, integers past 2^53) is caught
            # by the JCS canonicalizability check in Guardian.handle, which
            # runs before anything tries to sign the envelope.
            raw = json.loads(body.decode("utf-8"), parse_constant=_reject_non_finite)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
            # RecursionError: deeply nested JSON (~1000 levels, a few KB) is
            # under the body cap but past the parser's limit; it must be a
            # parse error, not a dropped connection.
            self._respond_json({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Parse error"}})
            return
        self._respond_json(self.guardian.handle(raw))

    def _respond_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            # Say so: an HTTP/1.1 client is otherwise entitled to reuse the
            # connection and would meet an EOF it was not told to expect.
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _respond_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
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
