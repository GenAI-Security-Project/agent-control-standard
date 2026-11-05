"""The ACS wire boundary: one JSON-RPC 2.0 endpoint, POST /acs.

The spec mandates no URL path convention -- ``/acs`` is this implementation's
choice -- so dispatch is by the JSON-RPC ``method`` field, never by path.

Dispatch order, and why it is this order (the probes in
``tests/test_external_probes.py`` assert the parts of it that are on their
wire; the rest is asserted by ``tests/test_server.py`` and
``tests/test_wrapped_mcp.py``):

1. JSON-RPC envelope shape -> ``-32600``, and JCS canonicalizability ->
   ``-32600`` (a number outside the JCS domain cannot be signed by anyone).
   A body nested past ``MAX_JSON_DEPTH`` is answered fail-closed before any
   recursive consumer (schema validation, canonicalization) can meet it.
2. The signature's ``key_id`` must name the configured secret: a request
   naming another label never resolves a key, so it is refused ``-32004``
   (unsigned, like every answer that established no key) instead of being
   verified with the deployment's secret.
3. Method routing: an undefined method -> ``-32601``; a method the standard
   defines and this Guardian never negotiates (``agbom/*``) -> ``-32003``.
4. Session lookup -> ``-32003`` when no handshake negotiated the session.
5. Under the session lock: replay -> ``-32005`` (before everything below, so
   a replay of a refused request is still a replay), then the session
   bindings and the closed check, answered as signed DENYs, then the
   negotiated-method check -> ``-32003``, then a step whose ``acs_version``
   does not share the session's negotiated major version -> ``-32001``
   (§3's forward-compat rule; the ServerHello names a version the client
   offered, and a step may not move off its major), then timestamp skew ->
   ``-32006``.
6. Payload: a wrapped MCP message read and checked -> ``-32602``; a native
   hook's payload validated against its schema -> ``-32602``.
7. Evaluation, the hook's permitted dispositions, §6's required fields,
   §6.3's composition and §6.5's substitution, the audit-chain append, a
   signed decision.

Once a step's signature has verified, a failure outside the registry — an
internal exception on the governed path — is answered with a signed DENY
carrying ``evaluation_failed``, never an error: an error without a decision
leaves the Observed Agent to its ``on_decision_failure`` posture, which by
default proceeds. Registry refusals (replay, skew, version, schema,
capability) keep their own signed error codes, as the spec defines them.

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
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import mcp, methods
from .canonical import canonical_bytes, request_signing_input, response_signing_input
from .chain import AuditChain
from .crypto import ALGORITHM, derive_session_key, sign, verify
from .engine import ALLOW, DENY, MODIFY, Evaluation, EvaluationRequest, PolicyEngine
from .errors import (
    CAPABILITY_NOT_NEGOTIATED,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REPLAY_DETECTED,
    SESSION_REFUSED,
    SIGNATURE_INVALID,
    TIMESTAMP_OUT_OF_WINDOW,
    UNSUPPORTED_VERSION,
    AcsError,
)
from .handshake import negotiate, same_major, server_hello
from .schemas import SchemaRegistry
from .session import Session, SessionStore

ACS_PATH = "/acs"
MAX_REQUEST_BODY_BYTES = 1_048_576
ACS_VERSION = "0.1.0"
# Bounds every recursive consumer of a request (schema validation, the
# built-in engine's payload walk): a few hundred levels of nesting is enough
# to exhaust Python's default recursion limit on some builds and stack
# depths, turning a denial into an unsigned error the agent may proceed on.
# 128 is far past any real hook payload.
MAX_JSON_DEPTH = 128
# The C JSON parser accepts roughly ten thousand nesting levels, but JCS
# canonicalization is pure-Python recursion the default limit rejects around
# a thousand. Over-deep bodies therefore verify and hash on a thread sized
# for the parser's maximum.
DEEP_RECURSION_LIMIT = 30_000
DEEP_THREAD_STACK_BYTES = 32 * 1024 * 1024
# Refused at the parse boundary: a body nested deeper than the enlarged
# thread's limit could never be canonicalized or verified by this Guardian,
# whatever the interpreter's parser happens to accept.
DEEP_PARSE_LIMIT = 10_000
_DEEP_LOCK = threading.Lock()

# A deployment's own audit record, e.g. a SIEM line. The standard requires
# audit events for some decisions (the §6.5 substitution, say) and leaves the
# sink to the deployment; the default writes one JSON object per line to
# stderr. It must not block and must not raise: a failed audit sink cannot be
# allowed to turn a governed step into an ungoverned one.
AuditHook = Callable[[dict[str, Any]], None]


def _stderr_audit(event: dict[str, Any]) -> None:
    print(json.dumps(event, separators=(",", ":"), ensure_ascii=False), file=sys.stderr)


@dataclass
class GuardianConfig:
    """Deployment configuration. The secret is deployment-provided key material (§10)."""

    secret: bytes
    # The label the deployment gives this one configured secret. No default:
    # the label is how a verifier resolves the secret, and "default" or
    # "conformance" as a fallback invites every deployment onto one label and
    # makes a rotation need a code change. The #118 decision: key_id is an
    # opaque deployment-chosen label, reserved values: none.
    key_id: str
    on_decision_failure: str = "proceed"
    timeout_ms: int = 5000
    skew_window_ms: int = 300_000
    policy_requires_provenance: bool = False
    spec_root: Path | None = None
    engine: PolicyEngine | None = None
    # A deployment that needs eviction (TTL, capacity) supplies its own store;
    # the default keeps sessions for the process lifetime.
    session_store: SessionStore | None = None
    audit: AuditHook | None = None
    host: str = "127.0.0.1"
    port: int = 8787


class Guardian:
    """The protocol logic, transport-independent so tests can drive it directly."""

    def __init__(self, config: GuardianConfig) -> None:
        if config.on_decision_failure not in ("proceed", "deny"):
            raise ValueError(f"on_decision_failure must be proceed or deny, got {config.on_decision_failure!r}")
        if len(config.secret) < 32:
            raise ValueError("the HMAC secret must be at least 32 bytes")
        if not config.key_id:
            raise ValueError("key_id must be a non-empty label naming this deployment's secret")
        self.config = config
        self.audit: AuditHook = config.audit if config.audit is not None else _stderr_audit
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
        if _exceeds_depth(raw, MAX_JSON_DEPTH):
            return self._over_deep(raw)
        try:
            # The authoritative envelope check: request-envelope.json, required
            # fields included (acs_version, request_id, timestamp, metadata).
            self.schemas.validate_request(raw)
        except AcsError as error:
            return self._error(_best_effort_id(raw), error.code, error.message, error.data)
        except RecursionError as error:  # defensive: the depth cap above should pre-empt this
            return self._error(
                _best_effort_id(raw),
                INVALID_REQUEST,
                f"request envelope could not be validated: {error}",
            )
        try:
            # ACS pins JCS (§10): an envelope whose numbers fall outside the
            # JCS domain (1e400, an integer past 2^53) cannot be signed or
            # verified by anyone, so it is invalid here rather than an
            # internal error later when canonicalization raises.
            canonical_bytes(raw)
        except (ValueError, RecursionError) as error:
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
            signature = params.get("signature")
            if isinstance(signature, dict) and isinstance(signature.get("key_id"), str):
                key_id = signature["key_id"]
            # The key resolves only for the configured label: a request naming
            # another key_id is not verified with this deployment's secret
            # (#118: a verifier MUST reject an unknown key_id and MUST NOT
            # fall back to another secret). It stays key-less, so its answer
            # is unsigned -- ping, exempt from signing, is still answered.
            if (
                key_id == self.config.key_id
                and isinstance(metadata, dict)
                and isinstance(metadata.get("session_id"), str)
            ):
                key = derive_session_key(self.config.secret, metadata["session_id"])

        try:
            if method == "handshake/hello":
                return self._handshake(raw, rpc_id, params, key)
            return self._step(raw, rpc_id, method, params, key)
        except AcsError as error:
            if error.signable and key is not None:
                # Signed under the deployment's key_id, like every response:
                # an error answered before a session exists has no session
                # key to name.
                return self._error(rpc_id, error.code, error.message, error.data, key=key)
            return self._error(rpc_id, error.code, error.message, error.data)
        except Exception as error:  # noqa: BLE001 - nothing may escape as a non-JSON-RPC answer
            # Details go to the operator's log, not the wire: an exception
            # message can carry filesystem paths and schema internals.
            #
            # Deliberately unsigned: this route is a bug in the Guardian, and
            # the request may not have authenticated (the key is derived from
            # metadata.session_id, not from a verified signature), so signing
            # would claim a key relationship that may not exist.
            print(f"guardian failed to handle a request: {error!r}", file=sys.stderr)
            return self._error(rpc_id, INTERNAL_ERROR, "guardian failed to handle the request")

    def _over_deep(self, raw: Any) -> dict[str, Any]:
        """Fail closed on a body nested past ``MAX_JSON_DEPTH``.

        The guard fires before schema validation and canonicalization, both of
        which recurse. Nothing here trusts the ``key_id`` label or the
        ``session_id`` alone — both travel on every request and are not
        secrets; trusting them would turn this route into a signing oracle.
        The body's own signature is verified first, shallowly enough for any
        depth the parser accepts (canonicalization that hits the default
        recursion limit is retried on an enlarged thread). A verified step is
        answered like any other verified failure — a signed, recorded
        decision — while a body that does not verify gets the plain error,
        unsigned.
        """
        rpc_id = _best_effort_id(raw)
        params = raw.get("params") if isinstance(raw, dict) else None
        metadata = params.get("metadata") if isinstance(params, dict) else None
        session_id = metadata.get("session_id") if isinstance(metadata, dict) else None
        method = raw.get("method") if isinstance(raw, dict) else None
        if isinstance(params, dict) and isinstance(session_id, str):
            signature = params.get("signature")
            key_id = signature.get("key_id") if isinstance(signature, dict) else None
            # The session is looked up before any verification work: the deep
            # thread serializes, and a request with no live session has no
            # decision to record anyway, so it has no reason to queue there.
            session = self.store.get(session_id)
            if session is not None and key_id == self.config.key_id:
                key = derive_session_key(self.config.secret, session_id)
                if self._signature_ok_any_depth(raw, params, key):
                    method_name = method if isinstance(method, str) else ""
                    try:
                        return self._over_deep_decision(rpc_id, session, params, method)
                    except Exception as error:  # noqa: BLE001 - a hook fails closed; other routes report
                        print(f"guardian failed on a verified over-deep step: {error!r}", file=sys.stderr)
                        if methods.route(method_name) not in (methods.ROUTE_HOOK, methods.ROUTE_WRAPPED):
                            # A ping or a refusal route has no decision to
                            # fail closed with; report the bug as the normal
                            # path would, unsigned.
                            return self._error(rpc_id, INTERNAL_ERROR, "guardian failed to handle the request")
                        request_id = params.get("request_id")
                        if not isinstance(request_id, str):
                            return self._error(
                                rpc_id, INVALID_PARAMS, "params.request_id is required", key=key
                            )
                        return self._fail_closed(
                            rpc_id, method_name, params, session_id, request_id, key, None
                        )
        return self._error(
            rpc_id,
            INVALID_REQUEST,
            f"request nesting exceeds the {MAX_JSON_DEPTH}-level implementation limit",
        )

    @staticmethod
    def _signature_ok_any_depth(raw: dict[str, Any], params: dict[str, Any], key: bytes) -> bool:
        """Verify a signature on a body of any depth the JSON parser accepts.

        JCS canonicalization of a body nested a few thousand levels raises
        ``RecursionError`` on the default limit while the body itself is
        well-formed, so the retry runs on an enlarged thread. A
        canonicalization failure there is a request no one could have signed
        the same way this Guardian would read it, so it verifies False.
        """
        try:
            return Guardian._signature_ok(raw, params, key)
        except RecursionError:
            pass
        except ValueError:
            return False
        ok, verified = _in_deep_thread(lambda: Guardian._signature_ok(raw, params, key))
        return ok and bool(verified)

    def _over_deep_decision(
        self,
        rpc_id: str | int | None,
        session: Session,
        params: dict[str, Any],
        method: Any,
    ) -> dict[str, Any]:
        """A signed, recorded decision for a verified step that is over-deep.

        The dispatch ladder mirrors the normal path: the route decides first
        — a ping answered without touching the chain or replay history, an
        undefined or unsupported method its own signed refusal (neither
        consuming the request_id, as the normal path refuses both before a
        session is read), a handshake refused as a renegotiation with its
        request_id and nonce recorded first, like ``_handshake`` — then
        replay (-32005), then the agent binding and the closed check (signed
        denials that write no entry), then the negotiated-method check, then
        the step's chain entry — hashed on an enlarged thread when the body
        is deeper than the default stack canonicalizes — with ``chain_hash``
        sent only when that entry is in the chain. The version and skew
        checks are not repeated: the answer here is fail-closed regardless of
        their outcome.
        """
        request_id = params.get("request_id")
        nonce = params.get("nonce")
        method_name = method if isinstance(method, str) else ""
        key = derive_session_key(self.config.secret, session.session_id)
        if not isinstance(request_id, str):
            # request-envelope.json requires a string request_id; a body
            # without one must not reach the chain (its entry would have no
            # id to deduplicate) or the response (a nested id could not be
            # hashed). The normal path refuses this before anything else
            # exists to do.
            return self._error(rpc_id, INVALID_PARAMS, "params.request_id is required", key=key)
        with session.lock:
            # The route decides first, like the normal path: a method the
            # standard does not define or this Guardian never negotiates is
            # refused without consuming the request_id (the normal path
            # refuses both before a session is read), while the handshake
            # branch consumes its ids before refusing, like _handshake.
            route = methods.route(method_name)
            if route == methods.ROUTE_PING:
                return self._signed_response_any_depth(_ping_result(rpc_id, params), key)
            if route == methods.ROUTE_HANDSHAKE:
                # A refused handshake consumes its request_id and nonce
                # before the refusal, in _handshake's check-both-then-record
                # order: a replay of the handshake is a replay, and a later
                # step reusing either is one too.
                if request_id in session.seen_request_ids:
                    return self._error(
                        rpc_id, REPLAY_DETECTED, "request_id was already seen in this session", key=key
                    )
                if isinstance(nonce, str) and nonce in session.seen_nonces:
                    return self._error(
                        rpc_id, REPLAY_DETECTED, "nonce was already seen in this session", key=key
                    )
                session.seen_request_ids.add(request_id)
                if isinstance(nonce, str):
                    session.seen_nonces.add(nonce)
                return self._error(
                    rpc_id,
                    SESSION_REFUSED,
                    "session is already negotiated; v0.1 defines no renegotiation",
                    data={"reason": "renegotiation_not_supported"},
                    key=key,
                )
            if route == methods.ROUTE_UNDEFINED:
                return self._error(
                    rpc_id, METHOD_NOT_FOUND, f"ACS v0.1 defines no method {method_name}", data={"method": method_name}, key=key
                )
            if route == methods.ROUTE_UNSUPPORTED:
                return self._error(
                    rpc_id,
                    CAPABILITY_NOT_NEGOTIATED,
                    f"this Guardian does not negotiate {method_name}",
                    data={"method": method_name},
                    key=key,
                )
            if request_id in session.seen_request_ids:
                return self._error(
                    rpc_id, REPLAY_DETECTED, "request_id was already seen in this session", key=key
                )
            session.seen_request_ids.add(request_id)
            if isinstance(nonce, str):
                if nonce in session.seen_nonces:
                    return self._error(
                        rpc_id, REPLAY_DETECTED, "nonce was already seen in this session", key=key
                    )
                session.seen_nonces.add(nonce)
            if params.get("metadata", {}).get("agent_id") != session.agent_id:
                return self._answer_denial(
                    rpc_id, session, request_id, key, method_name,
                    "agent_id_not_bound",
                    "the request names an agent other than the agent that opened this session",
                )
            if session.closed:
                return self._answer_denial(
                    rpc_id, session, request_id, key, method_name,
                    "session_closed",
                    "the session has ended; no step enters after steps/sessionEnd",
                )
            # After the bindings and the closed check, like _step: a closed
            # session or a foreign agent gets its signed denial, not a
            # capability error the posture may turn into a proceed.
            if method_name not in session.methods_evaluated:
                return self._error(
                    rpc_id,
                    CAPABILITY_NOT_NEGOTIATED,
                    f"method {method_name} was not negotiated for this session",
                    data={"method": method_name},
                    key=key,
                )
            appended = False
            try:
                self._append_step_entry(session, request_id, method_name, params)
                appended = True
            except Exception as error:  # noqa: BLE001 - the decision goes out regardless
                print(f"guardian could not append an over-deep step to the chain: {error!r}", file=sys.stderr)
            if method_name == "steps/sessionEnd":
                session.closed = True
            evaluation = _evaluation_failed(method_name)
            result = self._decision_result(session, request_id, evaluation, include_chain_hash=appended)
        response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        return self._sign(response, key, self.config.key_id)

    @staticmethod
    def _append_step_entry(session: Session, request_id: Any, method_name: str, params: dict[str, Any]) -> None:
        """Append one step's chain entry, canonicalizing on an enlarged thread if needed."""

        def append() -> None:
            session.chain.append(
                step_id=str(request_id),
                step_type=method_name,
                params=params,
                timestamp=_now_iso(),
                turn_id=_turn_id(params),
            )

        try:
            append()
        except RecursionError:
            ok, error = _in_deep_thread(append)
            if not ok:
                raise error

    # -- handshake ---------------------------------------------------------

    def _handshake(
        self,
        raw: dict[str, Any],
        rpc_id: str | int | None,
        params: Any,
        key: bytes | None,
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
        session = self._new_session(params, session_id, request_id, terms, nonce)
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
        terms: Any,
        nonce: Any = None,
    ) -> Session:
        return Session(
            session_id=session_id,
            agent_id=str((params.get("metadata") or {}).get("agent_id", "")),
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
            return self._ping(raw, rpc_id, params, key)

        # From here the request authenticated, and every failure is answered
        # as a signed DENY: an error without a decision leaves the Observed
        # Agent to its on_decision_failure posture, which by default proceeds.
        entries_before: int | None = None
        try:
            # The method table decides the route before the session is read
            # (the order the Go port in open PR #169 routes by): a method the
            # standard does not define is METHOD_NOT_FOUND, one it defines and
            # this Guardian never negotiates (agbom/*) is
            # CAPABILITY_NOT_NEGOTIATED.
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
            # checks, the chain append, and the decision must be one atomic
            # step, or two concurrent copies of a request both pass the check
            # and both append.
            with session.lock:
                entries_before = len(session.chain.entries)
                if isinstance(request_id, str):
                    if request_id in session.seen_request_ids:
                        raise AcsError(REPLAY_DETECTED, "request_id was already seen in this session")
                    session.seen_request_ids.add(request_id)
                nonce = params.get("nonce")
                if isinstance(nonce, str):
                    if nonce in session.seen_nonces:
                        raise AcsError(REPLAY_DETECTED, "nonce was already seen in this session")
                    session.seen_nonces.add(nonce)

                # A session answers only the agent that opened it. Answered as
                # a signed DENY, not an error: an error would leave the
                # Observed Agent to its failure posture, which by default
                # proceeds. (The key_id binding is upstream, in handle(): a
                # request naming another label never resolved a key, so it
                # never reaches a signature check, let alone this one.)
                if params.get("metadata", {}).get("agent_id") != session.agent_id:
                    return self._answer_denial(
                        rpc_id, session, request_id, key, method,
                        "agent_id_not_bound",
                        "the request names an agent other than the agent that opened this session",
                    )
                if session.closed:
                    return self._answer_denial(
                        rpc_id, session, request_id, key, method,
                        "session_closed",
                        "the session has ended; no step enters after steps/sessionEnd",
                    )
                if method not in session.methods_evaluated:
                    raise AcsError(
                        CAPABILITY_NOT_NEGOTIATED,
                        f"method {method} was not negotiated for this session",
                        data={"method": method},
                    )
                # §3's forward-compat rule: the ServerHello named a version
                # the client offered, and a step may not move off that major.
                # The rule and the error data are the Go port's (SameMajor,
                # supported_versions); this Guardian places the check after
                # the method check and before the skew check, where the Go
                # port checks the skew window first.
                if not same_major(str(params.get("acs_version", "")), session.negotiated_version):
                    raise AcsError(
                        UNSUPPORTED_VERSION,
                        f"acs_version {params.get('acs_version')!r} does not share the negotiated major version",
                        data={"supported_versions": [session.negotiated_version]},
                    )

                self._check_timestamp(params.get("timestamp"), session.skew_window_ms)
                evaluation = self._evaluate(method, params, session, request_id, route)

                # The chain entry is appended on arrival of an evaluated step,
                # before the verdict is delivered: a denied step is still a
                # step the session took (§8.6). The timestamp is the
                # Guardian's write clock and entry_id is the request_id, the
                # Go port's choices for the two fields ACS leaves undefined.
                session.chain.append(
                    step_id=str(request_id),
                    step_type=method,
                    params=params,
                    timestamp=_now_iso(),
                    turn_id=_turn_id(params),
                )
                if method == "steps/sessionEnd":
                    session.closed = True

                result = self._decision_result(session, request_id, evaluation)

            response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
            return self._sign(response, key, self.config.key_id)
        except AcsError:
            # Registry refusals (replay, skew, unnegotiated method/version)
            # keep their codes: the agent branches on them.
            raise
        except Exception as error:  # noqa: BLE001 - an authenticated step fails closed
            print(f"guardian failed on a verified step: {error!r}", file=sys.stderr)
            return self._fail_closed(rpc_id, method, params, session_id, request_id, key, entries_before)

    def _fail_closed(
        self,
        rpc_id: str | int | None,
        method: str,
        params: dict[str, Any],
        session_id: str,
        request_id: Any,
        key: bytes | None,
        entries_before: int | None,
    ) -> dict[str, Any]:
        """A signed DENY for a failure on the governed path, never an error.

        An error without a decision leaves the Observed Agent to its
        ``on_decision_failure`` posture (default: proceed), so a failure after
        the signature verified is answered like an engine failure: a signed
        DENY carrying ``evaluation_failed``. The step's chain entry is
        appended if the failure pre-empted it — the step did arrive (§8.6) —
        and ``chain_hash`` is sent only when this step's entry is in the
        chain, because the field names the head *after this step's entry*.
        ``steps/sessionEnd`` closes the session either way.
        """
        session = self.store.get(session_id)
        if session is None or key is None:
            # Nothing to bind a decision to; this route is a bug report, and
            # the request may not have authenticated, so it stays unsigned.
            return self._error(rpc_id, INTERNAL_ERROR, "guardian failed to handle the request")
        with session.lock:
            appended = entries_before is not None and len(session.chain.entries) > entries_before
            if not appended:
                try:
                    session.chain.append(
                        step_id=str(request_id),
                        step_type=method,
                        params=params,
                        timestamp=_now_iso(),
                        turn_id=_turn_id(params),
                    )
                    appended = True
                except Exception as error:  # noqa: BLE001 - the denial goes out regardless
                    print(f"guardian could not append a failed step to the chain: {error!r}", file=sys.stderr)
            if method == "steps/sessionEnd":
                session.closed = True
            evaluation = _evaluation_failed(method)
            result = self._decision_result(session, request_id, evaluation, include_chain_hash=appended)
        response = {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        return self._sign(response, key, self.config.key_id)

    def _answer_denial(
        self,
        rpc_id: str | int | None,
        session: Session,
        request_id: Any,
        key: bytes | None,
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
        # Guardian holds. Every session binds that same configured label.
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
        # cannot carry it (hooks.md "Decision"). Only after that, a MODIFY the
        # Observed Agent cannot apply is substituted too (§6.5), with its own
        # reason code: at a hook that permits no MODIFY the substitution above
        # already fired, and disposition_not_permitted is the accurate code
        # there.
        evaluation = _substitute_permitted(method, evaluation)
        if evaluation.decision == MODIFY and evaluation.client_cannot_apply_modify:
            policy_codes = list(evaluation.reason_codes)
            modifications = evaluation.modifications
            evaluation = _modify_unsupported(method, evaluation)
            # §9.2's precedent: the substitution is recorded as an audit
            # event. postCompact's requirement is explicit: the event names
            # the rewrite that could not be delivered, which is why the
            # reasoning (it names the redaction paths / override keys / the
            # replacement content) and the modifications themselves are part
            # of the event.
            event: dict[str, Any] = {
                "event": "modify_unsupported",
                "session_id": session.session_id,
                "request_id": str(request_id),
                "method": method,
                "reasoning": evaluation.reasoning,
                "reason_codes": ["modify_unsupported"],
            }
            if policy_codes:
                event["policy_reason_codes"] = policy_codes
            if isinstance(modifications, dict):
                event["intended_modifications"] = modifications
            self._audit(event)

        # A decision that cannot be expressed conformantly is not sent as one
        # (response-envelope.json requires reasoning on deny/modify/ask/defer,
        # the disposition's own details object, and §6.3's modification
        # composition): it fails closed instead.
        if not _decision_fit(self.schemas, method, evaluation):
            print(f"policy engine returned an unfit {evaluation.decision} decision on {method}", file=sys.stderr)
            return _evaluation_failed(method)
        return evaluation

    def _audit(self, event: dict[str, Any]) -> None:
        """Record a required audit event without letting the sink break governance."""
        try:
            self.audit(event)
        except Exception as error:  # noqa: BLE001 - a failed sink is reported, not raised
            print(f"the audit sink failed: {error!r}", file=sys.stderr)

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
        raw: dict[str, Any],
        rpc_id: str | int | None,
        params: dict[str, Any],
        key: bytes | None,
    ) -> dict[str, Any]:
        response = _ping_result(rpc_id, params)
        # Ping never requires a signature, and its answer is signed only when
        # the ping itself verified (the Go port's rule). Signing it on the
        # strength of metadata.session_id alone would make the endpoint a
        # signing oracle: anyone able to name a session could collect a
        # Guardian-signed ALLOW under that session's key, which an attacker on
        # the network path could substitute for a real signed DENY.
        if key is not None and self._signature_ok(raw, params, key):
            return self._sign(response, key, self.config.key_id)
        return response

    def _signed_response_any_depth(self, response: dict[str, Any], key: bytes) -> dict[str, Any]:
        """Sign a response whose content may be too deep for the request thread."""
        try:
            return self._sign(response, key, self.config.key_id)
        except RecursionError:
            ok, signed = _in_deep_thread(lambda: self._sign(response, key, self.config.key_id))
            if not ok:
                raise signed
            return signed

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


def _ping_result(rpc_id: str | int | None, params: dict[str, Any]) -> dict[str, Any]:
    """The liveness answer (§13), before any signing decision.

    Split from ``_ping`` so the over-deep path can build and sign the answer
    for a request whose signature it has already verified.
    """
    payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
    acs_version = params.get("acs_version")
    result = {
        "type": "final",
        "acs_version": acs_version if isinstance(acs_version, str) else ACS_VERSION,
        "request_id": params.get("request_id"),
        "decision": ALLOW,
        "payload": {
            "status": "ok",
            "echo": payload.get("echo"),
            "server_timestamp": _now_iso(),
        },
    }
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _turn_id(params: dict[str, Any]) -> str | None:
    """The envelope's ``metadata.turn_id``, when the framework set one.

    turnStart requires the framework to propagate it onto every per-step
    ContextEntry; the Go port carries it into the entry under the envelope
    field's name, since context-entry.json names no member for it.
    """
    metadata = params.get("metadata")
    turn = metadata.get("turn_id") if isinstance(metadata, dict) else None
    return turn if isinstance(turn, str) else None


def _exceeds_depth(value: Any, limit: int) -> bool:
    """Whether ``value`` nests past ``limit``, walked iteratively.

    Iterative on purpose: a recursive walk would itself hit the recursion
    limit it is meant to guard against, and the answer would depend on the
    thread's stack depth and the interpreter build. The count is structural
    (one per object/array level), so the same body always takes the same
    branch.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict) or isinstance(node, list):
            if depth > limit:
                return True
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return False


def _in_deep_thread(work: Callable[[], Any]) -> tuple[bool, Any]:
    """Run ``work`` on a thread sized for any body the JSON parser accepts.

    The C parser accepts roughly ten thousand nesting levels; JCS
    canonicalization is pure-Python recursion that the default limit rejects
    around a thousand. Anything deeper than MAX_JSON_DEPTH canonicalizes
    here instead, where the recursion limit and the thread's stack cover the
    parser's maximum. Serialized by a module lock: the recursion limit is
    process-global, so two overlapping calls could restore it under each
    other — leaving a verified body to fail verification, the fail-open this
    mechanism exists to prevent — and the lock also caps live deep threads at
    one. Callers check a live session before entering (see ``_over_deep``),
    so a spam of deep bodies can still queue here, but each holder's work is
    bounded by one request body. Threads other requests create during the
    window inherit the larger default stack — address space, not resident
    memory. Returns ``(True, value)`` or ``(False, error)``.
    """
    with _DEEP_LOCK:
        outcome: dict[str, Any] = {}

        def run() -> None:
            previous_limit = sys.getrecursionlimit()
            sys.setrecursionlimit(DEEP_RECURSION_LIMIT)
            try:
                outcome["value"] = work()
            except Exception as error:  # noqa: BLE001 - reported to the caller
                outcome["error"] = error
            finally:
                sys.setrecursionlimit(previous_limit)

        try:
            previous_stack = threading.stack_size(DEEP_THREAD_STACK_BYTES)
        except (ValueError, RuntimeError):
            # A platform that refuses the stack size still gets the raised
            # recursion limit, which is what pure-Python recursion needs.
            previous_stack = None
        try:
            worker = threading.Thread(target=run, name="acs-deep-canonicalization", daemon=True)
            worker.start()
            worker.join()
        finally:
            if previous_stack is not None:
                threading.stack_size(previous_stack)
        if "error" in outcome:
            return False, outcome["error"]
        return True, outcome.get("value")


def _bytes_nesting_exceeds(body: bytes, limit: int) -> bool:
    """Whether raw JSON text nests past ``limit``, walked iteratively.

    Counted on the bytes before parsing, so the bound does not depend on the
    interpreter's parser limits: a body this deep could never be
    canonicalized on the enlarged thread, and it is refused at the parse
    boundary (where no signature could have been checked yet either). String
    contents are skipped — a brace inside a string is not nesting — and UTF-8
    continuation bytes never collide with the ASCII structural characters.
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # double quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x7D, 0x5D) and depth:  # } ]
            depth -= 1
    return False


def _reject_non_finite(token: str) -> Any:
    raise ValueError(f"non-finite JSON number is not permitted: {token}")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate object members: two parsers must not read one body differently.

    JSON's grammar permits duplicates and most parsers keep the last, so a
    signed request containing ``{"a": 1, "a": 2}`` verifies against one
    reading and executes another. The Go port refuses the body too; raising
    ValueError lands it on the parse-error path (-32700).
    """
    members: dict[str, Any] = {}
    for key, value in pairs:
        if key in members:
            raise ValueError(f"duplicate object member: {key!r}")
        members[key] = value
    return members


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


def _modify_unsupported(method: str, evaluation: Evaluation) -> Evaluation:
    """§6.5: a MODIFY the Observed Agent cannot apply is substituted, never sent.

    DENY with ``reason_codes: ["modify_unsupported"]`` and a ``reasoning``
    that names the intended modification, except at a hook that permits no
    DENY (``postCompact``), where the substitution is ALLOW: the compaction
    has already happened, so a denial would change nothing and the audit
    event is what makes the un-delivered rewrite visible.
    """
    targets: list[str] = []
    modifications = evaluation.modifications if isinstance(evaluation.modifications, dict) else {}
    redactions = modifications.get("redactions")
    if isinstance(redactions, list):
        for redaction in redactions:
            if isinstance(redaction, dict) and isinstance(redaction.get("path"), str):
                targets.append(f"redact {redaction['path']}")
    overrides = modifications.get("parameter_overrides")
    if isinstance(overrides, dict):
        for argument in overrides:
            targets.append(f"override {argument}")
    if modifications.get("modified_content") is not None:
        targets.append("the replacement content (modified_content)")
    intended = ", ".join(targets) if targets else "the intended rewrite"
    detail = (
        f"the Observed Agent cannot apply MODIFY; the intended modification ({intended}) "
        "was not delivered, and the substitution is recorded as modify_unsupported"
    )
    reasoning = f"{evaluation.reasoning}. {detail}" if evaluation.reasoning else detail
    # §6.5 names the reason_codes value exactly: ["modify_unsupported"]. The
    # engine's own codes are not on the wire, but the audit event keeps them
    # (the audit event is where the deployment's record lives).
    codes = ["modify_unsupported"]
    if DENY in methods.permitted_dispositions(method):
        return Evaluation(decision=DENY, reasoning=reasoning, reason_codes=codes)
    return Evaluation(decision=ALLOW, reasoning=reasoning, reason_codes=codes)


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
        if _bytes_nesting_exceeds(body, DEEP_PARSE_LIMIT):
            # Refused before parsing: nested past what the enlarged thread
            # can canonicalize, so no one could verify it here anyway, and
            # the interpreter's own parser limit should not be the thing that
            # decides.
            self._respond_json({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Parse error"}})
            return
        try:
            # parse_constant rejects the literal NaN/Infinity tokens JSON.parse
            # accepts; numeric overflow (1e400, integers past 2^53) is caught
            # by the JCS canonicalizability check in Guardian.handle, which
            # runs before anything tries to sign the envelope; a duplicate
            # member is refused so two readers cannot disagree on the body's
            # meaning (it lands on the parse-error path, like the Go port's).
            raw = json.loads(
                body.decode("utf-8"),
                parse_constant=_reject_non_finite,
                object_pairs_hook=_reject_duplicate_members,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
            # RecursionError: JSON nested past the C parser's own limit (about
            # ten thousand levels, a few tens of KB) is under the body cap but
            # past what this server can read; it must be a parse error, not a
            # dropped connection.
            self._respond_json({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Parse error"}})
            return
        try:
            response = self.guardian.handle(raw)
        except Exception as error:  # noqa: BLE001 - an escaped exception must still answer
            # handle() catches its own failures; this is a last resort so a
            # bug cannot drop the connection (which the Observed Agent reads
            # as no decision at all, and its posture may then proceed).
            print(f"guardian escaped its own error handling: {error!r}", file=sys.stderr)
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": INTERNAL_ERROR, "message": "guardian failed to handle the request"},
            }
        self._respond_json(response)

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
