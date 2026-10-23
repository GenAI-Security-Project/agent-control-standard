"""
ACS middleware for the NVIDIA Agent Toolkit (NAT / NeMo Agent Toolkit).

Wires NAT's Middleware abstraction to an ACS Guardian. Intercepts every
function (tool / sub-workflow / LLM / etc.) call configured to use this
middleware, sends an ACS JSON-RPC request to the Guardian, and applies
the verdict to NAT's invocation context.

Schema sources:
  - NAT public repo `packages/nvidia_nat_core/src/nat/middleware/`
  - GenAI-Security-Project/agent-control-standard `specification/v0.1.0/`

Requires:
  pip install nvidia-nat-core
  (and nvidia-nat-security if you also want to register alongside NAT's
  defense middleware suite)

Compatibility:
  - nvidia-nat-core >= 1.7 (public release). Block via raising
    ACSGuardianDenied; modify via setting context.modified_kwargs / output.
  - Future versions that expose InvocationAction.SKIP are also supported:
    if the symbol is importable, the adapter sets context.action instead
    of raising, which produces cleaner traces.

Environment variables:
  ACS_AGENT_ID    Explicit agent_id for metadata. If unset, derived from
                  config.target_function_or_group, falling back to "nat".

Usage in NAT YAML:

  middleware:
    acs_guardian:
      _type: acs_guardian
      guardian_url: http://127.0.0.1:8787/acs
      target_function_or_group: <tool-or-group-or-workflow-name>
      default_deny: true

  function_groups:
    my_tools:
      middleware: [acs_guardian]

  workflow:
    _type: react_agent
    middleware: [acs_guardian]
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import is_dataclass, asdict
from pathlib import Path
from typing import Any, Optional

# Bootstrap shared helpers from sibling adapters/_common/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
# Carried in request metadata; bump on every behavior change to this file.
ADAPTER_VERSION = "0.1.2"

try:
    from acs_common import (  # noqa: E402
        MAX_REQUEST_BODY_BYTES,
        audit_event,
        ensure_session_handshake,
        guardian_error_cause,
        is_guardian_refusal,
        iso8601_now as _common_iso8601_now,
        modify_composition_violation,
        normalize_decision,
        response_matches_request,
        sign_envelope,
        validate_guardian_url,
        verify_signature,
    )
except ImportError as _acs_import_error:
    # acs_common hard-requires rfc8785 (§10 permits no alternative
    # canonicalization); a failed import would leave NAT running ungoverned,
    # so fail loudly and re-raise to abort middleware registration.
    _banner = (
        "\n" + "=" * 72 + "\n"
        "ACS MIDDLEWARE FAILED TO LOAD — NAT WILL RUN UNGOVERNED.\n"
        f"  reason: {_acs_import_error}\n"
        "  The ACS adapter requires the `rfc8785` package; without it it\n"
        "  cannot sign, verify, or evaluate any step, so there is NO policy\n"
        "  enforcement and NO audit trail on this run.\n"
        "  Fix: pip install -r adapters/nat/requirements.txt (pins rfc8785).\n"
        + "=" * 72 + "\n"
    )
    sys.stderr.write(_banner)
    try:
        import logging as _logging
        _logging.getLogger("acs").critical(
            "ACS middleware failed to load (%s) — NAT running UNGOVERNED; "
            "install rfc8785", _acs_import_error)
    except Exception:  # noqa: BLE001
        pass
    raise


class RequestTooLargeError(Exception):
    """Serialized envelope exceeds the Guardian's body cap; checked
    adapter-side before the POST so an oversized envelope fails closed
    instead of surfacing as a transport failure."""


class GuardianHTTPRefusalError(Exception):
    """Guardian answered non-2xx: alive and refusing at the HTTP layer —
    urllib raises HTTPError before the JSON-RPC error body is parsed, so
    it must be handled apart from transport failures."""

    def __init__(self, status: int, jsonrpc_error: dict | None):
        self.status = status
        self.jsonrpc_error = jsonrpc_error or {}
        super().__init__(f"HTTP {status}")

try:
    from nat.middleware.function_middleware import FunctionMiddleware
    from nat.middleware.middleware import InvocationContext
    from nat.data_models.middleware import FunctionMiddlewareBaseConfig
    _NAT_AVAILABLE = True
except ImportError:
    FunctionMiddleware = object  # type: ignore[assignment, misc]
    InvocationContext = Any  # type: ignore[assignment, misc]
    FunctionMiddlewareBaseConfig = object  # type: ignore[assignment, misc]
    _NAT_AVAILABLE = False

# Lifecycle observer: NAT's IntermediateStepManager fires the workflow-
# boundary hooks; FunctionMiddleware alone covers only toolCallRequest/
# toolCallResult of ACS-Core's 6-hook minimum (conformance.md:19).
try:
    from nat.data_models.intermediate_step import IntermediateStepType  # type: ignore[import-not-found]
    from nat.builder.context import Context as _NATContext  # type: ignore[import-not-found]
    _HAS_LIFECYCLE = True
except ImportError:
    IntermediateStepType = None  # type: ignore[assignment]
    _NATContext = None  # type: ignore[assignment]
    _HAS_LIFECYCLE = False

# InvocationAction.SKIP is on the dev branch; not in NAT 1.7.0 release.
try:
    from nat.middleware.middleware import InvocationAction  # type: ignore[attr-defined]
    _HAS_INVOCATION_ACTION = True
except (ImportError, AttributeError):
    InvocationAction = None  # type: ignore[assignment]
    _HAS_INVOCATION_ACTION = False

try:
    from nat.cli.register_workflow import register_middleware
    _HAS_REGISTRATION = True
except ImportError:
    register_middleware = None  # type: ignore[assignment]
    _HAS_REGISTRATION = False

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kw: None  # type: ignore[assignment, misc]


ACS_VERSION = "0.1.0"


class ACSGuardianDenied(Exception):
    """Raised by the ACS middleware to block a function call.

    NAT's documented blocking mechanism is to raise from pre_invoke (the
    docstring: "Raises: Any exception to abort execution"). This custom
    exception type lets observers and tests distinguish a policy-driven
    block from unrelated errors.
    """


# ----- Config -----

if _NAT_AVAILABLE:

    class ACSMiddlewareConfig(FunctionMiddlewareBaseConfig, name="acs_guardian"):  # type: ignore[misc, valid-type, call-arg]
        """Config schema for the ACS NAT middleware.

        Registered with NAT under `_type: acs_guardian`.
        """
        guardian_url: str = Field(
            default="http://127.0.0.1:8787/acs",
            description="ACS Guardian endpoint to POST requests to.",
        )
        default_deny: bool = Field(
            default=False,
            description="If True, block the call when the Guardian is unreachable, returns malformed responses, or returns an unknown disposition. Default False matches the ACS spec default (§6.4 fail-open with audit event); set True for deployments that prefer fail-closed availability tradeoff.",
        )
        session_id: Optional[str] = Field(
            default=None,
            description="Session id sent on every request. Auto-generated per-process if absent. Coerced to UUID format.",
        )
        timeout_s: float = Field(
            default=5.0,
            description="Per-request timeout for the Guardian round-trip.",
        )
        target_function_or_group: Optional[str] = None
        target_location: str = "input"


# ----- Helpers (module-scope so tests can exercise them without instantiating the middleware) -----


def _iso8601_now() -> str:
    return _common_iso8601_now()


def _coerce_uuid(raw: str | None) -> str:
    """request-envelope.json:66 wants session_id as UUID. Accept a UUID
    directly; otherwise derive a stable UUID5 from whatever NAT gave us."""
    if not raw:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"nat:{raw}"))


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json:26-37 — each arg is {value, provenance?}."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _stringify_step_data(data: Any) -> str:
    """Best-effort extraction of human-readable content from a NAT
    IntermediateStepPayload.data. The shape varies per event_type and per
    framework; we pull out a string when possible and json-dump otherwise.
    Returns empty string when there is genuinely nothing to forward."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    # NAT often wraps inputs/outputs in StreamEventData with .input/.output fields
    for attr in ("input", "output", "chunk", "value", "content"):
        v = getattr(data, attr, None)
        if isinstance(v, str) and v:
            return v
        if v is not None and not isinstance(v, (dict, list, type(None))):
            s = str(v)
            if s and s != "None":
                return s
    if isinstance(data, (dict, list)):
        try:
            return json.dumps(data, default=str)
        except (TypeError, ValueError):
            return str(data)
    return str(data)


KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def _extract_arguments(context: Any) -> dict[str, Any]:
    """Build a flat {arg_name: value} dict from NAT's invocation context.

    NAT captures the function input as `modified_args[0]` (a Pydantic
    model from `_convert_input`); `modified_kwargs` is only populated when
    the caller passes named kwargs directly, so both slots must be read.
    Pydantic models / dataclasses / dicts in args are flattened; scalars
    take the input-schema field name at their position (else `argN`).
    """
    out: dict[str, Any] = {}

    # 1. kwargs first — already named, no inference needed
    kwargs = getattr(context, "modified_kwargs", None) or {}
    for k, v in kwargs.items():
        out[str(k)] = v

    # 2. args — extract named fields
    args = getattr(context, "modified_args", None) or []
    if not args:
        return out

    # Try to read field names from the function's input schema (Pydantic)
    schema = None
    fc = getattr(context, "function_context", None)
    if fc is not None:
        schema = getattr(fc, "input_schema", None)
    schema_fields: list[str] = []
    if schema is not None:
        # Pydantic v2: model_fields. v1 / others: __fields__
        fields = getattr(schema, "model_fields", None) or getattr(schema, "__fields__", None)
        if fields:
            schema_fields = list(fields.keys())

    for idx, arg in enumerate(args):
        # Pydantic model — best case: dump and merge
        if hasattr(arg, "model_dump"):
            try:
                out.update(arg.model_dump())
                continue
            except Exception:  # noqa: BLE001
                pass
        # Pydantic v1 fallback
        if hasattr(arg, "dict") and callable(getattr(arg, "dict", None)):
            try:
                d = arg.dict()
                if isinstance(d, dict):
                    out.update(d)
                    continue
            except Exception:  # noqa: BLE001
                pass
        # Dataclass
        if is_dataclass(arg):
            try:
                out.update(asdict(arg))
                continue
            except Exception:  # noqa: BLE001
                pass
        # Plain dict — merge
        if isinstance(arg, dict):
            for k, v in arg.items():
                out[str(k)] = v
            continue
        # Scalar — use the schema field name at this position, else argN
        name = schema_fields[idx] if idx < len(schema_fields) else f"arg{idx}"
        out[name] = arg

    return out


def _redact_output(context: Any) -> None:
    """Clear context.output as the post_invoke redaction signal —
    InvocationContext is a strict Pydantic model, so `output=None` plus
    the accompanying audit event is the whole signal (ad-hoc attributes
    raise ValidationError)."""
    try:
        context.output = None
    except Exception:  # noqa: BLE001
        # No settable output field; the audit event still records the redaction.
        pass


def _apply_overrides_to_context(context: Any, overrides: dict[str, Any]) -> None:
    """Apply Guardian's MODIFY parameter_overrides to wherever NAT will
    actually read the function input.

    NAT executes `await call_next(*context.modified_args,
    **context.modified_kwargs)`, so the override must land in whichever
    slot holds the input: `modified_args[0]` (Pydantic model / dataclass /
    dict) or `modified_kwargs` for the direct keyword-arg path.
    """
    # 1. Mutate modified_args[0] when it holds the input
    args = list(getattr(context, "modified_args", ()) or ())
    if args:
        head = args[0]
        new_head: Any = None
        # Pydantic v2
        if hasattr(head, "model_copy"):
            try:
                new_head = head.model_copy(update=dict(overrides))
            except Exception:  # noqa: BLE001
                new_head = None
        # Pydantic v1
        if new_head is None and hasattr(head, "copy") and callable(getattr(head, "copy", None)):
            try:
                new_head = head.copy(update=dict(overrides))  # type: ignore[call-arg]
            except Exception:  # noqa: BLE001
                new_head = None
        # Dataclass
        if new_head is None and is_dataclass(head):
            try:
                from dataclasses import replace as _dc_replace
                new_head = _dc_replace(head, **overrides)
            except Exception:  # noqa: BLE001
                new_head = None
        # Plain dict
        if new_head is None and isinstance(head, dict):
            new_head = {**head, **overrides}
        if new_head is not None:
            args[0] = new_head
            # Tuple field with validate_assignment=True — assign a new tuple.
            try:
                context.modified_args = tuple(args)
            except Exception:  # noqa: BLE001
                # Write-back failed; in-place mutation already took effect by reference.
                pass

    # 2. Also write modified_kwargs — call_next reads exactly one of the
    # two slots depending on the function signature, so update both.
    try:
        kwargs = dict(getattr(context, "modified_kwargs", None) or {})
        kwargs.update(overrides)
        context.modified_kwargs = kwargs
    except Exception:  # noqa: BLE001
        pass


# ----- Middleware class -----

class ACSMiddleware(FunctionMiddleware):  # type: ignore[misc, valid-type]
    """NAT middleware that defers each call's allow/deny/modify decision to an ACS Guardian."""

    def __init__(self, config):
        if _NAT_AVAILABLE:
            super().__init__()
        self._config = config
        self._session_id = _coerce_uuid(
            getattr(config, "session_id", None) or os.environ.get("ACS_SESSION_ID")
        )
        target = getattr(config, "target_function_or_group", None) or "nat"
        self._agent_id = os.environ.get("ACS_AGENT_ID") or f"nat:{hashlib.sha256(target.encode()).hexdigest()[:8]}"
        self._handshake_done = False
        self._lifecycle_subscribed = False
        self._lifecycle_subscription = None
        # Locks the check-then-set in _ensure_lifecycle_subscribed
        # against double subscription from parallel pre_invoke calls.
        self._lifecycle_lock = threading.Lock()
        # WeakKeyDictionary fallback for frozen contexts — id(context)
        # would collide once GC recycles addresses.
        import weakref
        self._frozen_ctx_rids: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._frozen_ctx_lock = threading.Lock()

    def _ensure_handshake(self) -> None:
        if self._handshake_done or os.environ.get("ACS_HANDSHAKE", "1") != "1":
            return
        methods = ["steps/toolCallRequest", "steps/toolCallResult"]
        if _HAS_LIFECYCLE:
            methods += [
                "steps/sessionStart", "steps/userMessage",
                "steps/agentResponse", "steps/sessionEnd",
            ]
        # In-memory `_handshake_done` is the primary guard; the disk cache
        # keeps the handshake idempotent across process restarts.
        server_hello = ensure_session_handshake(
            guardian_url=self._config.guardian_url,
            session_id=self._session_id,
            agent_id=self._agent_id,
            platform="nat",
            methods_implemented=methods,
        )
        # §6.4: honor the ServerHello's declared fail posture,
        # most-restrictive-wins with the workflow.yml default_deny.
        if server_hello and server_hello.get("on_decision_failure") == "deny":
            self._server_deny = True
        # §6.4:154 — use the negotiated timeout, falling back to the
        # local config when none was negotiated.
        if server_hello:
            default_ms = (server_hello.get("timeout_config") or {}).get("default_ms")
            if isinstance(default_ms, (int, float)) and default_ms > 0:
                self._negotiated_timeout_s = default_ms / 1000.0
        self._handshake_done = True

    def _effective_default_deny(self) -> bool:
        return bool(self._config.default_deny or
                    getattr(self, "_server_deny", False))

    def _ensure_lifecycle_subscribed(self) -> None:
        """Subscribe to NAT's IntermediateStepManager so workflow-boundary
        events fire ACS sessionStart / userMessage / agentResponse /
        sessionEnd; idempotent and locked against double subscription.
        """
        if self._lifecycle_subscribed or not _HAS_LIFECYCLE:
            return
        with self._lifecycle_lock:
            # Re-check inside the lock.
            if self._lifecycle_subscribed:
                return
            try:
                ctx = _NATContext.get()
                mgr = ctx.intermediate_step_manager
            except Exception:  # noqa: BLE001
                # No active Context; function-call hooks still fire via FunctionMiddleware.
                return
            try:
                self._lifecycle_subscription = mgr.subscribe(
                    on_next=self._on_intermediate_step,
                    on_error=lambda e: audit_event(
                        "lifecycle_subscription_error",
                        session_id=self._session_id, error=str(e)),
                )
                self._lifecycle_subscribed = True
            except Exception as e:  # noqa: BLE001
                audit_event("lifecycle_subscribe_failed",
                            session_id=self._session_id, error=str(e))

    def _on_intermediate_step(self, step) -> None:
        """Translate workflow-boundary IntermediateStepType events into ACS
        hooks; function-level events are already covered by
        pre_invoke/post_invoke."""
        try:
            payload = step.payload
            event_type = payload.event_type
        except AttributeError:
            return

        if event_type == IntermediateStepType.WORKFLOW_START:
            # Workflow input becomes both sessionStart (boundary marker)
            # and userMessage (the input itself).
            self._emit_lifecycle_hook(
                "steps/sessionStart",
                payload={"platform_context": {"workflow_name": payload.name or ""}})
            input_text = _stringify_step_data(payload.data)
            if input_text:
                self._emit_lifecycle_hook(
                    "steps/userMessage",
                    payload={"content": [{"type": "text", "value": input_text}]})
        elif event_type == IntermediateStepType.WORKFLOW_END:
            # Workflow output becomes agentResponse; sessionEnd closes the boundary.
            output_text = _stringify_step_data(payload.data)
            if output_text:
                self._emit_lifecycle_hook(
                    "steps/agentResponse",
                    payload={"content": [{"type": "text", "value": output_text}]})
            self._emit_lifecycle_hook(
                "steps/sessionEnd",
                payload={"reason": "completed"})

    def _emit_lifecycle_hook(self, method: str, payload: dict) -> None:
        """Build, sign, and POST a lifecycle hook; errors are audited but
        never interrupt the workflow (enforcement lives in
        pre_invoke/post_invoke)."""
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {
                "acs_version": ACS_VERSION,
                "request_id": str(uuid.uuid4()),
                "timestamp": _iso8601_now(),
                "metadata": {
                    "agent_id": self._agent_id,
                    "session_id": self._session_id,
                    "platform": "nat",
                },
                "payload": payload,
            },
        }
        sign_envelope(request, session_id=self._session_id)
        try:
            self._call_guardian(request)
        except Exception as e:  # noqa: BLE001
            audit_event("lifecycle_hook_failed",
                        method=method, session_id=self._session_id, error=str(e))

    def _correlation_request_id(self, context) -> str:
        """Return a request_id unique per invocation but stable across
        pre_invoke + post_invoke: stash a uuid4 on the shared context,
        falling back to a WeakKeyDictionary for frozen contexts (id()
        would collide once GC recycles addresses).
        """
        existing = getattr(context, "_acs_correlation_request_id", None)
        if existing:
            return existing
        rid = str(uuid.uuid4())
        try:
            context._acs_correlation_request_id = rid
            return rid
        except (AttributeError, TypeError):
            pass
        # Frozen context — WeakKeyDictionary if it supports weak references.
        try:
            with self._frozen_ctx_lock:
                cached = self._frozen_ctx_rids.get(context)
                if cached is not None:
                    return cached
                self._frozen_ctx_rids[context] = rid
                return rid
        except TypeError:
            # Not weak-referenceable: return a fresh uuid4 each call
            # (pre→post correlation is lost) and audit the degradation.
            audit_event("frozen_unweakrefable_context",
                        session_id=self._session_id)
            return rid

    @property
    def enabled(self) -> bool:
        return True

    async def pre_invoke(self, context):
        """Gate the function call. Block via raising or InvocationAction.SKIP; modify args in place."""
        if os.environ.get("ACS_DISABLED") == "1":
            # Incident kill switch: pass through ungoverned, audited per §6.4:158.
            audit_event("acs_disabled_bypass", session_id=self._session_id,
                        method="steps/toolCallRequest",
                        detail="ACS_DISABLED=1 — pre_invoke bypassed ungoverned")
            return None
        self._ensure_handshake()
        self._ensure_lifecycle_subscribed()
        correlation_id = self._correlation_request_id(context)
        try:
            request = self._build_request(
                method="steps/toolCallRequest",
                tool_name=context.function_context.name,
                tool_arguments=_extract_arguments(context),
                request_id=correlation_id,
            )
            response = self._call_guardian(request)
        except RequestTooLargeError as e:
            audit_event("guardian_refusal_fail_closed",
                        cause="request_exceeds_max_payload",
                        session_id=self._session_id,
                        method="steps/toolCallRequest",
                        body_bytes=e.args[0])
            return self._block(context, "envelope exceeds Guardian body cap")
        except GuardianHTTPRefusalError as e:
            code = e.jsonrpc_error.get("code")
            cause = (guardian_error_cause(code) if code is not None
                     else f"http_{e.status}_refusal")
            audit_event("guardian_refusal_fail_closed",
                        cause=cause, http_status=e.status,
                        session_id=self._session_id,
                        method="steps/toolCallRequest",
                        error=e.jsonrpc_error.get("message", ""))
            return self._block(
                context, f"Guardian refused at HTTP layer ({e.status})")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # Distinct causes let an operator tell a slow Guardian from an
            # unreachable one; both are §6.4:156 decision failures.
            is_timeout = isinstance(e, TimeoutError) or isinstance(
                getattr(e, "reason", None), TimeoutError)
            return self._handle_decision_failure(
                context, "steps/toolCallRequest",
                cause="decision_timeout" if is_timeout else "transport_failure",
                error=str(e),
                deny_msg=(f"Guardian decision timed out: {e}" if is_timeout
                          else f"Guardian unreachable: {e}"))
        except Exception as e:  # noqa: BLE001
            return self._handle_decision_failure(
                context, "steps/toolCallRequest",
                cause="adapter_exception", error=str(e),
                deny_msg=f"adapter error: {e}")

        # Bind the response to THIS request first — the per-session HMAC
        # proves origin, not correspondence; a mis-bound response fails closed.
        if not response_matches_request(request, response or {}):
            audit_event("guardian_refusal_fail_closed",
                        cause="response_binding_mismatch",
                        session_id=self._session_id,
                        method="steps/toolCallRequest")
            return self._block(context, "response not bound to request")

        # Refusal codes mean an alive Guardian rejected the envelope —
        # attacker-reachable, so they fail closed regardless of posture;
        # non-refusal errors follow the §6.4 posture.
        err = (response or {}).get("error")
        if err is not None:
            # Error responses are signed too; an unverifiable error fails closed.
            if not verify_signature(response, session_id=self._session_id):
                audit_event("guardian_refusal_fail_closed",
                            cause="error_signature_invalid",
                            session_id=self._session_id,
                            method="steps/toolCallRequest",
                            # UNVERIFIED — for triage only.
                            claimed_error_code=err.get("code"),
                            claimed_cause=guardian_error_cause(err.get("code")))
                return self._block(context, "error response signature invalid")
            code = err.get("code")
            if is_guardian_refusal(code):
                audit_event("guardian_refusal_fail_closed",
                            cause=guardian_error_cause(code),
                            session_id=self._session_id,
                            method="steps/toolCallRequest",
                            jsonrpc_code=code,
                            error=err.get("message", ""))
                return self._block(
                    context,
                    f"Guardian refused envelope: {err.get('message','')}")
            return self._handle_decision_failure(
                context, "steps/toolCallRequest",
                cause=guardian_error_cause(code),
                error=err.get("message", ""),
                jsonrpc_code=code,
                deny_msg=f"Guardian rejected envelope: {err.get('message','')}")

        # Invalid signature on a well-formed response: fail closed, never posture.
        if not verify_signature(response, session_id=self._session_id):
            audit_event("guardian_refusal_fail_closed",
                        cause="response_signature_invalid",
                        session_id=self._session_id,
                        method="steps/toolCallRequest")
            return self._block(context, "response signature invalid")

        # Total coercion: malformed verdict fields must not throw here.
        decision, reasoning, mods = normalize_decision(
            (response or {}).get("result"))

        if decision == "allow":
            return None
        if decision == "deny":
            return self._block(context, reasoning or "denied by Guardian")
        if decision == "modify":
            violation = modify_composition_violation(mods)
            if violation:
                audit_event("modify_composition_invalid",
                            session_id=self._session_id,
                            method="steps/toolCallRequest", detail=violation)
                return self._block(
                    context,
                    f"MODIFY refused ({violation}); failing closed per §6.3:146")
            if mods.get("redactions"):
                # NAT has no JSON-Pointer redaction primitive; applying only
                # parameter_overrides would drop part of the compound decision.
                audit_event("modify_unapplied_redactions",
                            session_id=self._session_id,
                            method="steps/toolCallRequest")
                return self._block(
                    context, "MODIFY refused: NAT cannot apply the requested "
                    "redactions without dropping part of the decision")
            overrides = mods.get("parameter_overrides")
            if isinstance(overrides, dict):
                _apply_overrides_to_context(context, overrides)
                return context
            return self._block(context, f"MODIFY substituted to DENY: {reasoning}")
        if decision in ("ask", "defer"):
            # No pause-and-resume primitive on this boundary: substitute
            # block; ASK/DEFER deployments compose with NAT's HITL middleware.
            return self._block(context, f"{decision}: {reasoning}")

        # An arrived-but-uninterpretable decision fails closed; the spec
        # basis is tracked in issue #32.
        audit_event("unusable_disposition",
                    disposition=decision or "(missing)",
                    session_id=self._session_id,
                    method="steps/toolCallRequest")
        return self._block(
            context,
            f"unusable Guardian disposition '{decision}' — cannot be "
            f"interpreted; failing closed (see issue #32)")

    async def post_invoke(self, context):
        """Record the result. Apply Guardian's verdict to the output.

        - allow: pass through.
        - modify (with modified_content): replace context.output.
        - deny: clear context.output to None and tag with reasoning. The
          tool already ran (post_invoke fires after execution), so the
          side effect cannot be undone — but downstream consumers see no
          output. This matches Specification §6.4's output-redaction gate.
        - unknown: respect default_deny — drop output if true.
        """
        if os.environ.get("ACS_DISABLED") == "1":
            audit_event("acs_disabled_bypass", session_id=self._session_id,
                        method="steps/toolCallResult",
                        detail="ACS_DISABLED=1 — post_invoke bypassed ungoverned")
            return None
        # request_id_ref correlates the result with its originating
        # toolCallRequest (tool-call-result.json:19-23).
        correlation_id = self._correlation_request_id(context)
        try:
            request = self._build_request(
                method="steps/toolCallResult",
                tool_name=context.function_context.name,
                tool_arguments=_extract_arguments(context),
                result=context.output,
                request_id_ref=correlation_id,
            )
            response = self._call_guardian(request)
        except RequestTooLargeError as e:
            return self._post_invoke_refusal(
                context, cause="request_exceeds_max_payload",
                body_bytes=e.args[0])
        except GuardianHTTPRefusalError as e:
            code = e.jsonrpc_error.get("code")
            cause = (guardian_error_cause(code) if code is not None
                     else f"http_{e.status}_refusal")
            return self._post_invoke_refusal(
                context, cause=cause, http_status=e.status,
                error=e.jsonrpc_error.get("message", ""))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            is_timeout = isinstance(e, TimeoutError) or isinstance(
                getattr(e, "reason", None), TimeoutError)
            return self._post_invoke_failure(
                context,
                cause="decision_timeout" if is_timeout else "transport_failure",
                error=str(e))
        except Exception as e:  # noqa: BLE001
            return self._post_invoke_failure(
                context, cause="adapter_exception", error=str(e))

        # Same binding rule as pre_invoke: mis-bound → redact regardless of posture.
        if not response_matches_request(request, response or {}):
            return self._post_invoke_refusal(
                context, cause="response_binding_mismatch")

        # Same error split as pre_invoke: refusal codes redact regardless
        # of posture; other errors follow the posture.
        err = (response or {}).get("error")
        if err is not None:
            if not verify_signature(response, session_id=self._session_id):
                return self._post_invoke_refusal(
                    context, cause="error_signature_invalid",
                    claimed_error_code=err.get("code"),
                    claimed_cause=guardian_error_cause(err.get("code")))
            code = err.get("code")
            if is_guardian_refusal(code):
                return self._post_invoke_refusal(
                    context, cause=guardian_error_cause(code),
                    jsonrpc_code=code, error=err.get("message", ""))
            return self._post_invoke_failure(
                context, cause=guardian_error_cause(code),
                jsonrpc_code=code, error=err.get("message", ""))

        if not verify_signature(response, session_id=self._session_id):
            return self._post_invoke_refusal(
                context, cause="response_signature_invalid")

        decision, reasoning, mods = normalize_decision(
            (response or {}).get("result"))

        if decision == "deny":
            # The tool already executed; the redaction signal is
            # output=None plus the audit event (strict Pydantic model —
            # ad-hoc attributes raise ValidationError).
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="guardian_deny",
                        session_id=self._session_id,
                        method="steps/toolCallResult",
                        reasoning=reasoning or "output redacted by Guardian")
            return context
        if decision == "modify":
            violation = modify_composition_violation(mods)
            if violation:
                audit_event("modify_composition_invalid",
                            session_id=self._session_id,
                            method="steps/toolCallResult", detail=violation)
                _redact_output(context)
                audit_event("post_invoke_redacted",
                            cause="modify_composition_invalid",
                            session_id=self._session_id,
                            method="steps/toolCallResult")
                return context
            modified_content = mods.get("modified_content")
            if modified_content is not None:
                context.output = modified_content
                return context
            # A structured MODIFY on a result cannot be realized generically;
            # redact the whole result rather than silently ignore the Guardian.
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="modify_unapplied_structured_edits",
                        session_id=self._session_id,
                        method="steps/toolCallResult")
            return context
        if decision not in KNOWN_DECISIONS:
            # Arrived-but-uninterpretable decision: redact (fail closed);
            # spec basis tracked in issue #32.
            audit_event("unusable_disposition",
                        disposition=decision or "(missing)",
                        session_id=self._session_id,
                        method="steps/toolCallResult")
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="unusable_disposition",
                        session_id=self._session_id,
                        method="steps/toolCallResult",
                        decision=decision)
            return context
        return None

    # ----- helpers -----

    def _post_invoke_failure(self, context, *, cause: str, **fields: Any):
        """Posture-aware decision failure on the output gate; fail-closed
        here means redacting the output the Guardian never vetted.
        """
        base = dict(cause=cause, session_id=self._session_id,
                    method="steps/toolCallResult", **fields)
        if self._effective_default_deny():
            _redact_output(context)
            audit_event("decision_failure_fail_closed", **base)
            return context
        audit_event("fail_open_bypass", **base)
        return None

    def _post_invoke_refusal(self, context, *, cause: str, **fields: Any):
        """Refusal / binding / signature failure on the output gate —
        redact REGARDLESS of posture (attacker-shaped condition)."""
        _redact_output(context)
        audit_event("guardian_refusal_fail_closed",
                    cause=cause, session_id=self._session_id,
                    method="steps/toolCallResult", **fields)
        return context

    def _handle_decision_failure(self, context, method: str, *, cause: str,
                                   error: str, deny_msg: str,
                                   jsonrpc_code: int | None = None):
        """Single point for the pre_invoke decision-failure audit + posture;
        every emission carries a stable `cause` label for operator triage
        (same taxonomy as the Cursor/Claude adapters)."""
        fields: dict[str, Any] = {
            "cause": cause,
            "session_id": self._session_id,
            "method": method,
            "error": error,
        }
        if jsonrpc_code is not None:
            fields["jsonrpc_code"] = jsonrpc_code
        if self._effective_default_deny():
            audit_event("decision_failure_fail_closed", **fields)
            return self._block(context, deny_msg)
        audit_event("fail_open_bypass", **fields)
        return None

    def _block(self, context, reason: str):
        """Block the invocation. Prefer InvocationAction when available,
        fall back to raising for NAT releases that don't expose it."""
        if _HAS_INVOCATION_ACTION:
            context.action = InvocationAction.SKIP  # type: ignore[attr-defined]
            context.acs_block_reason = reason
            return context
        raise ACSGuardianDenied(reason)

    def _build_request(
        self,
        method: str,
        tool_name: str,
        tool_arguments: dict,
        result: Any = None,
        request_id: str | None = None,
        request_id_ref: str | None = None,
    ) -> dict:
        """Build a signed ACS request envelope matching request-envelope.json."""
        metadata = {
            "agent_id": self._agent_id,
            "session_id": self._session_id,
            "platform": "nat",
            "adapter_version": ADAPTER_VERSION,
        }
        if method == "steps/toolCallRequest":
            payload: dict[str, Any] = {
                "tool": {"name": tool_name},
                "arguments": _wrap_arguments(tool_arguments),
            }
        else:
            if result is None:
                outputs: list[dict[str, Any]] = []
            elif isinstance(result, (str, int, float, bool, dict, list)):
                outputs = [{"value": result}]
            else:
                outputs = [{"value": str(result)}]
            payload = {
                "tool": {"name": tool_name},
                "exit_status": "success",
                "outputs": outputs,
            }
            if request_id_ref:
                payload["request_id_ref"] = request_id_ref

        envelope = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {
                "acs_version": ACS_VERSION,
                "request_id": request_id or str(uuid.uuid4()),
                "timestamp": _iso8601_now(),
                "metadata": metadata,
                "payload": payload,
            },
        }
        sign_envelope(envelope, session_id=self._session_id)
        return envelope

    def _call_guardian(self, request: dict) -> dict:
        validate_guardian_url(self._config.guardian_url)  # SSRF: refuse file://, ftp://, etc.
        body = json.dumps(request).encode("utf-8")
        if len(body) > MAX_REQUEST_BODY_BYTES:
            raise RequestTooLargeError(len(body))
        req = urllib.request.Request(
            self._config.guardian_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        timeout_s = getattr(self, "_negotiated_timeout_s", None) or self._config.timeout_s
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            parsed = None
            try:
                parsed = json.loads(e.read().decode("utf-8")).get("error")
            except Exception:  # noqa: BLE001
                pass
            raise GuardianHTTPRefusalError(e.code, parsed) from e


# ----- NAT registration -----

if _NAT_AVAILABLE and _HAS_REGISTRATION:
    @register_middleware(config_type=ACSMiddlewareConfig)  # type: ignore[misc]
    async def build_acs_middleware(config: "ACSMiddlewareConfig", builder):  # type: ignore[name-defined]
        """NAT factory entry point. Yields the middleware instance for NAT to wire up."""
        yield ACSMiddleware(config)
