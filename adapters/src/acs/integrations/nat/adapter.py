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

import asyncio
import atexit
import collections
import contextvars
import hashlib
import json
import os
import sys
import threading
import uuid
import weakref
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from typing import Any, Optional

from acs import __version__

ADAPTER_VERSION = __version__

try:
    from acs.client import (
        Config,
        FailPosture,
        Handshake,
        Negotiated,
        Resolution,
        SessionRefused,
        Undecided,
        audit_event,
        audit_modify_unsupported,
        discard_session,
        open_session,
        round_trip,
    )
    from acs.core import (
        method_evaluated,
        modify_composition_violation,
        normalize_decision,
        request_envelope,
    )
except ImportError as _acs_import_error:
    # Without acs.core (rfc8785, §10) NAT would run ungoverned, so the import fails loudly.
    _banner = (
        "\n" + "=" * 72 + "\n"
        "ACS MIDDLEWARE FAILED TO LOAD — NAT WILL RUN UNGOVERNED.\n"
        f"  reason: {_acs_import_error}\n"
        "  The ACS adapter requires the `rfc8785` package; without it it\n"
        "  cannot sign, verify, or evaluate any step, so there is NO policy\n"
        "  enforcement and NO audit trail on this run.\n"
        "  Fix: pip install 'acs-adapters[nat]' (rfc8785 is a base dependency).\n"
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

# FunctionMiddleware covers only toolCallRequest and toolCallResult; a run's lifecycle hooks come from NAT's step stream.
try:
    from nat.data_models.intermediate_step import IntermediateStepType  # type: ignore[import-not-found]
    from nat.builder.context import Context as _NATContext  # type: ignore[import-not-found]
    from nat.builder.context import ContextState as _NATContextState  # type: ignore[import-not-found]
    _HAS_LIFECYCLE = True
except ImportError:
    IntermediateStepType = None  # type: ignore[assignment]
    _NATContext = None  # type: ignore[assignment]
    _NATContextState = None  # type: ignore[assignment]
    _HAS_LIFECYCLE = False

# A telemetry exporter is the hook NAT starts for each run, subscribed before the run's WORKFLOW_START.
try:
    from nat.cli.register_workflow import register_telemetry_exporter  # type: ignore[import-not-found]
    from nat.data_models.telemetry_exporter import TelemetryExporterBaseConfig  # type: ignore[import-not-found]
    from nat.observability.exporter.base_exporter import BaseExporter  # type: ignore[import-not-found]
    _HAS_EXPORTER = True
except ImportError:
    _HAS_EXPORTER = False

# InvocationAction.SKIP is absent from NAT 1.7.0.
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
        """ACS Guardian middleware, registered as _type: acs_guardian."""
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
            description="Session id of calls outside any NAT run, generated if absent and coerced to UUID format; each run's session gets a fresh id.",
        )
        timeout_s: float = Field(
            default=5.0,
            description="Per-request timeout for the Guardian round-trip.",
        )
        target_function_or_group: Optional[str] = None
        target_location: str = "input"


# ----- Helpers (module-scope so tests can exercise them without instantiating the middleware) -----


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


def _json_safe(value: Any) -> Any:
    """The value in JSON form the signer can canonicalize: a model dumped in JSON mode, and anything json cannot encode, such as a datetime, as its string."""
    if hasattr(value, "model_dump"):
        try:
            value = value.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            pass
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return str(value)


def _extract_arguments(context: Any) -> dict[str, Any]:
    return _json_safe(_collect_arguments(context))


def _collect_arguments(context: Any) -> dict[str, Any]:
    """Flat {name: value} arguments from modified_args[0] and modified_kwargs; a scalar takes the input schema's field name at its position, else argN."""
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
                out.update(arg.model_dump(mode="json"))
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
    """InvocationContext is a strict Pydantic model, so output=None with its audit event is the whole redaction signal."""
    try:
        context.output = None
    except Exception:  # noqa: BLE001
        # No settable output field; the audit event still records the redaction.
        pass


def _reads_back(value: Any, overrides: dict[str, Any]) -> bool:
    """Whether the function reads every override back from the rewritten input; a computed field keeps its own value."""
    for key, expected in overrides.items():
        try:
            actual = value[key] if isinstance(value, dict) else getattr(value, key)
        except Exception:  # noqa: BLE001
            return False
        if actual != expected:
            return False
    return True


def _apply_overrides_to_context(context: Any, overrides: dict[str, Any]) -> bool:
    """Apply Guardian's MODIFY parameter_overrides to the slot NAT reads the function input from; False when it cannot.

    NAT executes `await call_next(*context.modified_args,
    **context.modified_kwargs)`. An input passed positionally, a Pydantic
    model, dataclass or dict in `modified_args[0]`, is rewritten there and
    only there: the same fields as keywords as well would reach the function
    twice and raise TypeError. An input passed as keywords is rewritten in
    `modified_kwargs`.
    """
    args = list(getattr(context, "modified_args", ()) or ())
    if not args:
        try:
            context.modified_kwargs = {**dict(getattr(context, "modified_kwargs", None) or {}), **overrides}
            return True
        except Exception:  # noqa: BLE001
            return False
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
    if new_head is None or not _reads_back(new_head, overrides):
        return False
    args[0] = new_head
    try:
        # Tuple field with validate_assignment=True — assign a new tuple.
        context.modified_args = tuple(args)
    except Exception:  # noqa: BLE001
        return False
    return True


def _current_stream() -> Any:
    try:
        return _NATContextState.get().event_stream.get() if _NATContextState is not None else None
    except Exception:  # noqa: BLE001
        return None


def _current_run_id() -> str | None:
    try:
        return _NATContextState.get().workflow_run_id.get() if _NATContextState is not None else None
    except Exception:  # noqa: BLE001
        return None


class _LifecycleSender:
    """Sends one session's lifecycle hooks in order on a thread that exits while idle; close() drains and stops, seal() stops at once."""

    def __init__(self, send: Callable[..., None]) -> None:
        self._send = send
        self._pending: collections.deque = collections.deque()
        self._changed = threading.Condition()
        self._busy = False
        self._closed = False
        self._thread: threading.Thread | None = None
        _OPEN_SENDERS.add(self)

    def submit(self, *item: Any) -> bool:
        with self._changed:
            if self._closed:
                return False
            self._pending.append(item)
            self._wake()
            return True

    def sent(self) -> Future:
        """A future that completes once every hook accepted so far has gone out."""
        done: Future = Future()
        with self._changed:
            if self._pending or self._busy:
                self._pending.append(done)
                self._wake()
                return done
        done.set_result(None)
        return done

    def seal(self) -> None:
        with self._changed:
            self._closed = True
            self._changed.notify_all()

    def close(self) -> None:
        with self._changed:
            while self._pending or self._busy:
                self._changed.wait()
            self._closed = True
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()

    def _wake(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="acs-lifecycle", daemon=True)
            self._thread.start()
        self._changed.notify_all()

    def _run(self) -> None:
        while True:
            with self._changed:
                if not self._pending:
                    self._thread = None
                    self._changed.notify_all()
                    return
                item = self._pending.popleft()
                self._busy = True
            try:
                if not isinstance(item, Future):
                    self._send(*item)
                elif item.set_running_or_notify_cancel():
                    item.set_result(None)
            except Exception:  # noqa: BLE001
                # _send audits its own failures; nothing may stop the hooks queued behind this one.
                pass
            finally:
                with self._changed:
                    self._busy = False
                    self._changed.notify_all()


# Lifecycle threads are daemons, so interpreter exit sends what is still queued first.
_OPEN_SENDERS: weakref.WeakSet = weakref.WeakSet()
atexit.register(lambda: [sender.close() for sender in list(_OPEN_SENDERS)])


@dataclass(eq=False)
class _Session:
    """One ACS session: a root NAT Runner's, a run's seen only from its calls, or the middleware's own."""
    id: str
    lane: _LifecycleSender
    task: asyncio.Task | None = None
    # The WORKFLOW_START step of the Runner that owns the session.
    root_step: str | None = None
    # The run's step stream, for a run seen only from its calls.
    stream: weakref.ref | None = None
    platform_context: dict = field(default_factory=dict)
    decision: Handshake | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    # in_flight, closed, ended and failures are read and written under idle.
    idle: threading.Condition = field(default_factory=threading.Condition)
    in_flight: int = 0
    closed: bool = False
    ended: bool = False
    saw_end: bool = False
    failures: collections.Counter = field(default_factory=collections.Counter)


@dataclass(frozen=True)
class _Step:
    """The session a step belongs to: its id, the handshake's decision, and what that handshake negotiated."""
    session_id: str
    decision: Handshake
    server_hello: dict | None
    posture: FailPosture


class ACSMiddleware(FunctionMiddleware):  # type: ignore[misc, valid-type]
    """NAT middleware that defers each call's allow/deny/modify decision to an ACS Guardian.

    Each root NAT Runner is one ACS session with a fresh id: a Runner started while another of this middleware's
    sessions is open in its context, a nested workflow, joins that session. Calls outside any Runner use the
    middleware's own session, which ends at close().
    """

    def __init__(self, config):
        if _NAT_AVAILABLE:
            super().__init__()
        self._config = config
        # Read once, as they were when NAT built this middleware.
        self._acs = replace(
            Config.from_env(os.environ),
            guardian_url=config.guardian_url,
            posture=FailPosture(deny_on_failure=bool(config.default_deny), timeout_s=config.timeout_s),
        )
        self._session_id = _coerce_uuid(
            getattr(config, "session_id", None) or os.environ.get("ACS_SESSION_ID")
        )
        target = getattr(config, "target_function_or_group", None) or "nat"
        self._agent_id = os.environ.get("ACS_AGENT_ID") or f"nat:{hashlib.sha256(target.encode()).hexdigest()[:8]}"
        self._current: contextvars.ContextVar = contextvars.ContextVar(f"acs_nat_session_{id(self)}", default=None)
        self._sessions_lock = threading.Lock()
        self._open_sessions: set[_Session] = set()
        self._stream_sessions: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._own: _Session | None = None
        self._closed = False
        # WeakKeyDictionary fallback for frozen contexts — id(context)
        # would collide once GC recycles addresses.
        self._frozen_ctx_rids: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._frozen_ctx_lock = threading.Lock()

    @staticmethod
    def _methods() -> list[str]:
        methods = ["steps/toolCallRequest", "steps/toolCallResult"]
        if _HAS_LIFECYCLE:
            methods += [
                "steps/sessionStart", "steps/userMessage",
                "steps/agentResponse", "steps/sessionEnd",
            ]
        return methods

    def close(self) -> None:
        """Refuse new sessions, then end every open one after the hooks it already queued: the middleware's own as
        completed, a run still open as abandoned."""
        with self._sessions_lock:
            self._closed = True
            sessions = list(self._open_sessions)
        for session in sessions:
            self._end_session(session, "completed" if session is self._own else "abandoned")
        for session in sessions:
            session.lane.close()

    def _new_session(self, *, session_id: str | None = None, root_step: str | None = None, stream: Any = None,
                     platform_context: dict | None = None) -> _Session | None:
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        session = _Session(id=session_id or str(uuid.uuid4()), lane=_LifecycleSender(self._send_lifecycle_hook),
                           task=task, root_step=root_step,
                           stream=weakref.ref(stream) if stream is not None else None,
                           platform_context=dict(platform_context or {}))
        with self._sessions_lock:
            if self._closed:
                session.lane.seal()
                return None
            self._open_sessions.add(session)
        return session

    def _workflow_started(self, payload) -> _Session | None:
        current = self._current.get()
        if current is not None and not current.ended:
            return None
        context = {"workflow_name": payload.name or ""}
        provided = getattr(getattr(payload, "metadata", None), "provided_metadata", None) or {}
        for key in ("workflow_run_id", "conversation_id"):
            if provided.get(key):
                context[key] = provided[key]
        session = self._new_session(root_step=payload.UUID, platform_context=context)
        if session is None:
            return None
        self._current.set(session)
        self._queue(session, "steps/sessionStart", {"platform_context": context})
        text = _stringify_step_data(payload.data)
        if text:
            self._queue(session, "steps/userMessage", {"content": [{"type": "text", "value": text}]})
        return session

    def _workflow_ended(self, session: _Session, payload) -> None:
        session.saw_end = True
        text = _stringify_step_data(payload.data)
        if text:
            self._queue(session, "steps/agentResponse", {"content": [{"type": "text", "value": text}]})

    def _runner_stopped(self, session: _Session) -> None:
        task = session.task
        if session.saw_end:
            reason = "completed"
        elif task is not None and (task.cancelled() or task.cancelling() > 0):
            reason = "cancelled"
        else:
            reason = "error"
        self._end_session(session, reason)

    def _end_session(self, session: _Session, reason: str) -> None:
        with session.idle:
            if session.ended:
                return
            session.ended = True
            queued = session.lane.submit("steps/sessionEnd", {"reason": reason}, session)
        if not queued:
            audit_event("lifecycle_hook_not_sent", cause="middleware_closed", method="steps/sessionEnd",
                        session_id=session.id)
            self._finish(session)

    def _finish(self, session: _Session) -> None:
        session.lane.seal()
        with self._sessions_lock:
            self._open_sessions.discard(session)
        discard_session(session.id, self._acs.guardian_url)

    def _session_of_call(self) -> _Session | None:
        current = self._current.get()
        stream = _current_stream()
        if current is not None and (not current.ended or current.stream is None or current.stream() is stream):
            return current
        if stream is not None and _current_run_id() is not None:
            return self._stream_session(stream)
        return self._own_session()

    def _stream_session(self, stream: Any) -> _Session | None:
        with self._sessions_lock:
            session = self._stream_sessions.get(stream)
        if session is None:
            stack = _NATContextState.get().active_span_id_stack.get()
            session = self._new_session(root_step=stack[1] if len(stack) > 1 else None, stream=stream,
                                        platform_context={"workflow_run_id": _current_run_id()})
            if session is None:
                return None
            with self._sessions_lock:
                existing = self._stream_sessions.setdefault(stream, session)
            if existing is not session:
                self._finish(session)
                session = existing
            else:
                self._subscribe(session)
        self._current.set(session)
        return session

    def _subscribe(self, session: _Session) -> None:
        try:
            _NATContext.get().intermediate_step_manager.subscribe(
                on_next=lambda step: self._stream_step(session, step),
                on_error=lambda e: audit_event("lifecycle_subscription_error", session_id=session.id, error=str(e)),
                on_complete=lambda: self._runner_stopped(session),
            )
        except Exception as e:  # noqa: BLE001
            audit_event("lifecycle_subscribe_failed", session_id=session.id, error=str(e))

    def _stream_step(self, session: _Session, step) -> None:
        payload = getattr(step, "payload", None)
        if (getattr(payload, "event_type", None) == IntermediateStepType.WORKFLOW_END
                and payload.UUID == session.root_step):
            self._workflow_ended(session, payload)

    def _own_session(self) -> _Session | None:
        with self._sessions_lock:
            if self._own is not None or self._closed:
                return self._own
        session = self._new_session(session_id=self._session_id)
        with self._sessions_lock:
            if self._own is None:
                self._own = session
                return session
        if session is not None:
            self._finish(session)
        return self._own

    def _open(self, session: _Session | None, lifecycle: bool = False) -> _Step:
        if session is None:
            return _Step(self._session_id, SessionRefused("middleware_closed", {}), None, self._acs.posture)
        with session.lock:
            if session.decision is None:
                # A lifecycle hook queued before the session ended still goes out; a call after the end does not.
                if session.ended and not lifecycle:
                    return self._refused(session)
                session.decision = open_session(
                    config=self._acs, session_id=session.id, agent_id=self._agent_id, platform="nat",
                    methods_implemented=self._methods(), start=lambda negotiated: self._send_session_start(session, negotiated))
            decision = session.decision
        if isinstance(decision, Negotiated):
            # §6.4: deny wins over proceed, and a negotiated default timeout replaces the local one.
            return _Step(session.id, decision, dict(decision.server_hello),
                         self._acs.posture.negotiated(decision.server_hello))
        return _Step(session.id, decision, None, self._acs.posture)

    def _refused(self, session: _Session) -> _Step:
        return _Step(session.id, SessionRefused("session_ended", {"session_id": session.id}), None, self._acs.posture)

    def _send_session_start(self, session: _Session, negotiated: Negotiated):
        if not method_evaluated(negotiated.server_hello, "steps/sessionStart"):
            audit_event("method_not_evaluated", method="steps/sessionStart", session_id=session.id)
            return None
        request = request_envelope("steps/sessionStart", request_id=str(uuid.uuid4()),
                                   metadata=self._metadata(session.id),
                                   payload={"platform_context": session.platform_context})
        result = round_trip(request, guardian_url=self._acs.guardian_url,
                            posture=self._acs.posture.negotiated(negotiated.server_hello), session_id=session.id)
        if isinstance(result, Resolution):
            self._count_failure(session, result)
        return result

    async def _step_of(self, session: _Session | None) -> _Step:
        if session is not None:
            await asyncio.wrap_future(session.lane.sent())
        return await asyncio.to_thread(self._open, session)

    def _exchange(self, session: _Session, request: dict, step: _Step, gate: bool = False):
        with session.idle:
            if session.closed:
                return Resolution(False, "session_ended_fail_closed", "session_ended",
                                  {"session_id": step.session_id, "method": request.get("method", "")})
            session.in_flight += 1
        try:
            result = self._round_trip(request, step, gate)
            if isinstance(result, Resolution):
                self._count_failure(session, result)
            return result
        finally:
            with session.idle:
                session.in_flight -= 1
                session.idle.notify_all()

    def _count_failure(self, session: _Session, resolution: Resolution) -> None:
        if resolution.decision_failure:
            with session.idle:
                session.failures[resolution.fields.get("failure_class", "other")] += 1

    def _queue(self, session: _Session, method: str, payload: dict) -> None:
        with session.idle:
            queued = not session.ended and session.lane.submit(method, payload, session)
        if not queued:
            audit_event("lifecycle_hook_not_sent", cause="session_ended", method=method, session_id=session.id)

    def _send_lifecycle_hook(self, method: str, payload: dict, session: _Session) -> None:
        try:
            self._emit_lifecycle_hook(method, payload, session)
        except Exception as e:  # noqa: BLE001
            audit_event("lifecycle_hook_failed", cause="adapter_exception", error=str(e),
                        method=method, session_id=session.id)
        finally:
            if method == "steps/sessionEnd":
                self._finish(session)

    def _emit_lifecycle_hook(self, method: str, payload: dict, session: _Session) -> None:
        if self._acs.disabled:
            audit_event("acs_disabled_bypass", session_id=session.id, method=method,
                        detail="ACS_DISABLED=1 — lifecycle hook not sent")
            return
        if method == "steps/sessionEnd":
            self._send_session_end(session, payload)
            return
        step = self._open(session, lifecycle=True)
        if method == "steps/sessionStart":
            return
        gated = self._acs.gate(step.decision, method)
        if gated is not None:
            # §4.1: a refused or unanswered session sends the Guardian nothing.
            audit_event(gated.audit_type, **{**gated.fields, "cause": gated.cause,
                                             "session_id": step.session_id, "method": method})
            return
        if not method_evaluated(step.server_hello, method):
            audit_event("method_not_evaluated", method=method, session_id=step.session_id)
            return
        request = request_envelope(method, request_id=str(uuid.uuid4()), metadata=self._metadata(step.session_id),
                                   payload=payload)
        result = self._exchange(session, request, step)
        if isinstance(result, Resolution):
            audit_event("lifecycle_hook_failed", **{**result.fields, "cause": result.cause,
                                                    "method": method, "session_id": step.session_id})

    def _send_session_end(self, session: _Session, payload: dict) -> None:
        with session.idle:
            session.closed = True
            while session.in_flight:
                session.idle.wait()
            failures = dict(session.failures)
        with session.lock:
            decision = session.decision
        if decision is None:
            return
        step = self._open(session, lifecycle=True)
        gated = self._acs.gate(decision, "steps/sessionEnd")
        if gated is not None:
            audit_event(gated.audit_type, **{**gated.fields, "cause": gated.cause,
                                             "session_id": session.id, "method": "steps/sessionEnd"})
            return
        if not method_evaluated(step.server_hello, "steps/sessionEnd"):
            audit_event("method_not_evaluated", method="steps/sessionEnd", session_id=session.id)
            return
        request = request_envelope("steps/sessionEnd", request_id=str(uuid.uuid4()),
                                   metadata=self._metadata(session.id),
                                   payload={**payload, "summary": {"decision_failures": failures}})
        result = self._round_trip(request, step)
        if isinstance(result, Resolution):
            audit_event("lifecycle_hook_failed", **{**result.fields, "cause": result.cause,
                                                    "method": "steps/sessionEnd", "session_id": session.id})

    def _correlation_request_id(self, context) -> str:
        """A uuid4 per invocation, stable from pre_invoke to post_invoke: stashed on the context, else in a WeakKeyDictionary, since id() repeats after GC."""
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
        if self._acs.disabled:
            # Kill switch: pass through ungoverned, audited (§6.4).
            audit_event("acs_disabled_bypass", session_id=self._session_id,
                        method="steps/toolCallRequest",
                        detail="ACS_DISABLED=1 — pre_invoke bypassed ungoverned")
            return None
        session = self._session_of_call()
        step = await self._step_of(session)
        gated = self._acs.gate(step.decision)
        if gated is not None:
            # §4.1: a refused or unanswered session sends the Guardian nothing.
            return self._settle_pre(context, gated, step, f"{gated.label} ({gated.cause})")
        if not method_evaluated(step.server_hello, "steps/toolCallRequest"):
            # ALLOW-by-default (handshake.json): the call proceeds unsent.
            audit_event("method_not_evaluated", method="steps/toolCallRequest",
                        session_id=step.session_id)
            return None
        correlation_id = self._correlation_request_id(context)
        try:
            request = self._build_request(
                method="steps/toolCallRequest",
                tool_name=context.function_context.name,
                tool_arguments=_extract_arguments(context),
                request_id=correlation_id,
                session_id=step.session_id,
            )
        except Exception as e:  # noqa: BLE001
            result = step.posture.resolve(Undecided("adapter_exception", {"error": str(e)},
                                                     f"adapter error: {e}"))
            self._count_failure(session, result)
        else:
            result = await asyncio.to_thread(self._exchange, session, request, step, True)
        if isinstance(result, Resolution):
            return self._settle_pre(context, result, step)
        response = result.response

        decision = normalize_decision((response or {}).get("result"))

        if decision.disposition == "allow":
            return None
        if decision.disposition == "deny":
            return self._block(context, decision.reasoning or "denied by Guardian")
        if decision.disposition == "modify":
            violation = modify_composition_violation(decision.modifications)
            if violation:
                audit_event("modify_composition_invalid",
                            session_id=step.session_id,
                            method="steps/toolCallRequest", detail=violation)
                return self._block(
                    context,
                    f"MODIFY refused ({violation}); failing closed per §6.3")
            if decision.modifications.get("redactions"):
                # NAT has no redaction primitive, and applying only the overrides would drop part of the decision.
                audit_modify_unsupported("redactions", session_id=step.session_id,
                                         method="steps/toolCallRequest")
                return self._block(
                    context, "MODIFY refused: NAT cannot apply the requested "
                    "redactions without dropping part of the decision")
            overrides = decision.modifications.get("parameter_overrides")
            if isinstance(overrides, dict):
                if _apply_overrides_to_context(context, overrides):
                    return context
                unsupported = "the function input does not take the overrides"
            else:
                unsupported = "no parameter_overrides object"
            audit_modify_unsupported(unsupported, session_id=step.session_id, method="steps/toolCallRequest")
            return self._block(context, f"MODIFY substituted to DENY: {decision.reasoning}")
        if decision.disposition in ("ask", "defer"):
            # No pause primitive here, so ask and defer block; NAT's HITL middleware composes for approvals.
            return self._block(context, f"{decision.disposition}: {decision.reasoning}")

        # An arrived-but-uninterpretable decision fails closed; the spec
        # basis is tracked in issue #32.
        audit_event("unusable_disposition",
                    disposition=decision.disposition or "(missing)",
                    session_id=step.session_id,
                    method="steps/toolCallRequest")
        return self._block(
            context,
            f"unusable Guardian disposition '{decision.disposition}' — cannot be "
            f"interpreted; failing closed (see issue #32)")

    async def post_invoke(self, context):
        """Apply the verdict to the output: the tool already ran, so a deny or an unusable decision withholds the output (issue #32)."""
        if self._acs.disabled:
            audit_event("acs_disabled_bypass", session_id=self._session_id,
                        method="steps/toolCallResult",
                        detail="ACS_DISABLED=1 — post_invoke bypassed ungoverned")
            return None
        session = self._session_of_call()
        step = await self._step_of(session)
        gated = self._acs.gate(step.decision)
        if gated is not None:
            return self._settle_post(context, gated, step)
        if not method_evaluated(step.server_hello, "steps/toolCallResult"):
            audit_event("method_not_evaluated", method="steps/toolCallResult",
                        session_id=step.session_id)
            return None
        # request_id_ref correlates the result with its originating
        # toolCallRequest (tool-call-result.json:19-23); an unsent request
        # is never cited.
        correlation_id = self._correlation_request_id(context)
        request_sent = method_evaluated(step.server_hello, "steps/toolCallRequest")
        try:
            request = self._build_request(
                method="steps/toolCallResult",
                tool_name=context.function_context.name,
                tool_arguments=_extract_arguments(context),
                result=_json_safe(context.output),
                request_id_ref=correlation_id if request_sent else None,
                session_id=step.session_id,
            )
        except Exception as e:  # noqa: BLE001
            result = step.posture.resolve(Undecided("adapter_exception", {"error": str(e)},
                                                     f"adapter error: {e}"))
            self._count_failure(session, result)
        else:
            result = await asyncio.to_thread(self._exchange, session, request, step)
        if isinstance(result, Resolution):
            return self._settle_post(context, result, step)
        response = result.response

        decision = normalize_decision((response or {}).get("result"))

        if decision.disposition == "deny":
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="guardian_deny",
                        session_id=step.session_id,
                        method="steps/toolCallResult",
                        reasoning=decision.reasoning or "output redacted by Guardian")
            return context
        if decision.disposition == "modify":
            violation = modify_composition_violation(decision.modifications)
            if violation:
                audit_event("modify_composition_invalid",
                            session_id=step.session_id,
                            method="steps/toolCallResult", detail=violation)
                _redact_output(context)
                audit_event("post_invoke_redacted",
                            cause="modify_composition_invalid",
                            session_id=step.session_id,
                            method="steps/toolCallResult")
                return context
            modified_content = decision.modifications.get("modified_content")
            if modified_content is not None:
                context.output = modified_content
                return context
            # A structured MODIFY on a result has no generic form, so the whole result is withheld.
            audit_modify_unsupported("structured edits on a tool result", session_id=step.session_id,
                                     method="steps/toolCallResult")
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="modify_unapplied_structured_edits",
                        session_id=step.session_id,
                        method="steps/toolCallResult")
            return context
        if not decision.known:
            audit_event("unusable_disposition",
                        disposition=decision.disposition or "(missing)",
                        session_id=step.session_id,
                        method="steps/toolCallResult")
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause="unusable_disposition",
                        session_id=step.session_id,
                        method="steps/toolCallResult",
                        decision=decision.disposition)
            return context
        if decision.disposition in ("ask", "defer"):
            # The tool already ran and nothing can pause the output for a person: withhold what the Guardian did not release.
            _redact_output(context)
            audit_event("post_invoke_redacted",
                        cause=f"{decision.disposition}_substituted_to_deny",
                        session_id=step.session_id,
                        method="steps/toolCallResult",
                        reasoning=decision.reasoning)
            return context
        return None

    def _round_trip(self, request: dict, step: _Step, gate: bool = False):
        return round_trip(request, guardian_url=self._acs.guardian_url, posture=step.posture,
                          session_id=step.session_id, gate=gate)

    def _metadata(self, session_id: str | None = None) -> dict[str, Any]:
        return {"agent_id": self._agent_id, "session_id": session_id or self._session_id,
                "platform": "nat", "adapter_version": ADAPTER_VERSION}

    def _settle_pre(self, context, resolution: Resolution, step: _Step, message: str = ""):
        audit_event(resolution.audit_type, **{**resolution.fields, "cause": resolution.cause,
                                              "session_id": step.session_id,
                                              "method": "steps/toolCallRequest"})
        if resolution.proceed:
            return None
        return self._block(context, message or resolution.message or resolution.cause)

    def _settle_post(self, context, resolution: Resolution, step: _Step):
        """Settle a post_invoke step without a usable decision: redact the output the Guardian never vetted unless the resolution lets it through, and record why."""
        if not resolution.proceed:
            _redact_output(context)
        audit_event(resolution.audit_type, **{**resolution.fields, "cause": resolution.cause,
                                              "session_id": step.session_id,
                                              "method": "steps/toolCallResult"})
        return None if resolution.proceed else context

    def _block(self, context, reason: str):
        """Block with InvocationAction when NAT has it, else raise."""
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
        session_id: str | None = None,
    ) -> dict:
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

        return request_envelope(method, request_id=request_id or str(uuid.uuid4()),
                                metadata=self._metadata(session_id), payload=payload)


if _NAT_AVAILABLE and _HAS_REGISTRATION:
    @register_middleware(config_type=ACSMiddlewareConfig)  # type: ignore[misc]
    async def build_acs_middleware(config: "ACSMiddlewareConfig", builder):  # type: ignore[name-defined]
        """NAT factory entry point: register the exporter that reports each Runner, and end every open session when
        NAT shuts the middleware down."""
        middleware = ACSMiddleware(config)
        if not middleware._acs.disabled:
            add_exporter = getattr(builder, "add_telemetry_exporter", None)
            if add_exporter is not None and _HAS_EXPORTER and _HAS_LIFECYCLE:
                key = str(uuid.uuid4())
                _LIFECYCLE_MIDDLEWARES[key] = middleware
                await add_exporter(f"acs_lifecycle_{key}", ACSLifecycleExporterConfig(middleware_key=key))
        try:
            yield middleware
        finally:
            await asyncio.to_thread(middleware.close)


# The middleware each registered lifecycle exporter feeds, by the key in its config.
_LIFECYCLE_MIDDLEWARES: weakref.WeakValueDictionary = weakref.WeakValueDictionary()

if _NAT_AVAILABLE and _HAS_REGISTRATION and _HAS_EXPORTER and _HAS_LIFECYCLE:
    class ACSLifecycleExporterConfig(TelemetryExporterBaseConfig, name="acs_lifecycle"):  # type: ignore[misc, valid-type, call-arg]
        """Added by `acs_guardian` for its own middleware; it is not configured in YAML."""
        middleware_key: str

    class _LifecycleExporter(BaseExporter):  # type: ignore[misc, valid-type]
        """Reports one Runner's start and end to the middleware; NAT starts a copy of it for every Runner, before the
        Runner's WORKFLOW_START, and cleans the copy up when the Runner ends, whether it completed, failed or was
        cancelled."""

        _root_step: str | None = None
        _session: _Session | None = None

        def __init__(self, middleware: ACSMiddleware) -> None:
            super().__init__()
            self._middleware = middleware

        def export(self, event) -> None:
            try:
                payload = event.payload
                if payload.event_type == IntermediateStepType.WORKFLOW_START and self._root_step is None:
                    self._root_step = payload.UUID
                    self._session = self._middleware._workflow_started(payload)
                elif (payload.event_type == IntermediateStepType.WORKFLOW_END and self._session is not None
                      and payload.UUID == self._root_step):
                    self._middleware._workflow_ended(self._session, payload)
            except Exception as e:  # noqa: BLE001
                audit_event("lifecycle_export_failed", error=str(e))

        async def _cleanup(self) -> None:
            if self._session is not None:
                self._middleware._runner_stopped(self._session)

    @register_telemetry_exporter(config_type=ACSLifecycleExporterConfig)  # type: ignore[misc]
    async def build_acs_lifecycle_exporter(config: "ACSLifecycleExporterConfig", builder):  # type: ignore[name-defined]
        middleware = _LIFECYCLE_MIDDLEWARES.get(config.middleware_key)
        if middleware is None:
            raise ValueError("acs_lifecycle is added by the acs_guardian middleware; it is not configured on its own")
        yield _LifecycleExporter(middleware)
