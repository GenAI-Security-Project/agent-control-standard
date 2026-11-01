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
            description="Session id of calls outside a NAT run; each run's own session id derives from it. Auto-generated per-process if absent. Coerced to UUID format.",
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
    if new_head is None:
        return False
    args[0] = new_head
    try:
        # Tuple field with validate_assignment=True — assign a new tuple.
        context.modified_args = tuple(args)
    except Exception:  # noqa: BLE001
        return False
    return True


# ----- Middleware class -----

# Untracked runs whose decision failures wait for a sessionEnd; past this many, the oldest of them ages out.
_MAX_COUNTED_RUNS = 256
# Ended runs remembered so a late step of one is refused; past this many, the oldest is forgotten.
_MAX_ENDED_RUNS = 4096


class _LifecycleSender:
    """Sends lifecycle hooks on one thread, in the order they are accepted.

    close() waits until every accepted hook has gone out, still accepting
    hooks that arrive meanwhile, and then accepts no more.
    """

    def __init__(self, send: Callable[[str, dict, str | None], None]) -> None:
        self._send = send
        self._pending: collections.deque = collections.deque()
        self._changed = threading.Condition()
        self._busy = False
        self._closed = False
        self._thread: threading.Thread | None = None
        _OPEN_SENDERS.add(self)

    def submit(self, method: str, payload: dict, run: str | None = None) -> bool:
        """Queue a hook of a run behind the ones already accepted; False once closed."""
        with self._changed:
            if self._closed:
                return False
            self._pending.append((method, payload, run))
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

    def close(self) -> None:
        with self._changed:
            while self._pending or self._busy:
                self._changed.wait()
            self._closed = True
            self._changed.notify_all()
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
                while not self._pending and not self._closed:
                    self._changed.wait()
                if not self._pending:
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


# The lifecycle thread is a daemon, so interpreter exit sends what is still queued first.
_OPEN_SENDERS: weakref.WeakSet = weakref.WeakSet()
atexit.register(lambda: [sender.close() for sender in list(_OPEN_SENDERS)])


@dataclass
class _Run:
    """One NAT run, which is its own ACS session: the task running it, whether its sessionEnd is queued, and the session's decision."""
    session_id: str
    task: asyncio.Task | None = None
    ended: bool = False
    decision: Handshake | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    # The run's Guardian exchanges still running, and whether its sessionEnd has begun; both under `idle`.
    in_flight: int = 0
    closed: bool = False
    idle: threading.Condition = field(default_factory=threading.Condition)
    # Set once the sessionEnd has been handled; only the middleware's own session is kept after it.
    finished: bool = False


@dataclass(frozen=True)
class _Step:
    """The session a step belongs to: its id, the handshake's decision, and what that handshake negotiated."""
    session_id: str
    decision: Handshake
    server_hello: dict | None
    posture: FailPosture


class ACSMiddleware(FunctionMiddleware):  # type: ignore[misc, valid-type]
    """NAT middleware that defers each call's allow/deny/modify decision to an ACS Guardian."""

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
        # Replaced, never mutated, once the handshake negotiates (§6.4).
        self._posture = self._acs.posture
        self._session_id = _coerce_uuid(
            getattr(config, "session_id", None) or os.environ.get("ACS_SESSION_ID")
        )
        target = getattr(config, "target_function_or_group", None) or "nat"
        self._agent_id = os.environ.get("ACS_AGENT_ID") or f"nat:{hashlib.sha256(target.encode()).hexdigest()[:8]}"
        # The session's §4.1 decision, made by one handshake (in the builder, or on the first call) and reused by every call.
        self._session: Handshake | None = None
        self._session_lock = threading.Lock()
        # One thread sends lifecycle hooks off the event loop, in the order NAT reports them.
        self._lifecycle = _LifecycleSender(self._send_lifecycle_hook)
        self._server_hello: dict | None = None
        # Set when the builder registered a lifecycle exporter, which NAT starts for every run.
        self._lifecycle_exported = False
        # The run streams this middleware subscribed to itself, one subscription each; a stream leaves with its run.
        self._lifecycle_streams: weakref.WeakSet = weakref.WeakSet()
        # Locks the check-then-set in _ensure_lifecycle_subscribed
        # against double subscription from parallel pre_invoke calls.
        self._lifecycle_lock = threading.Lock()
        # WeakKeyDictionary fallback for frozen contexts — id(context)
        # would collide once GC recycles addresses.
        self._frozen_ctx_rids: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._frozen_ctx_lock = threading.Lock()
        # §6.4: decision failures per run and failure class; each run's sessionEnd reports its own run's.
        # Calls and the lifecycle thread both count; a run no sessionEnd will report ages out once it is no longer tracked.
        self._decision_failures: collections.OrderedDict = collections.OrderedDict()
        self._decision_failures_lock = threading.Lock()
        # The runs whose WORKFLOW_START was seen, each kept until its sessionEnd has been handled.
        self._runs: collections.OrderedDict = collections.OrderedDict()
        # Runs whose sessionEnd has been handled, so a late step of one is refused rather than opening its id again.
        self._ended_runs: collections.OrderedDict = collections.OrderedDict()
        self._runs_lock = threading.Lock()

    def _ensure_handshake(self) -> Handshake:
        """The session's decision, opened once under a lock so concurrent first calls share one handshake."""
        if self._session is not None:
            return self._session
        with self._session_lock:
            if self._session is None:
                self._session = self._open_session()
        return self._session

    @staticmethod
    def _methods() -> list[str]:
        methods = ["steps/toolCallRequest", "steps/toolCallResult"]
        if _HAS_LIFECYCLE:
            methods += [
                "steps/sessionStart", "steps/userMessage",
                "steps/agentResponse", "steps/sessionEnd",
            ]
        return methods

    def _open_session(self) -> Handshake:
        # The stored decision keeps the session's gate across middleware instances and processes.
        session = open_session(
            config=self._acs,
            session_id=self._session_id,
            agent_id=self._agent_id,
            platform="nat",
            methods_implemented=self._methods(),
        )
        if isinstance(session, Negotiated):
            # §6.4: deny wins over proceed, and a negotiated default timeout replaces the local one.
            self._posture = self._posture.negotiated(session.server_hello)
            self._server_hello = dict(session.server_hello)
        return session

    async def _lifecycle_sent(self) -> None:
        """Wait until the lifecycle hooks NAT reported earlier have gone out, so the Guardian sees steps in event order."""
        await asyncio.wrap_future(self._lifecycle.sent())

    def close(self) -> None:
        """End the middleware's own session if a step outside any run started it, send the lifecycle hooks still queued,
        including any that arrive meanwhile, then accept no more."""
        with self._runs_lock:
            own = self._runs.get(None)
        if own is not None:
            # A session still opening finishes first, so its sessionStart is not left without a sessionEnd.
            with own.lock:
                opened = own.decision is not None
                if not opened:
                    own.finished = True
            if opened and self._end_run(None):
                self._queue_lifecycle_hook("steps/sessionEnd", payload={"reason": "completed"}, run=None)
        self._lifecycle.close()

    def _ensure_lifecycle_subscribed(self) -> None:
        """Without the builder's exporter, subscribe to the current run's step stream on the run's first call.

        NAT builds a new stream for each run and pushes WORKFLOW_START before
        any call, so such a run reports from its first call on; the builder's
        exporter subscribes before the start. Locked against double subscription.
        """
        if self._lifecycle_exported or not _HAS_LIFECYCLE:
            return
        try:
            stream = _NATContextState.get().event_stream.get()
        except Exception:  # noqa: BLE001
            return
        if stream in self._lifecycle_streams:
            return
        with self._lifecycle_lock:
            if stream in self._lifecycle_streams:
                return
            try:
                mgr = _NATContext.get().intermediate_step_manager
            except Exception:  # noqa: BLE001
                # No active Context; function-call hooks still fire via FunctionMiddleware.
                return
            run = self._current_run()
            try:
                # NAT completes a run's stream when the run ends, whether or not it pushed WORKFLOW_END.
                mgr.subscribe(
                    on_next=self._on_intermediate_step,
                    on_error=lambda e: audit_event(
                        "lifecycle_subscription_error",
                        session_id=self._session_id, error=str(e)),
                    on_complete=lambda: self._run_stopped(run),
                )
                self._lifecycle_streams.add(stream)
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

        run = self._current_run()
        if event_type == IntermediateStepType.WORKFLOW_START:
            self._track_run(run)
            # Workflow input becomes both sessionStart (boundary marker)
            # and userMessage (the input itself).
            self._queue_lifecycle_hook(
                "steps/sessionStart",
                payload={"platform_context": {"workflow_name": payload.name or ""}}, run=run)
            input_text = _stringify_step_data(payload.data)
            if input_text:
                self._queue_lifecycle_hook(
                    "steps/userMessage",
                    payload={"content": [{"type": "text", "value": input_text}]}, run=run)
        elif event_type == IntermediateStepType.WORKFLOW_END:
            self._end_run(run)
            # Workflow output becomes agentResponse; sessionEnd closes the boundary.
            output_text = _stringify_step_data(payload.data)
            if output_text:
                self._queue_lifecycle_hook(
                    "steps/agentResponse",
                    payload={"content": [{"type": "text", "value": output_text}]}, run=run)
            self._queue_lifecycle_hook(
                "steps/sessionEnd",
                payload={"reason": "completed"}, run=run)

    def _run_session_id(self, run: str | None) -> str:
        """Each NAT run is its own ACS session, named from the configured session and the run; a step outside any run uses the configured one."""
        if run is None:
            return self._session_id
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"acs-nat-run:{self._session_id}:{run}"))

    def _run_state(self, run: str | None) -> _Run:
        """The run's state, created by its WORKFLOW_START or, for a run seen from its first call, by that call."""
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        with self._runs_lock:
            if run in self._ended_runs:
                return _Run(session_id=self._run_session_id(run), finished=True)
            state = self._runs.get(run)
            if state is None:
                state = self._runs[run] = _Run(session_id=self._run_session_id(run))
            if state.task is None:
                state.task = task
            return state

    def _track_run(self, run: str | None) -> None:
        """Record a run at its WORKFLOW_START, which NAT pushes in the task running it."""
        if run is not None:
            self._run_state(run)

    def _step(self, run: str | None, workflow_name: str = "") -> _Step:
        """The session a step belongs to, opened with its sessionStart: the run's own, or the middleware's for a step outside any run."""
        state = self._run_state(run)
        ended = _Step(state.session_id, SessionRefused("session_ended", {"session_id": state.session_id}), None,
                      self._acs.posture)
        with state.lock:
            # Checked under the lock, so a session that shutdown found unopened is never opened after it.
            if state.finished:
                return ended
            if state.decision is None:
                state.decision = open_session(
                    config=self._acs, session_id=state.session_id, agent_id=self._agent_id, platform="nat",
                    methods_implemented=self._methods(),
                    start=lambda session: self._send_session_start(run, state.session_id, session, workflow_name))
            decision = state.decision
        if isinstance(decision, Negotiated):
            # §6.4: deny wins over proceed, and a negotiated default timeout replaces the local one.
            return _Step(state.session_id, decision, dict(decision.server_hello),
                         self._acs.posture.negotiated(decision.server_hello))
        return _Step(state.session_id, decision, None, self._acs.posture)

    def _send_session_start(self, run: str | None, session_id: str, session: Negotiated, workflow_name: str):
        """The run's one sessionStart, sent as its session opens (hooks.md sessionStart: ALLOW / DENY)."""
        if not method_evaluated(session.server_hello, "steps/sessionStart"):
            audit_event("method_not_evaluated", method="steps/sessionStart", session_id=session_id)
            return None
        request = request_envelope("steps/sessionStart", request_id=str(uuid.uuid4()),
                                   metadata=self._metadata(session_id),
                                   payload={"platform_context": {"workflow_name": workflow_name}})
        result = round_trip(request, guardian_url=self._acs.guardian_url,
                            posture=self._acs.posture.negotiated(session.server_hello), session_id=session_id)
        if isinstance(result, Resolution):
            self._count_failure(result, run)
        return result

    def _end_run(self, run: str | None) -> bool:
        """Mark the run's sessionEnd as queued; False only when a tracked run's already was."""
        with self._runs_lock:
            state = self._runs.get(run)
            if state is None or state.ended:
                return state is None
            state.ended = True
            return True

    def _run_stopped(self, run: str | None) -> None:
        """NAT stopped the run's exporter: a run that started and pushed no WORKFLOW_END failed or was cancelled."""
        with self._runs_lock:
            state = self._runs.get(run)
            task = state.task if state is not None else None
        if state is None or not self._end_run(run):
            return
        cancelled = task is not None and (task.cancelled() or task.cancelling() > 0)
        self._queue_lifecycle_hook("steps/sessionEnd", payload={"reason": "cancelled" if cancelled else "error"}, run=run)

    def _close_run(self, run: str | None) -> None:
        """Before the run's sessionEnd: refuse its exchanges from now on, and wait for those already running, which a cancelled call leaves behind."""
        with self._runs_lock:
            state = self._runs.get(run)
        if state is None:
            return
        with state.idle:
            state.closed = True
            while state.in_flight:
                state.idle.wait()

    def _exchange(self, request: dict, step: _Step, run: str | None, gate: bool = False):
        """A call's round trip, counted so the run's sessionEnd goes out after it; refused once that sessionEnd has begun."""
        ended = Resolution(False, "session_ended_fail_closed", "session_ended",
                           {"session_id": step.session_id, "method": request.get("method", "")})
        with self._runs_lock:
            state = self._runs.get(run)
        # A worker that starts after the session's end finds its state gone or finished.
        if state is None or state.finished:
            return ended
        with state.idle:
            if state.closed:
                return ended
            state.in_flight += 1
        try:
            return self._round_trip(request, step, gate)
        finally:
            with state.idle:
                state.in_flight -= 1
                state.idle.notify_all()

    def _forget_run(self, run: str | None) -> None:
        """Drop a run once its sessionEnd has been handled, sent or not; the middleware's own session stays, ended, so a later step outside a run cannot open its id again."""
        with self._runs_lock:
            state = self._runs.get(run) if run is None else self._runs.pop(run, None)
            if state is not None:
                state.finished = True
            if run is not None:
                self._ended_runs[run] = None
                while len(self._ended_runs) > _MAX_ENDED_RUNS:
                    self._ended_runs.popitem(last=False)
        self._take_failure_counts(run)
        if state is not None:
            discard_session(state.session_id, self._acs.guardian_url)

    def _queue_lifecycle_hook(self, method: str, payload: dict, run: str | None = None) -> None:
        """Hand a lifecycle hook of a run to the lifecycle thread, so NAT's step callback returns without waiting on the Guardian."""
        if not self._lifecycle.submit(method, payload, run):
            audit_event("lifecycle_hook_not_sent", cause="middleware_closed", method=method,
                        session_id=self._session_id)
            if method == "steps/sessionEnd":
                self._forget_run(run)

    def _send_lifecycle_hook(self, method: str, payload: dict, run: str | None = None) -> None:
        try:
            self._emit_lifecycle_hook(method, payload, run)
        except Exception as e:  # noqa: BLE001
            audit_event("lifecycle_hook_failed", cause="adapter_exception", error=str(e),
                        method=method, session_id=self._session_id)
        finally:
            if method == "steps/sessionEnd":
                self._forget_run(run)

    def _emit_lifecycle_hook(self, method: str, payload: dict, run: str | None = None) -> None:
        """Build, sign, and POST a lifecycle hook; errors are audited but
        never interrupt the workflow (enforcement lives in
        pre_invoke/post_invoke)."""
        if self._acs.disabled:
            audit_event("acs_disabled_bypass", session_id=self._session_id, method=method,
                        detail="ACS_DISABLED=1 — lifecycle hook not sent")
            return
        if method == "steps/sessionStart":
            # The session opens here, and its sessionStart goes out as it does.
            self._step(run, (payload.get("platform_context") or {}).get("workflow_name", ""))
            return
        if method == "steps/sessionEnd":
            self._close_run(run)
        step = self._step(run)
        gated = self._acs.gate(step.decision, method)
        if gated is not None:
            # §4.1: a refused or unanswered session sends the Guardian nothing.
            audit_event(gated.audit_type, **{**gated.fields, "cause": gated.cause,
                                             "session_id": step.session_id, "method": method})
            return
        if not method_evaluated(step.server_hello, method):
            audit_event("method_not_evaluated", method=method,
                        session_id=step.session_id)
            return
        if method == "steps/sessionEnd":
            # Built as it is sent, so it counts the failures of every hook sent before it.
            payload = {**payload, "summary": {"decision_failures": self._take_failure_counts(run)}}
        request = request_envelope(method, request_id=str(uuid.uuid4()), metadata=self._metadata(step.session_id),
                                   payload=payload)
        result = self._round_trip(request, step)
        if isinstance(result, Resolution):
            audit_event("lifecycle_hook_failed", **{**result.fields, "cause": result.cause,
                                                    "method": method, "session_id": step.session_id})
            self._count_failure(result, run)

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
        """Gate the function call. Block via raising or InvocationAction.SKIP; modify args in place."""
        if self._acs.disabled:
            # Kill switch: pass through ungoverned, audited (§6.4).
            audit_event("acs_disabled_bypass", session_id=self._session_id,
                        method="steps/toolCallRequest",
                        detail="ACS_DISABLED=1 — pre_invoke bypassed ungoverned")
            return None
        self._ensure_lifecycle_subscribed()
        run = self._current_run()
        step = await self._step_of(run)
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
        else:
            await self._lifecycle_sent()
            result = await asyncio.to_thread(self._exchange, request, step, run, True)
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
                unsupported = "the overrides fit no slot NAT reads the function input from"
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
        run = self._current_run()
        step = await self._step_of(run)
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
        else:
            await self._lifecycle_sent()
            result = await asyncio.to_thread(self._exchange, request, step, run)
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

    async def _step_of(self, run: str | None) -> _Step:
        """A call's session, opened off the event loop after the lifecycle hooks reported before the call, so a run's sessionStart carries its workflow's name."""
        self._run_state(run)
        await self._lifecycle_sent()
        return await asyncio.to_thread(self._step, run)

    def _metadata(self, session_id: str | None = None) -> dict[str, Any]:
        return {"agent_id": self._agent_id, "session_id": session_id or self._session_id,
                "platform": "nat", "adapter_version": ADAPTER_VERSION}

    @staticmethod
    def _current_run() -> str | None:
        """The NAT run the current call or workflow event belongs to; None outside a Runner."""
        try:
            return _NATContextState.get().workflow_run_id.get() if _NATContextState is not None else None
        except Exception:  # noqa: BLE001
            return None

    def _count_failure(self, resolution: Resolution, run: str | None = None) -> None:
        """Count a step's own decision failure under its run and failure class (§6.4)."""
        if not resolution.decision_failure:
            return
        with self._runs_lock:
            tracked = set(self._runs)
        with self._decision_failures_lock:
            counts = self._decision_failures.setdefault(run, collections.Counter())
            counts[resolution.fields.get("failure_class", "other")] += 1
            # A tracked run keeps its counts until its sessionEnd; only untracked runs age out.
            untracked = [r for r in self._decision_failures if r not in tracked]
            for stale in untracked[:max(0, len(untracked) - _MAX_COUNTED_RUNS)]:
                del self._decision_failures[stale]

    def _take_failure_counts(self, run: str | None) -> dict[str, int]:
        """The run's decision failures per failure class, removed now that its sessionEnd reports them."""
        with self._decision_failures_lock:
            return dict(self._decision_failures.pop(run, {}))

    def _settle_pre(self, context, resolution: Resolution, step: _Step, message: str = ""):
        audit_event(resolution.audit_type, **{**resolution.fields, "cause": resolution.cause,
                                              "session_id": step.session_id,
                                              "method": "steps/toolCallRequest"})
        self._count_failure(resolution, self._current_run())
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
        self._count_failure(resolution, self._current_run())
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
        """NAT factory entry point: open the session off the event loop before NAT gets the middleware,
        and send the queued lifecycle hooks when NAT shuts it down."""
        middleware = ACSMiddleware(config)
        if not middleware._acs.disabled:
            await asyncio.to_thread(middleware._ensure_handshake)
            add_exporter = getattr(builder, "add_telemetry_exporter", None)
            if add_exporter is not None and _HAS_EXPORTER and _HAS_LIFECYCLE:
                key = str(uuid.uuid4())
                _LIFECYCLE_MIDDLEWARES[key] = middleware
                await add_exporter(f"acs_lifecycle_{key}", ACSLifecycleExporterConfig(middleware_key=key))
                middleware._lifecycle_exported = True
        try:
            yield middleware
        finally:
            await asyncio.to_thread(middleware.close)


# ----- Per-run lifecycle exporter -----

# The middleware each registered lifecycle exporter feeds, by the key in its config.
_LIFECYCLE_MIDDLEWARES: weakref.WeakValueDictionary = weakref.WeakValueDictionary()

if _NAT_AVAILABLE and _HAS_REGISTRATION and _HAS_EXPORTER and _HAS_LIFECYCLE:
    class ACSLifecycleExporterConfig(TelemetryExporterBaseConfig, name="acs_lifecycle"):  # type: ignore[misc, valid-type, call-arg]
        """Added by `acs_guardian` for its own middleware; it is not configured in YAML."""
        middleware_key: str

    class _LifecycleExporter(BaseExporter):  # type: ignore[misc, valid-type]
        """Hands every step of a run to the middleware's lifecycle callback; NAT subscribes it before WORKFLOW_START."""

        # The run this exporter instance reports; NAT copies the exporter for each run.
        _run: str | None = None

        def __init__(self, middleware: ACSMiddleware) -> None:
            super().__init__()
            self._middleware = middleware

        def export(self, event) -> None:
            if self._run is None:
                self._run = self._middleware._current_run()
            self._middleware._on_intermediate_step(event)

        async def _cleanup(self) -> None:
            # NAT stops a run's exporter when the run ends, whether or not it pushed WORKFLOW_END.
            self._middleware._run_stopped(self._run)

    @register_telemetry_exporter(config_type=ACSLifecycleExporterConfig)  # type: ignore[misc]
    async def build_acs_lifecycle_exporter(config: "ACSLifecycleExporterConfig", builder):  # type: ignore[name-defined]
        middleware = _LIFECYCLE_MIDDLEWARES.get(config.middleware_key)
        if middleware is None:
            raise ValueError("acs_lifecycle is added by the acs_guardian middleware; it is not configured on its own")
        yield _LifecycleExporter(middleware)
