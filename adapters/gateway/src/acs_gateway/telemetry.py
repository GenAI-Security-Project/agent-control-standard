"""OpenTelemetry spans for the gateway (LAB-09, issue #582): one trace per ACS session, exported over OTLP HTTP.

Off unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Off, every method returns at once and nothing from opentelemetry is
imported, so the gateway behaves exactly as it does without this module. On, spans go straight to the endpoint's
/v1/traces, Jaeger's OTLP HTTP port in the lab, with no collector between them (PREMORTEM P22).

The gateway's tracer provider is its own and never the process-wide one, so nothing else in the process starts
exporting because the gateway does.
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from acs_gateway.config import GatewayConfig

_LOG = logging.getLogger("acs_gateway.telemetry")
SERVICE_NAME = "acs-gateway"
TRACES_PATH = "/v1/traces"
# Names from specification/v0.1.0/trace/otel-mapping.json on integration, verbatim. PR #557 would rename the tool spans
# to execute_tool, and these follow it only once it merges (issue #582).
SESSION_SPAN = "acs.session"
STEP_SPANS = {"steps/toolCallRequest": "gen_ai.tool.call", "steps/toolCallResult": "gen_ai.tool.result"}
DECISION_EVENT = "acs.decision"
FAILURE_EVENT = "acs.decision.failure"
# acs.failure.class values the mapping enumerates. Any other cause is "other" with the cause as acs.failure.detail.
FAILURE_CLASSES = frozenset({"timeout", "unreachable", "malformed_response", "guardian_error", "observed_agent_error",
                             "signature_invalid", "handshake_failure", "other"})
# The OpenTelemetry GenAI operation names, so a GenAI backend keeps every span (issue #520). The mapping names none for
# a session or a model call, so the session span is the agent's invocation and the model call is a chat.
# Lab names, under acs.lab until a spec issue names an ASK hold or a replay miss in the mapping.
ASK_SPAN = "acs.lab.ask"
ASK_EVENT = "acs.lab.ask_resolved"
REPLAY_MISS_EVENT = "acs.lab.replay_miss"
# The ask_resolved audit fields a span may carry. The question is the Guardian's free text and may quote arguments.
_ASK_FIELDS = ("outcome", "approver", "ask_request_id", "request_id", "decision", "guardian_decision", "cause",
               "deadline_s", "waited_s", "tool", "call_id")
_REPLAY_FIELDS = ("cause", "step", "branch", "stream", "scenario")
SESSION_OPERATION = "invoke_agent"
TOOL_OPERATION = "execute_tool"
MODEL_OPERATION = "chat"
PROVIDER_NAME = "openai"
# The model call span in progress, so a replay miss inside the upstream transport finds it without importing anything.
_MODEL_SPAN: ContextVar[Any] = ContextVar("acs_gateway_model_span", default=None)


def traces_url(endpoint: str) -> str:
    """The OTLP HTTP traces URL under a base endpoint, as the OpenTelemetry exporter specification builds it."""
    return endpoint.rstrip("/") + TRACES_PATH


def session_trace_id(session_id: str) -> int:
    """A session's trace id: its session_id UUID as a 128 bit integer, so a reader finds the trace by session_id.

    The gateway mints every session_id as a UUID4. Anything else hashes to 128 bits, so a trace id never fails.
    """
    try:
        value = uuid.UUID(session_id).int
    except (ValueError, AttributeError, TypeError):
        value = int.from_bytes(hashlib.sha256(str(session_id).encode("utf-8")).digest()[:16], "big")
    return value or 1


def session_root_span_id(session_id: str) -> int:
    """The span id of a session's acs.session span, derived from the session_id.

    Every later span of the session names this parent without the gateway storing anything per session, so an evicted
    or retired session leaves nothing behind.
    """
    digest = hashlib.sha256(f"acs.session:{session_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") or 1


class Tracing:
    """The gateway's spans, or nothing when provider is None."""

    def __init__(self, provider: TracerProvider | None, mode: str = "off") -> None:
        self.provider = provider
        self.mode = mode
        self._tracer = provider.get_tracer("acs_gateway") if provider is not None else None

    @classmethod
    def from_config(cls, config: GatewayConfig) -> Tracing:
        if config.otlp_endpoint is None:
            return cls(None, config.mode)
        return cls(build_provider(config.otlp_endpoint), config.mode)

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    def now(self) -> int:
        """Wall clock nanoseconds for a span's start, or 0 when off, so off reads no clock."""
        return time.time_ns() if self._tracer is not None else 0

    def shutdown(self) -> None:
        if self.provider is not None:
            self.provider.shutdown()

    def _parent(self, session_id: str | None) -> Any:
        """The context whose parent is the session's acs.session span, or None for a span of no session."""
        if session_id is None:
            return None
        from opentelemetry import trace

        root = trace.SpanContext(session_trace_id(session_id), session_root_span_id(session_id), is_remote=False,
                                 trace_flags=trace.TraceFlags(trace.TraceFlags.SAMPLED))
        return trace.set_span_in_context(trace.NonRecordingSpan(root))

    def session(self, session_id: str, epoch: int, request_id: str | None, handshake: Any, started: int) -> None:
        """The acs.session span for one opening: the handshake and steps/sessionStart, rooting the session's trace.

        Recorded once the opening ends, with its real start time, so its ids can be the session's own.
        """
        if self._tracer is None:
            return
        from opentelemetry.context import Context

        attributes: dict[str, Any] = {"acs.session.id": session_id, "gen_ai.operation.name": SESSION_OPERATION,
                                      "acs.lab.mode": self.mode, "acs.lab.epoch": epoch,
                                      "acs.lab.handshake": type(handshake).__name__}
        if request_id is not None:
            attributes["acs.request_id"] = request_id
        ids = self.provider.id_generator
        ids.force(session_trace_id(session_id), session_root_span_id(session_id))
        try:
            # An empty context, so the span is a root whatever the caller's context holds.
            span = self._tracer.start_span(SESSION_SPAN, context=Context(), start_time=started or None,
                                           attributes=attributes)
        finally:
            ids.clear()
        _session_outcome(span, request_id, handshake)
        span.end()

    def step(self, session_id: str, method: str, payload: dict[str, Any], result: Any, started: int,
             shadow: bool) -> None:
        """The step span for one Guardian request, with its decision or its decision failure as an event.

        Recorded once the step settles, with its real start time. A step that never claimed a request_id never reached
        the Guardian, so it has no span (the mapping keys every step span on acs.request_id). Only the tool's name and
        version, the result's exit status and its request_id_ref come from the payload, never arguments or output.
        """
        name = STEP_SPANS.get(method)
        if self._tracer is None or name is None or result.request_id is None:
            return
        tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
        attributes: dict[str, Any] = {"acs.session.id": session_id, "acs.request_id": result.request_id,
                                      "gen_ai.operation.name": TOOL_OPERATION, "acs.lab.mode": self.mode,
                                      "gen_ai.tool.name": tool.get("name") if isinstance(tool.get("name"), str) else ""}
        if isinstance(tool.get("version"), str):
            attributes["acs.tool.version"] = tool["version"]
        if method == "steps/toolCallResult":
            exit_status = payload.get("exit_status")
            attributes["acs.exit_status"] = exit_status if isinstance(exit_status, str) else ""
            if isinstance(payload.get("request_id_ref"), str) and payload["request_id_ref"]:
                attributes["acs.request_id_ref"] = payload["request_id_ref"]
        decided = result.decision.disposition if result.cause is None and result.decision is not None else ""
        if decided:
            # Mirrored onto the span for readers that keep attributes and drop events (issue #520).
            attributes["acs.decision"] = decided
            if shadow:
                attributes["acs.lab.shadow_decision"] = decided
        span = self._tracer.start_span(name, context=self._parent(session_id), start_time=started or None,
                                       attributes=attributes)
        if decided:
            event: dict[str, Any] = {"acs.decision": decided}
            if result.reason_codes:
                event["acs.reason_codes"] = list(result.reason_codes)
            span.add_event(DECISION_EVENT, event)
        else:
            _failure_event(span, result.failure_class, result.cause)
        span.end()

    def ask_resolved(self, session_id: str, fields: dict[str, Any]) -> None:
        """An acs.lab.ask span covering one ASK's hold, back-dated by its wait, carrying its resolution as an event.

        The ASK's own step span and the resend's sit beside it in the session's trace.
        """
        if self._tracer is None:
            return
        end = time.time_ns()
        waited = fields.get("waited_s")
        start = end - int(waited * 1e9) if isinstance(waited, (int, float)) and waited >= 0 else end
        tool = fields.get("tool")
        attributes = {"acs.session.id": session_id, "gen_ai.operation.name": TOOL_OPERATION,
                      "gen_ai.tool.name": tool if isinstance(tool, str) else "", "acs.lab.mode": self.mode}
        span = self._tracer.start_span(ASK_SPAN, context=self._parent(session_id), start_time=start,
                                       attributes=attributes)
        span.add_event(ASK_EVENT, _scalars("acs.lab.ask", fields, _ASK_FIELDS), timestamp=end)
        span.end(end_time=end)

    @contextlib.contextmanager
    def model_call(self, session_id: str | None, body: Any, stream: bool) -> Iterator[ModelCall]:
        """A span for one call to the model upstream, from the send until the answer's headers arrive.

        A streamed answer's tool calls are gated after this span ends, and their step spans sit beside it in the trace.
        """
        if self._tracer is None:
            yield _OFF_CALL
            return
        model = body.get("model") if isinstance(body, dict) else None
        attributes: dict[str, Any] = {"gen_ai.operation.name": MODEL_OPERATION, "gen_ai.provider.name": PROVIDER_NAME,
                                      "acs.lab.mode": self.mode, "acs.lab.stream": stream}
        if isinstance(model, str) and model:
            attributes["gen_ai.request.model"] = model
            attributes["acs.lab.model"] = model
        if session_id is not None:
            attributes["acs.session.id"] = session_id
        name = f"{MODEL_OPERATION} {model}" if isinstance(model, str) and model else MODEL_OPERATION
        span = self._tracer.start_span(name, context=self._parent(session_id), attributes=attributes)
        token = _MODEL_SPAN.set(span)
        try:
            yield ModelCall(span)
        except BaseException as e:
            from opentelemetry.trace import Status, StatusCode

            # The error's type only. Its message can quote a URL or a body, which never goes on a span.
            span.set_attribute("error.type", type(e).__name__)
            span.set_status(Status(StatusCode.ERROR))
            raise
        finally:
            _MODEL_SPAN.reset(token)
            span.end()


class ModelCall:
    """The model call span a caller marks with the upstream's status."""

    def __init__(self, span: Any) -> None:
        self._span = span

    def status(self, code: int) -> None:
        if self._span is not None:
            self._span.set_attribute("http.response.status_code", code)


_OFF_CALL = ModelCall(None)


def replay_miss(**fields: Any) -> None:
    """Mark a replay miss on the model call span in progress, for LAB-06's replay transport (A.8).

    The transport runs inside the gateway's upstream send, so the span is the one that send opened. Outside a traced
    model call this does nothing, and it never imports OpenTelemetry.
    """
    span = _MODEL_SPAN.get()
    if span is not None:
        span.add_event(REPLAY_MISS_EVENT, _scalars("acs.lab.replay", fields, _REPLAY_FIELDS))


def _scalars(prefix: str, fields: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """The listed fields that hold a string, number or bool, named under prefix. Anything else stays off the span."""
    return {f"{prefix}.{key}": fields[key] for key in keys
            if isinstance(fields.get(key), (str, int, float, bool))}


def _failure_event(span: Any, failure_class: str | None, detail: str | None) -> None:
    """An acs.decision.failure event. The gateway always fails closed (D-045), and reports its own conduct."""
    attributes = {"acs.failure.posture": "fail_closed", "acs.failure.reported_by": "observed_agent"}
    if failure_class in FAILURE_CLASSES and failure_class != "other":
        attributes["acs.failure.class"] = failure_class
    else:
        # Text the gateway composes from its own cause token, never bytes from a request or response.
        attributes["acs.failure.class"] = "other"
        attributes["acs.failure.detail"] = f"gateway cause {detail or failure_class or 'unknown'}"
    span.add_event(FAILURE_EVENT, attributes)


def _session_outcome(span: Any, request_id: str | None, handshake: Any) -> None:
    """How the opening ended, read from acs.client's handshake outcome by shape, so this module imports no ACS code.

    A session that opened needs no event. A Guardian that denied sessionStart decided, so that is a decision event.
    Anything else that kept the session from opening is a decision failure on this span, as the mapping asks.
    """
    cause = getattr(handshake, "cause", None)
    if hasattr(handshake, "server_hello"):
        failure = getattr(handshake, "start_failure", None)
        if failure is None:
            return
        fields = failure.get("fields") or {}
        _failure_event(span, fields.get("failure_class"), failure.get("cause"))
        return
    fields = getattr(handshake, "fields", None) or {}
    if request_id is not None and cause == "session_start_denied" and isinstance(fields.get("decision"), str):
        span.add_event(DECISION_EVENT, {"acs.decision": fields["decision"]})
    elif request_id is not None and cause == "session_start_refused":
        _failure_event(span, "guardian_error", cause)
    else:
        _failure_event(span, "handshake_failure", cause)


def new_provider() -> TracerProvider:
    """A tracer provider whose id generator can give a session's root span the session's own ids."""
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    return TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}), id_generator=_session_ids())


def build_provider(endpoint: str) -> TracerProvider:
    """A provider that batches spans to endpoint's /v1/traces. Imported here, so off never loads the SDK.

    The batch processor only queues a span on the request's path. Exports run on its own thread, so a slow or absent
    Jaeger never delays a request, and a full queue drops spans rather than waiting.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    # The exporter logs every failed batch. quiet_exporter logs once per failure window instead.
    logging.getLogger("opentelemetry.exporter.otlp.proto.http").setLevel(logging.CRITICAL + 1)
    url = traces_url(endpoint)
    provider = new_provider()
    provider.add_span_processor(BatchSpanProcessor(quiet_exporter(OTLPSpanExporter(endpoint=url), url)))
    return provider


def quiet_exporter(inner: Any, url: str) -> Any:
    """Wrap a span exporter so a failure, raised or returned, is one log line per failure window and never raises.

    A window opens on the first failure after a success, or at startup, and closes on the next success. The error
    text stays out of the log, since an exporter's message can quote a response body.
    """
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class QuietExporter(SpanExporter):
        def __init__(self) -> None:
            self._failing = False

        def export(self, spans: Any) -> SpanExportResult:
            try:
                result = inner.export(spans)
            except Exception:  # noqa: BLE001
                result = SpanExportResult.FAILURE
            if result is SpanExportResult.SUCCESS:
                self._failing = False
                return result
            if not self._failing:
                self._failing = True
                _LOG.warning("acs-gateway: span export to %s is failing, so spans are dropped until it recovers", url)
            return SpanExportResult.FAILURE

        def shutdown(self) -> None:
            try:
                inner.shutdown()
            except Exception:  # noqa: BLE001
                return

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            try:
                return bool(inner.force_flush(timeout_millis))
            except Exception:  # noqa: BLE001
                return False

    return QuietExporter()


def _session_ids() -> Any:
    """An id generator that hands out a session's own trace and root span ids once when asked, and random ids
    otherwise. The SDK asks for the trace id, then the span id, inside one start_span call on one thread."""
    from opentelemetry.sdk.trace.id_generator import RandomIdGenerator

    class SessionIds(RandomIdGenerator):
        def __init__(self) -> None:
            self._forced = threading.local()

        def force(self, trace_id: int, span_id: int) -> None:
            self._forced.ids = (trace_id, span_id)

        def clear(self) -> None:
            self._forced.ids = None

        def generate_trace_id(self) -> int:
            ids = getattr(self._forced, "ids", None)
            return ids[0] if ids else super().generate_trace_id()

        def generate_span_id(self) -> int:
            ids = getattr(self._forced, "ids", None)
            if ids:
                self._forced.ids = None
                return ids[1]
            return super().generate_span_id()

    return SessionIds()
