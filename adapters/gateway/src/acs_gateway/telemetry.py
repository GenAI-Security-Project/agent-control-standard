"""OpenTelemetry spans for the gateway (LAB-09, issue #582): one trace per ACS session, exported over OTLP HTTP.

Off unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Off, every method returns at once and nothing from opentelemetry is
imported, so the gateway behaves exactly as it does without this module. On, spans go straight to the endpoint's
/v1/traces, Jaeger's OTLP HTTP port in the lab, with no collector between them (PREMORTEM P22).

The gateway's tracer provider is its own and never the process-wide one, so nothing else in the process starts
exporting because the gateway does.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from acs_gateway.config import GatewayConfig

SERVICE_NAME = "acs-gateway"
TRACES_PATH = "/v1/traces"


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


def build_provider(endpoint: str) -> TracerProvider:
    """A provider that batches spans to endpoint's /v1/traces. Imported here, so off never loads the SDK."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}), id_generator=_session_ids())
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=traces_url(endpoint))))
    return provider


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
