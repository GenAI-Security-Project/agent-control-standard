"""Tracing setup (LAB-09, issue #582): off unless OTEL_EXPORTER_OTLP_ENDPOINT is set, straight to Jaeger, never in a
request's way."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import uuid
from typing import Any

import pytest

from acs_gateway.config import GatewayConfig


def test_tracing_is_off_without_an_endpoint():
    from acs_gateway.telemetry import Tracing

    config = GatewayConfig.from_env({})
    assert config.otlp_endpoint is None
    assert Tracing.from_config(config).enabled is False


def test_off_imports_no_opentelemetry_and_answers_a_governed_request(guardian, upstream):
    # A fresh interpreter, so no other test's import hides one this path makes.
    script = f"""
import json, os, sys
from starlette.testclient import TestClient
from acs_gateway.app import create_app
from acs_gateway.config import GatewayConfig
env = {{"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": {guardian!r}, "ACS_UPSTREAM_URL": {upstream.url!r},
       "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"], "ACS_GUARDIAN_READY_TIMEOUT_S": "5"}}
body = {{"model": "gpt-5-nano", "input": [{{"role": "user", "content": "hi"}}]}}
with TestClient(create_app(GatewayConfig.from_env(env))) as client:
    status = client.post("/v1/responses", json=body).status_code
print(json.dumps({{"status": status, "otel": sorted(m for m in sys.modules if m.startswith("opentelemetry"))}}))
"""
    env = {k: v for k, v in os.environ.items() if k != "OTEL_EXPORTER_OTLP_ENDPOINT"}
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, check=True)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result == {"status": 200, "otel": []}


@pytest.mark.parametrize("value", ["ftp://jaeger:4318", "jaeger:4318", "http://", "http://jaeger:4318?x=1"])
def test_a_bad_endpoint_stops_startup(value):
    with pytest.raises(ValueError, match="OTEL_EXPORTER_OTLP_ENDPOINT"):
        GatewayConfig.from_env({"OTEL_EXPORTER_OTLP_ENDPOINT": value})


@pytest.mark.parametrize("value", ["http://jaeger:4318", "http://jaeger:4318/", " https://jaeger:4318/ "])
def test_the_endpoint_exports_to_v1_traces(value):
    from acs_gateway.telemetry import traces_url

    config = GatewayConfig.from_env({"OTEL_EXPORTER_OTLP_ENDPOINT": value})
    assert traces_url(config.otlp_endpoint) == value.strip().rstrip("/") + "/v1/traces"


def test_an_endpoint_builds_a_live_tracer_of_its_own():
    from opentelemetry import trace

    from acs_gateway.telemetry import Tracing

    tracing = Tracing.from_config(GatewayConfig.from_env({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9"}))
    try:
        assert tracing.enabled is True
        # The gateway's provider is its own, so nothing else in the process starts exporting.
        assert not isinstance(trace.get_tracer_provider(), type(tracing.provider))
    finally:
        tracing.shutdown()


def test_a_session_trace_id_is_its_session_id():
    from acs_gateway.telemetry import session_root_span_id, session_trace_id

    session_id = str(uuid.uuid4())
    assert session_trace_id(session_id) == uuid.UUID(session_id).int
    assert session_root_span_id(session_id) == session_root_span_id(session_id) != 0
    assert session_root_span_id(session_id) != session_root_span_id(str(uuid.uuid4()))


def test_a_failing_exporter_never_touches_a_request_and_logs_once(gateway, upstream, caplog, monkeypatch):
    from conftest import finbot_request, message_item, response_body

    # Nothing listens on port 9, so every export fails. A short timeout keeps the flush quick.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1")
    client = gateway(OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:9")
    tracing = client.app.state.gateway.tracing
    assert tracing.enabled
    try:
        with caplog.at_level(logging.DEBUG):
            for _ in range(2):
                for _ in range(3):
                    response = client.post("/v1/responses", json=finbot_request())
                    assert response.status_code == 200
                    assert response.json() == response_body(message_item("ok"))
                assert tracing.provider.force_flush(10_000)
    finally:
        tracing.shutdown()
    failing = [r for r in caplog.records if r.name == "acs_gateway.telemetry"]
    assert [r.getMessage() for r in failing] == [
        "acs-gateway: span export to http://127.0.0.1:9/v1/traces is failing, so spans are dropped until it recovers"]
    assert not [r for r in caplog.records if r.name.startswith("opentelemetry") and r.levelno >= logging.WARNING]


def test_export_failures_log_once_per_window_and_never_raise(caplog):
    from opentelemetry.sdk.trace.export import SpanExportResult

    from acs_gateway.telemetry import quiet_exporter

    results: list[Any] = [SpanExportResult.FAILURE, RuntimeError("boom"), SpanExportResult.SUCCESS,
                          RuntimeError("boom"), SpanExportResult.FAILURE]

    class Flaky:
        def export(self, spans):
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        def shutdown(self):
            return None

        def force_flush(self, timeout_millis=30000):
            return True

    exporter = quiet_exporter(Flaky(), "http://jaeger:4318/v1/traces")
    with caplog.at_level(logging.DEBUG, logger="acs_gateway.telemetry"):
        outcomes = [exporter.export([]) for _ in range(5)]
    assert outcomes == [SpanExportResult.FAILURE, SpanExportResult.FAILURE, SpanExportResult.SUCCESS,
                        SpanExportResult.FAILURE, SpanExportResult.FAILURE]
    assert len([r for r in caplog.records if r.name == "acs_gateway.telemetry"]) == 2
    assert "boom" not in caplog.text
