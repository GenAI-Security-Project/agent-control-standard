"""Tracing setup (LAB-09, issue #582): off unless OTEL_EXPORTER_OTLP_ENDPOINT is set, straight to Jaeger, never in a
request's way."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

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
