"""One session's trace in a real Jaeger, straight to its OTLP HTTP port with no collector (LAB-09, PREMORTEM P22).

Skipped unless ACS_TEST_JAEGER_OTLP names Jaeger's OTLP HTTP base URL, such as http://127.0.0.1:4318. Its query API is
read from ACS_TEST_JAEGER_QUERY, http://127.0.0.1:16686 by default. CI runs no Jaeger, so CI skips it.
"""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest

from conftest import call_item, finbot_request, response_body

OTLP = os.environ.get("ACS_TEST_JAEGER_OTLP", "").strip()
QUERY = os.environ.get("ACS_TEST_JAEGER_QUERY", "").strip() or "http://127.0.0.1:16686"

pytestmark = pytest.mark.skipif(not OTLP, reason="ACS_TEST_JAEGER_OTLP is not set, so no Jaeger to export to")


def test_one_session_is_one_jaeger_trace(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, OTEL_EXPORTER_OTLP_ENDPOINT=OTLP)
    tracing = client.app.state.gateway.tracing
    try:
        assert client.post("/v1/responses", json=finbot_request()).status_code == 200
        assert tracing.provider.force_flush(10_000)
    finally:
        tracing.close(10.0)
    session_id = next(e["session_id"] for e in audit() if e["acs_audit_event"] == "session_opened")
    trace_id = uuid.UUID(session_id).hex
    names: set[str] = set()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not {"acs.session", "chat gpt-5-nano", "gen_ai.tool.call"} <= names:
        answer = httpx.get(f"{QUERY}/api/traces/{trace_id}", timeout=5)
        if answer.status_code == 200:
            spans = [s for t in answer.json().get("data") or [] for s in t["spans"]]
            names = {s["operationName"] for s in spans}
            decided = [s for s in spans if s["operationName"] == "gen_ai.tool.call"]
        time.sleep(0.5)
    assert {"acs.session", "chat gpt-5-nano", "gen_ai.tool.call"} <= names
    events = [field["value"] for log in decided[0]["logs"] for field in log["fields"] if field["key"] == "event"]
    assert "acs.decision" in events
