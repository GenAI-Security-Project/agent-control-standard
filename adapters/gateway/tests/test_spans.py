"""The spans the gateway emits (LAB-09, issue #582), read from an in-memory exporter."""
from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan

from conftest import SSE, call_item, finbot_request, message_item, response_body, sse_events, transcript_lines


def traced(client: Any) -> Callable[[], list[ReadableSpan]]:
    """Swap the gateway's tracing for one that keeps finished spans in memory, and return a reader for them."""
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from acs_gateway.telemetry import Tracing, new_provider

    gateway = client.app.state.gateway
    exporter = InMemorySpanExporter()
    provider = new_provider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    gateway.tracing = Tracing(provider, gateway.config.mode)
    return lambda: list(exporter.get_finished_spans())


def named(spans: list[ReadableSpan], name: str) -> list[ReadableSpan]:
    return [s for s in spans if s.name == name]


def test_each_session_is_one_trace_named_by_its_session_id(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    spans = traced(client)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    upstream.reply(response_body(message_item("hello")))
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    assert client.post("/v1/responses", json=finbot_request(user="Another task")).status_code == 200
    opened = [e["session_id"] for e in audit() if e["acs_audit_event"] == "session_opened"]
    assert len(opened) == 2
    for session_id in opened:
        trace = [s for s in spans() if s.context.trace_id == uuid.UUID(session_id).int]
        roots = named(trace, "acs.session")
        assert len(roots) == 1 and roots[0].parent is None
        root = roots[0]
        assert root.attributes["acs.session.id"] == session_id
        assert root.attributes["gen_ai.operation.name"] == "invoke_agent"
        assert isinstance(root.attributes["acs.request_id"], str)
        children = [s for s in trace if s is not root]
        assert children and all(s.parent.span_id == root.context.span_id for s in children)
        assert len(named(trace, "chat gpt-5-nano")) == 1
    assert len(step_spans(spans())) == 1
    first = [s for s in spans() if s.context.trace_id == uuid.UUID(opened[0]).int]
    model = named(first, "chat gpt-5-nano")[0]
    assert model.attributes["gen_ai.operation.name"] == "chat"
    assert model.attributes["gen_ai.provider.name"] == "openai"
    assert model.attributes["gen_ai.request.model"] == "gpt-5-nano"
    assert model.attributes["acs.session.id"] == opened[0]
    assert model.attributes["acs.lab.mode"] == "enforce"
    assert model.attributes["http.response.status_code"] == 200


def test_a_streamed_call_is_spanned_in_its_session(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian)
    spans = traced(client)
    upstream.reply(SSE(sse_events("hello")))
    response = client.post("/v1/responses", json={**finbot_request(), "stream": True})
    assert response.status_code == 200
    session_id = next(e["session_id"] for e in audit() if e["acs_audit_event"] == "session_opened")
    model = named(spans(), "chat gpt-5-nano")
    assert len(model) == 1
    assert model[0].context.trace_id == uuid.UUID(session_id).int
    assert model[0].attributes["acs.lab.stream"] is True
    assert model[0].attributes["acs.lab.mode"] == "shadow"


def test_off_mode_spans_each_model_call_without_a_session(gateway, upstream):
    client = gateway()
    spans = traced(client)
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    (model,) = spans()
    assert model.name == "chat gpt-5-nano"
    assert model.parent is None
    assert "acs.session.id" not in model.attributes
    assert model.attributes["acs.lab.mode"] == "off"
    assert model.attributes["gen_ai.operation.name"] == "chat"


def test_an_unreachable_upstream_ends_the_model_span_in_error(gateway):
    from opentelemetry.trace import StatusCode

    client = gateway(ACS_UPSTREAM_URL="http://127.0.0.1:9/v1")
    spans = traced(client)
    assert client.post("/v1/responses", json=finbot_request()).status_code == 502
    (model,) = spans()
    assert model.status.status_code == StatusCode.ERROR
    assert model.attributes["error.type"] == "ConnectError"
    assert not model.events


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_failed_handshake_is_a_failure_event_on_the_session_span(gateway, harness_guardian, upstream, audit, mode):
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=harness_guardian(HARNESS_FAIL_HELLOS="5"))
    spans = traced(client)
    client.post("/v1/responses", json=finbot_request())
    (root,) = named(spans(), "acs.session")
    (event,) = [e for e in root.events if e.name == "acs.decision.failure"]
    assert event.attributes["acs.failure.class"] == "handshake_failure"
    assert event.attributes["acs.failure.posture"] == "fail_closed"
    assert event.attributes["acs.failure.reported_by"] == "observed_agent"


MAPPING = Path(__file__).resolve().parents[3] / "specification" / "v0.1.0" / "trace" / "otel-mapping.json"


def step_spans(spans: list[ReadableSpan]) -> list[ReadableSpan]:
    return [s for s in spans if s.name in ("gen_ai.tool.call", "gen_ai.tool.result")]


def test_step_span_names_and_required_attributes_match_the_mapping(gateway, harness_guardian, upstream, tmp_path):
    from acs_gateway.telemetry import DECISION_EVENT, FAILURE_EVENT, SESSION_SPAN, STEP_SPANS

    mapping = json.loads(MAPPING.read_text())["properties"]
    steps = mapping["step_to_span"]["default"]
    every_step = mapping["step_span_attributes"]["properties"]["required_attributes"]["default"]
    assert SESSION_SPAN == steps["steps/sessionStart"]["span_name"]
    assert DECISION_EVENT == mapping["decision_event"]["properties"]["event_name"]["const"]
    assert FAILURE_EVENT == mapping["decision_failure_event"]["properties"]["event_name"]["const"]
    for method, name in STEP_SPANS.items():
        assert name == steps[method]["span_name"]

    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    spans = traced(client)
    client.post("/v1/responses", json=finbot_request())
    result = {"type": "function_call_output", "call_id": "call_1", "output": json.dumps({"name": "Acme"})}
    client.post("/v1/responses", json=finbot_request(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
                                                     result))
    finished = spans()
    by_method = {"steps/toolCallRequest": named(finished, "gen_ai.tool.call"),
                 "steps/toolCallResult": named(finished, "gen_ai.tool.result")}
    requests = {line["envelope"]["params"]["request_id"]: line["envelope"]["params"]
                for line in transcript_lines(tmp_path) if line["dir"] == "req"}
    for method, found in by_method.items():
        assert len(found) == 1, method
        span = found[0]
        for attribute in [*steps[method]["required_attributes"], *every_step, "gen_ai.operation.name"]:
            assert attribute in span.attributes, (method, attribute)
        sent = requests[span.attributes["acs.request_id"]]
        assert sent["metadata"]["session_id"] == span.attributes["acs.session.id"]
        assert span.attributes["gen_ai.operation.name"] == "execute_tool"
        assert span.attributes["gen_ai.tool.name"] == "get_vendor_details"
        decision = [e for e in span.events if e.name == "acs.decision"]
        assert len(decision) == 1 and decision[0].attributes["acs.decision"] == span.attributes["acs.decision"]
    result_span = by_method["steps/toolCallResult"][0]
    request_span = by_method["steps/toolCallRequest"][0]
    assert result_span.attributes["acs.exit_status"] == "success"
    assert result_span.attributes["acs.request_id_ref"] == request_span.attributes["acs.request_id"]
    assert result_span.attributes["acs.decision"] == "modify"
    assert list(result_span.events[0].attributes["acs.reason_codes"]) == ["sensitive_field_redacted"]
    assert "acs.request_id_ref" not in request_span.attributes


def test_a_deny_records_the_decision_and_reason_codes(gateway, harness_guardian, upstream):
    upstream.reply(response_body(message_item("done")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    spans = traced(client)
    result = {"type": "function_call_output", "call_id": "call_1", "output": "leaked"}
    client.post("/v1/responses", json=finbot_request(call_item("leaky_tool", {}, "call_1"), result))
    (span,) = step_spans(spans())
    assert span.name == "gen_ai.tool.result"
    (event,) = span.events
    assert event.name == "acs.decision"
    assert event.attributes["acs.decision"] == "deny"
    assert list(event.attributes["acs.reason_codes"]) == ["leak_blocked"]
    assert "acs.lab.shadow_decision" not in span.attributes


@pytest.mark.parametrize("tool,failure_class", [
    ("slow_tool", "timeout"),
    ("rate_limited_tool", None),
    ("tampered_tool", "signature_invalid"),
])
def test_a_step_without_a_decision_records_a_failure_event(gateway, harness_guardian, upstream, audit, tool,
                                                           failure_class):
    upstream.reply(response_body(call_item(tool, {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(), ACS_DECISION_TIMEOUT_MS="500")
    spans = traced(client)
    client.post("/v1/responses", json=finbot_request())
    applied = next(e for e in audit() if e["acs_audit_event"] == "decision_applied")
    (span,) = step_spans(spans())
    assert span.attributes["acs.request_id"] == applied["request_id"]
    assert "acs.decision" not in span.attributes
    (event,) = span.events
    assert event.name == "acs.decision.failure"
    assert event.attributes["acs.failure.posture"] == "fail_closed"
    assert event.attributes["acs.failure.reported_by"] == "observed_agent"
    expected = failure_class or applied["failure_class"]
    if expected in ("timeout", "unreachable", "malformed_response", "guardian_error", "observed_agent_error",
                    "signature_invalid", "handshake_failure"):
        assert event.attributes["acs.failure.class"] == expected
    else:
        assert event.attributes["acs.failure.class"] == "other"
        assert event.attributes["acs.failure.detail"] == f"gateway cause {applied['cause']}"


def test_shadow_marks_the_shadow_decision(gateway, harness_guardian, upstream):
    upstream.reply(response_body(message_item("done")))
    client = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=harness_guardian())
    spans = traced(client)
    result = {"type": "function_call_output", "call_id": "call_1", "output": "leaked"}
    client.post("/v1/responses", json=finbot_request(call_item("leaky_tool", {}, "call_1"), result))
    (span,) = step_spans(spans())
    assert span.attributes["acs.lab.shadow_decision"] == "deny"
    assert span.attributes["acs.lab.mode"] == "shadow"


def test_no_body_argument_output_or_secret_reaches_a_span(gateway, harness_guardian, upstream):
    marker = "zz-sentinel-7f3a"
    upstream.reply(response_body(call_item("override_tool", {"to": f"{marker}-arg@example.com"}, "call_1"),
                                 message_item(f"{marker}-reply")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    spans = traced(client)
    headers = {"authorization": f"Bearer sk-{marker}-key"}
    client.post("/v1/responses", json=finbot_request(user=f"{marker}-user"), headers=headers)
    result = {"type": "function_call_output", "call_id": "call_1", "output": f"{marker}-output"}
    client.post("/v1/responses", json=finbot_request(call_item("override_tool", {"to": "ops@ns1.finbot"}, "call_1"),
                                                     result, user=f"{marker}-user"), headers=headers)
    finished = spans()
    assert step_spans(finished)
    secret = os.environ["ACS_HMAC_SECRET"]
    dumped = json.dumps([json.loads(s.to_json()) for s in finished])
    assert marker not in dumped
    assert secret not in dumped
    assert '"value"' not in dumped and "signature" not in dumped


@pytest.mark.parametrize("choice,outcome,decision", [("approve", "approved", "allow"), (None, "timed_out", "deny")])
def test_an_ask_resolution_is_a_span_event(gateway, harness_guardian, upstream, audit, tmp_path, choice, outcome,
                                           decision):
    from test_ask import approver, enforce

    upstream.reply(response_body(call_item("ask_tool", {"vendor_id": 7}, "call_1")))
    env = {} if choice else {"HARNESS_ASK_TIMEOUT_S": "1"}
    client = enforce(gateway, harness_guardian, tmp_path, **env)
    spans = traced(client)
    thread = approver(client, choice) if choice else None
    client.post("/v1/responses", json=finbot_request())
    if thread:
        thread.join()
    resolved = next(e for e in audit() if e["acs_audit_event"] == "ask_resolved")
    (hold,) = named(spans(), "acs.lab.ask")
    assert hold.context.trace_id == uuid.UUID(resolved["session_id"]).int
    assert hold.attributes["gen_ai.operation.name"] == "acs.lab.ask_hold"
    (event,) = hold.events
    assert event.name == "acs.lab.ask_resolved"
    assert event.attributes["acs.lab.ask.outcome"] == outcome
    assert event.attributes["acs.lab.ask.decision"] == decision
    assert event.attributes["acs.lab.ask.ask_request_id"] == resolved["ask_request_id"]
    assert event.attributes["acs.lab.ask.call_id"] == "call_1"
    assert (hold.end_time - hold.start_time) / 1e9 == pytest.approx(resolved["waited_s"], abs=0.05)
    assert "Approve?" not in json.dumps(json.loads(hold.to_json()))
    # The ASK itself and, after an approval, the resend are each their own step span.
    assert len(step_spans(spans())) == (2 if choice else 1)


def test_a_replay_miss_is_an_event_on_the_model_call_span(gateway, upstream):
    import httpx

    from acs_gateway.telemetry import replay_miss

    class MissingReplay(httpx.AsyncBaseTransport):
        """Stands in for LAB-06's ReplayTransport, which calls replay_miss when no recording fits."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            replay_miss(cause="no_recording", step=2, branch="a,d", stream=False, scenario=None)
            raw = json.dumps(response_body(message_item("I couldn't complete that action."))).encode()
            # Unread, as a network transport returns it, since off mode relays the raw stream.
            return httpx.Response(200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(raw))

    client = gateway()
    spans = traced(client)
    gateway_app = client.app.state.gateway
    original = gateway_app.http
    gateway_app.http = httpx.AsyncClient(transport=MissingReplay())
    try:
        assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    finally:
        gateway_app.http = original
    (model,) = spans()
    (event,) = model.events
    assert event.name == "acs.lab.replay_miss"
    assert dict(event.attributes) == {"acs.lab.replay.cause": "no_recording", "acs.lab.replay.step": 2,
                                      "acs.lab.replay.branch": "a,d", "acs.lab.replay.stream": False}


def test_a_replay_miss_outside_a_model_call_does_nothing():
    from acs_gateway.telemetry import replay_miss

    replay_miss(cause="no_recording", step=0, branch="", stream=False)


def test_a_fault_in_span_making_never_touches_a_request(gateway, harness_guardian, upstream, audit, caplog):
    import logging

    from acs_gateway.telemetry import Tracing, new_provider

    class Broken:
        def start_span(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("tracer broke")

    reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"))
    upstream.reply(reply)
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    tracing = Tracing(new_provider(), "enforce")
    tracing._tracer = Broken()
    client.app.state.gateway.tracing = tracing
    with caplog.at_level(logging.DEBUG, logger="acs_gateway.telemetry"):
        response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 200 and response.json() == reply
    assert not [e for e in audit() if e["acs_audit_event"] == "gateway_step_error"]
    assert len([r for r in caplog.records if r.name == "acs_gateway.telemetry"]) == 1


def _app(upstream: Any, **env: str) -> Any:
    from acs_gateway.app import create_app
    from acs_gateway.config import GatewayConfig

    base = {"ACS_UPSTREAM_URL": upstream.url, "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"]}
    return create_app(GatewayConfig.from_env({**base, **env}))


def test_shutdown_flushes_queued_spans(upstream):
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from starlette.testclient import TestClient

    from acs_gateway.telemetry import Tracing, new_provider

    app = _app(upstream)
    exporter = InMemorySpanExporter()
    provider = new_provider()
    # A long delay, so only the shutdown's flush can export the span.
    provider.add_span_processor(BatchSpanProcessor(exporter, schedule_delay_millis=600_000))
    app.state.gateway.tracing = Tracing(provider, "off")
    with TestClient(app) as client:
        assert client.post("/v1/responses", json=finbot_request()).status_code == 200
        assert exporter.get_finished_spans() == ()
    assert [s.name for s in exporter.get_finished_spans()] == ["chat gpt-5-nano"]


def test_a_hung_exporter_delays_exit_by_at_most_the_bound(upstream):
    import time

    from opentelemetry.sdk.trace import SpanProcessor
    from starlette.testclient import TestClient

    from acs_gateway.app import TRACING_CLOSE_S
    from acs_gateway.telemetry import Tracing, new_provider

    class Hung(SpanProcessor):
        def shutdown(self) -> None:
            time.sleep(30)

    app = _app(upstream)
    provider = new_provider()
    provider.add_span_processor(Hung())
    app.state.gateway.tracing = Tracing(provider, "off")
    with TestClient(app):
        started = time.monotonic()
    assert TRACING_CLOSE_S == 2.0
    assert time.monotonic() - started < TRACING_CLOSE_S + 1.0


def test_a_cancelled_open_still_records_the_session_root(tmp_path):
    import asyncio
    import time
    from concurrent.futures import ThreadPoolExecutor

    from acs.client import Negotiated

    from acs_gateway.app import Gateway
    from acs_gateway.config import GatewayConfig
    from acs_gateway.sessions import Session

    gateway = Gateway(GatewayConfig.from_env({"ACS_LAB_MODE": "enforce",
                                              "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"]}))
    spans = traced(type("Client", (), {"app": type("App", (), {"state": type("S", (), {"gateway": gateway})})})())

    class SlowGuardian:
        def open(self, session: Session) -> str:
            time.sleep(0.3)
            session.handshake = Negotiated({})
            return "11111111-1111-4111-8111-111111111111"

    gateway.guardian = SlowGuardian()
    gateway.executor = ThreadPoolExecutor(max_workers=1)
    session = Session(session_id=str(uuid.uuid4()), epoch=0)

    async def cancel_while_opening() -> None:
        task = asyncio.ensure_future(gateway._ensure_open(session))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_while_opening())
    gateway.executor.shutdown(wait=True)
    (root,) = named(spans(), "acs.session")
    assert root.context.trace_id == uuid.UUID(session.session_id).int
    assert root.attributes["acs.request_id"] == "11111111-1111-4111-8111-111111111111"


def test_an_unsigned_step_claims_no_request_id(gateway, guardian, upstream, audit):
    upstream.reply(response_body(call_item("get_vendor_details", '{"amount": NaN}', "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    spans = traced(client)
    client.post("/v1/responses", json=finbot_request())
    assert next(e for e in audit() if e["acs_audit_event"] == "decision_applied")["cause"] == "envelope_not_signable"
    (span,) = step_spans(spans())
    assert "acs.request_id" not in span.attributes
    assert [e.name for e in span.events] == ["acs.decision.failure"]


def test_a_cancelled_token_step_is_not_sent(guardian, tmp_path):
    from acs_gateway.config import GatewayConfig
    from acs_gateway.guardian import TOOL_CALL_REQUEST, GuardianClient, StepToken
    from acs_gateway.sessions import Session
    from acs_gateway.transcript import Transcript

    client = GuardianClient(GatewayConfig.from_env({"ACS_GUARDIAN_URL": guardian, "ACS_LAB_MODE": "enforce"}),
                            Transcript(tmp_path / "t"))
    session = Session(session_id=str(uuid.uuid4()), epoch=0)
    client.open(session)
    token = StepToken(float("inf"))
    assert token.cancel()
    result = client.step(session, TOOL_CALL_REQUEST, {"tool": {"name": "x"}, "arguments": {}}, token)
    assert result.sent is False
    sent = client.step(session, TOOL_CALL_REQUEST, {"tool": {"name": "x"}, "arguments": {}})
    assert sent.sent is True and sent.request_id


@pytest.mark.parametrize("mode", ["off", "enforce"])
def test_a_processor_fault_on_end_never_touches_a_relayed_answer(gateway, guardian, upstream, mode):
    from opentelemetry.sdk.trace import SpanProcessor

    from acs_gateway.telemetry import Tracing, new_provider

    class Raising(SpanProcessor):
        def on_end(self, span: Any) -> None:
            raise RuntimeError("processor broke")

    reply = response_body(message_item("relayed"))
    upstream.reply(reply)
    env = {"ACS_LAB_MODE": mode, "ACS_GUARDIAN_URL": guardian} if mode != "off" else {}
    client = gateway(**env)
    provider = new_provider()
    provider.add_span_processor(Raising())
    client.app.state.gateway.tracing = Tracing(provider, mode)
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 200 and response.json() == reply


def test_the_ask_hold_is_not_counted_as_a_tool_call(gateway, harness_guardian, upstream, audit, tmp_path):
    from test_ask import approver, enforce

    upstream.reply(response_body(call_item("ask_tool", {"vendor_id": 7}, "call_1")))
    client = enforce(gateway, harness_guardian, tmp_path)
    spans = traced(client)
    thread = approver(client, "approve")
    client.post("/v1/responses", json=finbot_request())
    thread.join()
    (hold,) = named(spans(), "acs.lab.ask")
    assert hold.attributes["gen_ai.operation.name"] == "acs.lab.ask_hold"
    assert "gen_ai.tool.name" not in hold.attributes
    assert hold.attributes["acs.lab.ask.tool"] == "ask_tool"


def test_the_verbatim_relay_parses_the_body_once(gateway, upstream, monkeypatch):
    import acs_gateway.app as app_module

    client = gateway(ACS_MODEL_INPUT_LOG=os.environ.get("ACS_GATEWAY_STATE_DIR", "") + "/model-inputs-once.jsonl")
    traced(client)
    calls: list[bytes] = []
    real = app_module._parse

    def counting(raw: bytes) -> Any:
        calls.append(raw)
        return real(raw)

    monkeypatch.setattr(app_module, "_parse", counting)
    assert client.post("/v1/responses", json=finbot_request()).status_code == 200
    assert len(calls) == 1


def test_an_answer_handed_back_late_keeps_its_request_id(gateway, guardian, upstream, audit, monkeypatch):
    """The Guardian answered in time and the worker handed the answer back after the deadline. The step still names the
    request the Guardian received, so the span joins the decision_applied line (rehearsal R4)."""
    from acs_gateway import guardian as g

    real = g.GuardianClient.step

    def late(self, session, method, payload, token=None):
        result = real(self, session, method, payload, token)
        if token is not None and method == "steps/toolCallRequest":
            time.sleep(max(0.0, token.deadline - time.monotonic()) + 0.05)
        return result

    monkeypatch.setattr(g.GuardianClient, "step", late)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_DECISION_TIMEOUT_MS="500")
    spans = traced(client)
    client.post("/v1/responses", json=finbot_request())
    applied = next(e for e in audit() if e["acs_audit_event"] == "decision_applied")
    assert applied["cause"] == "decision_timeout" and applied["request_id"]
    (span,) = step_spans(spans())
    assert span.attributes.get("acs.request_id") == applied["request_id"]
