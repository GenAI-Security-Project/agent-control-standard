# SPDX-License-Identifier: Apache-2.0
"""Tests for the Python Guardian + FastMCP sample (stdlib only).

Run:  python -m pytest samples/python-guardian-fastmcp -q
No third-party dependencies: HTTP via urllib, fake inner client,
async tests driven by asyncio.run (no plugin needed).
"""

import asyncio
import json
import threading
import urllib.request

import pytest

from guardian import Guardian, _KNOWN_METHODS, serve
from fastmcp_instrumentation import (
    GovernedClient,
    GovernedDenied,
    build_tool_call_envelope,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def live(tmp_path):
    server = serve(0, log_path=str(tmp_path / "env.jsonl"))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    thread.join(timeout=5)


def _post(url, envelope):
    req = urllib.request.Request(
        url + "/acs", data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _env(method, payload=None, session="11111111-2222-4333-8444-555555555555"):
    return {
        "jsonrpc": "2.0", "method": method, "id": 7,
        "params": {
            "acs_version": "0.1.0",
            "request_id": "22222222-3333-4444-8555-666666666666",
            "timestamp": "2026-09-10T00:00:00+00:00",
            "metadata": {"agent_id": "a", "session_id": session},
            "payload": payload or {},
        },
    }


def test_handshake(live):
    out = _post(live, _env("handshake/hello"))
    hello = out["result"]
    assert hello["negotiated_version"] == "0.1.0"
    assert hello["on_decision_failure"] == "deny"
    assert "steps/toolCallRequest" in hello["methods_evaluated"]


def test_ping_allows_without_chain_advance(live, tmp_path):
    out = _post(live, _env("system/ping", {"echo": "hi"}))
    assert out["result"]["decision"] == "allow"


def test_allow_and_deny(live):
    ok = _post(live, _env("steps/toolCallRequest",
                           {"tool": {"name": "search_web"},
                            "arguments": {"q": {"value": "x"}}}))
    assert ok["result"]["decision"] == "allow"
    no = _post(live, _env("steps/toolCallRequest",
                           {"tool": {"name": "delete_volume"},
                            "arguments": {}}))
    assert no["result"]["decision"] == "deny"
    assert no["result"]["reasoning"]  # reasoning REQUIRED on deny


def test_path_escape_denies(live):
    out = _post(live, _env("steps/toolCallRequest",
                            {"tool": {"name": "read_file"},
                             "arguments": {"path": {"value": "../../etc/passwd"}}}))
    assert out["result"]["decision"] == "deny"


def test_unknown_method_is_error_not_allow(live):
    out = _post(live, _env("steps/mindControl"))
    assert "error" in out and out["error"]["code"] == -32601


def test_version_mismatch_is_error(live):
    env = _env("system/ping")
    env["params"]["acs_version"] = "9.9.9"
    out = _post(live, env)
    assert "error" in out


def test_policy_exception_denies():
    def boom(tool, args, ctx):
        raise RuntimeError("policy blew up")

    g = Guardian(policy=boom)
    out = g.handle(_env("steps/toolCallRequest",
                        {"tool": {"name": "t"}, "arguments": {}}))
    assert out["result"]["decision"] == "deny"


def test_unknown_verdict_denies():
    g = Guardian(policy=lambda t, a, c: ("maybe", "shrugging"))
    out = g.handle(_env("steps/toolCallRequest",
                        {"tool": {"name": "t"}, "arguments": {}}))
    assert out["result"]["decision"] == "deny"


def test_known_methods_cover_sample_surface():
    assert {"handshake/hello", "system/ping", "steps/toolCallRequest"} <= _KNOWN_METHODS


class _FakeInner:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True}


def _governed(inner, monkeypatch, decision, reasoning="nope"):
    import fastmcp_instrumentation as fmi

    # NOTE: post_envelope is sync in production; the fake stays sync.
    def fake_post(url, envelope):
        return {"jsonrpc": "2.0", "id": 1,
                "result": {"type": "final", "acs_version": "0.1.0",
                           "request_id": "r", "decision": decision,
                           "reasoning": reasoning}}

    monkeypatch.setattr(fmi, "post_envelope", fake_post)
    return GovernedClient(inner, "http://guardian.invalid")


def test_governed_allow_calls_through(monkeypatch):
    inner = _FakeInner()
    governed = _governed(inner, monkeypatch, "allow")
    out = _run(governed.call_tool("search", {"q": "x"}))
    assert out == {"ok": True}
    assert inner.calls == [("search", {"q": "x"})]


def test_governed_deny_never_calls(monkeypatch):
    inner = _FakeInner()
    governed = _governed(inner, monkeypatch, "deny")
    with pytest.raises(GovernedDenied):
        _run(governed.call_tool("delete_volume", {}))
    assert inner.calls == []  # tool never ran


def test_governed_modify_ask_defer_deny_closed(monkeypatch):
    for verdict in ("modify", "ask", "defer"):
        inner = _FakeInner()
        governed = _governed(inner, monkeypatch, verdict)
        with pytest.raises(GovernedDenied):
            _run(governed.call_tool("t", {}))
        assert inner.calls == []


def test_governed_unreachable_denies(monkeypatch):
    import fastmcp_instrumentation as fmi

    def dead(url, envelope):
        raise ConnectionError("no route")

    monkeypatch.setattr(fmi, "post_envelope", dead)
    inner = _FakeInner()
    with pytest.raises(GovernedDenied, match="unreachable"):
        _run(GovernedClient(inner, "http://guardian.invalid").call_tool("t", {}))


def test_envelope_builder_shape():
    env = build_tool_call_envelope("t", {"a": 1}, "agent-9", "session-1")
    assert env["method"] == "steps/toolCallRequest"
    assert env["params"]["metadata"]["agent_id"] == "agent-9"
    assert env["params"]["payload"]["tool"] == {"name": "t"}
    # ACS v0.1 wraps each argument so provenance can attach per argument.
    assert env["params"]["payload"]["arguments"] == {"a": {"value": 1}}


def test_raw_arguments_are_rejected(live):
    """A scalar argument is not the ACS shape, and must not reach the policy."""
    out = _post(live, _env("steps/toolCallRequest",
                            {"tool": {"name": "search_web"},
                             "arguments": {"q": "x"}}))
    assert "error" in out and out["error"]["code"] == -32600
    assert "value" in out["error"]["message"]


def test_policy_receives_unwrapped_values():
    seen = {}

    def spy(tool, args, ctx):
        seen.update(args)
        return "allow", "ok"

    g = Guardian(policy=spy)
    g.handle(_env("steps/toolCallRequest",
                  {"tool": {"name": "t"},
                   "arguments": {"path": {"value": "/tmp/x"}}}))
    assert seen == {"path": "/tmp/x"}


def test_reason_codes_reach_the_result(live):
    out = _post(live, _env("steps/toolCallRequest",
                            {"tool": {"name": "delete_volume"},
                             "arguments": {}}))
    assert out["result"]["reason_codes"] == ["destructive_tool"]
