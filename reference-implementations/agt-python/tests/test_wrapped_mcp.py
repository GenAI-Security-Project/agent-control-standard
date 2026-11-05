"""Wrapped MCP: protocols/MCP/* (extend_mcp.md; the handler contract the
Go port in open PR #169 defines at internal/mcp/mcp.go)."""

from __future__ import annotations

import uuid

import pytest

from helpers import envelope, expect_decision, expect_error, handshake, signed_post

from acs_guardian import mcp
from acs_guardian.errors import INVALID_PARAMS, AcsError

MCP_VERSION = "2025-06-18"


def _mcp_request(method: str, arguments: dict, *, request_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {"name": "run", "arguments": arguments}}


def _mcp_response(request_id: int, *, result: dict | None = None, error: dict | None = None) -> dict:
    message: dict = {"jsonrpc": "2.0", "id": request_id}
    if result is not None:
        message["result"] = result
    if error is not None:
        message["error"] = error
    return message


def _wrapped_session(server, methods: list[str], *, versions: list[str] | None = None) -> str:
    session_id = str(uuid.uuid4())
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": methods,
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
            "wrapped_protocols": [{"protocol": "MCP", "version": v} for v in (versions or [MCP_VERSION])],
        },
    )
    response = signed_post(server.url, hello, session_id)
    return session_id


def test_wrapped_tools_call_is_evaluated_and_allowed(server) -> None:
    session_id = _wrapped_session(server, ["protocols/MCP/tools/call"])
    request = envelope("protocols/MCP/tools/call", session_id, _mcp_request("tools/call", {"command": "ls -la"}))
    response = signed_post(server.url, request, session_id)
    expect_decision(response, "allow", request["id"])
    assert response["result"]["chain_hash"]


def test_wrapped_tools_call_hits_the_same_destructive_rule(server) -> None:
    session_id = _wrapped_session(server, ["protocols/MCP/tools/call"])
    request = envelope("protocols/MCP/tools/call", session_id, _mcp_request("tools/call", {"command": "rm -rf /"}))
    response = signed_post(server.url, request, session_id)
    expect_decision(response, "deny", request["id"])
    assert response["result"]["reason_codes"] == ["destructive_shell_command_blocked"]


def test_a_wrapped_response_is_evaluated(server) -> None:
    session_id = _wrapped_session(server, ["protocols/MCP/tools/call"])
    request = envelope(
        "protocols/MCP/tools/call", session_id, _mcp_response(1, result={"content": [{"type": "text", "value": "ok"}]})
    )
    expect_decision(signed_post(server.url, request, session_id), "allow", request["id"])


def test_an_explicit_version_method_is_gated_by_wrapped_protocols(server) -> None:
    method = f"wrapped:mcp-{MCP_VERSION}/tools/call"
    declared = _wrapped_session(server, [method], versions=[MCP_VERSION])
    request = envelope(method, declared, _mcp_request("tools/call", {"command": "ls"}))
    expect_decision(signed_post(server.url, request, declared), "allow", request["id"])

    # A version the ClientHello never declared is not negotiated: -32003.
    undeclared = _wrapped_session(server, [method], versions=["2024-11-05"])
    request = envelope(method, undeclared, _mcp_request("tools/call", {"command": "ls"}))
    expect_error(signed_post(server.url, request, undeclared), -32003)


def test_a_wrapped_method_without_a_declared_protocol_is_not_negotiated(server) -> None:
    session_id = str(uuid.uuid4())
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["protocols/MCP/tools/call"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
            # no wrapped_protocols
        },
    )
    response = signed_post(server.url, hello, session_id)
    assert response["result"]["methods_evaluated"] == []
    request = envelope("protocols/MCP/tools/call", session_id, _mcp_request("tools/call", {"command": "ls"}))
    expect_error(signed_post(server.url, request, session_id), -32003)


def test_a_malformed_wrapped_message_is_invalid_params(server) -> None:
    session_id = _wrapped_session(server, ["protocols/MCP/tools/call"])
    request = envelope("protocols/MCP/tools/call", session_id, {"jsonrpc": "1.0", "method": "tools/call"})
    expect_error(signed_post(server.url, request, session_id), -32602)


@pytest.mark.parametrize(
    "message, expected",
    [
        ({"jsonrpc": "2.0", "method": "tools/call"}, None),  # a request without an id: a notification
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, None),
        ({"jsonrpc": "2.0", "id": "a", "method": "tools/call", "params": {"arguments": {}}}, None),
        ({"jsonrpc": "2.0", "id": 1, "result": {}}, None),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}, None),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, "wraps tools/call"),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "result": {}}, "neither result nor error"),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []}, "params must be an object"),
        ({"jsonrpc": "2.0", "id": None, "method": "tools/call"}, "id must be a string or a number"),
        ({"jsonrpc": "2.0", "result": {}}, "must carry the id"),
        ({"jsonrpc": "2.0", "id": 1}, "exactly one of result and error"),
        ({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": 1, "message": "x"}}, "exactly one of result"),
        ({"jsonrpc": "2.0", "id": 1, "result": []}, "result must be an object"),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": "x", "message": "y"}}, "integer code"),
        ({"jsonrpc": "2.0", "id": 1, "error": {"message": "y"}}, "integer code"),
        ({"jsonrpc": "1.0", "id": 1, "method": "tools/call"}, 'jsonrpc "2.0"'),
        ("not an object", "must be an object"),
    ],
)
def test_the_wrapped_message_rules(message, expected) -> None:
    if expected is None:
        assert mcp.read("tools/call", message) == message
    else:
        with pytest.raises(AcsError) as caught:
            mcp.read("tools/call", message)
        assert caught.value.code == INVALID_PARAMS
        assert expected in caught.value.message


def test_mcp_supports_well_formed_method_names_only() -> None:
    assert mcp.supports("tools/call")
    assert mcp.supports("notifications/resources/list_changed")
    assert not mcp.supports("tools//call")
    assert not mcp.supports("tools/call/")
    assert not mcp.supports("")
