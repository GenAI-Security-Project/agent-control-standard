"""The external conformance probes, ported from the harness.

``packages/conformance/src/external-guardian.ts`` in the Go port's #169 runs
ten black-box probes against a live Guardian: envelope refusal, pre-session
refusal, transport refusal, a full handshake, an allowed call, replay
detection (three times, including replays of refused requests), invalid-params
refusal, and unnegotiated-method refusal. Every signed request's response is
signature-verified, so a Guardian that answers correctly but signs wrong
fails here.

This test is the local acceptance gate until #169 merges and the official
mode can run against this implementation (README.md documents that run).
"""

from __future__ import annotations

import uuid

from helpers import (
    envelope,
    expect_decision,
    expect_error,
    handshake,
    http_post,
    signed_post,
)


def test_the_ten_external_probes(server) -> None:
    url = server.url

    # 1. Invalid JSON-RPC is refused at the JSON-RPC boundary.
    invalid = http_post(url, {"jsonrpc": "1.0", "method": "steps/toolCallRequest", "id": "bad", "params": {}})
    expect_error(invalid, -32600)

    # 2. A step before any handshake is CAPABILITY_NOT_NEGOTIATED.
    before_session = str(uuid.uuid4())
    request = envelope(
        "steps/toolCallRequest",
        before_session,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}, "raw_command": "ls -la"},
    )
    expect_error(signed_post(url, request, before_session), -32003)

    # 3. A handshake offering only stdio is SESSION_REFUSED.
    transport_session = str(uuid.uuid4())
    refused = envelope(
        "handshake/hello",
        transport_session,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["stdio"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
    )
    expect_error(signed_post(url, refused, transport_session), -32000)

    # 4. A valid handshake returns a correlated, signed ServerHello.
    session_id = str(uuid.uuid4())
    methods = ["steps/toolCallRequest", "steps/toolCallResult"]
    hello = handshake(url, session_id, methods)
    result = hello["result"]
    assert result["negotiated_version"] == "0.1.0"
    assert isinstance(result["methods_evaluated"], list)
    assert result["methods_evaluated"] == methods

    # 5. An allowed tool call returns a correlated ALLOW decision.
    allowed = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}, "raw_command": "ls -la"},
    )
    expect_decision(signed_post(url, allowed, session_id), "allow", allowed["id"])

    # 6. Replaying it is REPLAY_DETECTED.
    expect_error(signed_post(url, allowed, session_id), -32005)

    # 7. A tool call whose payload fails its hook schema is INVALID_PARAMS.
    invalid_payload = envelope("steps/toolCallRequest", session_id, {"tool": {"name": "Bash"}})
    expect_error(signed_post(url, invalid_payload, session_id), -32602)

    # 8. Replaying the invalid one is still a replay, not a second -32602.
    expect_error(signed_post(url, invalid_payload, session_id), -32005)

    # 9. A method the handshake did not negotiate is CAPABILITY_NOT_NEGOTIATED.
    unnegotiated = envelope("steps/userMessage", session_id, {"content": [{"type": "text", "value": "hello"}]})
    expect_error(signed_post(url, unnegotiated, session_id), -32003)

    # 10. And its replay is REPLAY_DETECTED.
    expect_error(signed_post(url, unnegotiated, session_id), -32005)
