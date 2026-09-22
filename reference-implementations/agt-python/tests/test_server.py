"""Guardian behavior beyond the probes: signing rules, ping, chain, refusals."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from helpers import (
    AGENT_ID,
    SECRET,
    envelope,
    expect_decision,
    expect_error,
    handshake,
    http_post,
    now_iso,
    signed_post,
    sign_request,
    verify_response,
)

from acs_guardian.canonical import canonical_bytes, response_signing_input
from acs_guardian.crypto import derive_session_key, sign
from acs_guardian.engine import ASK, DEFER, MODIFY, Evaluation
from acs_guardian.errors import INVALID_PARAMS, AcsError
from acs_guardian.schemas import HOOK_METHODS
from acs_guardian.server import Guardian, GuardianConfig


def _session(server, methods=("steps/toolCallRequest", "steps/toolCallResult", "system/ping")) -> str:
    session_id = str(uuid.uuid4())
    handshake(server.url, session_id, list(methods))
    return session_id


def test_a_decision_carries_a_verifiable_chain_hash_and_a_signed_result(server) -> None:
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    response = signed_post(server.url, request, session_id)
    result = response["result"]
    assert len(result["chain_hash"]) == 64
    assert result["type"] == "final"
    assert result["acs_version"] == "0.1.0"


def test_the_chain_head_advances_across_steps(server) -> None:
    session_id = _session(server)
    heads = []
    for command in ("ls", "pwd"):
        request = envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": command}}, "raw_command": command},
        )
        heads.append(signed_post(server.url, request, session_id)["result"]["chain_hash"])
    assert heads[0] != heads[1]


def test_destructive_command_is_denied_by_the_builtin_engine(server) -> None:
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}, "raw_command": "rm -rf /"},
    )
    response = signed_post(server.url, request, session_id)
    expect_decision(response, "deny", request["id"])
    assert response["result"]["reasoning"]
    assert response["result"]["reason_codes"] == ["destructive_shell_command_blocked"]


def test_a_missing_signature_is_refused_and_the_answer_is_unsigned(server) -> None:
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    response = http_post(server.url, request)
    expect_error(response, -32004)
    assert "signature" not in response["error"]


def test_a_wrong_signature_is_refused(server) -> None:
    session_id = _session(server)
    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
    )
    request["params"]["signature"]["value"] = "AAAA"
    expect_error(http_post(server.url, request), -32004)


def test_an_old_timestamp_is_outside_the_skew_window(server) -> None:
    session_id = _session(server)
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        timestamp=stale,
    )
    response = signed_post(server.url, request, session_id)
    expect_error(response, -32006)
    assert response["error"]["data"]["skew_window_ms"] == 300_000


def test_ping_is_always_allowed_and_does_not_touch_the_chain(server) -> None:
    session_id = _session(server)
    request = envelope("system/ping", session_id, {"echo": "hi"})
    response = signed_post(server.url, request, session_id)
    result = response["result"]
    assert result["decision"] == "allow"
    assert result["payload"]["status"] == "ok"
    assert result["payload"]["echo"] == "hi"
    assert "chain_hash" not in result


def test_ping_needs_no_signature(server) -> None:
    session_id = _session(server)
    response = http_post(server.url, envelope("system/ping", session_id, {}))
    assert response["result"]["decision"] == "allow"


def test_a_stale_handshake_is_outside_the_skew_window(server) -> None:
    """§10.3 applies to the handshake too: a recorded ClientHello must not replay."""
    session_id = str(uuid.uuid4())
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
        timestamp=stale,
    )
    expect_error(signed_post(server.url, hello, session_id), -32006)


def test_a_handshake_nonce_replay_is_replay_detected(server) -> None:
    session_id = str(uuid.uuid4())
    nonce = "0123456789abcdef0123456789abcdef"
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
    )
    hello["params"]["nonce"] = nonce
    signed_post(server.url, hello, session_id)

    again = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
    )
    again["params"]["nonce"] = nonce
    expect_error(signed_post(server.url, again, session_id), -32005)


def _recv_all(sock) -> bytes:
    """Read a socket to EOF; the server closing is what ends the loop."""
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def test_a_bad_content_length_is_refused_and_the_connection_closes(server) -> None:
    import json
    import socket

    with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5) as sock:
        sock.sendall(b"POST /acs HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n")
        raw = _recv_all(sock).decode()
    head, _, body = raw.partition("\r\n\r\n")
    assert "200" in head.splitlines()[0]
    assert "connection: close" in head.lower()
    expect_error(json.loads(body), -32600)


def test_a_request_without_content_length_is_refused(server) -> None:
    import json
    import socket

    with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5) as sock:
        sock.sendall(b"POST /acs HTTP/1.1\r\nHost: x\r\n\r\n")
        raw = _recv_all(sock).decode()
    _, _, body = raw.partition("\r\n\r\n")
    expect_error(json.loads(body), -32600)


def test_deeply_nested_json_is_a_parse_error_not_a_dropped_connection(server) -> None:
    import json
    import urllib.request

    # ~20 KB, far under the body cap, and far past the parser's ~1000-level
    # recursion limit.
    body = b"[" * 10_000 + b"]" * 10_000
    request = urllib.request.Request(
        server.url, data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32700)


def test_a_second_handshake_is_refused_but_its_replay_is_a_replay(server) -> None:
    session_id = _session(server)
    again = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
    )
    expect_error(signed_post(server.url, again, session_id), -32000)
    expect_error(signed_post(server.url, again, session_id), -32005)


def test_batching_is_refused_with_invalid_request(server) -> None:
    response = http_post(server.url, [{"jsonrpc": "2.0", "method": "system/ping", "id": 1, "params": {}}])
    expect_error(response, -32600)


def test_parse_error_gets_the_jsonrpc_code(server) -> None:
    import json
    import urllib.request

    request = urllib.request.Request(
        server.url, data=b"{not json", headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32700)


def test_literal_nan_tokens_are_a_parse_error(server) -> None:
    import json
    import urllib.request

    request = urllib.request.Request(
        server.url, data=b'{"jsonrpc":"2.0","method":"system/ping","id":"x","params":{"n":NaN}}',
        headers={"content-type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32700)


def test_a_number_outside_the_jcs_domain_is_invalid_request(server) -> None:
    """1e400 parses to inf, which JCS cannot represent; the envelope is invalid."""
    import json
    import urllib.request

    body = {
        "jsonrpc": "2.0",
        "method": "system/ping",
        "id": "x",
        "params": {
            "acs_version": "0.1.0",
            "request_id": str(uuid.uuid4()),
            "timestamp": now_iso(),
            "metadata": {"agent_id": AGENT_ID, "session_id": str(uuid.uuid4())},
            "payload": {},
        },
    }
    encoded = json.dumps(body).encode().replace(b'"payload": {}', b'"payload": {"n": 1e400}')
    request = urllib.request.Request(
        server.url, data=encoded, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32600)
    assert "JCS-canonicalizable" in payload["error"]["message"]


def test_a_method_the_standard_does_not_define_is_method_not_found(server) -> None:
    # The method table routes before the session is read (the Go port's order):
    # an undefined method is -32601, not -32003, which is for a defined method
    # the handshake did not negotiate.
    session_id = _session(server)
    request = envelope("steps/nonexistent", session_id, {})
    expect_error(signed_post(server.url, request, session_id), -32601)


def test_an_agbom_method_is_capability_not_negotiated(server) -> None:
    # Defined by the standard, never negotiated by this Guardian (no Inspect).
    session_id = _session(server)
    request = envelope("agbom/snapshot", session_id, {})
    expect_error(signed_post(server.url, request, session_id), -32003)


def test_the_server_hello_signature_verifies_with_the_session_key(server) -> None:
    session_id = str(uuid.uuid4())
    hello = handshake(server.url, session_id, ["steps/toolCallRequest"])
    # signed_post already verifies; this asserts the key it verified against is
    # the session-derived one, not a constant.
    key = derive_session_key(bytes(range(32)), session_id)
    holder = hello["result"]
    assert holder["signature"]["value"] == sign(key, response_signing_input(hello))


def test_a_replayed_nonce_is_replay_detected(server) -> None:
    """A fresh request_id with a seen nonce is still a replay (§10.3)."""
    session_id = _session(server)
    nonce = "0123456789abcdef0123456789abcdef"
    first = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    first["params"]["nonce"] = nonce
    expect_decision(signed_post(server.url, first, session_id), "allow", first["id"])

    second = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "pwd"}}, "raw_command": "pwd"},
    )
    second["params"]["nonce"] = nonce
    expect_error(signed_post(server.url, second, session_id), -32005)


def test_an_envelope_missing_a_required_field_is_invalid_request(server) -> None:
    """The envelope schema is authoritative, not the manual jsonrpc check.

    The answer is unsigned: envelope validation runs before any key is
    established, and a request that did not authenticate gets an unsigned
    answer.
    """
    session_id = _session(server)
    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
    )
    del request["params"]["acs_version"]
    response = http_post(server.url, request)
    expect_error(response, -32600)
    assert "signature" not in response["error"]


def test_request_hash_commits_to_the_params_including_the_signature(server) -> None:
    """The interop choice: request_hash hashes params as received, signature included."""
    session_id = _session(server)
    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
    )
    response = signed_post(server.url, request, session_id)
    expected = hashlib.sha256(canonical_bytes(request["params"])).hexdigest()
    session = server.guardian.store.get(session_id)
    assert session.chain.entries[-1].request_hash == expected
    assert response["result"]["chain_hash"] == session.chain.head


class _StubEngine:
    """Returns one fixed decision, so every disposition's wire shape is exercised."""

    def __init__(self, evaluation: Evaluation) -> None:
        self.evaluation = evaluation

    def evaluate(self, request) -> Evaluation:  # noqa: ANN001 - the Protocol's shape
        return self.evaluation


@pytest.mark.parametrize(
    "evaluation",
    [
        Evaluation(decision="allow"),
        Evaluation(decision="deny", reasoning="blocked by the stub"),
        Evaluation(
            decision=MODIFY,
            reasoning="redacted by the stub",
            modifications={"redactions": [{"path": "/outputs/0/value", "replacement": "[redacted]"}]},
        ),
        Evaluation(
            decision=ASK,
            reasoning="needs approval",
            ask_details={
                "approver": {"type": "human", "id": "ops", "endpoint": "https://approver.example/acs"},
                "question": "Approve this tool call?",
                "timeout_seconds": 300,
            },
        ),
        Evaluation(
            decision=DEFER,
            reasoning="not yet reachable",
            defer_details={
                "reason": "insufficient_context",
                "resolution_method": "additional_context",
                "resolution_timeout_ms": 60000,
                "timeout_decision": "deny",
            },
        ),
    ],
)
def test_all_five_dispositions_produce_schema_valid_decisions(evaluation: Evaluation) -> None:
    guardian = Guardian(GuardianConfig(secret=SECRET, port=0, engine=_StubEngine(evaluation)))
    session_id = str(uuid.uuid4())
    hello = sign_request(
        envelope(
            "handshake/hello",
            session_id,
            {
                "acs_versions_supported": ["0.1.0"],
                "methods_implemented": ["steps/toolCallRequest"],
                "transports_supported": ["http"],
                "provenance_producer": "none",
                "profiles_supported": ["acs-core"],
            },
        ),
        session_id,
    )
    handshake_response = guardian.handle(hello)
    verify_response(handshake_response, session_id, hello["id"])

    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == evaluation.decision
    # The outbound check the Guardian itself runs must find nothing: a
    # conformant decision, or the Guardian would have replaced it with a deny.
    assert guardian.schemas.validate_response(response) is None


def test_an_incomplete_engine_decision_fails_closed() -> None:
    """A modify without modifications cannot be sent as one; it becomes a deny."""
    guardian = Guardian(
        GuardianConfig(secret=SECRET, port=0, engine=_StubEngine(Evaluation(decision=MODIFY, reasoning="no payload")))
    )
    session_id = str(uuid.uuid4())
    hello = sign_request(
        envelope(
            "handshake/hello",
            session_id,
            {
                "acs_versions_supported": ["0.1.0"],
                "methods_implemented": ["steps/toolCallRequest"],
                "transports_supported": ["http"],
                "provenance_producer": "none",
                "profiles_supported": ["acs-core"],
            },
        ),
        session_id,
    )
    guardian.handle(hello)
    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]
    assert guardian.schemas.validate_response(response) is None


def _kebab(method: str) -> str:
    """steps/toolCallRequest -> tool-call-request (the namespace is dropped)."""
    name = method.split("/", 1)[1]
    out = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0:
            out.append("-")
        out.append(char.lower())
    return "".join(out)


def _guardian_handshake(engine, methods=("steps/toolCallRequest",), *, key_id: str | None = None) -> tuple[Guardian, str]:
    guardian = Guardian(GuardianConfig(secret=SECRET, port=0, engine=engine))
    session_id = str(uuid.uuid4())
    hello = sign_request(
        envelope(
            "handshake/hello",
            session_id,
            {
                "acs_versions_supported": ["0.1.0"],
                "methods_implemented": list(methods),
                "transports_supported": ["http"],
                "provenance_producer": "none",
                "profiles_supported": ["acs-core"],
            },
        ),
        session_id,
        **({"key_id": key_id} if key_id is not None else {}),
    )
    response = guardian.handle(hello)
    if key_id is not None:
        # The response label is the deployment's, not the client-chosen
        # binding the session was opened with.
        assert response["result"]["signature"]["key_id"] == "conformance"
    return guardian, session_id


def _guardian_wrapped(engine) -> tuple[Guardian, str]:
    guardian = Guardian(GuardianConfig(secret=SECRET, port=0, engine=engine))
    session_id = str(uuid.uuid4())
    hello = sign_request(
        envelope(
            "handshake/hello",
            session_id,
            {
                "acs_versions_supported": ["0.1.0"],
                "methods_implemented": ["protocols/MCP/tools/call"],
                "transports_supported": ["http"],
                "provenance_producer": "none",
                "profiles_supported": ["acs-core"],
                "wrapped_protocols": [{"protocol": "MCP", "version": "2025-06-18"}],
            },
        ),
        session_id,
    )
    guardian.handle(hello)
    return guardian, session_id


def _tool_call(
    guardian: Guardian,
    session_id: str,
    *,
    method: str = "steps/toolCallRequest",
    payload=None,
    key_id: str | None = None,
):
    request = sign_request(
        envelope(
            method,
            session_id,
            payload
            if payload is not None
            else {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
        **({"key_id": key_id} if key_id is not None else {}),
    )
    return request, guardian.handle(request)


@pytest.mark.parametrize(
    "method, disposition, expected",
    [
        # turnEnd is audit-only: a denial cannot be honored, the turn ended.
        ("steps/turnEnd", "deny", "allow"),
        # sessionStart permits ALLOW/DENY: a modify is substituted with a denial.
        ("steps/sessionStart", MODIFY, "deny"),
    ],
)
def test_a_disposition_the_hook_does_not_permit_is_substituted(method, disposition, expected) -> None:
    evaluation = Evaluation(decision=disposition, reasoning="stub", modifications={"modified_content": "x"})
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation), methods=(method,))
    payload = {"turn_id": "t1", "outcome": "completed"} if method == "steps/turnEnd" else {}
    request, response = _tool_call(guardian, session_id, method=method, payload=payload)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == expected
    assert response["result"]["reason_codes"] == ["disposition_not_permitted"]
    assert guardian.schemas.validate_response(response) is None


def test_an_evaluation_failure_at_an_audit_only_hook_is_an_allow() -> None:
    """A deny cannot be honored at postCompact or turnEnd: the failure becomes an ALLOW."""

    class Exploding:
        def evaluate(self, request):  # noqa: ANN001 - the Protocol's shape
            raise RuntimeError("engine down")

    guardian, session_id = _guardian_handshake(Exploding(), methods=("steps/turnEnd",))
    request, response = _tool_call(guardian, session_id, method="steps/turnEnd", payload={"turn_id": "t", "outcome": "completed"})
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "allow"
    assert response["result"]["reason_codes"] == ["evaluation_failed", "disposition_not_permitted"]
    assert guardian.schemas.validate_response(response) is None


@pytest.mark.parametrize(
    "modifications",
    [
        # modified_content stands alone (§6.3).
        {"modified_content": "x", "redactions": [{"path": "/outputs/0"}]},
        # A redaction and an override may not address the same field...
        {
            "redactions": [{"path": "/arguments/command"}],
            "parameter_overrides": {"command": "ls"},
        },
        # ...nor an ancestor or descendant of it.
        {
            "redactions": [{"path": "/arguments"}],
            "parameter_overrides": {"command": "ls"},
        },
        # An empty modifications carries no edit.
        {},
    ],
)
def test_a_modification_that_breaks_section_6_3_fails_closed(modifications) -> None:
    evaluation = Evaluation(decision=MODIFY, reasoning="stub", modifications=modifications)
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation))
    request, response = _tool_call(guardian, session_id)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]
    assert guardian.schemas.validate_response(response) is None


def test_a_disjoint_redaction_and_override_is_kept() -> None:
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="stub",
        modifications={
            "redactions": [{"path": "/outputs/0/value"}],
            "parameter_overrides": {"command": "ls"},
        },
    )
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation))
    request, response = _tool_call(guardian, session_id)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "modify"
    assert guardian.schemas.validate_response(response) is None


def test_a_modification_that_breaks_section_6_3_on_a_wrapped_call_fails_closed() -> None:
    """A wrapped call's override pointer is /params/arguments/<name>."""
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="stub",
        modifications={
            "redactions": [{"path": "/params/arguments/command"}],
            "parameter_overrides": {"command": "ls"},
        },
    )
    guardian, session_id = _guardian_wrapped(_StubEngine(evaluation))
    request = sign_request(
        envelope(
            "protocols/MCP/tools/call",
            session_id,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {"command": "rm -rf /"}}},
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]


def test_a_wrapped_override_pointer_escapes_json_pointer_characters() -> None:
    """An argument named a/b addresses /params/arguments/a~1b, so this pair overlaps."""
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="stub",
        modifications={
            "redactions": [{"path": "/params/arguments/a~1b"}],
            "parameter_overrides": {"a/b": "x"},
        },
    )
    guardian, session_id = _guardian_wrapped(_StubEngine(evaluation))
    request = sign_request(
        envelope(
            "protocols/MCP/tools/call",
            session_id,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {"a/b": "y"}}},
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]


def test_a_disjoint_wrapped_override_is_kept() -> None:
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="stub",
        modifications={
            "redactions": [{"path": "/params/arguments/body"}],
            "parameter_overrides": {"to": "audit@example.com"},
        },
    )
    guardian, session_id = _guardian_wrapped(_StubEngine(evaluation))
    request = sign_request(
        envelope(
            "protocols/MCP/tools/call",
            session_id,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {"to": "x", "body": "y"}}},
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "modify"
    assert guardian.schemas.validate_response(response) is None


def test_a_step_after_session_end_is_denied_and_a_replay_is_still_a_replay() -> None:
    guardian, session_id = _guardian_handshake(
        _StubEngine(Evaluation(decision="allow")), methods=("steps/sessionEnd", "steps/toolCallRequest")
    )
    end, response = _tool_call(guardian, session_id, method="steps/sessionEnd", payload={"reason": "completed"})
    verify_response(response, session_id, end["id"])
    assert response["result"]["decision"] == "allow"

    # A step after the session ended is denied (toolCallRequest permits DENY),
    # and carries no chain_hash: it wrote no entry, though the sessionEnd
    # above did (so the chain is not empty).
    request, response = _tool_call(guardian, session_id)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["session_closed"]
    assert "chain_hash" not in response["result"]

    # ...but at sessionEnd, an audit-only hook, the denial is substituted with
    # an ALLOW carrying the reason: the action already happened.
    again, response = _tool_call(guardian, session_id, method="steps/sessionEnd", payload={"reason": "cancelled"})
    verify_response(response, session_id, again["id"])
    assert response["result"]["decision"] == "allow"
    assert response["result"]["reason_codes"] == ["session_closed", "disposition_not_permitted"]

    # The same request again is a replay, reported before the closed check.
    response = guardian.handle(end)
    verify_response(response, session_id, end["id"])
    expect_error(response, -32005)


def test_a_wrong_key_id_is_a_signed_denial_not_an_error() -> None:
    # The session is opened with a client-chosen key_id, so the session's
    # key_id differs from the deployment's ("conformance"): the response label
    # must be the deployment's, and the binding must still be the client's.
    guardian, session_id = _guardian_handshake(
        _StubEngine(Evaluation(decision="allow")), key_id="client-chosen"
    )
    # A step first, so the chain is not empty: the denial still carries no
    # chain_hash, because it wrote no entry — the previous step's head would
    # be a false claim about this step, not a harmless omission.
    ok, response = _tool_call(guardian, session_id, key_id="client-chosen")
    verify_response(response, session_id, ok["id"])
    assert response["result"]["chain_hash"]

    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        ),
        session_id,
        key_id="some-other-key",
    )
    response = guardian.handle(request)
    # Signed under the deployment's key_id: key_id names the key a verifier
    # resolves, and that is the one this Guardian holds.
    verify_response(response, session_id, request["id"])
    assert response["result"]["signature"]["key_id"] == "conformance"
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["key_not_bound"]
    # The step never reached the chain, so no chain_hash is sent (a null
    # would fail response-envelope.json).
    assert "chain_hash" not in response["result"]
    assert guardian.schemas.validate_response(response) is None

    # The id was recorded on arrival, so the same request again is a replay.
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    expect_error(response, -32005)


def test_ping_is_signed_under_the_deployments_key_id() -> None:
    guardian, session_id = _guardian_handshake(
        _StubEngine(Evaluation(decision="allow")), methods=("system/ping",), key_id="client-chosen"
    )
    request = sign_request(
        envelope("system/ping", session_id, {"echo": "hi"}), session_id, key_id="client-chosen"
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["signature"]["key_id"] == "conformance"


def test_a_wrong_agent_id_is_a_signed_denial_not_an_error() -> None:
    guardian, session_id = _guardian_handshake(_StubEngine(Evaluation(decision="allow")))
    request = sign_request(
        envelope(
            "steps/toolCallRequest",
            session_id,
            {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
            agent_id="some-other-agent",
        ),
        session_id,
    )
    response = guardian.handle(request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["agent_id_not_bound"]
    assert guardian.schemas.validate_response(response) is None


@pytest.mark.parametrize("method", HOOK_METHODS)
def test_every_hook_payload_schema_loads_and_is_the_right_schema(guardian: Guardian, method: str) -> None:
    """Each hook's schema exists, compiles, and is pinned to the method name.

    The method -> file mapping is checked against an independent derivation
    (camelCase -> kebab-case), so a swapped pair in the table (turnStart's
    method pointing at turn-end.json, say) fails here rather than silently
    validating against the wrong schema.
    """
    from acs_guardian.schemas import _HOOK_SCHEMAS

    relative = f"hooks/{_kebab(method)}.json"
    assert _HOOK_SCHEMAS[method] == relative
    # And the file's own $id says it is that schema, so a wrong file at the
    # right path cannot pass either.
    schema_id = guardian.schemas.hook_schema_id(method)
    assert schema_id is not None and schema_id.endswith(f"/{relative}")
    try:
        guardian.schemas.validate_payload(method, {})
    except AcsError as error:
        assert error.code == INVALID_PARAMS
