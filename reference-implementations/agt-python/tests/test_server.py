"""Guardian behavior beyond the probes: signing rules, ping, chain, refusals."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from helpers import (
    AGENT_ID,
    KEY_ID,
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
from acs_guardian.chain import AuditChain
from acs_guardian.crypto import derive_session_key, sign
from acs_guardian.engine import ASK, DEFER, MODIFY, Evaluation
from acs_guardian.errors import INVALID_PARAMS, AcsError
from acs_guardian.schemas import HOOK_METHODS
from acs_guardian.server import (
    DEEP_PARSE_LIMIT,
    MAX_JSON_DEPTH,
    Guardian,
    GuardianConfig,
    _in_deep_thread,
    _modify_unsupported,
)


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
    # A signed ping's answer is signed too (the Go port's rule).
    assert result["signature"]["key_id"] == KEY_ID


def test_an_unsigned_ping_is_answered_but_not_signed(server) -> None:
    """Answering an unsigned ping signed would make the endpoint a signing oracle.

    Anyone able to name a session could collect a Guardian-signed ALLOW under
    that session's key, which an attacker on the network path could
    substitute for a real signed DENY.
    """
    session_id = _session(server)
    response = http_post(server.url, envelope("system/ping", session_id, {}))
    assert response["result"]["decision"] == "allow"
    assert "signature" not in response["result"]


def test_a_ping_with_a_bad_signature_is_answered_but_not_signed(server) -> None:
    session_id = _session(server)
    request = sign_request(envelope("system/ping", session_id, {"echo": "hi"}), session_id)
    request["params"]["signature"]["value"] = "AAAA"
    response = http_post(server.url, request)
    assert response["result"]["decision"] == "allow"
    assert "signature" not in response["result"]


def test_a_ping_with_an_unknown_key_id_is_answered_but_not_signed(server) -> None:
    session_id = _session(server)
    request = sign_request(envelope("system/ping", session_id, {}), session_id, key_id="some-other-key")
    response = http_post(server.url, request)
    assert response["result"]["decision"] == "allow"
    assert "signature" not in response["result"]


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

    # ~20 KB, far under the body cap, and past the C parser's ~10,000-level
    # recursion limit on the pinned interpreter.
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
    guardian = Guardian(GuardianConfig(secret=SECRET, key_id=KEY_ID, port=0, engine=_StubEngine(evaluation)))
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
        GuardianConfig(secret=SECRET, key_id=KEY_ID, port=0, engine=_StubEngine(Evaluation(decision=MODIFY, reasoning="no payload")))
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


def _guardian_handshake(engine, methods=("steps/toolCallRequest",), **config) -> tuple[Guardian, str]:
    guardian = Guardian(GuardianConfig(secret=SECRET, key_id=KEY_ID, port=0, engine=engine, **config))
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
    )
    response = guardian.handle(hello)
    verify_response(response, session_id, hello["id"])
    return guardian, session_id


def _guardian_wrapped(engine) -> tuple[Guardian, str]:
    guardian = Guardian(GuardianConfig(secret=SECRET, key_id=KEY_ID, port=0, engine=engine))
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


def test_a_request_naming_an_unknown_key_id_is_refused_unsigned() -> None:
    """#118: a verifier MUST reject an unknown key_id, never fall back to its secret."""
    guardian, session_id = _guardian_handshake(_StubEngine(Evaluation(decision="allow")))
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
    expect_error(response, -32004)
    # The request established no key under this label, so the answer is unsigned.
    assert "signature" not in response["error"]


def test_a_handshake_naming_an_unknown_key_id_is_refused_unsigned() -> None:
    guardian = Guardian(GuardianConfig(secret=SECRET, key_id=KEY_ID, port=0, engine=_StubEngine(Evaluation(decision="allow"))))
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
        key_id="client-chosen",
    )
    response = guardian.handle(hello)
    expect_error(response, -32004)
    assert "signature" not in response["error"]
    assert guardian.store.get(session_id) is None


def test_guardian_configuration_requires_a_key_id() -> None:
    with pytest.raises(TypeError):
        GuardianConfig(secret=SECRET, port=0)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="key_id"):
        Guardian(GuardianConfig(secret=SECRET, key_id="", port=0))


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


# -- fail-closed depth, version, §6.5, and Go alignment (review fixes) ------


def _nested(value, levels):
    for _ in range(levels):
        value = {"a": value}
    return value


def test_a_body_within_the_depth_limit_still_evaluates(server) -> None:
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "ls"}, "deep": {"value": _nested("leaf", MAX_JSON_DEPTH - 20)}},
            "raw_command": "ls",
        },
    )
    response = signed_post(server.url, request, session_id)
    assert response["result"]["decision"] == "allow"


def test_a_body_past_the_depth_limit_is_a_signed_denial(server) -> None:
    """Fail closed where failing open would be a run the Guardian never saw.

    Before this guard, a signed request nested a few hundred levels deep hit
    RecursionError on the signing path and came back as an unsigned -32603,
    which the Observed Agent's default posture turns into a proceed.
    """
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "rm -rf /"}, "deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}},
            "raw_command": "rm -rf /",
        },
    )
    response = signed_post(server.url, request, session_id)
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]
    # The verified step is recorded like any refusal: the entry is appended
    # and the published head is this step's.
    session = server.guardian.store.get(session_id)
    assert response["result"]["chain_hash"] == session.chain.head

    # Resending the same verified body is a replay: a signed -32005, and no
    # second entry (a repeated body must not grow the chain without bound).
    entries = len(session.chain.entries)
    replay = http_post(server.url, request)
    verify_response(replay, session_id, request["id"])
    expect_error(replay, -32005)
    assert len(session.chain.entries) == entries


def test_a_verified_step_deeper_than_the_default_stack_is_still_decided(server) -> None:
    """The parser accepts ~10,000 levels; JCS dies ~1,000 on the default limit.

    In between, a verified step must still get a signed decision — the retry
    canonicalizes on an enlarged thread — not an unsigned error the agent's
    posture turns into a proceed.
    """
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "rm -rf /"}, "deep": {"value": _nested("leaf", 3000)}},
            "raw_command": "rm -rf /",
        },
    )
    ok, _ = _in_deep_thread(lambda: sign_request(request, session_id))
    assert ok
    response = http_post(server.url, request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]
    session = server.guardian.store.get(session_id)
    assert response["result"]["chain_hash"] == session.chain.head


def test_a_verified_over_deep_postcompact_failure_substitutes_to_allow(server) -> None:
    """postCompact permits no DENY, so a verified over-deep failure is its ALLOW."""
    session_id = _session(server, methods=("steps/postCompact",))
    request = envelope(
        "steps/postCompact",
        session_id,
        {
            "summary": {"value": "compacted", "provenance": {"provenance_id": "p1", "origin": "agent_generated"}},
            "entries_compacted": ["s-1"],
            "pre_compact_chain_hash": "0" * 64,
            "post_compact_chain_hash": "0" * 64,
            "deep": _nested("leaf", MAX_JSON_DEPTH + 5),
        },
    )
    response = signed_post(server.url, request, session_id)
    assert response["result"]["decision"] == "allow"
    assert response["result"]["reason_codes"] == ["evaluation_failed", "disposition_not_permitted"]
    session = server.guardian.store.get(session_id)
    assert response["result"]["chain_hash"] == session.chain.head


def test_an_over_deep_body_that_does_not_verify_gets_no_signed_answer(server) -> None:
    """Nothing on this route may sign without verifying: key_id is not a secret.

    At postCompact the failure substitution turns a DENY into an ALLOW, so an
    unverified signing path here would mint a Guardian-signed ALLOW for an
    attacker-chosen request_id — the strongest form of the old ping oracle.
    """
    session_id = _session(server)
    payload = {
        "summary": {"value": "compacted", "provenance": {"provenance_id": "p1", "origin": "agent_generated"}},
        "entries_compacted": ["s-1"],
        "pre_compact_chain_hash": "0" * 64,
        "post_compact_chain_hash": "0" * 64,
        "deep": _nested("leaf", MAX_JSON_DEPTH + 5),
    }
    unsigned = envelope("steps/postCompact", session_id, payload)
    response = http_post(server.url, unsigned)
    expect_error(response, -32600)
    assert "signature" not in response["error"]

    bad = sign_request(envelope("steps/postCompact", session_id, payload), session_id)
    bad["params"]["signature"]["value"] = "AAAA"
    response = http_post(server.url, bad)
    expect_error(response, -32600)
    assert "signature" not in response["error"]


def test_an_over_deep_step_gets_the_normal_route_and_binding_checks(server) -> None:
    """Over-deep is a depth guard, not a bypass of the dispatch ladder."""
    session_id = _session(server, methods=("steps/toolCallRequest", "system/ping"))
    session = server.guardian.store.get(session_id)

    # A ping is answered without touching the chain, however deep it is.
    ping = envelope("system/ping", session_id, {"echo": "x", "deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    response = signed_post(server.url, ping, session_id)
    assert response["result"]["decision"] == "allow"
    assert "chain_hash" not in response["result"]
    assert len(session.chain.entries) == 0

    # An undefined method is its own refusal, signed, nothing appended.
    bogus = envelope("steps/noSuchHook", session_id, {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    response = signed_post(server.url, bogus, session_id)
    expect_error(response, -32601)
    assert len(session.chain.entries) == 0

    # A request naming another agent is a signed denial, nothing appended.
    other = envelope(
        "steps/toolCallRequest",
        session_id,
        {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}},
        agent_id="someone-else",
    )
    response = signed_post(server.url, other, session_id)
    assert response["result"]["reason_codes"] == ["agent_id_not_bound"]
    assert "chain_hash" not in response["result"]
    assert len(session.chain.entries) == 0


def test_an_over_deep_step_after_session_end_is_a_closed_denial(server) -> None:
    """The closed check runs before the negotiated-method check, like _step.

    The late step names a method this session never negotiated; a closed
    session must get its signed denial, not a -32003 error the posture could
    turn into a proceed.
    """
    session_id = _session(server, methods=("steps/toolCallRequest", "steps/sessionEnd"))
    signed_post(server.url, envelope("steps/sessionEnd", session_id, {"reason": "cancelled"}), session_id)
    session = server.guardian.store.get(session_id)
    entries = len(session.chain.entries)
    late = envelope("steps/memoryStore", session_id, {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    response = signed_post(server.url, late, session_id)
    assert response["result"]["reason_codes"] == ["session_closed"]
    assert "chain_hash" not in response["result"]
    assert len(session.chain.entries) == entries


def test_a_deep_verified_ping_is_answered_not_failed(server) -> None:
    """A ping past the default recursion limit must get the ping answer.

    Re-verifying and re-signing on the request thread would overflow, turning
    a ping into an evaluation_failed denial — and, in a narrow depth band,
    writing a chain entry, when pings never touch the chain.
    """
    session_id = _session(server, methods=("steps/toolCallRequest", "system/ping"))
    session = server.guardian.store.get(session_id)

    ping = envelope("system/ping", session_id, {"deep": {"value": _nested("leaf", 3000)}})
    ok, _ = _in_deep_thread(lambda: sign_request(ping, session_id))
    assert ok
    response = http_post(server.url, ping)
    verify_response(response, session_id, ping["id"])
    assert response["result"]["decision"] == "allow"
    assert "chain_hash" not in response["result"]
    # A ping is not a step: no replay rejection, and still nothing appended.
    again = http_post(server.url, ping)
    verify_response(again, session_id, ping["id"])
    assert again["result"]["decision"] == "allow"
    assert len(session.chain.entries) == 0

    # And a deep echo: signing the answer must also go through the enlarged
    # thread rather than fail the ping.
    echo_ping = envelope("system/ping", session_id, {"echo": {"value": _nested("leaf", 3000)}})
    ok, _ = _in_deep_thread(lambda: sign_request(echo_ping, session_id))
    assert ok
    echoed = http_post(server.url, echo_ping)
    ok, _ = _in_deep_thread(lambda: verify_response(echoed, session_id, echo_ping["id"]))
    assert ok
    assert echoed["result"]["decision"] == "allow"
    assert len(session.chain.entries) == 0


def test_an_over_deep_ping_with_a_nested_acs_version_still_answers(server) -> None:
    """The ping echoes its version only when it is a string; it must not str() deep objects."""
    session_id = _session(server, methods=("steps/toolCallRequest", "system/ping"))
    ping = envelope("system/ping", session_id, {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    ping["params"]["acs_version"] = {"nested": {"value": _nested("leaf", 5)}}
    signed = sign_request(ping, session_id)
    response = http_post(server.url, signed)
    verify_response(response, session_id, ping["id"])
    assert response["result"]["decision"] == "allow"
    assert response["result"]["acs_version"] == "0.1.0"


def test_a_failed_over_deep_ping_is_an_unsigned_internal_error(monkeypatch, server) -> None:
    """A ping has no decision to fail closed with: an internal failure is reported, not faked."""
    session_id = _session(server, methods=("steps/toolCallRequest", "system/ping"))
    session = server.guardian.store.get(session_id)
    ping = envelope("system/ping", session_id, {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    signed = sign_request(ping, session_id)

    def explode(*args, **kwargs):
        raise RuntimeError("ping signing exploded")

    monkeypatch.setattr(Guardian, "_signed_response_any_depth", explode)
    response = http_post(server.url, signed)
    expect_error(response, -32603)
    assert "signature" not in response["error"]
    assert len(session.chain.entries) == 0


def test_an_over_deep_handshake_consumes_its_request_id(server) -> None:
    """The normal handshake records the id/nonce before refusing; the deep one must too."""
    session_id = _session(server)
    shared_id = str(uuid.uuid4())
    shared_nonce = str(uuid.uuid4())
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
            "deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)},
        },
        request_id=shared_id,
    )
    hello["params"]["nonce"] = shared_nonce
    signed = sign_request(hello, session_id)
    response = http_post(server.url, signed)
    verify_response(response, session_id, hello["id"])
    expect_error(response, -32000)

    # A replay of the handshake is a replay...
    again = http_post(server.url, signed)
    verify_response(again, session_id, hello["id"])
    expect_error(again, -32005)

    # ...and the id and nonce are consumed: a later normal step reusing
    # either is a replay.
    step = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        request_id=shared_id,
    )
    replay = http_post(server.url, sign_request(step, session_id))
    verify_response(replay, session_id, step["id"])
    expect_error(replay, -32005)

    nonce_only = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    nonce_only["params"]["nonce"] = shared_nonce
    replay = http_post(server.url, sign_request(nonce_only, session_id))
    verify_response(replay, session_id, nonce_only["id"])
    expect_error(replay, -32005)


def test_the_parse_boundary_scanner_counts_structure_not_string_contents() -> None:
    from acs_guardian.server import _bytes_nesting_exceeds

    assert _bytes_nesting_exceeds(b"[" * (DEEP_PARSE_LIMIT + 1), DEEP_PARSE_LIMIT)
    assert not _bytes_nesting_exceeds(b"[" * DEEP_PARSE_LIMIT, DEEP_PARSE_LIMIT)
    # Braces and brackets inside a string are not structure (a naive counter
    # would see 21 levels here).
    assert not _bytes_nesting_exceeds(b'["[[[[[[[[[[{{{{{{{{{{"]', 1)
    # An escaped quote does not close the string early (the braces stay inside).
    assert not _bytes_nesting_exceeds(b'["a\\"{{{{{{{{{{"]', 1)
    # A real quote after an escaped backslash does close it; the depth after counts.
    assert _bytes_nesting_exceeds(b'["a\\\\"[[[', 2)


def test_a_body_past_the_parse_boundary_is_refused_by_the_scanner(server) -> None:
    """10,001 structural levels come back a parse error from whichever layer refuses."""
    import json
    import urllib.request

    n = DEEP_PARSE_LIMIT + 1
    body = b'{"a":' * n + b"1" + b"}" * n
    request = urllib.request.Request(server.url, data=body, headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32700)


def test_an_over_deep_body_without_a_string_request_id_is_a_signed_error(server) -> None:
    """A body with no id must not reach the chain (its entry would not dedupe)."""
    session_id = _session(server)
    request = envelope("steps/toolCallRequest", session_id, {"deep": {"value": _nested("leaf", MAX_JSON_DEPTH + 5)}})
    del request["params"]["request_id"]
    signed = sign_request(request, session_id)
    response = http_post(server.url, signed)
    verify_response(response, session_id, request["id"])
    expect_error(response, -32602)
    session = server.guardian.store.get(session_id)
    assert len(session.chain.entries) == 0

    # Repeats stay refusals, not chain growth.
    again = http_post(server.url, signed)
    expect_error(again, -32602)
    assert len(session.chain.entries) == 0


def test_concurrent_deep_canonicalization_keeps_the_limits_intact() -> None:
    """Two overlapping deep calls must not restore the global limits under each other.

    The recursion limit is process-global; without serialization, one call
    restoring it mid-recursion makes a verified body fail verification — the
    fail-open the deep thread exists to prevent.
    """
    import sys
    import threading

    original_limit = sys.getrecursionlimit()
    original_stack = threading.stack_size()
    deep = _nested("leaf", 3000)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def run() -> None:
        ok, _ = _in_deep_thread(lambda: canonical_bytes(deep))
        with lock:
            outcomes.append(ok)

    workers = [threading.Thread(target=run) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert outcomes == [True, True, True, True]
    assert sys.getrecursionlimit() == original_limit
    assert threading.stack_size() == original_stack


@pytest.mark.parametrize("levels", [500, 600, 985])
def test_the_reviewers_regression_requests_are_signed_denials(server, levels) -> None:
    """The depths from the review; 500 broke on the old code and 985 dropped the connection."""
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "rm -rf /"}, "nested": {"value": _nested("x", levels)}},
            "raw_command": "rm -rf /",
        },
    )
    ok, _ = _in_deep_thread(lambda: sign_request(request, session_id))
    assert ok
    response = http_post(server.url, request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]


def test_a_verified_step_near_the_parse_boundary_is_still_decided(server) -> None:
    """The enlarged thread must cover the whole range the parser accepts."""
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "rm -rf /"}, "nested": {"value": _nested("x", 9000)}},
            "raw_command": "rm -rf /",
        },
    )
    ok, _ = _in_deep_thread(lambda: sign_request(request, session_id))
    assert ok
    response = http_post(server.url, request)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["evaluation_failed"]
    session = server.guardian.store.get(session_id)
    assert response["result"]["chain_hash"] == session.chain.head


def test_an_over_deep_request_without_a_negotiated_session_is_a_bad_request(server) -> None:
    request = envelope("steps/toolCallRequest", str(uuid.uuid4()), {"deep": _nested("leaf", MAX_JSON_DEPTH + 5)})
    response = http_post(server.url, request)
    expect_error(response, -32600)
    assert "signature" not in response["error"]


def test_a_step_may_not_move_off_the_negotiated_major_version(server) -> None:
    """§3/§4: a step's acs_version must share the session's major; else -32001."""
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    request["params"]["acs_version"] = "7.3.0"
    response = signed_post(server.url, request, session_id)
    expect_error(response, -32001)
    assert response["error"]["data"]["supported_versions"] == ["0.1.0"]


def test_a_step_on_an_offered_major_still_evaluates(server) -> None:
    session_id = _session(server)
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
    )
    request["params"]["acs_version"] = "0.9.0"
    response = signed_post(server.url, request, session_id)
    assert response["result"]["decision"] == "allow"


def test_a_modify_the_agent_cannot_apply_is_substituted_with_a_denial() -> None:
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="redact the command",
        modifications={"redactions": [{"path": "/arguments/command"}]},
        client_cannot_apply_modify=True,
    )
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation))
    request, response = _tool_call(guardian, session_id)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    # §6.5 pins the reason_codes value exactly.
    assert response["result"]["reason_codes"] == ["modify_unsupported"]
    assert "/arguments/command" in response["result"]["reasoning"]
    assert guardian.schemas.validate_response(response) is None


def test_a_modify_the_agent_cannot_apply_at_postcompact_is_an_allow() -> None:
    events: list[dict] = []
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="rewrite the summary",
        modifications={"modified_content": "rewritten"},
        client_cannot_apply_modify=True,
    )
    guardian, session_id = _guardian_handshake(
        _StubEngine(evaluation), methods=("steps/postCompact",), audit=events.append
    )
    request, response = _tool_call(
        guardian,
        session_id,
        method="steps/postCompact",
        payload={
            "summary": {"value": "compacted", "provenance": {"provenance_id": "p1", "origin": "agent_generated"}},
            "entries_compacted": ["s-1"],
            "pre_compact_chain_hash": "0" * 64,
            "post_compact_chain_hash": "0" * 64,
        },
    )
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "allow"
    assert response["result"]["reason_codes"] == ["modify_unsupported"]
    # postCompact's audit event must name the rewrite it could not deliver.
    assert [event["event"] for event in events] == ["modify_unsupported"]
    assert events[0]["intended_modifications"] == {"modified_content": "rewritten"}
    assert "modified_content" in events[0]["reasoning"]


def test_a_modify_capable_agent_still_gets_modifications() -> None:
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="redact the command",
        modifications={"redactions": [{"path": "/arguments/command"}]},
    )
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation))
    request, response = _tool_call(guardian, session_id)
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "modify"


def test_the_modify_substitution_is_recorded_with_the_audit_sink() -> None:
    events: list[dict] = []
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="redact the command",
        modifications={"redactions": [{"path": "/arguments/command"}]},
        client_cannot_apply_modify=True,
    )
    guardian, session_id = _guardian_handshake(_StubEngine(evaluation), audit=events.append)
    _tool_call(guardian, session_id)
    assert [event["event"] for event in events] == ["modify_unsupported"]
    assert events[0]["session_id"] == session_id
    assert events[0]["method"] == "steps/toolCallRequest"
    assert events[0]["reason_codes"] == ["modify_unsupported"]
    assert "/arguments/command" in events[0]["reasoning"]
    assert events[0]["intended_modifications"] == {"redactions": [{"path": "/arguments/command"}]}


def test_a_modify_at_a_hook_without_modify_keeps_its_own_reason_code() -> None:
    """The permitted-dispositions substitution runs first: its code is the accurate one.

    sessionStart permits ALLOW/DENY only, so the MODIFY is substituted with
    disposition_not_permitted before §6.5 could ever see it — and no
    modify_unsupported event is recorded, because nothing tried to deliver a
    modification.
    """
    events: list[dict] = []
    evaluation = Evaluation(
        decision=MODIFY,
        reasoning="stub",
        modifications={"modified_content": "x"},
        client_cannot_apply_modify=True,
    )
    guardian, session_id = _guardian_handshake(
        _StubEngine(evaluation), methods=("steps/sessionStart",), audit=events.append
    )
    request, response = _tool_call(guardian, session_id, method="steps/sessionStart", payload={})
    verify_response(response, session_id, request["id"])
    assert response["result"]["decision"] == "deny"
    assert response["result"]["reason_codes"] == ["disposition_not_permitted"]
    assert events == []


def test_a_post_verification_failure_is_a_signed_denial(monkeypatch) -> None:
    """A failure after the signature verified must not become an error the agent may proceed on."""
    guardian, session_id = _guardian_handshake(_StubEngine(Evaluation(decision="allow")))

    def explode(*args, **kwargs):
        raise RuntimeError("chain append exploded")

    monkeypatch.setattr(AuditChain, "append", explode)
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
    assert "chain_hash" not in response["result"]


def test_a_duplicate_member_is_a_parse_error(server) -> None:
    """Two parsers must not disagree about one signed body (the Go port refuses it too)."""
    import json
    import urllib.request

    body = b'{"jsonrpc":"2.0","method":"system/ping","id":"x","id":"y","params":{}}'
    request = urllib.request.Request(server.url, data=body, headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode())
    expect_error(payload, -32700)


def test_a_step_entry_carries_the_go_port_choices(server) -> None:
    """entry_id = request_id, metadata.turn_id carried, timestamp is the write clock."""
    session_id = _session(server)
    request_timestamp = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    request = envelope(
        "steps/toolCallRequest",
        session_id,
        {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, "raw_command": "ls"},
        timestamp=request_timestamp,
    )
    request["params"]["metadata"]["turn_id"] = "t-1"
    before = datetime.now(timezone.utc)
    signed_post(server.url, request, session_id)
    after = datetime.now(timezone.utc)
    session = server.guardian.store.get(session_id)
    entry = session.chain.entries[-1].to_dict()
    assert entry["entry_id"] == request["params"]["request_id"]
    assert entry["step_id"] == request["params"]["request_id"]
    assert entry["turn_id"] == "t-1"
    # The entry's timestamp is when the entry was written (context-entry.json
    # says exactly that; the Go port does the same), not the request's stale
    # timestamp — proven by the write happening between the two clocks.
    written = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
    assert before <= written <= after


def test_modify_unsupported_names_the_intended_modification() -> None:
    substituted = _modify_unsupported(
        "steps/toolCallRequest",
        Evaluation(
            decision=MODIFY,
            reasoning="redact",
            modifications={"redactions": [{"path": "/arguments/token"}], "parameter_overrides": {"command": "ls"}},
        ),
    )
    assert substituted.decision == "deny"
    assert substituted.reason_codes == ["modify_unsupported"]
    assert "/arguments/token" in substituted.reasoning
    assert "command" in substituted.reasoning


def test_modify_unsupported_at_postcompact_is_an_allow() -> None:
    substituted = _modify_unsupported(
        "steps/postCompact",
        Evaluation(decision=MODIFY, reasoning="rewrite", modifications={"modified_content": "x"}),
    )
    assert substituted.decision == "allow"
    assert substituted.reason_codes == ["modify_unsupported"]
