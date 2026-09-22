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


def test_an_unimplemented_but_negotiated_method_cannot_happen_and_an_unknown_namespace_does_not(server) -> None:
    # steps/nonexistent is not in IMPLEMENTED_METHODS, so the handshake could
    # not have negotiated it; a client that sends it anyway gets -32003.
    session_id = _session(server)
    request = envelope("steps/nonexistent", session_id, {})
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
    """steps/toolCallRequest -> tool-call-request; system/ping -> system-ping."""
    name = method.split("/", 1)[1]
    out = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0:
            out.append("-")
        out.append(char.lower())
    return "".join(out)


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
