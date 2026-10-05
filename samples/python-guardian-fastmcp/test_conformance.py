# SPDX-License-Identifier: Apache-2.0
"""Validates every envelope this sample emits against the repository's own schemas.

The stdlib suite in test_sample.py checks behaviour. It cannot check shape,
because agreeing with yourself about a wire format proves nothing. These tests
load `specification/v0.1.0/` straight off disk and validate against it, so a
drift between the sample and the standard fails here rather than in someone
else's integration.

Needs `jsonschema`, which is not in `uv.lock`. It runs from
`.github/workflows/samples.yml`, not from the docs deploy gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
from referencing import Registry, Resource  # noqa: E402

from fastmcp_instrumentation import build_tool_call_envelope  # noqa: E402
from guardian import Guardian  # noqa: E402

SPEC = Path(__file__).resolve().parents[2] / "specification" / "v0.1.0"
SESSION = "11111111-2222-4333-8444-555555555555"


@pytest.fixture(scope="module")
def registry() -> Registry:
    """Every schema in the tree, keyed by its own $id.

    Relative refs (`handshake.json`, `../provenance.json`) then resolve
    against that base the way the spec authors intended.
    """
    registry = Registry()
    for path in SPEC.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in doc:
            registry = registry.with_resource(
                doc["$id"], Resource.from_contents(doc))
    return registry


def _validate(instance, schema_name: str, registry: Registry) -> None:
    schema = json.loads((SPEC / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema, registry=registry).validate(instance)


def _guardian_response(payload: dict, log_path,
                       method: str = "steps/toolCallRequest") -> dict:
    envelope = {
        "jsonrpc": "2.0", "method": method, "id": 1,
        "params": {
            "acs_version": "0.1.0",
            "request_id": "99999999-8888-4777-8666-555555555555",
            "timestamp": "2026-09-10T06:00:00+00:00",
            "metadata": {"agent_id": "a", "session_id": SESSION},
            "payload": payload,
        },
    }
    return Guardian(log_path=str(log_path)).handle(envelope)


def test_client_request_envelope_is_conformant(registry):
    env = build_tool_call_envelope("read_file", {"path": "/tmp/x", "lines": 10})
    _validate(env, "request-envelope.json", registry)


def test_client_payload_is_conformant(registry):
    env = build_tool_call_envelope("read_file", {"path": "/tmp/x"})
    _validate(env["params"]["payload"], "hooks/tool-call-request.json", registry)


def test_raw_arguments_would_have_failed(registry):
    """The regression guard.

    This is the exact shape the sample emitted before: arguments mapped to
    bare scalars. It is invalid, and this test is why nobody can put it back.
    """
    bad = {"tool": {"name": "read_file"}, "arguments": {"path": "/tmp/x"}}
    with pytest.raises(jsonschema.ValidationError):
        _validate(bad, "hooks/tool-call-request.json", registry)


@pytest.mark.parametrize("tool,args,expected", [
    ("search_web", {"q": {"value": "x"}}, "allow"),
    ("delete_volume", {}, "deny"),
    ("read_file", {"path": {"value": "../../etc/passwd"}}, "deny"),
])
def test_guardian_results_are_conformant(tool, args, expected, registry, tmp_path):
    out = _guardian_response(
        {"tool": {"name": tool}, "arguments": args}, tmp_path / "log.jsonl")
    # Assert the branch first. response-envelope.json accepts an `error`
    # response too, so conformance alone would pass on a Guardian that
    # never reached its policy at all.
    assert out["result"]["decision"] == expected, out
    _validate(out, "response-envelope.json", registry)


def test_guardian_handshake_is_conformant(registry, tmp_path):
    out = _guardian_response({}, tmp_path / "log.jsonl", method="handshake/hello")
    assert "negotiated_version" in out["result"], out
    _validate(out, "response-envelope.json", registry)


def test_guardian_error_is_conformant(registry, tmp_path):
    out = _guardian_response(
        {"tool": {"name": "t"}, "arguments": {"a": 1}}, tmp_path / "log.jsonl")
    assert out["error"]["code"] == -32600, out
    _validate(out, "response-envelope.json", registry)


def test_reasoning_present_on_every_deny(registry, tmp_path):
    out = _guardian_response(
        {"tool": {"name": "delete_volume"}, "arguments": {}},
        tmp_path / "log.jsonl")
    result = out["result"]
    assert result["decision"] == "deny"
    # response-envelope.json states reasoning is REQUIRED on deny.
    assert result["reasoning"]
