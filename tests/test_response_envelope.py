"""The response envelope must be able to state every response the wire carries.

`result` used to be an unconditional reference to AcsResult, which requires
`decision`. A ServerHello has no decision, so a conformant handshake/hello response
could not satisfy response-envelope.json, and an implementation checking its own
responses had to either call a correct handshake invalid or skip the check. These
tests hold `result` to both shapes and to nothing else.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE

SPEC = Path(__file__).resolve().parents[1] / "specification" / "v0.1.0"

SERVER_HELLO = {
    "negotiated_version": "0.1.0",
    "methods_evaluated": ["steps/toolCallRequest"],
    "selected_transport": "http",
    "timeout_config": {"default_ms": 5000},
    "on_decision_failure": "proceed",
}

ALLOW = {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "0d2b0f1e-3d3d-4e6b-9c7a-1c9d4b0b9a11",
    "decision": "allow",
}


def _response_envelope_validator() -> Draft202012Validator:
    """Build a validator over the whole package, so cross-file refs resolve by $id."""
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)
    envelope = json.loads((SPEC / "response-envelope.json").read_text(encoding="utf-8"))
    assert envelope["$id"] == BASE + "v0.1.0/response-envelope.json"
    return Draft202012Validator(envelope, registry=registry)


def _envelope(result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "result": result}


def test_a_decision_result_is_accepted():
    assert _response_envelope_validator().is_valid(_envelope(ALLOW))


def test_a_server_hello_result_is_accepted():
    assert _response_envelope_validator().is_valid(_envelope(SERVER_HELLO))


def test_a_decision_result_without_a_decision_is_rejected():
    """A malformed AcsResult must not be excused as a ServerHello."""
    lost = {key: value for key, value in ALLOW.items() if key != "decision"}
    assert not _response_envelope_validator().is_valid(_envelope(lost))


def test_a_server_hello_missing_a_required_field_is_rejected():
    """The ServerHello branch is checked against handshake.json, not merely permitted."""
    partial = {key: value for key, value in SERVER_HELLO.items() if key != "timeout_config"}
    assert not _response_envelope_validator().is_valid(_envelope(partial))
