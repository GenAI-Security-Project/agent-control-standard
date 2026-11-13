"""Wrapped MCP has a wire definition, and its documented examples validate.

Conformance makes `protocols/MCP/*` a Core MUST for any deployment whose sessions
involve MCP. For a long time nothing defined it beyond a `method` pattern: the
examples in `extend_mcp.md` carried no `acs_version`, `request_id`, `timestamp`,
`metadata` or `payload`, so none of them passed `request-envelope.json`, and the
Trace mappings never mentioned `protocols/`. These tests read the examples out of
the page and hold them to the envelope schemas and the wrapped MCP schemas, and
hold both Trace mappings to a `protocols/MCP/*` entry.
"""
import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specification" / "v0.1.0"
PAGE = ROOT / "docs" / "spec" / "instrument" / "extend_mcp.md"

FENCE = re.compile(r"^[ \t]*```json[ \t]*\n(.*?)^[ \t]*```", re.DOTALL | re.MULTILINE)
WRAPPED_PREFIX = "protocols/MCP/"
PAYLOAD_ID = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/protocols/mcp-payload.json"
RESULT_ID = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/protocols/mcp-result.json"


def _registry():
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(schema_file):
    schema = json.loads((SPEC / schema_file).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker())


REQUEST = _validator("request-envelope.json")
RESPONSE = _validator("response-envelope.json")
PAYLOAD = _validator("protocols/mcp-payload.json")
RESULT = _validator("protocols/mcp-result.json")


def _errors(validator, instance):
    return [error.message for error in validator.iter_errors(instance)]


def _examples():
    """Every JSON block on the page, in order, tagged by what it is."""
    tagged = []
    for text in FENCE.findall(PAGE.read_text(encoding="utf-8")):
        block = json.loads(text)
        method = block.get("method", "")
        if method.startswith(WRAPPED_PREFIX):
            kind = "wrapped_request"
        elif "method" in block:
            kind = "mcp_request"
        elif "decision" in block.get("result", {}):
            kind = "acs_result"
        elif "result" in block:
            kind = "mcp_response"
        else:
            kind = "other"
        tagged.append((kind, block))
    return tagged


EXAMPLES = _examples()


def _of_kind(kind):
    return [block for tag, block in EXAMPLES if tag == kind]


def test_the_page_carries_every_kind_of_example():
    kinds = {tag for tag, _ in EXAMPLES}
    assert kinds == {"mcp_request", "wrapped_request", "acs_result", "mcp_response"}, kinds
    directions = {block["params"]["payload"]["direction"] for block in _of_kind("wrapped_request")}
    assert {"request", "response"} <= directions
    decisions = {block["result"]["decision"] for block in _of_kind("acs_result")}
    assert {"allow", "modify", "deny"} <= decisions


@pytest.mark.parametrize("block", _of_kind("wrapped_request"), ids=lambda b: f"id{b['id']}")
def test_wrapped_requests_validate_against_the_envelope_and_the_payload_schema(block):
    assert not _errors(REQUEST, block)
    assert not _errors(PAYLOAD, block["params"]["payload"])
    payload = block["params"]["payload"]
    assert block["method"] == WRAPPED_PREFIX + payload["mcp_method"]
    # Required by Core on every request (Conformance, ACS-Core).
    assert "signature" in block["params"]


@pytest.mark.parametrize("block", _of_kind("acs_result"), ids=lambda b: f"id{b['id']}")
def test_guardian_results_validate_against_the_envelope_and_the_result_schema(block):
    assert not _errors(RESPONSE, block)
    assert not _errors(RESULT, block["result"])
    assert "signature" in block["result"]


def test_every_result_answers_a_wrapped_request():
    requests = {block["id"]: block for block in _of_kind("wrapped_request")}
    results = _of_kind("acs_result")
    assert {block["id"] for block in results} == set(requests)
    for result in results:
        request = requests[result["id"]]
        assert result["result"]["request_id"] == request["params"]["request_id"]
        assert result["result"]["acs_version"] == request["params"]["acs_version"]


def test_wrapped_payloads_carry_the_mcp_message_they_follow():
    """The raw MCP message above each wrapped example is the one the payload decomposes."""
    last_request = last_response = None
    checked = 0
    for kind, block in EXAMPLES:
        if kind == "mcp_request":
            last_request = block
        elif kind == "mcp_response":
            last_response = block
        elif kind == "wrapped_request":
            payload = block["params"]["payload"]
            if payload["direction"] == "request":
                assert payload["mcp_method"] == last_request["method"]
                assert payload["mcp_id"] == last_request["id"]
                assert payload["mcp_params"] == last_request["params"]
            else:
                assert payload["mcp_id"] == last_response["id"]
                assert payload["mcp_result"] == last_response["result"]
            checked += 1
    assert checked == len(_of_kind("wrapped_request"))


def test_a_modify_example_leaves_a_valid_payload_once_applied():
    modify = [b for b in _of_kind("acs_result") if b["result"]["decision"] == "modify"]
    assert modify
    for result in modify:
        request = next(b for b in _of_kind("wrapped_request") if b["id"] == result["id"])
        payload = copy.deepcopy(request["params"]["payload"])
        payload["mcp_params"].update(result["result"]["modifications"]["parameter_overrides"])
        assert not _errors(PAYLOAD, payload)


# --- the payload schema's rules ---------------------------------------------


def _request():
    return {"direction": "request", "mcp_method": "resources/read", "mcp_id": 7, "mcp_params": {"uri": "file:///a"}}


def _response():
    return {"direction": "response", "mcp_method": "resources/read", "mcp_id": 7, "mcp_result": {"contents": []}}


def _notification():
    return {"direction": "notification", "mcp_method": "notifications/initialized"}


def test_each_direction_has_a_valid_minimal_form():
    for payload in (_request(), _response(), _notification()):
        assert not _errors(PAYLOAD, payload), payload


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("direction"),
        lambda p: p.pop("mcp_method"),
        lambda p: p.update(direction="sideways"),
        lambda p: p.update(mcp_method="tools call"),
        lambda p: p.update(transport="carrier-pigeon"),
    ],
    ids=["no-direction", "no-method", "bad-direction", "spaced-method", "bad-transport"],
)
def test_a_payload_missing_or_misusing_a_core_field_is_rejected(mutate):
    payload = _request()
    mutate(payload)
    assert _errors(PAYLOAD, payload)


def test_a_request_needs_an_mcp_id_and_carries_no_result():
    no_id = _request()
    del no_id["mcp_id"]
    assert _errors(PAYLOAD, no_id)
    assert _errors(PAYLOAD, {**_request(), "mcp_result": {}})


def test_a_response_has_exactly_one_of_result_and_error():
    neither = _response()
    del neither["mcp_result"]
    both = {**_response(), "mcp_error": {"code": -32602, "message": "bad"}}
    error_only = {key: value for key, value in both.items() if key != "mcp_result"}
    assert _errors(PAYLOAD, neither)
    assert _errors(PAYLOAD, both)
    assert not _errors(PAYLOAD, error_only)
    assert _errors(PAYLOAD, {**_response(), "mcp_params": {}})


def test_a_notification_has_no_mcp_id_or_result():
    assert _errors(PAYLOAD, {**_notification(), "mcp_id": 1})
    assert _errors(PAYLOAD, {**_notification(), "mcp_result": {}})


# --- the result schema's rules ----------------------------------------------


def _allow():
    return {
        "type": "final",
        "acs_version": "0.1.0",
        "request_id": "dad3aa3a-6bb9-4a9f-bccb-344b7121d536",
        "decision": "allow",
    }


def test_a_modify_may_not_replace_the_payload_with_an_opaque_string():
    structured = {**_allow(), "decision": "modify", "reasoning": "mask", "modifications": {"redactions": [{"path": "/mcp_params/arguments/body"}]}}
    opaque = {**structured, "modifications": {"modified_content": "x"}}
    assert not _errors(RESULT, structured)
    assert _errors(RESULT, opaque)
    # The envelope alone accepts it, which is why the wrapped schema exists.
    assert not _errors(RESPONSE, {"jsonrpc": "2.0", "id": 1, "result": opaque})


def test_the_result_schema_keeps_the_envelope_rules():
    assert _errors(RESULT, {**_allow(), "decision": "deny"})


# --- Trace mappings ---------------------------------------------------------


def _default(mapping, table):
    path = SPEC / "trace" / mapping
    return json.loads(path.read_text(encoding="utf-8"))["properties"][table]["default"]


def test_the_otel_mapping_names_a_span_for_protocols_mcp():
    entry = _default("otel-mapping.json", "step_to_span")[WRAPPED_PREFIX + "*"]
    assert entry["span_name"] == "acs.mcp"
    # Both source fields are required on the payload, so neither is conditional.
    schema = json.loads((SPEC / "protocols" / "mcp-payload.json").read_text(encoding="utf-8"))
    assert {"direction", "mcp_method"} <= set(schema["required"])
    assert entry["required_attributes"] == ["acs.mcp.method", "acs.mcp.direction"]
    assert "conditional_attributes" not in entry
    sources = {"acs.mcp.id": "mcp_id", "acs.mcp.server_id": "server_id", "acs.mcp.transport": "transport", "acs.mcp.protocol_version": "protocol_version"}
    assert set(entry["optional_attributes"]) == set(sources)
    for field in sources.values():
        assert field in schema["properties"]
        assert field not in schema["required"]


def test_the_ocsf_mapping_names_a_class_for_protocols_mcp():
    entry = _default("ocsf-mapping.json", "step_to_class")[WRAPPED_PREFIX + "*"]
    assert (entry["class_uid"], entry["class_name"]) == (6003, "API Activity")


def test_the_trace_pages_state_the_mcp_rows():
    events = (ROOT / "docs" / "spec" / "trace" / "events.md").read_text(encoding="utf-8")
    ocsf = (ROOT / "docs" / "spec" / "trace" / "extend_ocsf.md").read_text(encoding="utf-8")
    assert "| `protocols/MCP/*` | `acs.mcp` |" in events
    assert "| `protocols/MCP/*` | API Activity | 6003" in events
    assert "| `protocols/MCP/*` | API Activity | 6003" in ocsf
