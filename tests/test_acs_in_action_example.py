"""Keep docs/topics/ACS_in_action_example.md and docs/topics/authorization-paradigms.md valid against v0.1.0.

The walkthrough previously emitted agbom/snapshot before steps/sessionStart, omitted
signature and chain_hash on its full envelopes without saying so, claimed to populate
trust when no JSON block did, and repeated structured IDs/versions inside reasoning.
"""

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
PAGE = ROOT / "docs" / "topics" / "ACS_in_action_example.md"
PARADIGMS_PAGE = ROOT / "docs" / "topics" / "authorization-paradigms.md"

RFC2119_RE = re.compile(
    r"\b(MUST NOT|SHOULD NOT|SHALL NOT|MUST|SHALL|SHOULD|REQUIRED|RECOMMENDED|MAY|OPTIONAL)\b"
)


def _load_schemas():
    schemas = {}
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            schemas[path.relative_to(SPEC).as_posix()] = doc
    return schemas


SCHEMAS = _load_schemas()
REGISTRY = Registry().with_resources(
    (doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
    for doc in SCHEMAS.values()
)


def _validate(schema, instance):
    Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker()).validate(instance)


def _json_blocks(text: str) -> list[dict]:
    return [json.loads(block) for block in re.findall(r"```json\n(.*?)```", text, re.DOTALL)]


def _rego_blocks(text: str) -> list[str]:
    return re.findall(r"```rego\n(.*?)```", text, re.DOTALL)


def _iter_provenance_objects(obj):
    if isinstance(obj, dict):
        if "provenance" in obj and isinstance(obj["provenance"], dict):
            yield obj["provenance"]
        for value in obj.values():
            yield from _iter_provenance_objects(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_provenance_objects(item)


def test_sequence_puts_session_start_before_agbom_snapshot_and_shows_deny():
    text = PAGE.read_text(encoding="utf-8")
    mermaid = re.search(r"```mermaid\n(.*?)```", text, re.DOTALL)
    assert mermaid, "ACS_in_action_example.md has no mermaid sequence diagram"
    diagram = mermaid.group(1)
    assert diagram.index("steps/sessionStart") < diagram.index("agbom/snapshot"), (
        "agbom/snapshot must fire after steps/sessionStart (hooks.md / inspect/README.md)"
    )
    assert "deny" in diagram, "sequence diagram must show that deny is a legal verdict"


def test_full_wire_messages_validate_against_v01_schemas_and_carry_core_fields():
    blocks = _json_blocks(PAGE.read_text(encoding="utf-8"))
    envelopes = [b for b in blocks if b.get("jsonrpc") == "2.0"]
    requests = [e for e in envelopes if "method" in e]
    responses = [e for e in envelopes if "result" in e]

    assert len(requests) >= 1
    assert len(responses) >= 2

    req = requests[0]
    for r in requests:
        _validate(SCHEMAS["request-envelope.json"], r)
        assert r["method"] == "steps/toolCallRequest"
        _validate(SCHEMAS["hooks/tool-call-request.acs-provenance.json"], r["params"]["payload"])
        assert "signature" in r["params"], "ACS-Core requests require params.signature"
        for prov in _iter_provenance_objects(r):
            assert "trust" not in prov, "factual-only provenance example must not populate trust"

    decisions = {}
    for resp in responses:
        _validate(SCHEMAS["response-envelope.json"], resp)
        result = resp["result"]
        decisions[result["decision"]] = resp
        assert "signature" in result, "ACS-Core responses require result.signature"
        assert "chain_hash" in result, "toolCallRequest responses require result.chain_hash"

    assert {"allow", "deny"} <= set(decisions), (
        f"expected both allow and deny full responses, got {set(decisions)}"
    )
    allow_resp = decisions["allow"]
    assert allow_resp["id"] == req["id"], "allow response id must match the worked request"
    assert allow_resp["result"]["request_id"] == req["params"]["request_id"], (
        "allow response request_id must match the worked request"
    )
    assert "reasoning" not in allow_resp["result"], (
        "allow example should demonstrate omitting optional reasoning per §6.1"
    )


def test_paradigm_excerpts_fit_acs_result_and_avoid_structured_reasoning_dumps():
    blocks = _json_blocks(PAGE.read_text(encoding="utf-8"))
    excerpts = [b for b in blocks if b.get("jsonrpc") != "2.0"]
    assert len(excerpts) >= 5, "expected excerpts for IBAC, FIDES, CaMeL, AARM, and composition"

    for excerpt in excerpts:
        wrapped = {
            "jsonrpc": "2.0",
            "id": "excerpt-check",
            "result": {
                "type": "final",
                "acs_version": "0.1.0",
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                **excerpt,
            },
        }
        _validate(SCHEMAS["response-envelope.json"], wrapped)
        ibac = excerpt.get("policy_data", {}).get("ibac")
        if isinstance(ibac, dict) and "intent_parsed" in ibac:
            intent_parsed_schema = SCHEMAS["hooks/session-start.json"]["properties"]["intent"]["properties"]["parsed"]
            _validate(intent_parsed_schema, ibac["intent_parsed"])

    for block in blocks:
        result = block.get("result", block)
        reasoning = result.get("reasoning", "")
        if not reasoning:
            continue
        assert "provenance_id=" not in reasoning, reasoning
        assert "version v" not in reasoning, reasoning
        assert not re.search(r"\b(session|step)\s+[a-z0-9-]+", reasoning, re.I), reasoning
        for ref in result.get("policy_references", []):
            assert ref["policy_id"] not in reasoning, reasoning
            if "rule_id" in ref:
                assert ref["rule_id"] not in reasoning, reasoning
        for pid in result.get("cited_provenance_ids", []):
            assert not re.search(rf"\b{re.escape(pid)}\b", reasoning), reasoning


def test_rego_examples_declare_rego_v1_and_topics_pages_are_non_normative():
    for page in (PAGE, PARADIGMS_PAGE):
        text = page.read_text(encoding="utf-8")
        rego_blocks = _rego_blocks(text)
        assert rego_blocks, f"{page.name} should include an OPA/Rego example"
        for block in rego_blocks:
            assert "import rego.v1" in block, f"Rego snippet in {page.name} must declare import rego.v1"

        prose = re.sub(r"```.*?```", "", text, flags=re.S)
        prose = re.sub(r"`[^`]+`", "", prose)
        hits = RFC2119_RE.findall(prose)
        assert not hits, f"Non-normative page {page.name} must not use RFC 2119 keywords: {hits}"
