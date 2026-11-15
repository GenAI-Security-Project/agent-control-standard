"""Guards for the disposition catalog, the ASK and DEFER contract, and optional reasoning.

Three surfaces state which dispositions a hook accepts: the catalog on the Hooks page,
the taxonomy table in Specification section 5, and `x-acs-allowed-dispositions` in each
hook schema. Before the catalog, section 5 marked three hooks decision-eligible while
the Hooks page marked fourteen, and 23 of 29 hook schemas said nothing. These tests hold
the three views to one set, and hold the response envelope to the confidential-policy
rule: `reasoning` is optional on every decision.
"""
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
HOOK_SCHEMAS = SPEC / "hooks"
SPECIFICATION = (ROOT / "docs" / "spec" / "instrument" / "specification.md").read_text(encoding="utf-8")
HOOKS_PAGE = (ROOT / "docs" / "spec" / "instrument" / "hooks.md").read_text(encoding="utf-8")
AGENTS = (ROOT / "docs" / "concepts" / "agents.md").read_text(encoding="utf-8")

DISPOSITIONS = {"allow", "deny", "modify", "ask", "defer"}
ALLOW_ONLY = {"subagentStop", "skillUnload", "turnEnd", "sessionEnd", "system/ping"}
REQUEST_ID = "0d2b0f1e-3d3d-4e6b-9c7a-1c9d4b0b9a11"

CATALOG_ROW = re.compile(r"^\|\s*(?:\[)?`([A-Za-z][A-Za-z0-9/*]*)`(?:\]\([^)]*\))?\s*\|(.*)$")
TITLE = re.compile(r"^((?:steps|agbom|system)/[A-Za-z]+) payload")


def _dispositions(cell: str) -> set[str]:
    return {m.lower() for m in re.findall(r"`(ALLOW|DENY|MODIFY|ASK|DEFER)`", cell)}


def _catalog() -> dict[str, set[str]]:
    """Method -> dispositions, read from the Hooks page catalog (Dispositions is column 3)."""
    section = HOOKS_PAGE.split("## Disposition catalog (normative)", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        match = CATALOG_ROW.match(line)
        if not match:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        name = re.sub(r"[\[\]`]|\(#.*?\)", "", cells[0])
        rows[name] = _dispositions(cells[2])
    return rows


def _taxonomy() -> dict[str, set[str]]:
    """Hook -> dispositions, read from the Specification section 5 table (column 4)."""
    section = SPECIFICATION.split("## 5. Hook Taxonomy", 1)[1].split("\n## 6.", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].isdigit():
            rows[cells[1].strip("`")] = _dispositions(cells[3])
    return rows


def _schemas() -> dict[str, dict]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(HOOK_SCHEMAS.glob("*.json"))
    }


def _method(schema: dict) -> str:
    return TITLE.match(schema["title"]).group(1)


def _validator() -> Draft202012Validator:
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    envelope = json.loads((SPEC / "response-envelope.json").read_text(encoding="utf-8"))
    return Draft202012Validator(envelope, registry=Registry().with_resources(resources))


def _result(decision: str, **extra) -> dict:
    result = {"type": "final", "acs_version": "0.1.0", "request_id": REQUEST_ID, "decision": decision}
    result.update(extra)
    return {"jsonrpc": "2.0", "id": "rpc-1", "result": result}


ASK_DETAILS = {
    "approver": {"type": "human", "id": "alice"},
    "question": "Send the wire?",
    "timeout_seconds": 60,
}
DEFER_DETAILS = {"reason": "low_confidence", "resolution_method": "human_approval", "resolution_timeout_ms": 30000}


def test_every_hook_schema_declares_its_dispositions():
    for name, schema in _schemas().items():
        allowed = schema.get("x-acs-allowed-dispositions")
        assert allowed, f"{name} does not declare x-acs-allowed-dispositions"
        assert set(allowed) <= DISPOSITIONS and len(allowed) == len(set(allowed)), name
        assert "allow" in allowed, f"{name}: ALLOW is legal at every hook"


def test_the_provenance_variants_match_their_base_schema():
    schemas = _schemas()
    for name, schema in schemas.items():
        if name.endswith(".acs-provenance.json"):
            base = schemas[name.replace(".acs-provenance.json", ".json")]
            assert schema["x-acs-allowed-dispositions"] == base["x-acs-allowed-dispositions"], name


def test_the_catalog_matches_the_schemas():
    catalog = _catalog()
    by_method = {
        _method(s): set(s["x-acs-allowed-dispositions"])
        for n, s in _schemas().items()
        if not n.endswith(".acs-provenance.json")
    }
    for method, allowed in by_method.items():
        key = method.removeprefix("steps/")
        assert key in catalog, f"{method} is missing from the catalog"
        assert catalog[key] == allowed, f"{method}: catalog {sorted(catalog[key])} != schema {sorted(allowed)}"


def test_the_catalog_covers_the_wrapped_mcp_namespace():
    assert _catalog()["protocols/MCP/*"] == DISPOSITIONS


def test_section_5_matches_the_catalog():
    catalog = _catalog()
    taxonomy = _taxonomy()
    assert len(taxonomy) == 19
    for hook, allowed in taxonomy.items():
        assert allowed == catalog[hook], f"section 5 and the catalog disagree on {hook}"


def test_audit_only_hooks_accept_only_allow():
    catalog = _catalog()
    for hook in ALLOW_ONLY:
        assert catalog[hook] == {"allow"}, hook
    decision_eligible = [h for h, d in _taxonomy().items() if d - {"allow"} and h != "postCompact"]
    assert len(decision_eligible) == 14


def test_post_compact_accepts_modify_but_not_deny():
    assert _catalog()["postCompact"] == {"allow", "modify"}


def test_only_tool_calls_accept_ask_and_defer():
    asking = {h for h, d in _catalog().items() if {"ask", "defer"} & d}
    assert asking == {"toolCallRequest", "protocols/MCP/*"}


def test_section_6_says_what_happens_on_an_illegal_disposition():
    section = SPECIFICATION.split("## 6. Disposition Vocabulary", 1)[1].split("### 6.1", 1)[0]
    assert "Legal dispositions per hook (normative)" in section
    assert "MUST NOT return a disposition outside that set" in section
    assert "malformed_response" in section and "disposition_not_allowed" in section


@pytest.mark.parametrize("decision, extra", [
    ("deny", {}),
    ("modify", {"modifications": {"modified_content": "x"}}),
    ("ask", {"ask_details": ASK_DETAILS}),
    ("defer", {"defer_details": DEFER_DETAILS}),
])
def test_reasoning_is_optional_on_every_decision(decision, extra):
    validator = _validator()
    assert validator.is_valid(_result(decision, **extra))
    assert validator.is_valid(_result(decision, reasoning="because", **extra))


@pytest.mark.parametrize("decision", ["modify", "ask", "defer"])
def test_the_disposition_payload_is_still_required(decision):
    assert not _validator().is_valid(_result(decision, reasoning="because"))


def test_a_confidential_deny_may_keep_its_codes_off_the_wire():
    assert _validator().is_valid(_result("deny"))
    assert "MAY omit `reasoning` from the wire" in SPECIFICATION
    assert "The log still carries it" in AGENTS


def test_ask_requires_a_designated_approver():
    ask_details = json.loads((SPEC / "ask-details.json").read_text(encoding="utf-8"))
    assert "approver" in ask_details["required"]
    assert "`approver` is REQUIRED whenever the Guardian returns `ASK`" in SPECIFICATION
    section = SPECIFICATION.split("## 9. Approver Model", 1)[1].split("### 9.1", 1)[0]
    assert "MUST NOT return `ASK`" in section
    assert "presents the prompt" in section
    assert "MUST NOT return `ask`" in AGENTS
    assert "presents the prompt" in AGENTS


def test_section_9_2_covers_a_missing_approver():
    section = SPECIFICATION.split("### 9.2", 1)[1].split("## 10.", 1)[0]
    assert "no Approver is designated or reachable" in section
    assert "`DEFER`" in section and "`DENY`" in section


def test_defer_states_where_inputs_and_answers_go():
    defer_details = json.loads((SPEC / "defer-details.json").read_text(encoding="utf-8"))
    assert {"approver", "question", "required_context"} <= set(defer_details["properties"])
    assert "Guardian obtains these inputs itself" in defer_details["properties"]["required_context"]["description"]
    assert "never through the Observed Agent" in SPECIFICATION
    validator = Draft202012Validator(
        defer_details,
        registry=Registry().with_resources(
            (json.loads(p.read_text(encoding="utf-8"))["$id"],
             Resource.from_contents(json.loads(p.read_text(encoding="utf-8")), default_specification=DRAFT202012))
            for p in SPEC.rglob("*.json") if "$id" in json.loads(p.read_text(encoding="utf-8"))
        ),
    )
    assert validator.is_valid({**DEFER_DETAILS, "approver": {"type": "human", "id": "alice"}, "question": "Release it?"})
    assert not validator.is_valid({**DEFER_DETAILS, "approver": {"type": "robot", "id": "x"}})


def test_the_deferral_bound_has_a_default_and_an_outcome():
    assert "the default is 3" in SPECIFICATION
    assert 'reason_codes: ["deferral_limit_reached"]' in SPECIFICATION
