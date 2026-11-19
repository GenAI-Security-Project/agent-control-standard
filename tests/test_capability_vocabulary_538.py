"""Regression guards for Issue #538 (items 1, 2, and 4):
capability vocabulary and matching, Capability vs. AgBOM agent_capability
disambiguation and concept count parity, and Section 11 resource URI rules.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SPEC_V010 = ROOT / "specification" / "v0.1.0"

CAPABILITY_DOC = DOCS / "concepts" / "capability.md"
SKILL_DOC = DOCS / "concepts" / "skill.md"
CONCEPTS_README = DOCS / "concepts" / "README.md"
IDENTITY_OVERVIEW = DOCS / "identity" / "overview.md"
INSTRUMENT_SPEC = DOCS / "spec" / "instrument" / "specification.md"
ACS_IN_ACTION = DOCS / "topics" / "ACS_in_action_example.md"
AGBOM_COMPONENT = SPEC_V010 / "agbom" / "component.json"
TOOL_CALL_REQUEST = SPEC_V010 / "hooks" / "tool-call-request.json"

CORE_CAPABILITIES = (
    "filesystem.read",
    "filesystem.write",
    "filesystem.delete",
    "network.egress",
    "process.execute",
    "memory.read",
    "memory.write",
    "subagent.spawn",
)


def _section_11_text() -> str:
    text = INSTRUMENT_SPEC.read_text(encoding="utf-8")
    match = re.search(
        r"^## 11\. Platform / OS Independence\b(.*?)(?=^## 12\.)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, "Section 11 heading not found in specification.md"
    return match.group(1)


def test_capability_matching_and_core_illustrative_set():
    """Item 1: capability.md, specification.md §11, and tool-call-request.json
    state that v0.1 has no central capability registry, uses deployment-local
    exact string matching over domain.verb, and lists the core illustrative set.
    """
    cap_doc = CAPABILITY_DOC.read_text(encoding="utf-8")
    sec11 = _section_11_text()
    tcr_schema = json.loads(TOOL_CALL_REQUEST.read_text(encoding="utf-8"))
    tcr_desc = tcr_schema["properties"]["capability"]["description"]

    for label, surface in (
        ("docs/concepts/capability.md", cap_doc),
        ("docs/spec/instrument/specification.md §11", sec11),
        ("specification/v0.1.0/hooks/tool-call-request.json", tcr_desc),
    ):
        assert "no central capability registry" in surface, (
            f"{label} must state that v0.1 defines no central capability registry"
        )
        assert "deployment-local exact string matching" in surface, (
            f"{label} must state deployment-local exact string matching"
        )
        assert "domain.verb" in surface, (
            f"{label} must name the hierarchical domain.verb convention"
        )
        for cap in CORE_CAPABILITIES:
            assert cap in surface, f"{label} omits core illustrative capability {cap!r}"


def test_capability_vs_agbom_agent_capability_disambiguation():
    """Item 2a: capability.md and skill.md distinguish the abstract permission
    Capability from the AgBOM agent_capability inventory component, and skill.md
    links to both Inspect and Capability.
    """
    cap_doc = CAPABILITY_DOC.read_text(encoding="utf-8")
    assert "agent_capability" in cap_doc
    assert "agbom/component.json" in cap_doc
    assert "../spec/inspect/README.md" in cap_doc

    skill_doc = SKILL_DOC.read_text(encoding="utf-8")
    assert "[`agent_capability`](../spec/inspect/README.md)" in skill_doc
    assert "[Capability](./capability.md)" in skill_doc
    assert "agbom/component.json" in skill_doc


def test_concept_count_and_list_match_across_concepts_and_identity():
    """Item 2b: docs/concepts/README.md and docs/identity/overview.md agree on
    all eight cross-cutting concepts and match the Pages table.
    """
    concepts_text = CONCEPTS_README.read_text(encoding="utf-8")
    identity_text = IDENTITY_OVERVIEW.read_text(encoding="utf-8")

    assert "eight foundational concepts" in concepts_text
    assert "eight cross-cutting concepts" in identity_text

    table_rows = re.findall(
        r"^\|\s*\[([^\]]+)\]\(\./[^)]+\.md\)\s*\|",
        concepts_text,
        flags=re.MULTILINE,
    )
    assert len(table_rows) == 8, f"Expected 8 concept pages in table, got {table_rows}"

    for concept in (
        "agents",
        "identity",
        "session lifecycle",
        "intent",
        "provenance",
        "capability",
        "skill",
        "trust basis",
    ):
        assert concept in concepts_text.lower(), (
            f"docs/concepts/README.md prose/table missing {concept!r}"
        )
        assert concept in identity_text.lower(), (
            f"docs/identity/overview.md concept list missing {concept!r}"
        )


def test_section_11_resource_uri_rules_and_worked_example():
    """Item 4: Section 11 scopes RFC 3986 URIs to addressable endpoints
    (component.endpoint, definition.ref) while allowing deployment-canonical
    identifiers for domain-specific resource scopes; ACS_in_action_example.md
    uses mailto: for email resources; agbom/component.json cites Section 11.
    """
    sec11 = _section_11_text()
    assert "Resource identifiers MUST use URI form" not in sec11
    assert "component.endpoint" in sec11
    assert "definition.ref" in sec11
    assert "RFC 3986" in sec11
    assert "Intent.parsed[].resource" in sec11
    assert "mailto:" in sec11

    example_text = ACS_IN_ACTION.read_text(encoding="utf-8")
    assert '"resource": "manager@example.com"' not in example_text
    assert example_text.count('"resource": "mailto:manager@example.com"') >= 2

    comp_raw = AGBOM_COMPONENT.read_text(encoding="utf-8")
    assert "Section 3.11" not in comp_raw
    assert "posix:///" not in comp_raw
    comp_schema = json.loads(comp_raw)
    endpoint_desc = comp_schema["properties"]["endpoint"]["description"]
    assert "Section 11" in endpoint_desc
    assert "file:///" in endpoint_desc
    assert "https://" in endpoint_desc
