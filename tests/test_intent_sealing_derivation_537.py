"""Regression guards for Issue #537: Intent sealing mechanism, wire representation, and goal-to-capability derivation."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTENT_CONCEPT = ROOT / "docs" / "concepts" / "intent.md"
INSTRUMENT_SPEC = ROOT / "docs" / "spec" / "instrument" / "specification.md"
WORKED_EXAMPLE = ROOT / "docs" / "topics" / "ACS_in_action_example.md"
TOOL_CALL_SCHEMA = ROOT / "specification" / "v0.1.0" / "hooks" / "tool-call-request.json"
AGT_GO_TOOL_CALL_SCHEMA = (
    ROOT
    / "reference-implementations"
    / "agt-go"
    / "internal"
    / "schema"
    / "specification"
    / "v0.1.0"
    / "hooks"
    / "tool-call-request.json"
)


def _section_8_4() -> str:
    text = INSTRUMENT_SPEC.read_text(encoding="utf-8")
    start = text.index("### 8.4 Intent")
    end = text.index("### 8.5 ", start)
    return text[start:end]


def test_item1_intent_immutability_mechanism_and_origin_check():
    """Both docs/concepts/intent.md and §8.4 define the three-part mechanism."""
    for label, text in (
        ("docs/concepts/intent.md", INTENT_CONCEPT.read_text(encoding="utf-8")),
        ("specification.md §8.4", _section_8_4()),
    ):
        assert "Host-side capture" in text, f"{label} missing Host-side capture"
        assert "Guardian sealing & state pinning" in text, f"{label} missing Guardian sealing & state pinning"
        assert "Origin check" in text, f"{label} missing Origin check"
        assert "chain_hash" in text, f"{label} missing chain_hash binding"
        assert "D-031" in text, f"{label} missing D-031 pin rule"
        assert "user_input" in text, f"{label} missing user_input origin requirement"
        assert "model_generated" in text, f"{label} missing model_generated rejection"
        assert "tool_output" in text, f"{label} missing tool_output rejection"


def test_item2_intent_wire_representation_and_tool_call_request_distinction():
    """docs/concepts/intent.md drops 'not a wire format' and distinguishes toolCallRequest.intent."""
    concept = INTENT_CONCEPT.read_text(encoding="utf-8")
    assert "not a wire format" not in concept
    for token in (
        "on-wire representation",
        "sessionStart",
        "agentTrigger",
        "subagentStart",
        "scope_expansion",
        "toolCallRequest.intent",
        "never trusted as session authorization",
    ):
        assert token in concept, f"docs/concepts/intent.md missing {token!r}"

    schema = json.loads(TOOL_CALL_SCHEMA.read_text(encoding="utf-8"))
    intent_prop = schema["properties"]["intent"]
    assert set(intent_prop["properties"]) == {"description", "goal"}
    desc = intent_prop["description"]
    assert "self-reported rationale" in desc
    assert "distinct from session Intent" in desc
    assert "never trusted as session authorization" in desc
    assert TOOL_CALL_SCHEMA.read_bytes() == AGT_GO_TOOL_CALL_SCHEMA.read_bytes()


def test_item3_goal_to_capability_derivation_and_worked_example():
    """Derivation contract and approximation bounds are documented and the worked example uses {tool, operation, resource}."""
    for label, text in (
        ("docs/concepts/intent.md", INTENT_CONCEPT.read_text(encoding="utf-8")),
        ("specification.md §8.4", _section_8_4()),
    ):
        assert "Intent.raw" in text, f"{label} missing Intent.raw"
        assert "AgBOM" in text, f"{label} missing AgBOM tool inventory input"
        assert "Under-approximation" in text, f"{label} missing Under-approximation handling"
        assert "Over-approximation" in text, f"{label} missing Over-approximation handling"
        assert "scope_expansion" in text, f"{label} missing scope_expansion reference"

    example = WORKED_EXAMPLE.read_text(encoding="utf-8")
    assert "Summarize Q3 board deck and email highlights to team@acme.com" in example
    assert "Intent.raw" in example
    assert '"tool": "docs.read", "operation": "summarize", "resource": "q3-board-deck"' in example
    assert '"intent_parsed": ["summarize.read"]' not in example
