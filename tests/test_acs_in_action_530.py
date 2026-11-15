from pathlib import Path


ROOT = Path(__file__).parents[1]
PAGE = (ROOT / "docs" / "topics" / "ACS_in_action_example.md").read_text(encoding="utf-8")


def test_acs_in_action_orders_session_start_before_agbom_snapshot():
    sequence = PAGE.split("```mermaid", 1)[1].split("```", 1)[0]
    assert sequence.index("steps/sessionStart") < sequence.index("agbom/snapshot")
    assert "DENY" in sequence


def test_acs_in_action_explains_optional_paradigm_styles():
    assert "The ACS wire is paradigm-neutral." in PAGE
    assert "profiles, not paradigm names" in PAGE
    assert "role, identity, and resource rule" in PAGE
    assert '"trust": "trusted"' in PAGE
    assert "omit `signature` and `chain_hash` for brevity" in PAGE
