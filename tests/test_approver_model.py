"""Approver rules in Specification §9 and ask-details.json (#51)."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "spec" / "instrument" / "specification.md"
ASK = ROOT / "specification" / "v0.1.0" / "ask-details.json"


def approver_section():
    text = SPEC.read_text(encoding="utf-8")
    return text.split("## 9. Approver Model", 1)[1].split("## 10.", 1)[0]


def test_every_approver_type_must_authenticate():
    section = approver_section()
    assert "REQUIRED across all three approver types" in section
    assert "the Guardian MUST verify" in section
    assert "out of band" in section
    assert "a claimed `approver.id` alone is insufficient" in section
    assert "does not by itself establish that verification occurred" in section
    assert "when and only when a verified approver grants" in section


def test_the_v0_1_0_wire_contract_is_unchanged():
    """A required `auth` breaks valid payloads, so issue #51 keeps it for a later spec version."""
    schema = json.loads(ASK.read_text(encoding="utf-8"))
    assert schema["properties"]["approver"]["required"] == ["type", "id"]
    assert schema["properties"]["timeout_disposition"]["default"] == "deny"
