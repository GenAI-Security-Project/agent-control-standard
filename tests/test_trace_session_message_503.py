import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
MAPPING = json.loads(
    (ROOT / "specification" / "v0.1.0" / "trace" / "otel-mapping.json").read_text()
)["properties"]["step_to_span"]["default"]


def test_message_spans_require_ordered_content_types():
    for step in ("steps/userMessage", "steps/agentResponse"):
        assert "acs.content.types" in MAPPING[step]["required_attributes"]
        assert "payload.content order" in MAPPING[step]["_note"]


def test_session_start_attributes_are_conditional_with_sources():
    session = MAPPING["steps/sessionStart"]
    assert session["conditional_attributes"] == [
        "acs.tenant_id",
        "acs.user.id",
        "acs.policy_mode",
    ]
    assert "params.tenant_id" in session["_note"]
    assert "payload.user_identity.user_id" in session["_note"]
    assert "payload.policy_mode" in session["_note"]
