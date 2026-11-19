"""Regression guards for issue #533 (items 1, 2, 5, and 6): handshake capability declarations and normative prose."""

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
HANDSHAKE_SCHEMA = ROOT / "specification" / "v0.1.0" / "handshake.json"
AGT_GO_HANDSHAKE_SCHEMA = (
    ROOT
    / "reference-implementations"
    / "agt-go"
    / "internal"
    / "schema"
    / "specification"
    / "v0.1.0"
    / "handshake.json"
)
SPECIFICATION_MD = ROOT / "docs" / "spec" / "instrument" / "specification.md"
CONFORMANCE_MD = ROOT / "docs" / "spec" / "conformance.md"


def _section(text: str, heading: str) -> str:
    """Return markdown content from `heading` up to the next heading of the same or higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    pattern = re.compile(
        r"^" + re.escape(heading) + r"\s*$(.*?)(?=^#{1," + str(level) + r"}\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match is not None, f"Heading {heading!r} not found"
    return match.group(1)


def _client_hello_validator() -> Draft202012Validator:
    schema = json.loads(HANDSHAKE_SCHEMA.read_text(encoding="utf-8"))
    return Draft202012Validator(schema["$defs"]["ClientHello"])


def test_item1_methods_implemented_and_evaluated_rationale_stated():
    spec_s4 = _section(SPECIFICATION_MD.read_text(encoding="utf-8"), "## 4. Capability Negotiation Handshake")
    conformance = CONFORMANCE_MD.read_text(encoding="utf-8")

    for surface_name, text in (("specification.md §4", spec_s4), ("conformance.md", conformance)):
        assert "ClientHello.methods_implemented" in text, f"{surface_name} must name ClientHello.methods_implemented"
        assert "ServerHello.methods_evaluated" in text, f"{surface_name} must name ServerHello.methods_evaluated"
        assert "subagentStart" in text and "protocols/MCP/*" in text, (
            f"{surface_name} must explain conditional Core hook coverage (subagentStart and protocols/MCP/*)"
        )
        assert "synchronous round-trips" in text, (
            f"{surface_name} must state that methods_evaluated lets the Observed Agent skip synchronous round-trips on unevaluated hooks"
        )


def test_item2_client_hello_supports_modify_and_supports_ask_schema():
    schema = json.loads(HANDSHAKE_SCHEMA.read_text(encoding="utf-8"))
    client_hello = schema["$defs"]["ClientHello"]
    props = client_hello["properties"]
    required = set(client_hello["required"])

    for field in ("supports_modify", "supports_ask"):
        assert field in props, f"ClientHello.properties missing {field}"
        assert props[field]["type"] == "boolean", f"ClientHello.{field} must be boolean"
        assert field not in required, f"ClientHello.{field} must remain optional"

    validator = _client_hello_validator()
    baseline_payload = {
        "acs_versions_supported": ["0.1.0"],
        "methods_implemented": ["steps/toolCallRequest"],
        "transports_supported": ["http"],
        "provenance_producer": "none",
    }
    assert validator.is_valid(baseline_payload)
    assert validator.is_valid({**baseline_payload, "supports_modify": False, "supports_ask": False})
    assert validator.is_valid({**baseline_payload, "supports_modify": True, "supports_ask": True})
    assert not validator.is_valid({**baseline_payload, "supports_modify": "no"})
    assert not validator.is_valid({**baseline_payload, "supports_ask": 0})


def test_item2_spec_sections_key_substitutions_on_supports_modify_and_supports_ask():
    spec_text = SPECIFICATION_MD.read_text(encoding="utf-8")
    spec_s4 = _section(spec_text, "## 4. Capability Negotiation Handshake")
    spec_s65 = _section(spec_text, "### 6.5 MODIFY-incapable clients (normative)")
    spec_s92 = _section(spec_text, "### 9.2 Approver-incapable clients (normative)")

    assert "`supports_modify`" in spec_s4 and "`supports_ask`" in spec_s4
    assert "`supports_modify`" in spec_s65 and "`supports_modify: false`" in spec_s65
    assert "ACS does not put this declaration on the wire in v0.1" not in spec_s65
    assert "`supports_ask`" in spec_s92 and "`supports_ask: false`" in spec_s92
    assert "ACS does not put this declaration on the wire in v0.1" not in spec_s92


def test_item5_every_server_hello_field_has_normative_definition_and_trace_section_ref_fixed():
    schema = json.loads(HANDSHAKE_SCHEMA.read_text(encoding="utf-8"))
    server_hello_props = set(schema["$defs"]["ServerHello"]["properties"])
    spec_s4 = _section(SPECIFICATION_MD.read_text(encoding="utf-8"), "## 4. Capability Negotiation Handshake")

    defined_bullets = {
        match.group(1): match.group(2)
        for match in re.finditer(r"^- `([a-z0-9_]+)`:\s+(.+)$", spec_s4, flags=re.MULTILINE)
    }
    assert set(defined_bullets) == server_hello_props, (
        f"§4 ServerHello normative list {sorted(defined_bullets)} != schema properties {sorted(server_hello_props)}"
    )
    assert "MUST send every listed method that it implements" in defined_bullets["methods_evaluated"]
    assert "ClientHello.transports_supported" in defined_bullets["selected_transport"]
    assert "`default_ms`" in defined_bullets["timeout_config"] and "`per_method_ms`" in defined_bullets["timeout_config"]
    assert "`ASK`" in defined_bullets["approver_types_supported"] and "§9" in defined_bullets["approver_types_supported"]
    assert "OpenTelemetry" in defined_bullets["trace_emission"] and "OCSF" in defined_bullets["trace_emission"]
    assert "§15" in defined_bullets["trace_emission"]

    raw_schema = HANDSHAKE_SCHEMA.read_text(encoding="utf-8")
    assert "Section 3.15" not in raw_schema
    trace_props = schema["$defs"]["ServerHello"]["properties"]["trace_emission"]["properties"]
    assert "Section 15" in trace_props["otel_enabled"]["description"]
    assert "Section 15" in trace_props["ocsf_enabled"]["description"]


def test_item6_section_4_1_puts_mid_session_handshake_action_on_observed_agent():
    spec_s41 = _section(SPECIFICATION_MD.read_text(encoding="utf-8"), "### 4.1 Handshake failure (normative)")
    assert "Whether a Guardian can attach mid-flight to a session that started unguarded is undefined in v0.1" not in spec_s41
    assert "startup_posture: proceed" in spec_s41
    assert "does not re-send `handshake/hello` mid-session" in spec_s41
    assert "retries `handshake/hello` at the start of the next session" in spec_s41


def test_embedded_agt_go_handshake_schema_stays_in_sync():
    assert HANDSHAKE_SCHEMA.read_bytes() == AGT_GO_HANDSHAKE_SCHEMA.read_bytes()
