"""Schema and specification guards for additive items in issue #536.

Covers:
  - Item 2: system/ping result subschema ($defs.PingPayload and $defs.PingResult)
    in specification/v0.1.0/response-envelope.json and §13 of specification.md
  - Item 3: SessionContext schema in specification/v0.1.0/session-context.json
    and §8 of specification.md
  - Item 5: BCP 47 (RFC 5646) optional lang tags on user-message ContentPart,
    session-start $defs.Intent, response-envelope AcsResult, and ask-details
  - Item 6: optional attestation object on skill-register.json, skill-load.json,
    and docs/spec/instrument/hooks.md
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specification" / "v0.1.0"
SPECIFICATION_MD = ROOT / "docs" / "spec" / "instrument" / "specification.md"
HOOKS_MD = ROOT / "docs" / "spec" / "instrument" / "hooks.md"


def _load_schema(rel_path: str) -> dict:
    return json.loads((SPEC / rel_path).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append(
                (doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
            )
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(schema: dict) -> Draft202012Validator:
    return Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker())


# --- Item 3: SessionContext schema ----------------------------------------


def test_session_context_schema_exists_and_validates():
    schema = _load_schema("session-context.json")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == BASE + "v0.1.0/session-context.json"
    assert set(schema["required"]) == {
        "session_id",
        "chain_hash",
        "entries",
        "provenance_summary",
    }
    assert schema["additionalProperties"] is True
    assert schema["properties"]["entries"]["items"]["$ref"] == "context-entry.json"
    assert (
        schema["properties"]["intent"]["$ref"]
        == "hooks/session-start.json#/$defs/Intent"
    )

    valid_instance = {
        "session_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36",
        "chain_hash": "a" * 64,
        "entries": [
            {
                "entry_id": "entry-1",
                "step_id": "0d2b0f1e-3d3d-4e6b-9c7a-1c9d4b0b9a11",
                "step_type": "steps/sessionStart",
                "previous_hash": None,
                "entry_hash": "b" * 64,
            }
        ],
        "provenance_summary": {"origins_seen": ["user_input"], "entry_count": 1},
        "intent": {
            "raw": "Summarize Q3 report",
            "lang": "en-US",
            "scope_mode": "strict",
        },
        "guardian_custom_state": {"active_bundle": "corp-v2"},
    }
    assert _validator(schema).is_valid(valid_instance)

    bad_hash = dict(valid_instance, chain_hash="NOT_HEX")
    assert not _validator(schema).is_valid(bad_hash)


def test_specification_section_8_references_session_context_schema():
    text = SPECIFICATION_MD.read_text(encoding="utf-8")
    assert "session-context.json" in text
    assert "The SessionContext container is intentionally not schematized" not in text


# --- Item 2: system/ping result subschema ---------------------------------


def test_ping_payload_and_ping_result_subschemas():
    envelope = _load_schema("response-envelope.json")
    defs = envelope["$defs"]
    assert "PingPayload" in defs
    assert "PingResult" in defs

    ping_payload = defs["PingPayload"]
    assert set(ping_payload["required"]) == {"status", "echo", "server_timestamp"}
    assert ping_payload["additionalProperties"] is False
    assert ping_payload["properties"]["status"] == {"const": "ok"}

    ping_result_schema = {
        "$schema": envelope["$schema"],
        "$id": envelope["$id"],
        "$defs": defs,
        "$ref": "#/$defs/PingResult",
    }
    valid_ping_result = {
        "type": "final",
        "acs_version": "0.1.0",
        "request_id": "0d2b0f1e-3d3d-4e6b-9c7a-1c9d4b0b9a11",
        "decision": "allow",
        "payload": {
            "status": "ok",
            "echo": "probe-1",
            "server_timestamp": "2026-11-18T21:00:00Z",
        },
    }
    assert _validator(ping_result_schema).is_valid(valid_ping_result)
    assert _validator(envelope).is_valid(
        {"jsonrpc": "2.0", "id": "ping-1", "result": valid_ping_result}
    )

    missing_echo = {
        **valid_ping_result,
        "payload": {"status": "ok", "server_timestamp": "2026-11-18T21:00:00Z"},
    }
    assert not _validator(ping_result_schema).is_valid(missing_echo)

    extra_field = {
        **valid_ping_result,
        "payload": {
            **valid_ping_result["payload"],
            "unexpected": True,
        },
    }
    assert not _validator(ping_result_schema).is_valid(extra_field)


def test_specification_section_13_references_ping_subschemas():
    text = SPECIFICATION_MD.read_text(encoding="utf-8")
    assert "PingResult" in text
    assert "PingPayload" in text


# --- Item 5: BCP 47 language tags -----------------------------------------


def test_bcp47_lang_tags_across_natural_language_surfaces():
    user_msg = _load_schema("hooks/user-message.json")
    item_props = user_msg["properties"]["content"]["items"]["properties"]
    assert item_props["lang"]["type"] == "string"
    assert "BCP 47" in item_props["lang"]["description"]
    assert user_msg["$defs"]["ContentPart"]["properties"]["lang"]["type"] == "string"
    assert _validator(user_msg).is_valid(
        {"content": [{"type": "text", "value": "Bonjour", "lang": "fr-CA"}]}
    )

    session_start = _load_schema("hooks/session-start.json")
    intent_def = session_start["$defs"]["Intent"]
    assert intent_def["properties"]["lang"]["type"] == "string"
    assert "BCP 47" in intent_def["properties"]["lang"]["description"]
    assert _validator(session_start).is_valid(
        {"intent": {"raw": "Chercher les rapports", "lang": "fr"}}
    )

    resp_env = _load_schema("response-envelope.json")
    acs_result_props = resp_env["$defs"]["AcsResult"]["properties"]
    assert acs_result_props["lang"]["type"] == "string"
    assert "BCP 47" in acs_result_props["lang"]["description"]
    assert _validator(resp_env).is_valid(
        {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "type": "final",
                "acs_version": "0.1.0",
                "request_id": "0d2b0f1e-3d3d-4e6b-9c7a-1c9d4b0b9a11",
                "decision": "deny",
                "reasoning": "Accès refusé par la politique.",
                "lang": "fr",
            },
        }
    )

    ask_details = _load_schema("ask-details.json")
    assert ask_details["properties"]["lang"]["type"] == "string"
    assert "BCP 47" in ask_details["properties"]["lang"]["description"]
    assert _validator(ask_details).is_valid(
        {
            "approver": {"type": "human", "id": "sec-ops"},
            "question": "Autoriser l'exportation ?",
            "context": "Action hors périmètre initial",
            "lang": "fr-FR",
            "timeout_seconds": 60,
        }
    )


# --- Item 6: skillRegister and skillLoad attestation ----------------------


@pytest.mark.parametrize("hook_file", ["hooks/skill-register.json", "hooks/skill-load.json"])
def test_skill_hooks_define_optional_attestation(hook_file: str):
    schema = _load_schema(hook_file)
    assert "attestation" not in schema.get("required", [])
    attestation = schema["properties"]["attestation"]
    assert attestation["type"] == "object"
    props = attestation["properties"]
    assert set(props) >= {
        "publisher",
        "digest",
        "scanner",
        "verdict",
        "registry_uri",
        "attested_at",
    }
    assert props["verdict"]["enum"] == ["pass", "warn", "fail"]


def test_skill_register_and_load_validate_with_attestation():
    att = {
        "publisher": "owasp-genai",
        "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "scanner": "skill-vet-v1",
        "verdict": "pass",
        "registry_uri": "https://registry.example.com/skills/ triage/1.0.0".replace(" ", ""),
        "attested_at": "2026-11-18T20:00:00Z",
    }
    reg_schema = _load_schema("hooks/skill-register.json")
    reg_payload = {
        "skill_id": "skill.triage",
        "definition": {"digest": {"algorithm": "sha-256", "value": "ab" * 32}},
        "declared_capabilities": ["filesystem.read"],
        "attestation": att,
    }
    assert _validator(reg_schema).is_valid(reg_payload)

    bad_reg = {**reg_payload, "attestation": {**att, "verdict": "unknown"}}
    assert not _validator(reg_schema).is_valid(bad_reg)

    load_schema = _load_schema("hooks/skill-load.json")
    load_payload = {
        "skill_id": "skill.triage",
        "digest": {"algorithm": "sha-256", "value": "ab" * 32},
        "load_trigger": "user",
        "load_path": [{"skill_id": "skill.triage"}],
        "attestation": att,
    }
    assert _validator(load_schema).is_valid(load_payload)


def test_hooks_doc_mentions_skill_attestation():
    text = HOOKS_MD.read_text(encoding="utf-8")
    assert "attestation" in text
