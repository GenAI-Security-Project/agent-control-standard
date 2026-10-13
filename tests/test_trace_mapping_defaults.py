"""The Trace mappings keep their data in `default` keys, and nothing checked it.

`otel-mapping.json` and `ocsf-mapping.json` are JSON Schemas whose normative
tables sit in `default`. `test_publish_schemas.py` checks each file against the
JSON Schema metaschema, which never looks inside `default`. A misspelled list
name such as `conditonal_attributes` therefore passed every check, and both
readers (the conformance checker and the trace exporter) skip keys they do not
know, so the attribute it held stopped being emitted with nothing turning red.

These tests validate every `default` against the schema it sits in, reject
keys an entry schema does not declare, and hold each `step_to_span` entry to
one list per attribute.
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

TRACE = Path(__file__).resolve().parents[1] / "specification" / "v0.1.0" / "trace"
MAPPINGS = sorted(TRACE.glob("*.json"))
ATTRIBUTE_LISTS = ("required_attributes", "conditional_attributes", "optional_attributes")


def nodes_with_defaults(node, path="#"):
    """Every schema node under `node` that carries a `default`, with its path."""
    if isinstance(node, dict):
        if "default" in node:
            yield path, node
        for key, child in node.items():
            if key != "default":
                yield from nodes_with_defaults(child, f"{path}/{key}")


@pytest.mark.parametrize("path", MAPPINGS, ids=lambda p: p.name)
def test_every_default_validates_against_its_own_schema(path):
    mapping = json.loads(path.read_text(encoding="utf-8"))
    checked = 0
    for pointer, node in nodes_with_defaults(mapping):
        schema = {key: value for key, value in node.items() if key != "default"}
        errors = sorted(Draft202012Validator(schema).iter_errors(node["default"]), key=str)
        assert not errors, f"{path.name} {pointer}: " + "; ".join(error.message for error in errors)
        checked += 1
    # A refactor that moves the tables out of `default` would otherwise turn
    # this into a test of nothing.
    assert checked >= 4, f"{path.name}: found only {checked} defaults to check"


def test_every_step_span_entry_uses_only_known_keys():
    # Checked here, not by closing the published schema with
    # additionalProperties: false, which would change what a deployment may
    # publish. A misspelled list name fails this instead.
    mapping = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))
    entry_schema = mapping["properties"]["step_to_span"]["additionalProperties"]
    known = set(entry_schema["properties"])
    unknown = {
        method: sorted(set(entry) - known)
        for method, entry in mapping["properties"]["step_to_span"]["default"].items()
        if set(entry) - known
    }
    assert not unknown, f"step_to_span entries with keys the entry schema does not declare: {unknown}"


def test_no_attribute_sits_in_two_lists_of_one_step_span():
    mapping = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))
    overlaps = {}
    for method, entry in mapping["properties"]["step_to_span"]["default"].items():
        seen = {}
        for name in ATTRIBUTE_LISTS:
            for attribute in entry.get(name, []):
                if attribute in seen:
                    overlaps.setdefault(method, []).append(f"{attribute} in {seen[attribute]} and {name}")
                seen[attribute] = name
    assert not overlaps, f"attributes listed twice: {overlaps}"


# Every conditional attribute and the wire field it comes from. The
# conformance checker's "every required row is emittable" test covers only the
# six methods the reference Guardian evaluates, so this one holds the other
# fifteen: moving an attribute back to required, or a schema making its
# source required, fails here.
CONDITIONAL_SOURCES = {
    ("steps/toolCallRequest", "acs.capability"): ("tool-call-request.json", "capability"),
    ("steps/toolCallResult", "acs.request_id_ref"): ("tool-call-result.json", "request_id_ref"),
    ("steps/knowledgeRetrieval", "acs.source.type"): ("knowledge-retrieval.json", "source"),
    ("steps/memoryStore", "acs.memory_store.name"): ("memory-store.json", "memory_store"),
    ("steps/memoryStore", "acs.operation"): ("memory-store.json", "operation"),
    ("steps/memoryContextRetrieval", "acs.memory_store.name"): ("memory-context-retrieval.json", "memory_store"),
    ("steps/subagentStop", "acs.subagent.final_chain_hash"): ("subagent-stop.json", "final_chain_hash"),
    ("agbom/changed", "acs.agbom.change_reason"): ("agbom-changed.json", "reason"),
}


def test_every_conditional_attribute_stays_conditional_and_its_source_stays_optional():
    table = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))["properties"]["step_to_span"]["default"]
    listed = {(method, attribute) for method, entry in table.items() for attribute in entry.get("conditional_attributes", [])}
    assert listed == set(CONDITIONAL_SOURCES), f"conditional lists drifted: {sorted(listed ^ set(CONDITIONAL_SOURCES))}"
    for (method, attribute), (hook, field) in CONDITIONAL_SOURCES.items():
        payload = json.loads((TRACE.parent / "hooks" / hook).read_text(encoding="utf-8"))
        assert field in payload["properties"], f"{hook} has no {field}, so {attribute} on {method} has no source"
        assert field not in payload.get("required", []), (
            f"{hook} now requires {field}, so {attribute} on {method} belongs in required_attributes"
        )


def test_ocsf_decision_tables_match_the_wire():
    """The disposition and severity tables key exactly the five dispositions,
    acs_fields names only real response fields, and every enumerated failure
    attribute is one the failure event lists. A typo in any of them used to
    pass every check."""
    acs_result = json.loads((TRACE.parent / "response-envelope.json").read_text(encoding="utf-8"))["$defs"]["AcsResult"]["properties"]
    ocsf = json.loads((TRACE / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]
    dispositions = set(acs_result["decision"]["enum"])
    assert set(ocsf["decision_class"]["properties"]["disposition_mapping"]["default"]) == dispositions
    assert set(ocsf["severity_mapping"]["default"]) == dispositions
    assert set(ocsf["decision_class"]["properties"]["acs_fields"]["default"]) <= set(acs_result)
    assert ocsf["decision_class"]["properties"]["join_fields"]["default"] == ["request_id", "session_id"]
    failure = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))["properties"]["decision_failure_event"]["properties"]
    listed = set(failure["required_attributes"]["default"]) | set(failure["conditional_attributes"]["default"])
    assert set(failure["attribute_values"]["default"]) <= listed


def test_ocsf_decision_codes_match_the_answered_proposal():
    # The Spec leads fixed these values on issue #228. Defer is 99, not 14
    # (Delayed), because an ACS defer holds the step and denies on timeout;
    # modify gets action_id 4 because disposition_id has no value for it.
    decision = json.loads((TRACE / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]["decision_class"]["properties"]
    assert decision["disposition_mapping"]["default"] == {"allow": 1, "deny": 2, "modify": 99, "ask": 99, "defer": 99}
    assert decision["action_mapping"]["default"] == {"allow": 1, "deny": 2, "modify": 4, "ask": 99, "defer": 99}
    assert decision["alert_mapping"]["default"] == {"allow": False, "deny": True, "modify": False, "ask": True, "defer": True}
    severity = json.loads((TRACE / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]["severity_mapping"]["default"]
    assert {d: severity[d] >= 3 for d in severity} == decision["alert_mapping"]["default"], "is_alert must be true exactly when severity_id is 3 or higher"
    assert decision["required_fields"]["default"] == [
        "finding_info", "finding_info.title", "action_id", "action", "disposition_id", "disposition", "evidences", "metadata.correlation_uid",
    ]
    assert decision["late_decision"]["properties"]["finding_types"]["default"] == [
        "late_decision_fail_open", "late_decision_fail_closed",
    ]
    failure = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))["properties"]["decision_failure_event"]["properties"]
    failure_fields = {name.removeprefix("acs.failure.") for name in failure["required_attributes"]["default"] + failure["conditional_attributes"]["default"]}
    assert set(decision["late_decision"]["properties"]["failure_fields"]["default"]) <= failure_fields


def test_padded_source_fields_reject_the_empty_string():
    # Trace pads the policy and provenance arrays with "" where a value is
    # absent, so "" must never be a legal wire value for these fields (#263).
    spec = TRACE.parent
    policy = json.loads((spec / "response-envelope.json").read_text(encoding="utf-8"))["$defs"]["AcsResult"]["properties"]["policy_references"]["items"]["properties"]
    for field in ("policy_id", "policy_version", "policy_name", "rule_id"):
        assert policy[field].get("minLength") == 1, f"policy_references.{field} accepts an empty string"
    provenance = json.loads((spec / "provenance.json").read_text(encoding="utf-8"))["properties"]
    assert provenance["source_id"].get("minLength") == 1, "provenance source_id accepts an empty string"


def test_every_step_to_class_entry_uses_only_known_keys():
    # The OCSF twin of the step_to_span key check: a typo such as activty_id
    # would otherwise drop the activity and change type_uid with every check
    # green. Checked here so the published schema stays open.
    ocsf = json.loads((TRACE / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]["step_to_class"]
    known = set(ocsf["additionalProperties"]["properties"])
    unknown = {method: sorted(set(entry) - known) for method, entry in ocsf["default"].items() if set(entry) - known}
    assert not unknown, f"step_to_class entries with keys the entry schema does not declare: {unknown}"
