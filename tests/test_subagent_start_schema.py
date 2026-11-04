"""steps/subagentStart must accept only spawns a Guardian can check.

The payload used to validate with no subagent_intent, so "strict subset" had nothing
to compare; with a derived_from_parent intent that cited nothing, so the derivation
could not be tied to its parent; and with a fresh intent that no user produced. These
tests hold the schema to the stricter shape and keep the one rule JSON Schema cannot
express, a child session id that differs from its parent's, stated in the schema's own
text where a Guardian author reads it.
"""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SPEC = Path(__file__).resolve().parents[1] / "specification" / "v0.1.0"

PARENT = "11111111-1111-4111-8111-111111111111"
CHILD = "22222222-2222-4222-8222-222222222222"

PARSED = [{"tool": "read_file", "operation": "read", "resource": "*"}]


def _validator() -> Draft202012Validator:
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    schema = json.loads((SPEC / "hooks" / "subagent-start.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=Registry().with_resources(resources))


VALIDATOR = _validator()


def _intent(origin="agent_generated", derived_from=None):
    provenance = {"provenance_id": "p-child-intent", "origin": origin}
    if derived_from is not None:
        provenance["derived_from"] = derived_from
    return {"parsed": copy.deepcopy(PARSED), "parser_provenance": provenance}


def _payload(derivation, **changes):
    payload = {
        "subagent_session_id": CHILD,
        "parent_session_id": PARENT,
        "parent_step_id": "step-7",
        "intent_derivation": derivation,
        "subagent_intent": _intent(),
    }
    payload.update(changes)
    return payload


def _valid(payload) -> bool:
    return VALIDATOR.is_valid(payload)


def _without(payload, key):
    return {name: value for name, value in payload.items() if name != key}


GOOD = {
    "inherit_full": _payload("inherit_full"),
    "inherit_subset": _payload("inherit_subset"),
    "derived_from_parent": _payload(
        "derived_from_parent",
        parent_intent_id="p-parent-intent",
        subagent_intent=_intent(derived_from=["p-parent-intent"]),
    ),
    "fresh": _payload("fresh", subagent_intent=_intent(origin="user_input")),
}


@pytest.mark.parametrize("derivation", sorted(GOOD))
def test_subagent_start_accepts_a_complete_spawn_for_each_derivation(derivation):
    assert _valid(GOOD[derivation])


@pytest.mark.parametrize("derivation", sorted(GOOD))
def test_subagent_start_requires_subagent_intent_for_every_derivation(derivation):
    assert not _valid(_without(GOOD[derivation], "subagent_intent"))


@pytest.mark.parametrize("missing", ["parsed", "parser_provenance"])
def test_subagent_start_requires_the_intent_to_carry_parsed_and_its_provenance(missing):
    payload = copy.deepcopy(GOOD["inherit_subset"])
    del payload["subagent_intent"][missing]
    assert not _valid(payload)


def test_subagent_start_accepts_an_empty_parsed_capability_set():
    payload = copy.deepcopy(GOOD["inherit_subset"])
    payload["subagent_intent"]["parsed"] = []
    assert _valid(payload)


def test_derived_from_parent_requires_parent_intent_id():
    assert not _valid(_without(GOOD["derived_from_parent"], "parent_intent_id"))


def test_derived_from_parent_requires_a_provenance_that_cites_something():
    payload = copy.deepcopy(GOOD["derived_from_parent"])
    del payload["subagent_intent"]["parser_provenance"]["derived_from"]
    assert not _valid(payload)
    payload["subagent_intent"]["parser_provenance"]["derived_from"] = []
    assert not _valid(payload)


def test_parent_intent_id_must_not_be_empty():
    payload = copy.deepcopy(GOOD["derived_from_parent"])
    payload["parent_intent_id"] = ""
    assert not _valid(payload)


@pytest.mark.parametrize("derivation", ["inherit_full", "inherit_subset", "fresh"])
def test_parent_intent_id_is_only_required_for_derived_from_parent(derivation):
    assert "parent_intent_id" not in GOOD[derivation]
    assert _valid(GOOD[derivation])


@pytest.mark.parametrize("origin", ["agent_generated", "tool_output", "retrieved", "a2a_inbound", "external", "system"])
def test_fresh_intent_must_come_from_user_input(origin):
    assert not _valid(_payload("fresh", subagent_intent=_intent(origin=origin)))


def test_the_parents_provenance_summary_is_carried_and_checked_against_its_schema():
    summary = {"origins_seen": ["user_input", "retrieved"], "entry_count": 4}
    assert _valid(_payload("inherit_subset", parent_provenance_summary=summary))
    assert not _valid(_payload("inherit_subset", parent_provenance_summary={"origins_seen": ["made_up"]}))


def test_the_parents_provenance_summary_stays_optional():
    assert "parent_provenance_summary" not in GOOD["inherit_full"]
    assert _valid(GOOD["inherit_full"])


def test_the_schema_states_the_rules_it_cannot_express():
    schema = json.loads((SPEC / "hooks" / "subagent-start.json").read_text(encoding="utf-8"))
    session_id = schema["properties"]["subagent_session_id"]["description"]
    assert "MUST differ from parent_session_id" in session_id
    assert "metadata.session_id" in session_id
    top = schema["description"]
    assert "MUST deny a spawn whose subagent_session_id equals parent_session_id" in top
    assert "never one the payload supplies" in top
    summary = schema["properties"]["parent_provenance_summary"]["description"]
    assert "MUST NOT seed the child with less than its own record" in summary
    derivation = schema["properties"]["intent_derivation"]["description"]
    for derivation_name in ("inherit_full", "inherit_subset", "derived_from_parent", "fresh"):
        assert derivation_name in derivation
    assert "MUST be a subset of the parent's parsed" in derivation
