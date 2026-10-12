"""The Trace mappings keep their data in `default` keys, and nothing checked it.

`otel-mapping.json` and `ocsf-mapping.json` are JSON Schemas whose normative
tables sit in `default`. `test_publish_schemas.py` checks each file against the
JSON Schema metaschema, which never looks inside `default`. A misspelled list
name such as `conditonal_attributes` therefore passed every check, and both
readers (the conformance checker and the trace exporter) skip keys they do not
know, so the attribute it held stopped being emitted with nothing turning red.

These tests validate every `default` against the schema it sits in, and hold
each `step_to_span` entry to one list per attribute.
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


def test_a_misspelled_attribute_list_is_rejected():
    mapping = json.loads((TRACE / "otel-mapping.json").read_text(encoding="utf-8"))
    entry_schema = mapping["properties"]["step_to_span"]["additionalProperties"]
    misspelled = {"span_name": "acs.x", "required_attributes": [], "conditonal_attributes": ["acs.y"]}
    assert list(Draft202012Validator(entry_schema).iter_errors(misspelled))


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
