"""Guard the parsed-intent wire shape and its normative comparison contract."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(params=[
    ("session-start", "intent"),
    ("agent-trigger", "intent"),
    ("subagent-start", "subagent_intent"),
])
def entry_validator(request):
    hook, field = request.param
    schema = json.loads(
        (REPO / "specification" / "v0.1.0" / "hooks" / f"{hook}.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    entry = schema["properties"][field]["properties"]["parsed"]["items"]
    return Draft202012Validator(entry)


@pytest.mark.parametrize("entry", [
    {"capability": "filesystem.delete"},
    {"capability": "tool.invoke", "tool": "Bash"},
    {"capability": "filesystem.delete", "tool": "FileManager",
     "operation": "delete", "resource": "/workspace/report.txt"},
    {"tool": "FileManager", "operation": "delete", "resource": "/workspace/report.txt"},
])
def test_accepts_abstract_and_tool_scoped_entries(entry_validator, entry):
    entry_validator.validate(entry)


@pytest.mark.parametrize("capability", [None, 42, ["filesystem.delete"], {}])
def test_rejects_non_string_capabilities(entry_validator, capability):
    assert not entry_validator.is_valid({"capability": capability})


def test_comparison_defines_alternatives_constraints_and_policy_boundary():
    spec = (REPO / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    comparison = spec.split("**Intent comparison (normative).**", 1)[1].split(
        "**Intent immutability enforcement", 1
    )[0]
    for rule in [
        "MUST evaluate entries as alternatives",
        "all supplied constraints MUST match",
        "case-sensitive string equality",
        "If the request omits `capability`, that entry does not match",
        "matching capability MUST NOT override a different tool constraint",
        "If the request omits `operation`, that entry does not match",
        "MUST NOT treat an unresolved resource constraint as satisfied",
        "none of these members MUST NOT match any request",
        "Deployments MUST document that mapping",
        "not an unconditional ALLOW",
    ]:
        assert rule in comparison
