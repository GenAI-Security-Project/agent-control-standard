"""Keep the walkthrough's process example aligned with its stated scenario.

The OCSF tab previously used an invented class, a seconds timestamp, and the
agent's identity as an identity provider. MkDocs and the link guards accepted
it. Read the published JSON itself so those mistakes cannot return unnoticed.

These are focused documentation checks, not a complete OCSF validator. The
required process context follows OCSF 1.9.0's Process Activity, System Activity,
Process, and Device definitions at schema commit
856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba. Upstream event validation is a separate
check before publication.
"""

import json
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"


def walkthrough_tab():
    source = (ROOT / "docs" / "acs.md").read_text(encoding="utf-8")
    return source.partition('    === "OCSF"\n')[2].partition("\n    === ")[0]


def walkthrough_event():
    blocks = re.findall(r"```json\n(.*?)```", walkthrough_tab(), re.DOTALL)
    assert len(blocks) == 1, "The OCSF tab must contain one complete event example"
    return json.loads(blocks[0])


def declared_objects_only(schema):
    """Reject invented wrapper fields in this example, leaving output values opaque.

    The wire schemas remain extensible. This constraint applies only to the
    documentation's claim to copy existing ACS fields.
    """
    if isinstance(schema, list):
        return [declared_objects_only(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {key: declared_objects_only(value) for key, value in schema.items()}
    if schema.get("type") == "object" and "properties" in schema:
        result["additionalProperties"] = False
    return result


def validate_copied_acs_fields(acs):
    envelope = json.loads((SPEC / "request-envelope.json").read_text(encoding="utf-8"))
    hook = json.loads((SPEC / "hooks" / "tool-call-result.json").read_text(encoding="utf-8"))
    metadata = envelope["$defs"]["Metadata"]
    payload_fields = hook["properties"]
    metadata_fields = metadata["properties"]
    allowed = set(payload_fields) | set(metadata_fields) | {"method", "request_id"}
    assert not set(acs) - allowed, f"Undeclared ACS fields: {set(acs) - allowed}"

    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(schema, dict) and "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)

    for schema, value in (
        (metadata, {key: value for key, value in acs.items() if key in metadata_fields}),
        (hook, {key: value for key, value in acs.items() if key in payload_fields}),
        (envelope["properties"]["method"], acs["method"]),
        (envelope["$defs"]["AcsParams"]["properties"]["request_id"], acs["request_id"]),
    ):
        Draft202012Validator(
            declared_objects_only(schema), registry=registry, format_checker=FormatChecker()
        ).validate(value)

    assert acs["method"] == "steps/toolCallResult"
    assert acs["request_id"] != acs["request_id_ref"]


def test_walkthrough_uses_the_mapped_process_class():
    event = walkthrough_event()
    method = event["unmapped"]["acs"].get("method")
    assert method == "steps/toolCallResult"
    mapping = json.loads(
        (SPEC / "trace" / "ocsf-mapping.json")
        .read_text(encoding="utf-8")
    )["properties"]["step_to_class"]["default"][method]

    assert event["class_uid"] == mapping["class_uid"]
    assert event["class_name"] == mapping["class_name"]
    assert event["category_uid"] == 1  # System Activity
    assert event["category_name"] == "System Activity"
    assert event["activity_id"] == 2  # A subprocess exiting on its own
    assert event["activity_name"] == "Terminate"
    assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]
    assert event["metadata"]["version"] == "1.9.0"
    assert event["metadata"]["product"]["name"]
    assert "ocsf" not in event["metadata"]


def test_walkthrough_represents_a_reflexive_process_exit():
    event = walkthrough_event()
    assert "process" in event["actor"], "The actor must identify the exiting process"
    assert "device" in event, "Process Activity requires the actual host device"
    assert "process" in event, "The tool's subprocess must be identified"
    assert event["actor"]["process"] == event["process"], (
        "A self-exit's actor and target must both identify the exiting process"
    )
    assert type(event["process"]["pid"]) is int
    assert event["process"]["pid"] > 0
    parent = event["process"]["parent_process"]
    assert type(parent["pid"]) is int and parent["pid"] > 0
    assert parent["pid"] != event["process"]["pid"]
    assert type(event["device"]["type_id"]) is int
    assert "idp" not in event["actor"]

    acs = event["unmapped"]["acs"]
    assert event["device"]["uid"] != acs["agent_id"]
    assert type(event["exit_code"]) is int
    assert event["exit_code"] == 0 and acs["exit_status"] == "success"
    assert "acs_extensions" not in event
    assert "asop" not in event["unmapped"]


def test_walkthrough_copies_declared_acs_fields():
    validate_copied_acs_fields(walkthrough_event()["unmapped"]["acs"])


@pytest.mark.parametrize("path,value", [
    (("tool", "id"), "run_command"),
    (("tool", "execution_id"), "exec_123"),
    (("step",), {"id": "step_result_1", "type": "toolCallResult"}),
    (("session_id",), "sess_123"),
    (("request_id",), "step_result_1"),
    (("request_id_ref",), "exec_123"),
])
def test_copied_acs_fields_reject_old_aliases_and_non_uuid_ids(path, value):
    acs = deepcopy(walkthrough_event()["unmapped"]["acs"])
    validate_copied_acs_fields(acs)
    target = acs
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises((AssertionError, ValidationError)):
        validate_copied_acs_fields(acs)


def test_walkthrough_timestamps_match_the_documented_exit():
    event = walkthrough_event()
    timestamp = re.search(r"at `([^`]+Z)`", walkthrough_tab())
    assert timestamp, "The scenario must state its occurrence time in UTC"
    exited_at = datetime.fromisoformat(timestamp[1])
    expected_ms = int(exited_at.timestamp() * 1000)
    assert event["time"] == expected_ms, "OCSF occurrence time uses milliseconds"
    assert event["process"]["terminated_time"] == expected_ms
    assert event["actor"]["process"]["terminated_time"] == expected_ms
