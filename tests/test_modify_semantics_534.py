"""Guards for MODIFY replacement semantics across hooks (#534).

Verifies:
1. modifications.json and Specification §6.3 define which leaf string field
   modified_content replaces at each hook while keeping type: "string" for
   v0.1.0 compatibility and requiring redactions / parameter_overrides for
   structured object or multi-part edits.
2. hooks.md agentTrigger states that MODIFY rewrites or redacts the trigger
   payload before delivery to the agent (matching userMessage), with the audit
   chain recording both the original request_hash and the applied modification.
3. hooks.md postCompact and Specification §6.3 define the target
   (summary.value), Guardian-supplied provenance (origin: "system",
   trust: "trusted", source_id), and post-MODIFY ContextEntry / response
   chain_hash commitment (with request_hash covering the original request).
4. hooks.md preCompact defines the three bounded recovery actions when
   preCompact returns DENY on a size_threshold trigger.
"""

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
MODIFICATIONS_SCHEMA = ROOT / "specification" / "v0.1.0" / "modifications.json"
GO_MODIFICATIONS_SCHEMA = (
    ROOT
    / "reference-implementations"
    / "agt-go"
    / "internal"
    / "schema"
    / "specification"
    / "v0.1.0"
    / "modifications.json"
)
SPECIFICATION = ROOT / "docs" / "spec" / "instrument" / "specification.md"
HOOKS = ROOT / "docs" / "spec" / "instrument" / "hooks.md"


def _subsection(path: Path, heading_prefix: str) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.startswith(heading_prefix)),
        None,
    )
    assert start is not None, f"Missing heading {heading_prefix!r} in {path}"
    level = len(heading_prefix) - len(heading_prefix.lstrip("#"))
    stop_pattern = re.compile(rf"^#{{1,{level}}}\s")
    for offset, line in enumerate(lines[start + 1 :], start=start + 1):
        if stop_pattern.match(line):
            return "\n".join(lines[start:offset])
    return "\n".join(lines[start:])


def test_modifications_schema_defines_leaf_targets_and_preserves_string_contract():
    schema = json.loads(MODIFICATIONS_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    if GO_MODIFICATIONS_SCHEMA.is_file():
        assert (
            MODIFICATIONS_SCHEMA.read_bytes() == GO_MODIFICATIONS_SCHEMA.read_bytes()
        ), "Embedded agt-go copy of modifications.json must match specification/v0.1.0/modifications.json"

    mc = schema["properties"]["modified_content"]
    assert mc["type"] == "string"
    desc = mc["description"]
    for token in (
        "summary.value",
        "postCompact",
        "content[0].value",
        "userMessage",
        "agentResponse",
        "agentTrigger",
        "outputs[0].value",
        "toolCallResult",
        "redactions",
        "parameter_overrides",
    ):
        assert token in desc, f"modifications.json modified_content description missing {token!r}"

    validator = Draft202012Validator(schema)
    assert validator.is_valid({"modified_content": "sanitized summary"})
    assert validator.is_valid({"redactions": [{"path": "/summary/value"}]})
    assert validator.is_valid({"parameter_overrides": {"amount": 100}})
    assert not validator.is_valid(
        {
            "modified_content": "sanitized",
            "redactions": [{"path": "/summary/value"}],
        }
    )


def test_spec_section_6_3_defines_leaf_replacement_and_postcompact_provenance():
    sec = _subsection(SPECIFICATION, "### 6.3 MODIFY composition")
    for token in (
        "summary.value",
        "postCompact",
        "content[0].value",
        "userMessage",
        "agentResponse",
        "agentTrigger",
        "outputs[0].value",
        "toolCallResult",
        "redactions",
        "parameter_overrides",
        'origin: "system"',
        'trust: "trusted"',
        "source_id",
        "post-MODIFY",
        "chain_hash",
        "request_hash",
    ):
        assert token in sec, f"Specification §6.3 missing {token!r}"
    assert "v0.1 defines no Guardian-injected `origin`" not in sec


def test_agent_trigger_modify_specifies_before_delivery_to_the_agent():
    sec = _subsection(HOOKS, "## agentTrigger")
    assert "before delivery to the agent" in sec
    assert "request_hash" in sec
    assert "before activation" not in sec


def test_post_compact_modify_defines_target_provenance_and_chain_hash():
    sec = _subsection(HOOKS, "## postCompact")
    for token in (
        "summary.value",
        "/summary/value",
        'origin: "system"',
        'trust: "trusted"',
        "source_id",
        "post-MODIFY",
        "chain_hash",
        "request_hash",
    ):
        assert token in sec, f"hooks.md postCompact missing {token!r}"


def test_pre_compact_deny_on_size_threshold_defines_recovery_actions():
    sec = _subsection(HOOKS, "## preCompact")
    for token in (
        "size_threshold",
        "MUST NOT silently compact",
        "Drop the untrusted or policy-flagged entries",
        "tainted lineage preserved",
        'trust: "untrusted"',
        "sessionEnd",
    ):
        assert token in sec, f"hooks.md preCompact missing {token!r}"
