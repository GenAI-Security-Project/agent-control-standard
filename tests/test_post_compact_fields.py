"""Guards for payload fields a sender cannot honestly fill.

`postCompact` required `post_compact_chain_hash`, "the chain_hash after this
postCompact ContextEntry is written". The Guardian writes that entry and
chooses its `entry_id`, so the sender could not compute the value, and under
ACS-Audit `request_hash` covers `params`, so the value would also have hashed
itself. It also required `summary.provenance`, while Specification section 7
says a `provenance_producer: none` client emits no Provenance objects, so a
conformant ACS-Core client could not send a valid `postCompact`. `turnEnd` and
`subagentStop` had the same shape whenever `summary` was present.

The base schemas now leave both out of the required set. The strict
`*.acs-provenance.json` variants put `summary.provenance` back for deployments
that claim ACS-Provenance.
"""

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "specification" / "v0.1.0"
HOOKS_PAGE = ROOT / "docs" / "spec" / "instrument" / "hooks.md"
SPECIFICATION = ROOT / "docs" / "spec" / "instrument" / "specification.md"

_DOCUMENTS = [json.loads(p.read_text(encoding="utf-8")) for p in SCHEMAS.rglob("*.json")]
REGISTRY = Registry().with_resources(
    (d["$id"], Resource.from_contents(d)) for d in _DOCUMENTS if isinstance(d, dict) and "$id" in d
)


def load(name: str) -> dict:
    return json.loads((SCHEMAS / "hooks" / name).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load(name), registry=REGISTRY)


def valid(validator_, payload) -> bool:
    return not list(validator_.iter_errors(payload))


PROVENANCE = {"provenance_id": "p-sum-1", "origin": "agent_generated", "derived_from": ["p-a", "p-b"]}
HASH = "a" * 64


def post_compact(**changes):
    payload = {"summary": {"value": "Earlier turns, summarized."}, "entries_compacted": ["step-1", "step-2"]}
    payload.update(changes)
    return payload


# postCompact.

def test_a_post_compact_from_a_client_that_emits_no_provenance_validates():
    assert valid(validator("post-compact.json"), post_compact())


def test_a_post_compact_needs_no_chain_hash_the_sender_cannot_compute():
    payload = post_compact()
    assert "pre_compact_chain_hash" not in payload and "post_compact_chain_hash" not in payload
    assert valid(validator("post-compact.json"), payload)


def test_the_base_schema_no_longer_requires_either_chain_hash_or_summary_provenance():
    schema = load("post-compact.json")
    assert set(schema["required"]) == {"summary", "entries_compacted"}
    assert schema["properties"]["summary"]["required"] == ["value"]


def test_the_post_compact_chain_hash_is_not_a_request_field():
    assert "post_compact_chain_hash" not in load("post-compact.json")["properties"]


def test_a_client_that_tracks_the_chain_may_still_send_the_pre_compact_hash():
    base = validator("post-compact.json")
    assert valid(base, post_compact(pre_compact_chain_hash=HASH))
    assert not valid(base, post_compact(pre_compact_chain_hash="not-a-hash"))


def test_the_post_compact_summary_value_and_entries_are_still_required():
    base = validator("post-compact.json")
    assert not valid(base, {"entries_compacted": ["step-1"]})
    assert not valid(base, {"summary": {"provenance": PROVENANCE}, "entries_compacted": ["step-1"]})
    assert not valid(base, post_compact(entries_compacted=[]))
    assert not valid(base, {"summary": {"value": "x"}})


def test_provenance_present_on_a_post_compact_summary_is_still_checked():
    base = validator("post-compact.json")
    assert valid(base, post_compact(summary={"value": "x", "provenance": PROVENANCE}))
    assert not valid(base, post_compact(summary={"value": "x", "provenance": {"origin": "agent_generated"}}))


def test_the_strict_profile_puts_summary_provenance_back_on_post_compact():
    strict = validator("post-compact.acs-provenance.json")
    assert not valid(strict, post_compact())
    assert valid(strict, post_compact(summary={"value": "x", "provenance": PROVENANCE}))


# turnEnd and subagentStop, where summary is optional.

TURN_END = {"turn_id": "t-1", "outcome": "completed"}
SUBAGENT_STOP = {"subagent_session_id": "5f2f7e6e-3c8a-4f4e-9b43-0a1c2d3e4f50", "outcome": "completed"}


@pytest.mark.parametrize("base_payload, base, strict", [
    (TURN_END, "turn-end.json", "turn-end.acs-provenance.json"),
    (SUBAGENT_STOP, "subagent-stop.json", "subagent-stop.acs-provenance.json"),
])
class TestOptionalSummaryProvenance:
    def test_a_hook_without_a_summary_validates_under_both_profiles(self, base_payload, base, strict):
        assert valid(validator(base), base_payload)
        assert valid(validator(strict), base_payload)

    def test_a_summary_without_provenance_validates_in_the_base_schema(self, base_payload, base, strict):
        payload = {**base_payload, "summary": {"value": "What happened."}}
        assert valid(validator(base), payload)

    def test_the_strict_profile_refuses_a_summary_without_provenance(self, base_payload, base, strict):
        payload = {**base_payload, "summary": {"value": "What happened."}}
        assert not valid(validator(strict), payload)

    def test_a_summary_with_provenance_validates_under_both_profiles(self, base_payload, base, strict):
        payload = {**base_payload, "summary": {"value": "What happened.", "provenance": PROVENANCE}}
        assert valid(validator(base), payload)
        assert valid(validator(strict), payload)

    def test_a_summary_still_needs_its_value(self, base_payload, base, strict):
        payload = {**base_payload, "summary": {"provenance": PROVENANCE}}
        assert not valid(validator(base), payload)


# The strict variants follow the existing pattern.

@pytest.mark.parametrize("stem", ["post-compact", "turn-end", "subagent-stop"])
def test_each_strict_variant_extends_its_base_and_is_well_formed(stem):
    strict = load(f"{stem}.acs-provenance.json")
    Draft202012Validator.check_schema(strict)
    assert strict["$id"] == load(f"{stem}.json")["$id"].replace(f"{stem}.json", f"{stem}.acs-provenance.json")
    assert strict["allOf"] == [{"$ref": f"./{stem}.json"}]


# The prose that restates the rules.

def section(text: str, heading: str) -> str:
    match = re.search(rf"^{re.escape(heading)}\n(.*?)(?=^## |^---$|\Z)", text, re.S | re.M)
    assert match, f"{heading!r} not found"
    return match.group(1)


def test_the_hooks_page_says_the_post_compact_hash_is_the_guardians_to_report():
    body = section(HOOKS_PAGE.read_text(encoding="utf-8"), "## postCompact")
    assert "`chain_hash`" in body and "86-chain-head-publication-normative" in body
    assert "post_compact_chain_hash" not in body
    assert "OPTIONAL" in body


def test_the_hooks_page_marks_summary_provenance_optional_outside_acs_provenance():
    text = HOOKS_PAGE.read_text(encoding="utf-8")
    for heading in ("## turnEnd", "## subagentStop", "## postCompact"):
        body = section(text, heading)
        assert "REQUIRED under ACS-Provenance" in body, f"{heading} does not say when provenance is required"


def test_no_schema_or_doc_still_requires_the_post_compact_chain_hash():
    for path in [*SCHEMAS.rglob("*.json"), *(ROOT / "docs").rglob("*.md")]:
        text = path.read_text(encoding="utf-8")
        if "post_compact_chain_hash" in text:
            pytest.fail(f"{path.relative_to(ROOT)} still names post_compact_chain_hash")


def test_the_specification_names_the_summary_variants_under_acs_provenance():
    text = SPECIFICATION.read_text(encoding="utf-8")
    assert "`postCompact`, `turnEnd` and `subagentStop`" in text
