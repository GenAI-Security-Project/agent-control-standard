"""Pins the approval-lifetime rule (section 9.3) so a later edit cannot drop it unnoticed.

Section 17 says every mandated refusal maps to a fixed code. Section 9.3 mandates three
refusals of a presented approval: consumed, in flight for another request, and bound to an
earlier session. All three use REPLAY_CONSUMED (-32009). Deleting the section, the code, the
registry row or the cross-reference from section 10.3 must fail this file.
"""
from __future__ import annotations

import re
from pathlib import Path

SPEC = Path(__file__).resolve().parents[1] / "docs" / "spec" / "instrument" / "specification.md"
POSTURE = (Path(__file__).resolve().parents[1] / "reference-implementations" / "agt" / "packages"
           / "host-adapter" / "src" / "failure-posture.ts")
CODE = "REPLAY_CONSUMED"
NUMBER = "-32009"


def section(heading_prefix: str) -> str:
    """The body under the heading that starts with heading_prefix, up to the next ## or ### heading."""
    text = SPEC.read_text(encoding="utf-8")
    match = re.search(rf"^#{{2,3}} {re.escape(heading_prefix)}[^\n]*\n(.*?)(?=^#{{2,3}} |\Z)", text, re.M | re.S)
    assert match, f"specification.md has no heading starting '{heading_prefix}'"
    return match.group(1)


def test_section_9_3_exists_and_names_the_code_and_number():
    body = section("9.3 Approval lifetime")
    assert CODE in body, f"section 9.3 no longer names {CODE}"
    assert NUMBER in body, f"section 9.3 no longer names {NUMBER}"


def test_the_consumed_approval_must_text_is_present_and_names_the_code():
    body = section("9.3 Approval lifetime")
    musts = [s for s in re.split(r"(?<=[.!?])\s+", body) if "MUST refuse" in s]
    assert musts, "section 9.3 has no 'MUST refuse' sentence"
    assert any(CODE in s and NUMBER in s and "consumed" in s for s in musts), (
        "no 'MUST refuse' sentence in section 9.3 names the consumed approval with the code and number"
    )


def test_the_in_flight_refusal_names_a_code():
    """The bullet that refuses a request arriving before the decision returns must carry its own code."""
    body = section("9.3 Approval lifetime")
    in_flight = [line for line in body.splitlines() if "before that decision returns" in line]
    assert len(in_flight) == 1, "section 9.3 must state the in-flight refusal exactly once"
    assert CODE in in_flight[0] and NUMBER in in_flight[0], "the in-flight refusal names no code"
    assert "still awaiting its decision" in body, (
        "the MUST sentence must cover a one-time approval another request is still awaiting a decision for"
    )


def test_the_error_registry_row_covers_all_three_refusals():
    text = SPEC.read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith(f"| `{NUMBER}`")]
    assert len(rows) == 1, f"the section 17.1 table needs exactly one {NUMBER} row"
    row = rows[0]
    assert f"`{CODE}`" in row
    for phrase in ("already consumed", "still awaiting its decision", "earlier session"):
        assert phrase in row, f"the {NUMBER} row no longer covers '{phrase}'"
    assert "(§9.3)" in row


def test_replay_protection_points_at_the_approval_rule():
    body = section("10.3 Replay protection")
    assert "(#93-approval-lifetime-normative)" in body, "section 10.3 no longer points at section 9.3"


def test_the_host_adapter_fails_closed_on_the_code():
    """A host that does not count -32009 as a refusal keeps its failure posture, and the default
    posture is proceed, so a Guardian emitting the code would fail open on the replayed approval."""
    text = POSTURE.read_text(encoding="utf-8")
    match = re.search(r"const REFUSAL_RPC_CODES = new Set\(\[([^\]]*)\]\)", text)
    assert match, "failure-posture.ts no longer declares REFUSAL_RPC_CODES"
    codes = {c.strip() for c in match.group(1).split(",")}
    assert NUMBER in codes, f"REFUSAL_RPC_CODES no longer holds {NUMBER}, so the host fails open on it"

