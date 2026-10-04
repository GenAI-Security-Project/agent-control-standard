"""Tests for the roadmap rules: issue classes, milestone states, quarters, and assembly.

The states test checks every combination against a hand-written oracle, because a
first-match table always matches exactly one row, so "exactly one state" proves nothing.
"""
from __future__ import annotations

import itertools
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from roadmap_model import (  # noqa: E402
    ACCEPTED,
    DEFERRED,
    IssueRecord,
    OWASP_STATUS,
    Roster,
    build_roadmap,
    classify,
    due_date,
    empty_roadmap,
    is_quarter_end,
    milestone_state,
    parse_description,
    quarter_label,
    target_passed,
    unknown_reason,
)

TRUSTED = frozenset({"rocklambros", "afogel"})


def issue(**kw) -> IssueRecord:
    base = dict(number=1, state="OPEN", state_reason=None, labels=frozenset(), author="x", closed_by=None)
    base.update(kw)
    return IssueRecord(**base)


@pytest.mark.parametrize(
    "record, expected",
    [
        (issue(state="CLOSED", state_reason="COMPLETED", closed_by="RockLambros"), "done"),
        (issue(state="CLOSED", state_reason="COMPLETED", closed_by="outsider"), "unverified"),
        (issue(state="CLOSED", state_reason="NOT_PLANNED", closed_by="outsider"), "unverified"),
        (issue(state="CLOSED", state_reason="COMPLETED", closed_by=None), "unverified"),
        (issue(state="CLOSED", state_reason="NOT_PLANNED", closed_by="afogel"), "dropped"),
        (issue(state="CLOSED", state_reason="DUPLICATE", closed_by="afogel"), "dropped"),
        (issue(state="CLOSED", state_reason="SOMETHING_NEW", closed_by="afogel"), "dropped"),
        (issue(labels=frozenset({ACCEPTED})), "planned"),
        (issue(labels=frozenset({ACCEPTED, DEFERRED})), "planned"),
        (issue(labels=frozenset({DEFERRED})), "deferred"),
        (issue(labels=frozenset({"status:needs-triage"})), "untriaged"),
    ],
)
def test_classify(record, expected):
    assert classify(record, TRUSTED) == expected


def test_unknown_reason():
    assert unknown_reason(issue(state="CLOSED", state_reason="SOMETHING_NEW"))
    assert unknown_reason(issue(state="CLOSED", state_reason=None))
    assert not unknown_reason(issue(state="CLOSED", state_reason="COMPLETED"))
    assert not unknown_reason(issue())


def oracle(closed, has_due, done, unverified, planned, deferred):
    remaining = unverified + planned
    if closed:
        if done == 0:
            return "withdrawn"
        return "published" if remaining == 0 else "closed_with_open_work"
    if done == 0 and remaining == 0:
        return "deferred" if deferred else "skipped"
    if not has_due:
        return "ongoing"
    if done and remaining == 0:
        return "ready"
    if done:
        return "in_progress"
    return "planning"


@pytest.mark.parametrize(
    "closed, has_due, done, unverified, planned, deferred, dropped, untriaged",
    list(itertools.product([False, True], [False, True], [0, 1], [0, 1], [0, 1], [0, 1], [0, 1], [0, 1])),
)
def test_milestone_state_matches_oracle(closed, has_due, done, unverified, planned, deferred, dropped, untriaged):
    counts = dict(done=done, unverified=unverified, planned=planned, deferred=deferred, dropped=dropped, untriaged=untriaged)
    assert milestone_state(closed, has_due, counts) == oracle(closed, has_due, done, unverified, planned, deferred)


def test_every_state_has_an_owasp_status_entry():
    for state in ("withdrawn", "published", "closed_with_open_work", "skipped", "deferred", "ongoing", "ready", "in_progress", "planning"):
        assert state in OWASP_STATUS
    assert OWASP_STATUS["withdrawn"] is None and OWASP_STATUS["skipped"] is None
    assert OWASP_STATUS["published"] == "Published"


@pytest.mark.parametrize(
    "procedure, closed, counts, expected",
    [
        ("ship", True, dict(done=3), "published"),
        ("withdraw, nothing delivered", True, dict(planned=2), "withdrawn"),
        ("close partway, rest open", True, dict(done=1, planned=2), "closed_with_open_work"),
        ("close partway, rest not planned", True, dict(done=1, dropped=2), "published"),
        ("add a deliverable, no issues yet", False, dict(), "skipped"),
        ("drop the only issue by clearing its milestone", False, dict(), "skipped"),
        ("move a deliverable to another quarter", False, dict(planned=1), "planning"),
    ],
)
def test_changing_the_roadmap_procedures(procedure, closed, counts, expected):
    full = dict(done=0, unverified=0, planned=0, deferred=0, dropped=0, untriaged=0)
    full.update(counts)
    assert milestone_state(closed, True, full) == expected, procedure


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-12-31T00:00:00Z", "Q4 2026"),
        ("2027-01-01T00:00:00Z", "Q1 2027"),
        ("2026-10-01T00:00:00Z", "Q4 2026"),
        ("2026-03-31T23:59:59Z", "Q1 2026"),
    ],
)
def test_quarter_from_date_part_only(raw, expected):
    assert quarter_label(due_date(raw)) == expected


def test_quarter_end_and_target_passed():
    assert is_quarter_end(date(2026, 12, 31)) and is_quarter_end(date(2026, 6, 30))
    assert not is_quarter_end(date(2026, 12, 30))
    q4 = date(2026, 12, 31)
    assert not target_passed(q4, None, date(2026, 12, 31))
    assert target_passed(q4, None, date(2027, 1, 1))
    assert target_passed(q4, date(2026, 12, 9), date(2026, 12, 10))
    assert not target_passed(q4, date(2026, 12, 9), date(2026, 12, 9))
    assert not target_passed(None, None, date(2030, 1, 1))


def test_parse_description_lines_and_errors():
    raw = "Ship the thing.\n\nCommitted: 2026-12-09\nWorkstream: Spec\nType: Document\n"
    parsed = parse_description(raw, {"Spec"})
    assert parsed.text == "Ship the thing."
    assert parsed.committed == date(2026, 12, 9)
    assert parsed.workstream == "Spec" and parsed.deliverable_type == "Document"
    assert parsed.errors == ()

    bad = parse_description("Committed: soon\nWorkstream: Nope\nType: Poem", {"Spec"})
    assert set(bad.errors) == {"committed", "workstream", "type"}
    missing = parse_description(None, {"Spec"})
    assert set(missing.errors) == {"workstream", "type"}
    assert parse_description("Workstream: Project\nType: Other", {"Spec"}).errors == ()


ROSTER = Roster(
    project_leads=(("Rock Lambros", "rocklambros"),),
    workstreams={"Spec": (("Bar Kaduri", "bar-capsule"),), "Documentation": ()},
)


def test_build_roadmap_shape_and_no_issue_titles():
    milestones = [
        {
            "number": 7, "title": "Spec fixes", "description": "Fix it.\nWorkstream: Spec\nType: Document",
            "state": "OPEN", "dueOn": "2026-12-31T00:00:00Z", "url": "https://github.com/x/milestone/7",
            "issues": [
                {"number": 1, "state": "CLOSED", "stateReason": "COMPLETED", "author": "a", "labels": [ACCEPTED], "closedBy": "rocklambros", "title": "MUST NOT LEAK"},
                {"number": 2, "state": "OPEN", "stateReason": None, "author": "a", "labels": [ACCEPTED], "closedBy": None},
            ],
        },
        {"number": 8, "title": "Empty", "description": None, "state": "OPEN", "dueOn": None, "url": "u", "issues": []},
    ]
    out = build_roadmap(milestones, ROSTER, TRUSTED, date(2026, 11, 1), "2026-11-01T00:00:00Z", "abc", "9")
    assert out["status"] == "ok" and out["schema_version"] == 1 and out["commit"] == "abc"
    assert out["project_leads"] == ["Rock Lambros"]
    assert out["co_owners"] == ["Rock Lambros"]
    assert out["workstreams"]["Spec"] == ["Bar Kaduri"]
    first = next(m for m in out["milestones"] if m["number"] == 7)
    assert first["state"] == "in_progress" and first["owasp_status"] == "In Progress"
    assert first["quarter"] == "Q4 2026" and first["counts"]["done"] == 1
    assert first["issues"]["done"] == [1] and first["issues"]["planned"] == [2]
    assert first["description"] == "Fix it." and first["workstream"] == "Spec"
    assert "MUST NOT LEAK" not in repr(out)
    empty = next(m for m in out["milestones"] if m["number"] == 8)
    assert empty["state"] == "skipped" and empty["quarter"] is None


def test_empty_roadmap():
    out = empty_roadmap("unavailable", "t", "c", "r", reason="rate_limit")
    assert out["milestones"] == [] and out["status"] == "unavailable" and out["reason"] == "rate_limit"


def test_skipped_milestone_never_reports_target_passed():
    # The sweep excludes skipped milestones, so roadmap.json must agree.
    milestones = [{"number": 8, "title": "Empty", "description": None, "state": "OPEN", "dueOn": "2026-03-31T00:00:00Z", "url": "u", "issues": []}]
    out = build_roadmap(milestones, ROSTER, TRUSTED, date(2026, 11, 1), "t", "c", "r")
    entry = out["milestones"][0]
    assert entry["state"] == "skipped" and entry["target_passed"] is False
