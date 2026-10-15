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
    DELIVERABLE_TYPES,
    REASON_CODES,
    IssueRecord,
    OWASP_STATUS,
    Roster,
    assess,
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

TRUSTED = frozenset({"rocklambros", "afogel", "victorm-hernandez"})
LEADS = frozenset({"rocklambros", "afogel"})


def issue(**kw) -> IssueRecord:
    base = dict(number=1, state="OPEN", state_reason=None, labels=frozenset(), author="x", closed_by=None)
    base.update(kw)
    return IssueRecord(**base)


# A close by a merged pull request in this repository that declares the close and landed.
LANDED = dict(
    state="CLOSED", state_reason="COMPLETED", closed_by="victorm-hernandez", closer_kind="pull_request",
    closer_in_repo=True, declares_close=True, closer_landing="on_main", references_landing="on_main",
)
# A project lead's hand close with every referencing pull request on main.
HAND = dict(state="CLOSED", state_reason="COMPLETED", closed_by="RockLambros", closer_kind="none",
            references_landing="on_main")


@pytest.mark.parametrize(
    "record, expected",
    [
        (issue(**LANDED), ("done", None)),
        (issue(**dict(LANDED, closer_kind="commit")), ("done", None)),
        (issue(**HAND), ("done", None)),
        (issue(**dict(LANDED, closed_by="outsider")), ("unverified", "untrusted_closer")),
        (issue(**dict(LANDED, closed_by=None)), ("unverified", "untrusted_closer")),
        (issue(state="CLOSED", state_reason="NOT_PLANNED", closed_by="outsider"), ("unverified", "untrusted_closer")),
        (issue(state="CLOSED", state_reason="NOT_PLANNED", closed_by="afogel"), ("dropped", None)),
        (issue(state="CLOSED", state_reason="DUPLICATE", closed_by="afogel"), ("dropped", None)),
        (issue(state="CLOSED", state_reason="SOMETHING_NEW", closed_by="afogel"), ("dropped", None)),
        (issue(**dict(LANDED, closer_landing="not_on_main")), ("unverified", "not_on_main")),
        (issue(**dict(LANDED, closer_landing=None)), ("unverified", "not_on_main")),
        (issue(**dict(LANDED, closer_landing="reverted")), ("unverified", "reverted")),
        (issue(**dict(LANDED, declares_close=False)), ("unverified", "no_close_declared")),
        # A "Fixes #N" subject over a "Part of #N" body contributes, so it does not close.
        (issue(**dict(LANDED, declares_contribution=True)), ("unverified", "contributing")),
        (issue(**dict(LANDED, declares_close=False, declares_contribution=True)), ("unverified", "contributing")),
        (issue(**dict(LANDED, closer_in_repo=False)), ("unverified", "other_repository")),
        (issue(**dict(HAND, closed_by="victorm-hernandez")), ("unverified", "not_a_lead")),
        (issue(**dict(LANDED, unparsed=True)), ("unverified", "unparsed")),
        (issue(**dict(LANDED, closer_kind="project_board")), ("unverified", "unknown_closer")),
        (issue(**dict(LANDED, closer_kind="unknown")), ("unverified", "unknown_closer")),
        # A lead's hand close with an unpromoted pull request behind it is not delivery.
        (issue(**dict(HAND, references_landing="not_on_main")), ("unverified", "not_on_main")),
        (issue(**dict(HAND, references_landing="reverted")), ("unverified", "reverted")),
        (issue(**dict(LANDED, references_landing="not_on_main")), ("unverified", "not_on_main")),
        (issue(labels=frozenset({ACCEPTED})), ("planned", None)),
        (issue(labels=frozenset({ACCEPTED, DEFERRED})), ("planned", None)),
        (issue(labels=frozenset({DEFERRED})), ("deferred", None)),
        (issue(labels=frozenset({"status:needs-triage"})), ("untriaged", None)),
        (issue(labels=frozenset({"status:blocked"})), ("untriaged", None)),
    ],
)
def test_assess(record, expected):
    assert assess(record, TRUSTED, LEADS) == expected
    assert classify(record, TRUSTED, LEADS) == expected[0]


def test_every_reason_code_is_reachable_and_listed():
    assert set(REASON_CODES) == {
        "not_on_main", "reverted", "no_close_declared", "contributing", "other_repository",
        "not_a_lead", "untrusted_closer", "unparsed", "unknown_closer",
    }


def test_a_record_without_close_facts_never_counts_as_done():
    bare = issue(state="CLOSED", state_reason="COMPLETED", closed_by="rocklambros")
    assert assess(bare, TRUSTED, LEADS) == ("unverified", "unknown_closer")


def test_deliverable_types_are_the_sheet_dropdown():
    assert DELIVERABLE_TYPES == ("Application/Tool", "Cheat Sheet", "Code Sample", "Document", "OSS Project", "Other")


def test_unknown_reason():
    assert unknown_reason(issue(state="CLOSED", state_reason="SOMETHING_NEW"))
    assert unknown_reason(issue(state="CLOSED", state_reason=None))
    assert not unknown_reason(issue(state="CLOSED", state_reason="COMPLETED"))
    assert not unknown_reason(issue())


def oracle(closed, has_due, done, unverified, planned, deferred, untriaged):
    # Every open issue in a milestone is remaining work, whatever its labels.
    remaining = unverified + planned + deferred + untriaged
    if closed:
        if done == 0:
            return "withdrawn"
        return "published" if remaining == 0 else "closed_with_open_work"
    if done == 0 and unverified + planned + untriaged == 0:
        return "deferred" if deferred else "skipped"
    if not has_due:
        return "ongoing"
    if remaining == 0:
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
    assert milestone_state(closed, has_due, counts) == oracle(closed, has_due, done, unverified, planned, deferred, untriaged)


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
        ("close with an untriaged or blocked issue still open", True, dict(done=1, untriaged=1), "closed_with_open_work"),
        ("close with a deferred issue still open", True, dict(done=1, deferred=1), "closed_with_open_work"),
        ("all done but one untriaged", False, dict(done=2, untriaged=1), "in_progress"),
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
    assert parse_description("Workstream: Spec\nType: OSS Project", {"Spec"}).errors == ()
    assert parse_description("Workstream: Spec\nType: Open Source tool", {"Spec"}).errors == ("type",)


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
                {"number": 1, "state": "CLOSED", "stateReason": "COMPLETED", "author": "a", "labels": [ACCEPTED],
                 "closedBy": "rocklambros", "title": "MUST NOT LEAK", "closerKind": "pull_request", "closerInRepo": True,
                 "declaresClose": True, "declaresContribution": False, "unparsed": False,
                 "closerLanding": "on_main", "referencesLanding": "on_main"},
                {"number": 2, "state": "OPEN", "stateReason": None, "author": "a", "labels": [ACCEPTED], "closedBy": None},
                {"number": 3, "state": "CLOSED", "stateReason": "COMPLETED", "author": "a", "labels": [ACCEPTED],
                 "closedBy": "rocklambros", "closerKind": "pull_request", "closerInRepo": True,
                 "declaresClose": True, "declaresContribution": False, "unparsed": False,
                 "closerLanding": "reverted", "referencesLanding": "on_main"},
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
    assert first["issues"]["unverified"] == [3] and first["unverified_reasons"] == {"3": "reverted"}
    assert first["description"] == "Fix it." and first["workstream"] == "Spec"
    assert "MUST NOT LEAK" not in repr(out)
    empty = next(m for m in out["milestones"] if m["number"] == 8)
    assert empty["state"] == "skipped" and empty["quarter"] is None and empty["unverified_reasons"] == {}


def test_empty_roadmap():
    out = empty_roadmap("unavailable", "t", "c", "r", reason="rate_limit")
    assert out["milestones"] == [] and out["status"] == "unavailable" and out["reason"] == "rate_limit"


def test_skipped_milestone_never_reports_target_passed():
    # The sweep excludes skipped milestones, so roadmap.json must agree.
    milestones = [{"number": 8, "title": "Empty", "description": None, "state": "OPEN", "dueOn": "2026-03-31T00:00:00Z", "url": "u", "issues": []}]
    out = build_roadmap(milestones, ROSTER, TRUSTED, date(2026, 11, 1), "t", "c", "r")
    entry = out["milestones"][0]
    assert entry["state"] == "skipped" and entry["target_passed"] is False
