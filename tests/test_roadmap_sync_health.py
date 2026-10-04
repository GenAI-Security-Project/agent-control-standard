"""Tests for the nightly health report.

The report is the weekly call's triage agenda, so these pin both its content and the
contract the roadmap monitor parses: the status line, the marker, and that no fetched
issue text or contributor login ever appears in it.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from roadmap_model import REPO  # noqa: E402
from roadmap_sync import (  # noqa: E402
    SyncError,
    build_report,
    choose_health_issue,
    record_from_rest,
    render_health,
    status_line,
)

TRUSTED = frozenset({"rocklambros"})


def issue(number, labels=(), state="open", milestone=1, reason=None, title="SECRET TITLE", author="outsider"):
    return {
        "number": number, "state": state, "state_reason": reason, "title": title,
        "labels": [{"name": n} for n in labels], "user": {"login": author},
        "milestone": {"number": milestone} if milestone else None,
    }


SNAPSHOT = {
    "milestones": [
        {"number": 1, "title": "Ready one", "state": "open", "due_on": "2026-12-31T00:00:00Z", "description": "Workstream: Spec\nType: Document"},
        {"number": 2, "title": "Late one", "state": "open", "due_on": "2026-06-30T00:00:00Z", "description": "Workstream: Spec\nType: Document"},
        {"number": 3, "title": "Odd date", "state": "open", "due_on": "2026-11-15T00:00:00Z", "description": None},
        {"number": 4, "title": "Closed early", "state": "closed", "due_on": "2026-12-31T00:00:00Z", "description": "Workstream: Spec\nType: Document"},
        {"number": 5, "title": "Closed by mistake", "state": "closed", "due_on": "2026-12-31T00:00:00Z", "description": "Workstream: Spec\nType: Document"},
    ],
    "milestoned": [
        issue(10, ["status:accepted"], state="closed", reason="completed"),
        issue(20, ["status:accepted"], milestone=2),
        issue(21, ["status:needs-triage"], milestone=2),
        issue(22, ["wontfix"], milestone=2),
        issue(23, ["scope:deferred"], milestone=2),
        issue(30, ["status:accepted"], state="closed", reason="completed", milestone=3),
        issue(40, ["status:accepted"], milestone=4),
        issue(41, ["status:accepted"], state="closed", reason="completed", milestone=4),
        issue(50, [], state="closed", reason="not_planned", milestone=2),
        issue(70, ["status:accepted"], milestone=5),
    ],
    "unmilestoned_open": [issue(60, ["scope:in-focus"], milestone=None), issue(61, ["status:accepted"], milestone=None)],
    "closed_by": {10: "rocklambros", 30: "outsider", 41: "rocklambros", 50: "outsider"},
    "bot_accepted": [[20, "rocklambros"]],
}
SWITCHES = {"ROADMAP_RENDER_ENABLED": "true", "ROADMAP_REFRESH_ENABLED": "yes", "ROADMAP_SYNC_ENABLED": "true"}


def report():
    return build_report(SNAPSHOT, TRUSTED, {"Spec"}, date(2026, 11, 1), SWITCHES)


def test_record_from_rest_uppercases_reason():
    record = record_from_rest(issue(10, state="closed", reason="not_planned"), "x")
    assert record.state == "CLOSED" and record.state_reason == "NOT_PLANNED" and record.closed_by == "x"


def test_sections():
    r = report()
    assert r["ready_to_publish"] == [1]
    assert r["target_passed"] == [2]
    assert r["closed_with_open_work"] == [4]
    assert r["untriaged_in_milestone"] == [21]
    assert r["declined_by_triage_label"] == [22]
    assert r["awaiting_confirmation"] == [30, 50]
    assert r["in_focus_without_milestone"] == [60]
    assert r["accepted_without_milestone"] == [61]
    assert r["accepted_this_week"] == [[20, "rocklambros"]]
    assert r["off_quarter_dates"] == [3]
    assert r["missing_description_lines"] == [3]
    assert r["switches"] == [
        ["ROADMAP_REFRESH_ENABLED", "yes", True],
        ["ROADMAP_RENDER_ENABLED", "true", False],
        ["ROADMAP_SYNC_ENABLED", "true", False],
    ]
    assert r["closed_nothing_done"] == [5]


def test_render_never_leaks_titles_or_mentions():
    body = render_health(report(), "ok", "2026-11-01T04:12:09Z", "123", [])
    assert body.splitlines()[0] == "<!-- acs-sweep: ok 2026-11-01T04:12:09Z run 123 -->"
    assert "<!-- acs-roadmap-health -->" in body
    assert "SECRET TITLE" not in body
    assert "@rocklambros" not in body and "`rocklambros`" in body
    assert "outsider" not in body


def test_degraded_status_line_lists_sections():
    line = status_line("degraded", "2026-11-01T04:12:09Z", "9", ["accepted_this_week"])
    assert line == "<!-- acs-sweep: degraded 2026-11-01T04:12:09Z run 9 accepted_this_week -->"


def bot(number, state="open", body="x <!-- acs-roadmap-health --> y"):
    return {"number": number, "state": state, "user": {"login": "github-actions[bot]"}, "body": body}


def test_choose_health_issue():
    assert choose_health_issue([]) is None
    assert choose_health_issue([bot(1)])["number"] == 1
    forged = {"number": 2, "state": "open", "user": {"login": "attacker"}, "body": "<!-- acs-roadmap-health -->"}
    assert choose_health_issue([forged, bot(3)])["number"] == 3
    assert choose_health_issue([bot(4, body="no marker")]) is None
    with pytest.raises(SyncError, match="more than one"):
        choose_health_issue([bot(5), bot(6)])
    promotion_pr = dict(bot(7), pull_request={})
    assert choose_health_issue([promotion_pr]) is None


def test_health_listing_spelling():
    # A wrong creator value returns an empty list with status 200, which would create a
    # duplicate health issue every night.
    from roadmap_sync import HEALTH_LISTING
    assert HEALTH_LISTING == f"repos/{REPO}/issues?creator=github-actions%5Bbot%5D&state=all&per_page=100"


class FakeHealthGitHub:
    def __init__(self, issues=None, listing=None):
        self.issues = issues or {}
        self.listing = listing or []

    def get(self, path):
        return self.issues[int(path.rsplit("/", 1)[1])]

    def paginate(self, path):
        return self.listing


def test_health_issue_selection_by_variable_and_listing(monkeypatch):
    from roadmap_sync import _health_issue
    monkeypatch.setenv("ROADMAP_HEALTH_ISSUE", "12")
    assert _health_issue(FakeHealthGitHub(issues={12: bot(12)}))["number"] == 12
    with pytest.raises(SyncError):
        _health_issue(FakeHealthGitHub(issues={12: dict(bot(12), user={"login": "attacker"})}))
    monkeypatch.setenv("ROADMAP_HEALTH_ISSUE", "twelve")
    with pytest.raises(SyncError):
        _health_issue(FakeHealthGitHub())
    monkeypatch.delenv("ROADMAP_HEALTH_ISSUE")
    assert _health_issue(FakeHealthGitHub(listing=[])) is None
    assert _health_issue(FakeHealthGitHub(listing=[bot(3)]))["number"] == 3
