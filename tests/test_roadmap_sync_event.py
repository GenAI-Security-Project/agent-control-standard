"""Tests for the event job's acceptance rule and the migration planner.

Pure planning functions only. No test here calls `gh`.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from roadmap_sync import Action, delivered_by, execute, missing_acceptance, plan_event, plan_migration  # noqa: E402


def rest(labels=(), state="open", milestone_state="open", pr=False, number=5):
    issue = {
        "number": number,
        "state": state,
        "labels": [{"name": name} for name in labels],
        "milestone": {"number": 2, "state": milestone_state} if milestone_state else None,
    }
    if pr:
        issue["pull_request"] = {}
    return issue


@pytest.mark.parametrize(
    "issue, expected",
    [
        (rest(), [Action("add_labels", 5, ("status:accepted", "scope:in-focus"))]),
        (rest(["scope:in-focus"]), [Action("add_labels", 5, ("status:accepted",))]),
        (
            rest(["status:needs-triage"]),
            [Action("add_labels", 5, ("status:accepted", "scope:in-focus")), Action("remove_label", 5, ("status:needs-triage",))],
        ),
        (rest(["status:accepted", "status:needs-triage"]), [Action("remove_label", 5, ("status:needs-triage",))]),
        (rest(["status:accepted"]), []),
        (rest(["scope:deferred"]), []),
        (rest(["wontfix"]), []),
        (rest(["status:blocked", "status:needs-triage"]), []),
        (rest(state="closed"), []),
        (rest(milestone_state=None), []),
        (rest(milestone_state="closed"), []),
        (rest(pr=True), []),
    ],
)
def test_plan_event(issue, expected):
    assert plan_event(issue) == expected


def test_plan_never_touches_milestones_or_other_labels():
    for labels in ([], ["status:needs-triage"], ["status:accepted", "status:needs-triage"]):
        for action in plan_event(rest(labels)):
            assert action.kind in ("add_labels", "remove_label")
            if action.kind == "remove_label":
                assert action.labels == ("status:needs-triage",)


class FakeGitHub:
    def __init__(self, fail_delete_404=False):
        self.calls = []
        self.fail_delete_404 = fail_delete_404

    def call(self, *args):
        self.calls.append(args)
        if self.fail_delete_404 and "DELETE" in args:
            return 1, "", "gh: Label does not exist (HTTP 404)"
        return 0, "{}", ""


def test_execute_treats_missing_label_as_success():
    gh = FakeGitHub(fail_delete_404=True)
    execute(gh, [Action("remove_label", 5, ("status:needs-triage",))])
    assert gh.calls[0][:3] == ("api", "-X", "DELETE")


def test_execute_paces_writes():
    gh = FakeGitHub()
    slept = []
    execute(gh, [Action("add_labels", 1, ("a",)), Action("add_labels", 2, ("a",))], pace=1.0, sleep=slept.append)
    assert slept == [1.0, 1.0]


def test_plan_migration_refuses_prs_and_closed_and_unknown_milestones():
    table = {"assignments": {"Spec fixes": [1, 2, 3], "Missing": [4]}}
    milestones = [{"number": 9, "title": "Spec fixes", "state": "open"}]
    issues = {
        1: rest(number=1, milestone_state=None),
        2: rest(number=2, pr=True, milestone_state=None),
        3: rest(number=3, state="closed", milestone_state=None),
    }
    actions, refusals = plan_migration(table, milestones, issues)
    assert Action("set_milestone", 1, milestone=9) in actions
    assert Action("add_labels", 1, ("status:accepted", "scope:in-focus")) in actions
    assert any("#2" in r and "pull request" in r for r in refusals)
    assert any("#3" in r and "closed" in r for r in refusals)
    assert any("Missing" in r for r in refusals)


def test_delivered_by_reads_merged_pull_requests_only():
    nodes = [
        {"source": {"number": 168, "merged": True}},
        {"source": {"number": 20, "merged": False}},
        {"source": {}},
        {},
    ]
    assert delivered_by(nodes) == [168]


def test_missing_acceptance():
    issues = [
        rest(["status:accepted"], number=1),
        rest([], number=2),
        rest(["scope:deferred"], number=3),
        rest([], number=4, state="closed"),
        rest([], number=5, pr=True),
    ]
    assert missing_acceptance(issues) == [2]


def test_plan_migration_refuses_bad_numbers_and_duplicates():
    table = {"assignments": {"Spec fixes": [1, "@~/.ssh/id_rsa", 0], "Other": [1]}}
    milestones = [{"number": 9, "title": "Spec fixes", "state": "open"}, {"number": 10, "title": "Other", "state": "open"}]
    _actions, refusals = plan_migration(table, milestones, {1: rest(number=1, milestone_state=None)})
    assert any("not an issue number" in r for r in refusals)
    assert any("more than one milestone" in r for r in refusals)


def test_plan_migration_is_empty_once_applied():
    table = {"assignments": {"Spec fixes": [1]}}
    milestones = [{"number": 9, "title": "Spec fixes", "state": "open"}]
    done = rest(["status:accepted", "scope:in-focus"], number=1)
    done["milestone"] = {"number": 9, "state": "open"}
    actions, refusals = plan_migration(table, milestones, {1: done})
    assert actions == [] and refusals == []


def test_decision_constants_change_the_plan(monkeypatch):
    import roadmap_model

    monkeypatch.setattr(roadmap_model, "ADD_IN_FOCUS_ON_ACCEPT", False)
    assert plan_event(rest()) == [Action("add_labels", 5, ("status:accepted",))]
    monkeypatch.setattr(roadmap_model, "MILESTONE_ACCEPTS", False)
    assert plan_event(rest()) == []
