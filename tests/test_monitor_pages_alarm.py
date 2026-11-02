"""Tests for the issue a failed scheduled site monitor run opens.

The alarm must reach a person once, stay on one issue, and write nothing it fetched.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import monitor_pages_alarm as alarm  # noqa: E402
from roadmap_model import REPO  # noqa: E402

RUN = f"https://github.com/{REPO}/actions/runs/9"
LEADS = ["rocklambros", "afogel"]


class FakeGh:
    def __init__(self, issues=(), fail=()):
        self.issues = list(issues)
        self.fail = fail
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if any(word in " ".join(args) for word in self.fail):
            return 1, "", "boom"
        if "--slurp" in args:
            return 0, json.dumps([self.issues]), ""
        return 0, "{}", ""

    def writes(self):
        return [call for call in self.calls if "POST" in call]

    def field(self, name):
        return next(arg.split("=", 1)[1] for arg in self.writes()[0] if arg.startswith(f"{name}="))


def bot_issue(number, title=alarm.TITLE, **extra):
    return {"number": number, "title": title, **extra}


def test_failed_jobs_counts_a_timeout_as_failed():
    results = {"check": {"result": "cancelled"}, "navigation": {"result": "success"}}
    assert alarm.failed_jobs(json.dumps(results)) == ["check"]
    assert alarm.failed_jobs(json.dumps({"check": {"result": "skipped"}})) == []


def test_listing_spelling():
    # A wrong creator value returns an empty list with status 200, which opens a duplicate.
    assert alarm.OPEN_ISSUES == f"repos/{REPO}/issues?creator=github-actions%5Bbot%5D&state=open&per_page=100"


def test_the_first_failure_opens_one_unlabeled_issue_that_mentions_the_leads():
    gh = FakeGh()
    assert alarm.sound(gh, ["check"], RUN, LEADS) == "opened the issue"
    assert gh.writes()[0][3] == f"repos/{REPO}/issues"
    assert gh.field("title") == "Site monitor failing"
    body = gh.field("body")
    assert body.startswith("@rocklambros @afogel ")
    assert "Failed jobs: check." in body and RUN in body
    assert not any("label" in arg for arg in gh.writes()[0])




def test_an_open_issue_gets_a_comment_without_mentions():
    gh = FakeGh([bot_issue(7), bot_issue(5)])
    assert alarm.sound(gh, ["navigation"], RUN, LEADS) == "commented on #5"
    assert len(gh.writes()) == 1
    assert gh.writes()[0][3] == f"repos/{REPO}/issues/5/comments"
    assert "@" not in gh.field("body") and RUN in gh.field("body")


def test_other_issues_and_pull_requests_are_not_reused():
    gh = FakeGh([bot_issue(1, title="Roadmap health"), bot_issue(2, pull_request={})])
    assert alarm.sound(gh, ["check"], RUN, LEADS) == "opened the issue"


def test_a_failed_listing_opens_nothing():
    gh = FakeGh(fail=("--slurp",))
    with pytest.raises(alarm.monitor_roadmap.AlarmError):
        alarm.sound(gh, ["check"], RUN, LEADS)
    assert not gh.writes()


def run_main(monkeypatch, gh, leads=None):
    monkeypatch.setenv("JOB_RESULTS", json.dumps({"check": {"result": "failure"}}))
    monkeypatch.setenv("RUN_URL", RUN)
    monkeypatch.setattr(alarm.monitor_roadmap, "_gh", gh)
    if leads:
        monkeypatch.setattr(alarm.monitor_roadmap, "project_lead_logins", leads)
    return alarm.main()


def test_main_mentions_the_real_project_leads(monkeypatch):
    gh = FakeGh()
    assert run_main(monkeypatch, gh) == 0
    assert "@rocklambros" in gh.field("body")


def test_main_opens_the_issue_when_the_roster_does_not_parse(monkeypatch, capsys):
    def unreadable(_root):
        raise alarm.model.RosterError("GOVERNANCE.md: cannot read every person")

    gh = FakeGh()
    assert run_main(monkeypatch, gh, unreadable) == 0
    assert gh.field("body").startswith("The site monitor failed")
    assert "mentions nobody" in capsys.readouterr().out


def test_main_fails_when_the_alarm_cannot_post(monkeypatch, capsys):
    assert run_main(monkeypatch, FakeGh(fail=("POST",))) == 1
    assert "did not post" in capsys.readouterr().out
