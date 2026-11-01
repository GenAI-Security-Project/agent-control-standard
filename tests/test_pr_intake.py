"""Tests for the intake check. Every handle here is invented."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pr_intake  # noqa: E402

GOVERNANCE = """# Governance

Founder ([@founder](https://github.com/founder)).

## Project leads

| Project Lead | Pat ([@Pat-Lead](https://github.com/Pat-Lead)) |

## Workstream leads

| Docs | Sam ([@sam-lead](https://github.com/sam-lead)) |

## Triage volunteers

| Val ([@val](https://github.com/val)) |
"""
BOT_COMMENT = ["github-actions[bot]", f"Earlier. {pr_intake.SEEN}."]


class FakeGh:
    """Answers each listing from a table of canned rows, and records the writes."""

    def __init__(self, reviews=(), assigned=(), events=None, comments=(), fail=""):
        self.tables = {"/reviews": reviews, "/issues?assignee=": assigned, "/comments": comments}
        self.events, self.fail, self.writes, self.reads = events or {}, fail, [], []

    def __call__(self, *args):
        if args[0] != "api":
            if self.fail == args[1]:
                raise subprocess.CalledProcessError(1, "gh")
            self.writes.append(args)
            return ""
        path = args[2]
        self.reads.append(path)
        if self.fail and self.fail in path:
            raise subprocess.CalledProcessError(1, "gh")
        table = next((rows for key, rows in self.tables.items() if key in path), None)
        if table is None:
            table = self.events.get(path.split("/issues/")[1].split("/")[0], [])
        return "".join(json.dumps(row) + "\n" for row in table)


def run(fake, monkeypatch, author="newcomer", body="Closes #5", kind="User"):
    monkeypatch.setattr(pr_intake, "gh", fake)
    env = {"REPO": "o/n", "PR_NUMBER": "7", "PR_AUTHOR": author, "PR_AUTHOR_TYPE": kind, "PR_BODY": body}
    pr_intake.run(env, GOVERNANCE)
    return [write[:2] for write in fake.writes]


FLAGGED = [("pr", "edit"), ("pr", "comment")]


def test_roster_takes_only_the_lead_sections():
    assert pr_intake.leads(GOVERNANCE) == {"pat-lead", "sam-lead"}


def test_roster_reads_from_the_real_governance_file():
    # A reshaped GOVERNANCE.md fails here, not as a silent stop on every pull request.
    assert len(pr_intake.leads((ROOT / "GOVERNANCE.md").read_text(encoding="utf-8"))) >= 3


def test_nobody_asked_for_it_flags_once(monkeypatch):
    fake = FakeGh()
    assert run(fake, monkeypatch) == FLAGGED
    assert fake.writes[0][-1] == pr_intake.LABEL


@pytest.mark.parametrize("author", ["sam-lead", "PAT-LEAD"])
def test_a_lead_is_never_flagged_and_costs_no_call(author, monkeypatch):
    fake = FakeGh()
    assert run(fake, monkeypatch, author=author) == []
    assert fake.reads == []


@pytest.mark.parametrize(("author", "kind"), [("dependabot[bot]", "Bot"), ("helper-app", "Bot"), ("", "User")])
def test_bots_and_deleted_authors_are_skipped(author, kind, monkeypatch):
    fake = FakeGh()
    assert run(fake, monkeypatch, author=author, kind=kind) == []
    assert fake.reads == []


@pytest.mark.parametrize(("reviewer", "writes"), [("Sam-Lead", []), ("val", FLAGGED), (None, FLAGGED)])
def test_only_a_lead_review_clears_it(reviewer, writes, monkeypatch):
    assert run(FakeGh(reviews=[reviewer]), monkeypatch) == writes


@pytest.mark.parametrize(
    ("event", "writes"),
    [
        (["assigned", "newcomer", "pat-lead"], []),
        (["assigned", "newcomer", "val"], FLAGGED),
        (["assigned", "someone", "pat-lead"], FLAGGED),
        (["labeled", None, None], FLAGGED),
    ],
)
def test_only_a_leads_assignment_of_the_author_clears_it(event, writes, monkeypatch):
    assert run(FakeGh(assigned=[5], events={"5": [event]}), monkeypatch) == writes


def test_an_assignment_on_an_issue_the_body_does_not_reference_counts_for_nothing(monkeypatch):
    fake = FakeGh(assigned=[6], events={"6": [["assigned", "newcomer", "pat-lead"]]})
    assert run(fake, monkeypatch, body="Closes #5") == FLAGGED


def test_a_long_body_cannot_spend_the_token_budget(monkeypatch):
    fake = FakeGh(assigned=[399])
    run(fake, monkeypatch, body=" ".join(f"#{n}" for n in range(1, 400)))
    assert len(fake.reads) == 4


def test_empty_body_flags_without_crashing(monkeypatch):
    assert run(FakeGh(), monkeypatch, body="") == FLAGGED


def test_no_second_comment_and_no_label_after_a_lead_clears_it(monkeypatch):
    assert run(FakeGh(comments=[BOT_COMMENT]), monkeypatch) == []


def test_an_author_quoting_the_phrase_or_another_bot_comment_does_not_suppress(monkeypatch):
    comments = [["newcomer", BOT_COMMENT[1]], ["github-actions[bot]", "Roadmap note."], [None, None]]
    assert run(FakeGh(comments=comments), monkeypatch) == FLAGGED


def test_a_failed_lookup_still_flags(monkeypatch):
    assert run(FakeGh(fail="/reviews"), monkeypatch) == FLAGGED


@pytest.mark.parametrize("fail", ["edit", "/comments"])
def test_main_never_fails_the_job(fail, monkeypatch, capsys):
    monkeypatch.setattr(pr_intake, "gh", FakeGh(fail=fail))
    monkeypatch.chdir(ROOT)
    for key, value in {"REPO": "o/n", "PR_NUMBER": "7", "PR_AUTHOR": "newcomer", "PR_BODY": "#5 SECRET"}.items():
        monkeypatch.setenv(key, value)
    assert pr_intake.main() == 0
    out = capsys.readouterr().out
    assert "::warning::" in out and "SECRET" not in out


def test_main_survives_a_missing_environment_and_a_missing_roster(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert pr_intake.main() == 0
