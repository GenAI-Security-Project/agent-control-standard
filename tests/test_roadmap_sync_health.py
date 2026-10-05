"""Tests for the nightly health report.

The report is the weekly call's triage agenda, so these pin both its content and the
contract the roadmap monitor parses: the status line, the marker, and that no fetched
issue text or contributor login ever appears in it.
"""
from __future__ import annotations

import subprocess
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
LEADS = frozenset({"rocklambros"})


def landed(login: str) -> dict:
    """Close facts for a merged pull request here that declares the close and reached main."""
    return {
        "closedBy": login, "closerKind": "pull_request", "closerInRepo": True, "declaresClose": True,
        "declaresContribution": False, "unparsed": False, "closerLanding": "on_main", "referencesLanding": "on_main",
    }


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
    "facts": {10: landed("rocklambros"), 30: landed("outsider"), 41: landed("rocklambros"), 50: {"closedBy": "outsider"}},
    "bot_accepted": [[20, "rocklambros"]],
}
SWITCHES = {"ROADMAP_RENDER_ENABLED": "true", "ROADMAP_REFRESH_ENABLED": "yes", "ROADMAP_SYNC_ENABLED": "true"}


def report():
    return build_report(SNAPSHOT, TRUSTED, LEADS, {"Spec"}, date(2026, 11, 1), SWITCHES)


def test_record_from_rest_uppercases_reason():
    record = record_from_rest(issue(10, state="closed", reason="not_planned"), {"closedBy": "x"})
    assert record.state == "CLOSED" and record.state_reason == "NOT_PLANNED" and record.closed_by == "x"
    assert record.closer_kind == "unknown"
    landed_record = record_from_rest(issue(10, state="closed", reason="completed"), landed("rocklambros"))
    assert landed_record.closer_kind == "pull_request" and landed_record.closer_landing == "on_main"
    assert record_from_rest(issue(11), None).closed_by is None


def test_sections():
    r = report()
    assert r["ready_to_publish"] == [1]
    assert r["target_passed"] == [2]
    assert r["closed_with_open_work"] == [4]
    assert r["untriaged_in_milestone"] == [21]
    assert r["declined_by_triage_label"] == [22]
    assert r["unverified_closes"] == [[30, 3, "untrusted_closer"], [50, 2, "untrusted_closer"]]
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


class TimeoutGitHub:
    def paginate(self, path):
        raise subprocess.TimeoutExpired(["gh"], 120)


def test_sweep_survives_a_non_sync_error_and_still_renders_switches(monkeypatch, capsys):
    import roadmap_sync
    monkeypatch.setattr(roadmap_sync, "GitHub", TimeoutGitHub)
    monkeypatch.setenv("ROADMAP_RENDER_ENABLED", "true")
    code = roadmap_sync._sweep(False)
    out = capsys.readouterr().out
    assert code == 1
    assert "<!-- acs-sweep: degraded" in out and "switches" not in out.splitlines()[0]
    assert "Could not be read on this run." in out
    assert "`ROADMAP_RENDER_ENABLED` is `true`" in out
    assert "TimeoutExpired" in out and "120" not in out.split("::warning::")[1].splitlines()[0]


class MigrateGitHub:
    def __init__(self, graphql):
        self.graphql = graphql

    def paginate(self, path):
        return []

    def get(self, path):
        return {"number": int(path.rsplit("/", 1)[1]), "state": "open", "labels": [], "user": {"login": "x"}, "html_url": "u"}

    def call(self, *args):
        return self.graphql


@pytest.mark.parametrize("graphql", [(1, "", "boom"), (0, "not json", ""), (0, "{}", "")])
def test_migrate_says_when_it_could_not_check(monkeypatch, tmp_path, capsys, graphql):
    import argparse
    import json as _json
    import roadmap_sync
    monkeypatch.setattr(roadmap_sync, "GitHub", lambda: MigrateGitHub(graphql))
    table = tmp_path / "t.json"
    table.write_text(_json.dumps({"assignments": {"M": [5]}}))
    roadmap_sync.cmd_migrate(argparse.Namespace(table=str(table), apply=False))
    assert "COULD NOT CHECK #5" in capsys.readouterr().out


def test_sweep_degrades_on_a_roster_that_does_not_parse(monkeypatch, capsys):
    import roadmap_sync

    def unreadable(_repo_root):
        raise roadmap_sync.model.RosterError("GOVERNANCE.md: cannot read every person")

    monkeypatch.setattr(roadmap_sync.model, "trusted_logins", unreadable)
    monkeypatch.setattr(roadmap_sync, "GitHub", TimeoutGitHub)
    code = roadmap_sync._sweep(False)
    out = capsys.readouterr().out
    assert code == 1
    assert "<!-- acs-sweep: degraded" in out
    assert "::warning::sweep failed: RosterError" in out
    assert "cannot read every person" not in out



def test_every_reason_code_has_one_remedy():
    from roadmap_model import REASON_CODES
    from roadmap_sync import REMEDIES
    assert set(REMEDIES) == set(REASON_CODES)
    # Reclosing a close the data rejects only restates the claim.
    for code in ("not_on_main", "reverted"):
        assert "reclose" not in REMEDIES[code].lower() and "Do not close it again" in REMEDIES[code]
    assert "project lead recloses" in REMEDIES["not_a_lead"]


def test_unverified_close_lines_carry_numbers_codes_and_remedies_only():
    snapshot = dict(SNAPSHOT, facts=dict(SNAPSHOT["facts"]))
    snapshot["facts"][10] = dict(landed("rocklambros"), closerLanding="not_on_main")
    body = render_health(build_report(snapshot, TRUSTED, LEADS, {"Spec"}, date(2026, 11, 1), SWITCHES), "ok", "t", "1", [])
    assert ("- #10 in [milestone 1](https://github.com/GenAI-Security-Project/agent-control-standard/milestone/1): "
            "`not_on_main`. Promote integration to main, or reopen the issue. Do not close it again.") in body
    assert "## Unverified closes" in body and "Awaiting maintainer confirmation" not in body


def test_a_missing_workstream_line_alone_is_not_reported():
    snapshot = dict(SNAPSHOT, milestones=[
        {"number": 6, "title": "No workstream", "state": "open", "due_on": "2026-12-31T00:00:00Z", "description": "Type: Document"},
        {"number": 7, "title": "No type", "state": "open", "due_on": "2026-12-31T00:00:00Z", "description": "Workstream: Spec"},
    ])
    assert build_report(snapshot, TRUSTED, LEADS, {"Spec"}, date(2026, 11, 1), SWITCHES)["missing_description_lines"] == [7]


def test_gh_calls_time_out_after_thirty_seconds(monkeypatch):
    import roadmap_sync
    seen = {}

    def slow(args, **kwargs):
        seen.update(kwargs)
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(roadmap_sync.subprocess, "run", slow)
    assert roadmap_sync.GitHub().call("api", "x") == (124, "", "gh timed out after 30 seconds")
    assert seen["timeout"] == 30
    with pytest.raises(SyncError):
        roadmap_sync.GitHub().get("x")


class FactsGitHub:
    def paginate(self, path):
        return []

    def call_list(self, args):
        import json as _json
        empty = {"data": {"repository": {"milestones": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}}}}
        return 0, "HTTP/2.0 200 OK\r\n\r\n" + _json.dumps(empty), ""


def test_snapshot_degrades_when_close_verification_fails():
    import roadmap_sync

    def shallow_git(args):
        return 0, "true\n"

    with pytest.raises(SyncError, match="verification"):
        roadmap_sync._snapshot(FactsGitHub(), shallow_git, date(2026, 11, 1), [])



class PlacedGitHub(MigrateGitHub):
    def get(self, path):
        number = int(path.rsplit("/", 1)[1])
        milestone = {"number": 7, "state": "open"} if number == 5 else None
        return {"number": number, "state": "open", "labels": [], "user": {"login": "x"}, "html_url": "u",
                "milestone": milestone}


def test_migrate_dry_run_prints_each_current_milestone(monkeypatch, tmp_path, capsys):
    import argparse
    import json as _json
    import roadmap_sync
    monkeypatch.setattr(roadmap_sync, "GitHub", lambda: PlacedGitHub((1, "", "boom")))
    table = tmp_path / "t.json"
    table.write_text(_json.dumps({"assignments": {"M": [5, 6]}}))
    roadmap_sync.cmd_migrate(argparse.Namespace(table=str(table), apply=False))
    out = capsys.readouterr().out
    assert "#5 issue by x open [] milestone 7 u" in out
    assert "#6 issue by x open [] milestone none u" in out
