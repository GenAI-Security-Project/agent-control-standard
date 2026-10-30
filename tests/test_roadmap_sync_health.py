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
    # Created dates give 42, 22, 7, and 2 days on 2026-11-01. Pull request 104 carries the
    # label and no data line.
    "queued_pulls": [
        [101, "no_accepted", "2026-09-21", "62:2026-10-02", "2026-09-20T09:00:00Z"],
        [102, "awaiting_rereview", "2026-10-25", "", "2026-10-25T09:00:00Z"],
        [103, "sent_back", "2026-10-10", "", "2026-10-10T09:00:00Z"],
        [104, None, None, "", "2026-10-30T09:00:00Z"],
    ],
    "intake_claims": [[62, 30, 101]],
    "intake_sweep": ["success", 555, "2026-11-01T03:00:00Z"],
    "intake_recent": [
        [201, False, None, "2026-10-20T00:00:00Z"],
        [202, True, "hand", "2026-10-21T00:00:00Z"],
        [203, False, "review", "2026-08-01T00:00:00Z"],
    ],
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
    assert r["queued_pulls"] == [
        [101, "no_accepted", 42, "62:2026-10-02"], [103, "sent_back", 22, ""], [102, "awaiting_rereview", 7, ""],
    ]
    assert r["queued_unrecorded"] == [104]
    assert r["queued_meta"] == ["success", 555, "2026-11-01T03:00:00Z"]
    assert r["queued_unreadable"] == 0
    assert r["intake_counts"] == {
        "median_age_days": 22, "hand_cleared_60d": 1, "non_roster_merges_60d": 1,
        "non_roster_merges_prior_60d": 1, "claims_waiting": 1,
    }


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

    def call_list(self, args, stdin=None):
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


def test_switches_heading_says_every_value_is_listed():
    # The section lists every switch so the weekly call sees rendering turned off, and only
    # flags odd values. The heading must not claim it lists odd values alone.
    import roadmap_sync
    note = dict((key, note) for key, _title, note in roadmap_sync.SECTION_TITLES)["switches"]
    assert note == "The current value of each roadmap variable, flagged when it is neither true nor false."


# The queued pull requests section. The intake gate's state is read from the bot's data
# line, and the section renders numbers, reason codes, dates, and days only.

def intake_comment(line, login="github-actions[bot]"):
    return {"user": {"login": login}, "body": f"{line}\n<!-- acs-intake -->\nQueued text that must never render."}


def labeled_pull(number, author="outsider", created="2026-10-01T00:00:00Z"):
    return {
        "number": number, "state": "open", "pull_request": {}, "title": "SECRET TITLE", "user": {"login": author},
        "labels": [{"name": "status:needs-triage"}], "created_at": created,
    }


CLOSED_PAGE = f"repos/{REPO}/pulls?state=closed&sort=updated&direction=desc&per_page=100&page="


class IntakeGitHub:
    """Serves the intake reads. `closed` is page 1 of the closed listing, `pages` every page."""

    def __init__(self, labeled=(), comments=None, closed=(), runs=None, pages=None):
        self.labeled = list(labeled)
        self.comments = comments or {}
        self.pages = pages if pages is not None else [list(closed)]
        self.runs = runs if runs is not None else {"workflow_runs": []}
        self.paths = []

    def paginate(self, path):
        self.paths.append(("paginate", path))
        assert "actions/" not in path, "the runs path returns an object, never a list of pages"
        assert "/pulls?" not in path, "the closed listing is read page by page so it can stop early"
        if "/comments" in path:
            return self.comments.get(int(path.split("/issues/")[1].split("/")[0]), [])
        if "/issues?" in path:
            return self.labeled
        raise AssertionError(path)

    def get(self, path):
        self.paths.append(("get", path))
        if path.endswith("actions/workflows/pr-intake.yml/runs?event=schedule&status=completed&per_page=1"):
            return self.runs
        if path.startswith(CLOSED_PAGE):
            page = int(path[len(CLOSED_PAGE):])
            return self.pages[page - 1] if page <= len(self.pages) else []
        raise AssertionError(path)

    def requested(self, kind):
        return [path for how, path in self.paths if kind in path]


def closed_pull(number, closed, merged=None, login="outsider", updated=None):
    return {
        "number": number, "user": {"login": login}, "closed_at": closed, "merged_at": merged,
        "updated_at": updated or closed,
    }


def intake_body(gh, today=date(2026, 11, 1), trusted=TRUSTED, failed=()):
    from roadmap_sync import intake_snapshot
    snapshot = dict(SNAPSHOT, **intake_snapshot(gh, today, trusted))
    r = build_report(snapshot, TRUSTED, LEADS, {"Spec"}, today, SWITCHES)
    return r, render_health(r, "ok", "t", "1", list(failed))


def test_queued_section_renders_numbers_reasons_days_only():
    gh = IntakeGitHub(
        labeled=[labeled_pull(301)],
        comments={301: [intake_comment("<!-- acs-intake-data reason=no_accepted since=2026-10-01 claimed=62:2026-10-02 head=abc -->")]},
        runs={"workflow_runs": [{"id": 777, "conclusion": "success", "created_at": "2026-11-01T03:00:00Z"}]},
    )
    r, body = intake_body(gh)
    assert r["queued_pulls"] == [[301, "no_accepted", 31, "62:2026-10-02"]]
    assert "## Queued pull requests" in body
    assert "- #301: no_accepted, 31 days" in body
    assert "the nightly intake sweep run 777 concluded success" in body
    assert "- #62: commented 30 days ago by the author of PR #301 (14 days or more)" in body
    assert "Any comment by the author before the pull request counts, so read the issue before acting." in body
    assert (f"[All queued pull requests with authors](https://github.com/{REPO}/pulls?q="
            "is%3Apr+is%3Aopen+label%3Astatus%3Aneeds-triage)") in body
    assert "outsider" not in body and "SECRET TITLE" not in body and "Queued text" not in body
    assert ("get", f"repos/{REPO}/actions/workflows/pr-intake.yml/runs?event=schedule&status=completed&per_page=1") in gh.paths


def test_queued_section_says_when_no_scheduled_run_completed():
    _r, body = intake_body(IntakeGitHub())
    assert "No completed scheduled run of the nightly intake sweep." in body


def test_queued_section_ignores_a_data_line_from_anyone_but_the_bot():
    forged = intake_comment("<!-- acs-intake-data reason=no_accepted since=2020-01-01 claimed=62:2020-01-01 -->", login="outsider")
    r, body = intake_body(IntakeGitHub(labeled=[labeled_pull(302)], comments={302: [forged]}))
    assert r["queued_pulls"] == [] and r["queued_unrecorded"] == [302]
    assert r["intake_counts"]["claims_waiting"] == 0
    assert "Labeled without a gate record" in body and "- #302" in body


@pytest.mark.parametrize("line", [
    "<!-- acs-intake-data reason=bogus since=2026-10-01 -->",
    "<!-- acs-intake-data reason=no_accepted since=yesterday -->",
    "<!-- acs-intake-data reason=no_accepted since=2026-13-40 -->",
    "<!-- acs-intake-data reason=no_accepted since=2026-10-01 claimed=62:soon -->",
    "<!-- acs-intake-data reason=no_accepted since=2026-10-01 since=2026-10-02 -->",
    "not a data line",
])
def test_queued_section_drops_a_malformed_data_line(line):
    r, body = intake_body(IntakeGitHub(labeled=[labeled_pull(303)], comments={303: [intake_comment(line)]}))
    assert r["queued_pulls"] == [] and r["queued_unrecorded"] == []
    assert r["queued_unreadable"] == 1
    assert "bogus" not in body and "yesterday" not in body and "soon" not in body
    assert "Data lines that could not be read: 1." in body


def test_queued_headings_for_thirty_days_awaiting_sent_back_and_unrecorded():
    body = render_health(report(), "ok", "t", "1", [])
    section = body.split("## Queued pull requests", 1)[1].split("\n## ", 1)[0]
    for heading in ("Queued more than 30 days", "Awaiting re-review", "Sent back, no response", "Labeled without a gate record"):
        assert heading in section
    after = lambda heading: section.split(heading, 1)[1].split("\n\n", 2)[1]  # noqa: E731
    assert after("Queued more than 30 days").splitlines() == ["- #101: no_accepted, 42 days"]
    assert after("Awaiting re-review").splitlines() == ["- #102: awaiting_rereview, 7 days"]
    assert after("Sent back, no response").splitlines() == ["- #103: sent_back, 22 days"]
    assert after("Labeled without a gate record").splitlines() == ["- #104"]
    # Grouped by reason, in the gate's reason order.
    assert section.index("- #101: no_accepted") < section.index("- #103: sent_back") < section.index("- #102: awaiting_rereview")


def test_claims_counted_once_per_author_and_issue():
    line = "<!-- acs-intake-data reason=no_accepted since=2026-10-01 claimed={} -->"
    gh = IntakeGitHub(
        labeled=[labeled_pull(311, "alice"), labeled_pull(312, "Alice"), labeled_pull(313, "bob")],
        comments={
            311: [intake_comment(line.format("62:2026-10-20,63:2026-10-30"))],
            312: [intake_comment(line.format("62:2026-10-10"))],
            313: [intake_comment(line.format("62:2026-10-25"))],
        },
    )
    r, body = intake_body(gh)
    assert r["intake_counts"]["claims_waiting"] == 3
    claims = body.split("Claims waiting on a lead", 1)[1].split("Any comment", 1)[0]
    assert [row for row in claims.splitlines() if row.startswith("- ")] == [
        "- #62: commented 22 days ago by the author of PR #312 (14 days or more)",
        "- #62: commented 7 days ago by the author of PR #313",
        "- #63: commented 2 days ago by the author of PR #311",
    ]
    assert "alice" not in body.lower() and "bob" not in body


def test_hand_cleared_counts_the_route_not_the_merge():
    cleared = "<!-- acs-intake-data reason=cleared route={} cleared=2026-10-01 -->"
    gh = IntakeGitHub(
        closed=[
            {"number": 401, "user": {"login": "rocklambros"}, "closed_at": "2026-10-20T00:00:00Z", "merged_at": "2026-10-20T00:00:00Z"},
            {"number": 402, "user": {"login": "outsider"}, "closed_at": "2026-10-21T00:00:00Z", "merged_at": "2026-10-21T00:00:00Z"},
            {"number": 403, "user": {"login": "outsider"}, "closed_at": "2026-08-15T00:00:00Z", "merged_at": "2026-08-15T00:00:00Z"},
            {"number": 404, "user": {"login": "outsider"}, "closed_at": "2026-10-22T00:00:00Z", "merged_at": None},
            {"number": 405, "user": {"login": "outsider"}, "closed_at": "2026-05-01T00:00:00Z", "merged_at": "2026-05-01T00:00:00Z"},
            # Bot merges are not outside contributions, in either window.
            closed_pull(406, "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z", login="dependabot[bot]"),
            closed_pull(407, "2026-08-10T00:00:00Z", "2026-08-10T00:00:00Z", login="Dependabot[bot]"),
        ],
        comments={
            401: [intake_comment(cleared.format("hand"))],
            402: [intake_comment(cleared.format("review"))],
            403: [intake_comment(cleared.format("hand"))],
        },
    )
    r, body = intake_body(gh)
    from roadmap_sync import intake_snapshot
    assert [row[0] for row in intake_snapshot(gh, date(2026, 11, 1), TRUSTED)["intake_recent"]] == [401, 402, 403, 404]
    assert r["intake_counts"]["hand_cleared_60d"] == 1
    assert r["intake_counts"]["non_roster_merges_60d"] == 1
    assert r["intake_counts"]["non_roster_merges_prior_60d"] == 1
    assert "Hand-cleared in the last 60 days: 1." in body
    assert "Non-roster merges in the last 60 days: 1, against 1 in the 60 days before." in body


def test_intake_recent_keeps_no_login():
    from roadmap_sync import intake_snapshot
    gh = IntakeGitHub(closed=[{"number": 401, "user": {"login": "outsider"}, "closed_at": "2026-10-20T00:00:00Z", "merged_at": None}])
    snapshot = intake_snapshot(gh, date(2026, 11, 1), TRUSTED)
    assert snapshot["intake_recent"] == [[401, False, None, None]]
    assert "outsider" not in repr(snapshot)


def test_baseline_line_when_unset_and_when_set(monkeypatch):
    monkeypatch.delenv("PR_INTAKE_BASELINES", raising=False)
    body = render_health(report(), "ok", "t", "1", [])
    assert "Baseline not recorded. A project lead sets PR_INTAKE_BASELINES." in body
    assert "Review due" not in body
    monkeypatch.setenv("PR_INTAKE_BASELINES", "recorded=2026-11-01 median_age=12 hand_cleared_60d=3 non_roster_merges_60d=4")
    body = render_health(report(), "ok", "t", "1", [])
    assert "Baseline recorded 2026-11-01: median age 12 days, 3 hand-cleared, 4 non-roster merges in 60 days." in body
    assert ("Review due 2026-12-31: if claims waiting rose or non-roster merges fell against the prior 60 days, "
            "a project lead sets PR_INTAKE_ENFORCED=false.") in body
    monkeypatch.setenv("PR_INTAKE_BASELINES", "recorded=soon <b>x</b>")
    body = render_health(report(), "ok", "t", "1", [])
    assert "Baseline not recorded." in body and "<b>" not in body


class FailingIntakeGitHub(FactsGitHub):
    def get(self, path):
        raise SyncError("boom")


def test_intake_read_failure_degrades_one_section():
    import roadmap_sync

    def git(args):
        return 0, "false\n"

    failed = []
    snapshot = roadmap_sync._snapshot(FailingIntakeGitHub(), git, date(2026, 11, 1), failed)
    assert "queued_pulls" in failed
    assert "in_focus_without_milestone" not in failed and "accepted_this_week" not in failed
    assert snapshot["queued_pulls"] == [] and snapshot["intake_recent"] == [] and snapshot["intake_sweep"] == []
    r = build_report(snapshot, TRUSTED, LEADS, {"Spec"}, date(2026, 11, 1), SWITCHES)
    body = render_health(r, "degraded", "t", "1", failed)
    section = body.split("## Queued pull requests", 1)[1].split("\n## ", 1)[0]
    assert "Could not be read on this run." in section


def test_closed_listing_stops_at_the_window_start():
    # The window starts 2026-07-04. Page 1 ends on a pull request updated before it, and
    # closed_at is never later than updated_at, so page 2 cannot hold anything in the window.
    first = [closed_pull(500 + n, "2026-10-01T00:00:00Z") for n in range(99)]
    first.append(closed_pull(599, "2026-06-01T00:00:00Z"))
    second = [closed_pull(600, "2026-10-02T00:00:00Z")]
    gh = IntakeGitHub(pages=[first, second])
    from roadmap_sync import intake_snapshot
    snapshot = intake_snapshot(gh, date(2026, 11, 1), TRUSTED)
    assert gh.requested("&page=") == [CLOSED_PAGE + "1"]
    assert len(snapshot["intake_recent"]) == 99


def test_closed_listing_reads_the_next_page_while_inside_the_window():
    first = [closed_pull(500 + n, "2026-10-01T00:00:00Z") for n in range(100)]
    second = [closed_pull(700, "2026-09-01T00:00:00Z")]
    gh = IntakeGitHub(pages=[first, second])
    from roadmap_sync import intake_snapshot
    snapshot = intake_snapshot(gh, date(2026, 11, 1), TRUSTED)
    assert gh.requested("&page=") == [CLOSED_PAGE + "1", CLOSED_PAGE + "2"]
    assert len(snapshot["intake_recent"]) == 101


def test_closed_listing_past_the_page_cap_degrades_rather_than_undercounts():
    from roadmap_sync import CLOSED_PAGE_CAP, intake_snapshot
    full = [closed_pull(500 + n, "2026-10-01T00:00:00Z") for n in range(100)]
    gh = IntakeGitHub(pages=[full] * (CLOSED_PAGE_CAP + 1))
    with pytest.raises(SyncError, match="page"):
        intake_snapshot(gh, date(2026, 11, 1), TRUSTED)
    assert len(gh.requested("&page=")) == CLOSED_PAGE_CAP


def test_comments_are_read_only_for_merges_in_the_last_sixty_days():
    hand = "<!-- acs-intake-data reason=cleared route=hand cleared=2026-08-01 -->"
    gh = IntakeGitHub(
        closed=[
            closed_pull(801, "2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z"),
            closed_pull(802, "2026-08-03T00:00:00Z", "2026-08-03T00:00:00Z"),
            closed_pull(803, "2026-10-21T00:00:00Z", None),
        ],
        comments={801: [intake_comment(hand)], 802: [intake_comment(hand)], 803: [intake_comment(hand)]},
    )
    from roadmap_sync import intake_snapshot
    snapshot = intake_snapshot(gh, date(2026, 11, 1), TRUSTED)
    assert gh.requested("/comments") == [f"repos/{REPO}/issues/801/comments?per_page=100"]
    assert snapshot["intake_recent"] == [
        [801, False, "hand", "2026-10-20T00:00:00Z"], [802, False, None, "2026-08-03T00:00:00Z"], [803, False, None, None],
    ]


def test_a_far_future_baseline_reads_as_not_recorded(monkeypatch):
    monkeypatch.setenv("PR_INTAKE_BASELINES", "recorded=9999-12-01 median_age=1 hand_cleared_60d=1 non_roster_merges_60d=1")
    body = render_health(report(), "ok", "t", "1", [])
    assert "Baseline not recorded. A project lead sets PR_INTAKE_BASELINES." in body
    assert "9999" not in body


def test_a_legacy_intake_comment_is_not_called_a_missing_record():
    legacy = {"user": {"login": "github-actions[bot]"}, "body": "Thanks for this. It is queued rather than ignored. More text."}
    forged = {"user": {"login": "outsider"}, "body": "Thanks for this. It is queued rather than ignored."}
    gh = IntakeGitHub(labeled=[labeled_pull(321), labeled_pull(322)], comments={321: [legacy], 322: [forged]})
    r, body = intake_body(gh)
    assert r["queued_legacy"] == [321] and r["queued_unrecorded"] == [322]
    section = body.split("## Queued pull requests", 1)[1].split("\n## ", 1)[0]
    assert section.split("Queued under the earlier intake comment:", 1)[1].split("\n\n", 2)[1].splitlines() == ["- #321"]
    assert section.split("Labeled without a gate record:", 1)[1].split("\n\n", 2)[1].splitlines() == ["- #322"]
    assert "More text" not in body
