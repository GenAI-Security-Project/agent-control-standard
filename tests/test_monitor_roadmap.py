"""Tests for the roadmap monitor's conditions."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from monitor_roadmap import check_health, check_page  # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "monitor-roadmap.yml"


@pytest.mark.parametrize(
    "doc, problems",
    [
        ({"status": "ok", "generated": "2026-11-02T05:20:00Z"}, 0),
        ({"status": "ok", "generated": "2026-10-31T05:20:00Z"}, 1),
        ({"status": "unavailable", "generated": "2026-11-02T05:20:00Z"}, 1),
        ({"status": "disabled", "generated": "2026-11-02T05:20:00Z"}, 1),
        (None, 1),
    ],
)
def test_check_page(doc, problems):
    assert len(check_page(doc, NOW)) == problems


def health(line, author="github-actions[bot]", marker=True):
    body = line + "\n" + ("<!-- acs-roadmap-health -->" if marker else "")
    return {"user": {"login": author}, "body": body}


@pytest.mark.parametrize(
    "configured, issue, problems",
    [
        ("12", health("<!-- acs-sweep: ok 2026-11-02T04:12:00Z run 5 -->"), 0),
        ("12", health("<!-- acs-sweep: degraded 2026-11-02T04:12:00Z run 5 accepted_this_week -->"), 1),
        ("12", health("<!-- acs-sweep: ok 2026-10-30T04:12:00Z run 5 -->"), 1),
        ("12", health("<!-- acs-sweep: ok 2026-11-03T04:12:00Z run 5 -->"), 1),
        ("12", health("<!-- acs-sweep: ok 2026-11-02T04:12:00Z run 5 -->", author="attacker"), 1),
        ("12", health("<!-- acs-sweep: ok 2026-11-02T04:12:00Z run 5 -->", marker=False), 1),
        ("12", health("no status line"), 1),
        ("", None, 1),
        ("twelve", None, 1),
    ],
)
def test_check_health(configured, issue, problems):
    assert len(check_health(configured, issue, NOW)) == problems


EXPECTED = {
    "name": "Monitor roadmap",
    True: {"schedule": [{"cron": "47 */6 * * *"}], "workflow_dispatch": {"inputs": {"test_alarm": {
        "description": "Post the failing alarm and then the recovery comment, without a real failure.",
        "type": "boolean", "default": False,
    }}}},
    "permissions": {},
    "jobs": {"check": {
        "if": "vars.ROADMAP_RENDER_ENABLED == 'true' || vars.ROADMAP_SYNC_ENABLED == 'true'",
        "runs-on": "ubuntu-latest", "timeout-minutes": 5,
        "permissions": {"contents": "read", "issues": "write"},
        "steps": [
            {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "with": {"persist-credentials": False, "ref": "main"}},
            {"name": "Check the roadmap outputs",
             "env": {
                 "GH_TOKEN": "${{ github.token }}",
                 "PAGE_URL": "https://genai-security-project.github.io/agent-control-standard",
                 "ROADMAP_RENDER_ENABLED": "${{ vars.ROADMAP_RENDER_ENABLED }}",
                 "ROADMAP_SYNC_ENABLED": "${{ vars.ROADMAP_SYNC_ENABLED }}",
                 "ROADMAP_HEALTH_ISSUE": "${{ vars.ROADMAP_HEALTH_ISSUE }}",
                 "TEST_ALARM": "${{ inputs.test_alarm }}",
             },
             "run": "python3 -I -S tools/monitor_roadmap.py"},
        ],
    }},
}


def test_monitor_workflow_is_exactly_this():
    # PyYAML reads the key `on` as the boolean True.
    assert yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")) == EXPECTED


@pytest.mark.parametrize("render, sync, expected", [
    ("false", "false", 0),
    ("true", "false", 1),
    ("false", "true", 1),
    ("true", "true", 2),
])
def test_evaluate_runs_only_switched_on_checks(render, sync, expected):
    from monitor_roadmap import evaluate
    env = {"ROADMAP_RENDER_ENABLED": render, "ROADMAP_SYNC_ENABLED": sync, "ROADMAP_HEALTH_ISSUE": "12"}
    problems = evaluate(env, read_json=lambda url: None, read_issue=lambda n: None, now=NOW)
    assert len(problems) == expected


def test_check_page_never_echoes_fetched_status():
    hostile = "bad\n::error::injected"
    problems = check_page({"status": hostile, "generated": "2026-11-02T05:20:00Z"}, NOW)
    assert problems == ["roadmap.json status is not ok"]
    assert "injected" not in "".join(problems)
    assert check_page({"status": "disabled", "generated": "x"}, NOW) == ["roadmap.json status is 'disabled'"]


@pytest.mark.parametrize("doc", [[], "text", 5, [{"status": "ok"}]])
def test_check_page_non_object_is_unreadable(doc):
    assert check_page(doc, NOW) == ["roadmap.json could not be read"]


@pytest.mark.parametrize("generated", ["2026-11-02T05:20:00", 5, None, "junk"])
def test_check_page_unparseable_generated(generated):
    problems = check_page({"status": "ok", "generated": generated}, NOW)
    assert problems == ["roadmap.json has no readable generated time"]


def test_check_health_time_without_zone_is_unparseable():
    problems = check_health("12", health("<!-- acs-sweep: ok 2026-11-02T04:12:00 run 5 -->"), NOW)
    assert problems == ["the status line time does not parse"]


def test_check_health_malformed_issue_shapes():
    assert len(check_health("12", {"user": "x", "body": "b"}, NOW)) == 1
    assert len(check_health("12", {"user": {"login": "github-actions[bot]"}, "body": 5}, NOW)) == 1


@pytest.mark.parametrize("failure", [
    subprocess.TimeoutExpired(cmd="gh", timeout=60),
    json.JSONDecodeError("bad", "doc", 0),
])
def test_read_issue_failures_return_none(monkeypatch, failure):
    import monitor_roadmap

    def boom(*args, **kwargs):
        raise failure

    monkeypatch.setattr(monitor_roadmap.subprocess, "run", boom)
    assert monitor_roadmap._read_issue("12") is None


def test_read_issue_non_object_returns_none(monkeypatch):
    import monitor_roadmap

    done = subprocess.CompletedProcess([], 0, stdout="[1]", stderr="")
    monkeypatch.setattr(monitor_roadmap.subprocess, "run", lambda *a, **k: done)
    assert monitor_roadmap._read_issue("12") is None


@pytest.mark.parametrize("value, passed", [(" 12 ", "12"), ("\u0661\u0662", None), ("1 2", None), ("", None)])
def test_evaluate_validates_and_strips_issue_number(value, passed):
    from monitor_roadmap import evaluate
    seen = []
    env = {"ROADMAP_RENDER_ENABLED": "false", "ROADMAP_SYNC_ENABLED": "true", "ROADMAP_HEALTH_ISSUE": value}
    problems = evaluate(env, read_json=lambda url: None, read_issue=lambda n: seen.append(n), now=NOW)
    assert seen == ([passed] if passed else [])
    assert len(problems) == 1



# --- The lead alarm (decision 17) ---------------------------------------------------------

from monitor_roadmap import AlarmError, alarm_body, last_alarm, sound  # noqa: E402

LEADS = ["rocklambros", "afogel", "bar-capsule"]


def bot_comment(state, login="github-actions[bot]"):
    return {"user": {"login": login}, "body": f"<!-- acs-roadmap-alarm: {state} -->\nText."}


class FakeGh:
    """Records every gh call. Comments come back as one slurped page."""

    def __init__(self, comments=(), fail=()):
        self.comments = list(comments)
        self.fail = set(fail)
        self.calls: list[list[str]] = []

    def __call__(self, args):
        self.calls.append(args)
        verb = args[2] if len(args) > 2 and args[1] == "-X" else "GET"
        if verb in self.fail:
            return 1, "", "HTTP 403"
        if verb == "POST":
            body = next(a for a in args if a.startswith("body="))[5:]
            self.comments.append({"user": {"login": "github-actions[bot]"}, "body": body})
        if verb == "GET":
            return 0, json.dumps([self.comments]), ""
        return 0, "{}", ""

    def posted(self):
        return [next(a for a in c if a.startswith("body="))[5:] for c in self.calls if "POST" in c]


def test_last_alarm_reads_only_the_bot():
    assert last_alarm([]) is None
    assert last_alarm([bot_comment("failing"), bot_comment("passing")]) == "passing"
    assert last_alarm([bot_comment("failing"), bot_comment("passing", login="attacker")]) == "failing"
    assert last_alarm([{"user": {"login": "github-actions[bot]"}, "body": "no marker"}]) is None


def test_first_failure_mentions_every_lead_through_unlock_comment_relock():
    gh = FakeGh()
    assert sound(gh, "12", True, ["the roadmap health issue"], LEADS) == ["failing"]
    verbs = [c[2] for c in gh.calls if c[1] == "-X"]
    assert verbs == ["DELETE", "POST", "PUT"]
    body = gh.posted()[0]
    assert body.startswith("<!-- acs-roadmap-alarm: failing -->")
    assert "@rocklambros @afogel @bar-capsule" in body and "the roadmap health issue" in body


def test_repeated_failure_posts_nothing():
    gh = FakeGh(comments=[bot_comment("failing")])
    assert sound(gh, "12", True, ["the published roadmap.json"], LEADS) == []
    assert gh.posted() == []


def test_recovery_posts_once_without_mentions():
    gh = FakeGh(comments=[bot_comment("failing")])
    assert sound(gh, "12", False, [], LEADS) == ["passing"]
    assert "@" not in gh.posted()[0].split("-->", 1)[1]
    assert sound(gh, "12", False, [], LEADS) == []


def test_a_first_passing_run_posts_nothing():
    gh = FakeGh()
    assert sound(gh, "12", False, [], LEADS) == [] and gh.posted() == []


def test_another_logins_marker_does_not_silence_the_alarm():
    gh = FakeGh(comments=[bot_comment("failing", login="attacker")])
    assert sound(gh, "12", True, ["the roadmap health issue"], LEADS) == ["failing"]


def test_the_test_input_posts_failing_then_recovery():
    gh = FakeGh()
    assert sound(gh, "12", False, [], LEADS, test=True) == ["failing", "passing"]
    first, second = gh.posted()
    assert "@rocklambros" in first and "an alarm test" in first
    assert second.startswith("<!-- acs-roadmap-alarm: passing -->")
    assert [c[2] for c in gh.calls if c[1] == "-X"] == ["DELETE", "POST", "PUT", "DELETE", "POST", "PUT"]


def test_already_unlocked_issue_and_failed_relock_still_alarm(capsys):
    gh = FakeGh(fail={"DELETE", "PUT"})
    assert sound(gh, "12", True, ["the roadmap health issue"], LEADS) == ["failing"]
    assert "relock" in capsys.readouterr().out


def test_failed_comment_raises():
    with pytest.raises(AlarmError):
        sound(FakeGh(fail={"POST"}), "12", True, ["the roadmap health issue"], LEADS)


def test_alarm_body_holds_fixed_text_only():
    assert alarm_body("passing", [], LEADS) == "<!-- acs-roadmap-alarm: passing -->\nThe roadmap monitor passes again."
    assert alarm_body("failing", [], LEADS).endswith("Failing checks: an unnamed check. The monitor's run log names each problem.")


def run_main(monkeypatch, env, gh, checks):
    import monitor_roadmap
    for name in ("ROADMAP_RENDER_ENABLED", "ROADMAP_SYNC_ENABLED", "ROADMAP_HEALTH_ISSUE", "TEST_ALARM"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(monitor_roadmap, "evaluate_checks", lambda *a, **k: checks)
    monkeypatch.setattr(monitor_roadmap, "_gh", gh)
    return monitor_roadmap.main()


def test_main_without_the_variable_still_fails_and_comments_nowhere(monkeypatch):
    gh = FakeGh()
    assert run_main(monkeypatch, {}, gh, {"page": ["roadmap.json status is 'disabled'"]}) == 1
    assert gh.calls == []
    assert run_main(monkeypatch, {"TEST_ALARM": "true"}, gh, {}) == 1


def test_main_fails_when_the_comment_fails_even_on_recovery(monkeypatch):
    gh = FakeGh(comments=[bot_comment("failing")], fail={"POST"})
    assert run_main(monkeypatch, {"ROADMAP_HEALTH_ISSUE": "12"}, gh, {"health": []}) == 1


def test_main_posts_with_the_real_project_leads(monkeypatch):
    gh = FakeGh()
    assert run_main(monkeypatch, {"ROADMAP_HEALTH_ISSUE": "12"}, gh, {"health": ["the last sweep was degraded"]}) == 1
    body = gh.posted()[0]
    assert "@rocklambros @afogel @bar-capsule" in body and "the roadmap health issue" in body
    assert "degraded" not in body
