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
    True: {"schedule": [{"cron": "47 */6 * * *"}], "workflow_dispatch": None},
    "permissions": {},
    "jobs": {"check": {
        "if": "vars.ROADMAP_RENDER_ENABLED == 'true' || vars.ROADMAP_SYNC_ENABLED == 'true'",
        "runs-on": "ubuntu-latest", "timeout-minutes": 5,
        "permissions": {"contents": "read", "issues": "read"},
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
