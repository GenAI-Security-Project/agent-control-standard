"""Pins roadmap-sync.yml. Two jobs hold issues: write, so every key is allowlisted."""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "roadmap-sync.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SWITCH_ENV = {
    "ROADMAP_RENDER_ENABLED": "${{ vars.ROADMAP_RENDER_ENABLED }}",
    "ROADMAP_REFRESH_ENABLED": "${{ vars.ROADMAP_REFRESH_ENABLED }}",
    "ROADMAP_SYNC_ENABLED": "${{ vars.ROADMAP_SYNC_ENABLED }}",
    "ROADMAP_HEALTH_ISSUE": "${{ vars.ROADMAP_HEALTH_ISSUE }}",
}


def load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_triggers_are_exact():
    # PyYAML reads the key `on` as the boolean True.
    on = load()[True]
    assert set(on) == {"issues", "schedule", "workflow_dispatch"}
    assert on["issues"] == {"types": ["milestoned"]}
    assert on["schedule"] == [{"cron": "10 4 * * *"}]
    assert set(on["workflow_dispatch"]["inputs"]) == {"issue"}


def test_top_level_keys():
    assert set(load()) == {"name", True, "permissions", "jobs"}
    assert load()["permissions"] == {}


def test_jobs_are_exact():
    jobs = load()["jobs"]
    assert set(jobs) == {"event", "sweep", "dryrun"}
    allowed = {"if", "runs-on", "timeout-minutes", "permissions", "concurrency", "steps"}
    for job in jobs.values():
        assert set(job) <= allowed
        assert job["runs-on"] == "ubuntu-latest"
    assert jobs["event"]["if"] == "github.event_name == 'issues' && vars.ROADMAP_SYNC_ENABLED == 'true'"
    assert jobs["sweep"]["if"] == "github.event_name == 'schedule' && vars.ROADMAP_SYNC_ENABLED == 'true'"
    assert jobs["dryrun"]["if"] == "github.event_name == 'workflow_dispatch'"
    assert jobs["event"]["permissions"] == {"contents": "read", "issues": "write"}
    assert jobs["sweep"]["permissions"] == {"contents": "read", "issues": "write"}
    assert jobs["dryrun"]["permissions"] == {"contents": "read", "issues": "read"}
    # Keyed per issue. A newer pending run replacing an older one for the same issue loses
    # nothing, because each run re-reads the issue's live state. No `queue: max`: actionlint
    # 1.7.12 rejects it, zizmor does not validate it, and a stalled-dispatch report exists.
    assert jobs["event"]["concurrency"] == {
        "group": "roadmap-event-${{ github.event.issue.number }}", "cancel-in-progress": False,
    }
    assert jobs["sweep"]["concurrency"] == {"group": "roadmap-sweep", "cancel-in-progress": False}


def test_steps_are_exact():
    jobs = load()["jobs"]
    expected_runs = {
        "event": 'python3 -I -S tools/roadmap_sync.py event --issue "$ISSUE_NUMBER" --apply',
        "sweep": "python3 -I -S tools/roadmap_sync.py sweep --apply",
        "dryrun": 'python3 -I -S tools/roadmap_sync.py dryrun --issue "$ISSUE_NUMBER"',
    }
    expected_env = {
        "event": {"GH_TOKEN": "${{ github.token }}", "ISSUE_NUMBER": "${{ github.event.issue.number }}"},
        "sweep": {"GH_TOKEN": "${{ github.token }}", "RUN_ID": "${{ github.run_id }}", **SWITCH_ENV},
        "dryrun": {"GH_TOKEN": "${{ github.token }}", "RUN_ID": "${{ github.run_id }}", "ISSUE_NUMBER": "${{ inputs.issue }}", **SWITCH_ENV},
    }
    for name, job in jobs.items():
        checkout, tool = job["steps"]
        assert checkout["uses"] == CHECKOUT
        assert checkout["with"] == {"persist-credentials": False, "ref": "main"}
        assert set(tool) == {"name", "env", "run"}
        assert tool["run"] == expected_runs[name]
        assert tool["env"] == expected_env[name]
        assert "${{" not in tool["run"] and "uv" not in tool["run"]
