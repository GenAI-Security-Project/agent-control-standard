"""Pins the monitor workflow's jobs, so each check keeps its own conclusion.

The schema and navigation checks fail for unrelated reasons. One job
holding them all would hide the later ones behind the first and report one red mark for
several problems. The fourth job holds the only write grant, so it is pinned key by key.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "monitor-pages.yml"


def load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_monitor_pages_jobs_that_read_site_files_check_out_main():
    workflow = load()
    assert workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert set(jobs) == {"check", "navigation", "report-failure"}
    for name in ("check", "navigation"):
        job = jobs[name]
        assert job["permissions"] == {"contents": "read"}, name
        assert isinstance(job["timeout-minutes"], int), name
        assert "needs" not in job, name
        checkout = next(step for step in job["steps"] if step.get("name") == "Check out the repository")
        # The site publishes from main whichever branch is default, so each job must
        # verify main's files against it.
        assert checkout["with"] == {"persist-credentials": False, "ref": "main"}, name
    assert jobs["check"]["timeout-minutes"] == 20
    assert jobs["navigation"]["timeout-minutes"] == 15
    runs = [step["run"].strip() for step in jobs["navigation"]["steps"] if "run" in step]
    assert runs == ['python3 tools/verify_site_nav.py "$PAGE_URL"']
    verify = next(step for step in jobs["navigation"]["steps"] if "run" in step)
    assert verify["env"] == {"PAGE_URL": "https://owaspacs.org/"}
    assert "continue-on-error" not in verify
    schemas = next(step for step in jobs["check"]["steps"] if "run" in step)
    # The $id URIs stay on github.io. Moving this to the domain fails every schema.
    assert schemas["env"] == {"PAGE_URL": "https://genai-security-project.github.io/agent-control-standard/"}
    assert all("verify_site_nav" not in step.get("run", "") for step in jobs["check"]["steps"])


def test_report_failure_runs_only_after_a_failed_scheduled_run_with_issues_write():
    job = load()["jobs"]["report-failure"]
    assert set(job) == {"needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"}
    assert job["needs"] == ["check", "navigation"]
    assert job["permissions"] == {"issues": "write"}
    # A timed-out job reports cancelled, so this must count both results. cancelled() stops
    # a run someone cancelled by hand from raising the alarm.
    assert job["if"] == (
        "!cancelled() && github.event_name == 'schedule' && "
        "(contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled'))"
    )
    checkout, tool = job["steps"]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"] == {"persist-credentials": False}
    assert set(tool) == {"name", "env", "run"}
    assert tool["run"].strip() == "python3 -I -S tools/monitor_pages_alarm.py"
    assert tool["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "JOB_RESULTS": "${{ toJSON(needs) }}",
        "RUN_URL": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}",
    }


def test_monitor_runs_interpolate_nothing():
    for job in load()["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in step.get("run", "")
