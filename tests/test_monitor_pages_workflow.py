"""Pins the monitor workflow's three jobs, so each check keeps its own conclusion.

The schema, navigation, and origin certificate checks fail for unrelated reasons. One job
holding them all would hide the later ones behind the first and report one red mark for
several problems.
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
    assert set(jobs) == {"check", "navigation", "origin-cert"}
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


def test_origin_cert_job_runs_the_check_read_only_from_its_own_ref():
    job = load()["jobs"]["origin-cert"]
    assert job["permissions"] == {"contents": "read"}
    assert isinstance(job["timeout-minutes"], int)
    assert "needs" not in job
    checkout = next(step for step in job["steps"] if step.get("name") == "Check out the repository")
    # Pinning ref: main here would skip the alarm until the next promotion.
    assert checkout["with"] == {"persist-credentials": False}
    verify = next(step for step in job["steps"] if "run" in step)
    assert verify["run"].strip() == "python3 -I -S tools/check_origin_cert.py"
    assert "if" not in verify
    assert "continue-on-error" not in verify


def test_monitor_runs_interpolate_nothing():
    for job in load()["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in step.get("run", "")
