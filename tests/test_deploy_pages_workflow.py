"""Pins the deploy workflow's permissions, job wiring, and token placement.

Round four of the premortem found that a separate fetch job would have skipped build and
deploy silently through `needs`. These tests pin `needs` and `if` exactly so that defect
cannot return unnoticed.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "deploy-pages.yml"


def load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_job_permissions_are_exact():
    jobs = load()["jobs"]
    assert jobs["test"]["permissions"] == {"contents": "read"}
    assert jobs["build"]["permissions"] == {"contents": "read", "pages": "read", "issues": "read"}
    assert jobs["deploy"]["permissions"] == {"contents": "read", "pages": "write", "id-token": "write"}


def test_job_wiring_is_exact():
    jobs = load()["jobs"]
    assert jobs["build"]["needs"] == "test"
    assert "if" not in jobs["build"]
    assert jobs["build"]["outputs"] == {"publish": "${{ steps.gate.outputs.publish }}"}
    assert jobs["deploy"]["needs"] == "build"
    assert jobs["deploy"]["if"] == (
        "needs.build.outputs.publish == 'true' && github.event_name != 'pull_request' "
        "&& github.ref == 'refs/heads/main'"
    )


def test_dispatch_inputs():
    # PyYAML reads the key `on` as the boolean True.
    inputs = load()[True]["workflow_dispatch"]["inputs"]
    assert inputs["source"] == {"description": inputs["source"]["description"], "type": "string", "default": "manual"}
    assert inputs["preview"]["type"] == "boolean" and inputs["preview"]["default"] is False


def test_token_reaches_only_the_fetch_step():
    steps = load()["jobs"]["build"]["steps"]
    names = [step.get("name") for step in steps]
    fetch = names.index("Fetch roadmap data")
    setup = names.index("Install uv")
    assert fetch < setup, "the fetch must run before any package is installed"
    for index, step in enumerate(steps):
        env_text = repr(step.get("env", {})) + repr(step.get("with", {}))
        if index == fetch:
            assert step["env"] == {"GH_TOKEN": "${{ github.token }}"}
        else:
            assert "github.token" not in env_text
    assert steps[setup]["with"]["github-token"] == ""
    assert steps[fetch]["run"] == 'python3 -I -S tools/fetch_roadmap.py --out "$RUNNER_TEMP/roadmap-data.json"'
    assert steps[fetch]["timeout-minutes"] == 5
    assert steps[fetch]["continue-on-error"] is True


def test_no_run_passes_a_gh_override_or_interpolates():
    for job in load()["jobs"].values():
        for step in job["steps"]:
            run = step.get("run", "")
            assert "--gh" not in run
            assert "${{" not in run


def test_fetch_step_condition_is_exact():
    steps = load()["jobs"]["build"]["steps"]
    fetch = next(step for step in steps if step.get("name") == "Fetch roadmap data")
    assert fetch["if"] == "github.event_name != 'pull_request' && (vars.ROADMAP_RENDER_ENABLED == 'true' || inputs.preview)"
