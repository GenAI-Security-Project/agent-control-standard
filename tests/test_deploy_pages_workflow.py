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
    assert jobs["build"]["permissions"] == {
        "contents": "read", "pages": "read", "issues": "read", "pull-requests": "read",
    }
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



def test_build_checkout_is_a_full_clone():
    steps = load()["jobs"]["build"]["steps"]
    checkout = next(step for step in steps if step.get("name") == "Check out the repository")
    assert checkout["with"] == {"persist-credentials": False, "fetch-depth": 0}


def test_docs_build_precedes_the_404_copy_and_the_render():
    # Pages serves only a root-level 404.html. MkDocs writes its own into _site/docs, so
    # without the copy a missed address gets GitHub's page and no navigation pane.
    steps = load()["jobs"]["build"]["steps"]
    names = [step.get("name") for step in steps]
    build = names.index("Build the documentation site")
    copy = names.index("Copy the 404 page to the site root")
    render = names.index("Render the landing page")
    assert build + 1 == copy < render
    assert steps[copy]["run"] == "cp _site/docs/404.html _site/404.html"
    assert set(steps[copy]) == {"name", "run"}


def test_render_step_has_no_env():
    steps = load()["jobs"]["build"]["steps"]
    render = next(step for step in steps if step.get("name") == "Render the landing page")
    assert "env" not in render


def test_no_step_after_uv_install_references_a_token():
    # Every step after setup-uv runs code uv installed, so none of them may see a token.
    steps = load()["jobs"]["build"]["steps"]
    setup = [step.get("name") for step in steps].index("Install uv")
    for step in steps[setup + 1:]:
        assert "token" not in repr(step).lower(), step.get("name")
        assert "secrets." not in repr(step), step.get("name")


def test_navigation_verify_is_its_own_step_with_a_timeout_and_no_continue_on_error():
    steps = load()["jobs"]["deploy"]["steps"]
    names = [step.get("name") for step in steps]
    schemas = names.index("Verify the published schemas")
    navigation = names.index("Verify the published navigation")
    assert navigation == schemas + 1 == len(steps) - 1
    step = steps[navigation]
    assert step["timeout-minutes"] == 15
    assert step["env"] == {"PAGE_URL": "${{ steps.deployment.outputs.page_url }}"}
    assert step["run"].strip() == 'python3 tools/verify_site_nav.py "$PAGE_URL"'
    assert "continue-on-error" not in step
    assert "verify_site_nav" not in steps[schemas]["run"]


def test_schema_verify_reads_the_id_uris_not_the_page_url():
    # verify_published.py requires a schema to serve the URL it was asked for. On the
    # custom domain page_url names a host no $id declares, so it would fail all of them.
    step = next(s for s in load()["jobs"]["deploy"]["steps"] if s.get("name") == "Verify the published schemas")
    assert step["env"] == {"PAGE_URL": "https://genai-security-project.github.io/agent-control-standard/"}


def test_the_custom_domain_file_lands_in_the_uploaded_artifact():
    steps = load()["jobs"]["build"]["steps"]
    names = [step.get("name") for step in steps]
    write = names.index("Name the custom domain in the artifact")
    assert steps[write]["run"] == "printf 'owaspacs.org\\n' > _site/CNAME"
    # The last writer into _site before the upload, so no later step can drop it.
    assert names.index("Upload the artifact") == write + 1
