"""Runs pr-intake's closing-keyword step against a fake gh, and pins the workflow's safety.

The keyword logic lives in the YAML, so these tests lift the script out and run it. The
intake check itself is tools/pr_intake.py, tested in tests/test_pr_intake.py.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "pr-intake.yml"

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["GH_LOG"]
with open(log, "a") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
state = json.loads(os.environ["GH_STATE"])
if args[:1] == ["api"] and "milestone=*" in " ".join(args):
    print("\n".join(str(n) for n in state["milestoned"]))
elif args[:2] == ["pr", "view"]:
    print("\n".join(state.get("comments", [])))
'''


def step(name: str) -> str:
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["triage"]["steps"]
    return next(s for s in steps if s["name"] == name)["run"]


def run_step(tmp_path, name, body, state):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(0o755)
    log = tmp_path / "gh.log"
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin", "GH_LOG": str(log), "GH_STATE": json.dumps(state),
        "REPO": "o/n", "PR_NUMBER": "7", "PR_BODY": body, "GH_TOKEN": "x",
        "GITHUB_OUTPUT": str(tmp_path / "out"),
    }
    done = subprocess.run(["bash", "-e", "-c", step(name)], env=env, capture_output=True, text=True, timeout=60)
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return done, calls


def test_closing_keyword_on_a_roadmap_issue_comments_once(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    done, calls = run_step(tmp_path, name, "Fixes typo. Closes: #132 and resolves #9", {"milestoned": [132]})
    assert done.returncode == 0, done.stderr
    comments = [c for c in calls if c[:2] == ["pr", "comment"]]
    assert len(comments) == 1
    text = comments[0][comments[0].index("--body") + 1]
    assert "<!-- acs-closing-keyword:132 -->" in text and "#132" in text and "#9" not in text
    assert "Part of" not in text


def test_url_and_qualified_forms_are_caught(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    body = "Resolves https://github.com/GenAI-Security-Project/agent-control-standard/issues/132"
    _done, calls = run_step(tmp_path, name, body, {"milestoned": [132]})
    assert any(c[:2] == ["pr", "comment"] for c in calls)


def test_no_comment_when_already_flagged_or_not_on_roadmap(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    state = {"milestoned": [132], "comments": ["<!-- acs-closing-keyword:132 -->"]}
    _done, calls = run_step(tmp_path, name, "Closes #132", state)
    assert not any(c[:2] == ["pr", "comment"] for c in calls)
    other = tmp_path / "b"
    other.mkdir()
    _done, calls = run_step(other, name, "Closes #5. disclose #132", {"milestoned": [132]})
    assert not any(c[:2] == ["pr", "comment"] for c in calls)


def test_no_step_interpolates_into_run():
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["triage"]["steps"]
    assert all("${{" not in s.get("run", "") for s in steps)


def test_keyword_step_runs_after_an_earlier_failure_but_skips_body_free_edits():
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["triage"]["steps"]
    flag = next(s for s in steps if s["name"] == "Flag closing keywords on roadmap issues")
    assert flag["if"] == "always() && (github.event.action != 'edited' || github.event.changes.body)"


def test_the_intake_step_runs_the_base_commit_and_never_the_pull_request_head():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request.head" not in text
    steps = yaml.safe_load(text)["jobs"]["triage"]["steps"]
    checkout = steps[0]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"])
    assert checkout["with"] == {"persist-credentials": False, "ref": "${{ github.sha }}"}
    assert steps[1]["run"] == "python3 -I -S tools/pr_intake.py"
