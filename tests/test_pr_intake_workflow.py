"""Runs pr-intake's shell steps against a fake gh, as the workflow would.

pr-intake checks out no code by design, so its logic lives in the YAML. These tests lift
each step's script out of the YAML and run it, so the behavior is tested, not just read.
"""
from __future__ import annotations

import json
import os
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
if args[:2] == ["issue", "list"]:
    print("\n".join(str(n) for n in state["accepted"]))
elif args[:1] == ["api"] and "milestone=*" in " ".join(args):
    print("\n".join(str(n) for n in state["milestoned"]))
elif args[:2] == ["pr", "view"]:
    jq = args[args.index("--jq") + 1] if "--jq" in args else ""
    if "length" in jq:
        print(state.get("bot_comment_count", 0))
    else:
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


def test_accepted_lookup_is_one_call_whatever_the_body(tmp_path):
    body = " ".join(f"#{n}" for n in range(1, 400))
    done, calls = run_step(tmp_path, "Check whether a referenced issue is accepted", body, {"accepted": [399], "milestoned": []})
    assert done.returncode == 0, done.stderr
    assert sum(1 for c in calls if c[:2] == ["issue", "list"]) == 1
    assert not any(c[:2] == ["issue", "view"] for c in calls)


def test_closing_keyword_on_a_roadmap_issue_comments_once(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    done, calls = run_step(tmp_path, name, "Fixes typo. Closes: #132 and resolves #9", {"accepted": [], "milestoned": [132]})
    assert done.returncode == 0, done.stderr
    comments = [c for c in calls if c[:2] == ["pr", "comment"]]
    assert len(comments) == 1
    text = comments[0][comments[0].index("--body") + 1]
    assert "<!-- acs-closing-keyword:132 -->" in text and "#132" in text and "#9" not in text
    assert "Part of" not in text


def test_url_and_qualified_forms_are_caught(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    body = "Resolves https://github.com/GenAI-Security-Project/agent-control-standard/issues/132"
    _done, calls = run_step(tmp_path, name, body, {"accepted": [], "milestoned": [132]})
    assert any(c[:2] == ["pr", "comment"] for c in calls)


def test_no_comment_when_already_flagged_or_not_on_roadmap(tmp_path):
    name = "Flag closing keywords on roadmap issues"
    state = {"accepted": [], "milestoned": [132], "comments": ["<!-- acs-closing-keyword:132 -->"]}
    _done, calls = run_step(tmp_path, name, "Closes #132", state)
    assert not any(c[:2] == ["pr", "comment"] for c in calls)
    other = tmp_path / "b"
    other.mkdir()
    _done, calls = run_step(other, name, "Closes #5. disclose #132", {"accepted": [], "milestoned": [132]})
    assert not any(c[:2] == ["pr", "comment"] for c in calls)


def test_keyword_comment_does_not_suppress_the_queue_comment(tmp_path):
    # One bot comment exists, but it is the keyword comment, so the length check reads 0.
    done, calls = run_step(
        tmp_path, "Check whether a referenced issue is accepted", "Closes #132",
        {"accepted": [], "milestoned": [132], "bot_comment_count": 0},
    )
    assert done.returncode == 0, done.stderr
    assert any(c[:2] == ["pr", "comment"] for c in calls)


def test_no_step_interpolates_into_run():
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["triage"]["steps"]
    assert all("${{" not in s.get("run", "") for s in steps)
