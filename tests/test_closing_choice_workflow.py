"""Pins closing-choice.yml. It runs under pull_request_target, so every key is fixed: the
triggers, the base branch, the read-only permission, the concurrency group, and a checkout
of main that never touches the pull request's head."""
from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "closing-choice.yml"

RUN = (
    "if [ -f tools/closing_choice.py ]; then\n"
    "  python3 -I -S tools/closing_choice.py\n"
    "else\n"
    '  echo "::notice::main does not carry the closing-choice check yet."\n'
    "fi\n"
)
EXPECTED = {
    "name": "Closing choice",
    True: {"pull_request_target": {"types": ["opened", "edited", "synchronize", "reopened"], "branches": ["integration"]}},
    "permissions": {},
    "concurrency": {"group": "closing-choice-${{ github.event.pull_request.number }}", "cancel-in-progress": True},
    "jobs": {"closing-choice": {
        "runs-on": "ubuntu-latest",
        "timeout-minutes": 5,
        "permissions": {"contents": "read"},
        "steps": [
            {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "with": {"persist-credentials": False, "ref": "main"}},
            {"name": "Check the closing choice for each referenced issue",
             "env": {
                 "PR_TITLE": "${{ github.event.pull_request.title }}",
                 "PR_BODY": "${{ github.event.pull_request.body }}",
                 "PR_AUTHOR": "${{ github.event.pull_request.user.login }}",
                 "PR_HEAD_REF": "${{ github.event.pull_request.head.ref }}",
                 "PR_HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
                 "PR_CREATED_AT": "${{ github.event.pull_request.created_at }}",
                 "CLOSING_CHOICE_SINCE": "${{ vars.CLOSING_CHOICE_SINCE }}",
             },
             "run": RUN},
        ],
    }},
}


def test_workflow_is_exactly_this():
    # PyYAML reads the key `on` as the boolean True.
    assert yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")) == EXPECTED


def test_never_checks_out_the_pull_request_head():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "head.sha" not in text and "refs/pull" not in text and "merge_commit_sha" not in text


def test_run_passes_with_a_notice_when_main_lacks_the_script(tmp_path):
    done = subprocess.run(["bash", "-e", "-c", RUN], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0
    assert "::notice::main does not carry the closing-choice check yet." in done.stdout
