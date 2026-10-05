"""Pins roadmap-refresh.yml to one exact shape.

It holds actions: write, which can also re-run, cancel, and delete runs. Its safety rests
on staying trivial, and zizmor does not flag a widened trigger or an added step, so any
change to this file must change this test too.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "roadmap-refresh.yml"

EXPECTED = {
    "name": "Refresh roadmap",
    True: {"schedule": [{"cron": "15 5 * * *"}]},
    "permissions": {},
    "jobs": {
        "dispatch": {
            "if": "vars.ROADMAP_REFRESH_ENABLED == 'true'",
            "runs-on": "ubuntu-latest",
            "timeout-minutes": 2,
            "permissions": {"actions": "write"},
            "steps": [
                {
                    "name": "Start a nightly deploy of main",
                    "env": {"GH_TOKEN": "${{ github.token }}"},
                    "run": 'gh workflow run deploy-pages.yml --repo "$GITHUB_REPOSITORY" --ref main -f source=nightly',
                }
            ],
        }
    },
}


def test_refresh_workflow_is_exactly_this():
    # PyYAML reads the key `on` as the boolean True, which is why EXPECTED uses True.
    assert yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")) == EXPECTED
