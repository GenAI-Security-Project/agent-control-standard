"""Pins the Dependabot keys that fail without any error a reviewer would see.

Dependabot reports a missing label or a retired key in a comment on the pull request it
opens, and opens the pull request anyway. Nothing fails, so the drift has to be caught
here.
"""
from __future__ import annotations

from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[1] / ".github" / "dependabot.yml"

# Verified against `gh label list` on 2026-10-29. `python:uv` exists and is unused.
EXISTING_LABELS = {"dependencies"}


def load() -> dict:
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def test_dependabot_labels_exist():
    labels: set[str] = set()
    for update in load()["updates"]:
        labels |= set(update.get("labels", []))
    assert labels <= EXISTING_LABELS, f"labels the repository does not have: {sorted(labels - EXISTING_LABELS)}"


def test_dependabot_has_no_retired_reviewers_key():
    # GitHub retired `reviewers` on 2025-05-20. CODEOWNERS assigns reviewers instead.
    for update in load()["updates"]:
        assert "reviewers" not in update, update["package-ecosystem"]
