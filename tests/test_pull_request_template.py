"""The pull request template and CONTRIBUTING.md must teach the closing choice the check
enforces, and the untouched template must pass the check rather than close anything."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from closing_choice import SECTION, evaluate, normalize, parse_references  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (REPO_ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
SPELLINGS = ("Closes", "Fixes", "Resolves", "Part of", "Refs", "Contributes to")


def test_template_drops_the_prefilled_close_and_names_all_six_spellings():
    assert "Closes #" not in TEMPLATE
    assert SECTION in TEMPLATE.splitlines()
    for spelling in SPELLINGS:
        assert spelling in TEMPLATE


def test_unmodified_template_references_nothing_and_passes():
    assert parse_references(normalize(TEMPLATE)) == []
    verdict = evaluate("Add the adapter", TEMPLATE, author="contributor", head_ref="feature",
                       head_repo="someone/fork", created_at="2026-10-20T12:00:00Z", since="2026-10-10",
                       trusted=frozenset())
    assert verdict.passed and verdict.errors == ()


def test_contributing_explains_the_choice():
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "`Contributes to` before one it only" in text
