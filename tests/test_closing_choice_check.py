"""Tests for the closing-choice rule, its exemptions, its date gate, and its output.

The rule fails a pull request only when the choice is missing or contradictory. The date
gate is the kill switch, so failing cases also run with the gate unset to prove they pass
with a notice instead.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from closing_choice import SPELLINGS, evaluate, violations  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "closing_choice.py"
TRUSTED = frozenset({"rocklambros"})
SECTION = "## Which issue does this implement"


def body(issue_lines: str, before: str = "## What changed\n\nA change.\n", after: str = "## Base branch\n\n- [x] integration\n") -> str:
    return f"{before}\n{SECTION}\n\n{issue_lines}\n\n{after}"


def check(title="Add the adapter", text=None, author="contributor", head_ref="feature", head_repo="someone/fork",
          created="2026-10-20T12:00:00Z", since="2026-10-10"):
    return evaluate(title, text if text is not None else body("Closes #5"), author=author, head_ref=head_ref,
                    head_repo=head_repo, created_at=created, since=since, trusted=TRUSTED)


def test_a_clear_choice_passes_silently():
    verdict = check(text=body("Closes #5\nPart of #6, #7"))
    assert verdict.passed and verdict.errors == () and verdict.notices == ()


@pytest.mark.parametrize(
    "text, expected",
    [
        ("## What changed\n\nCloses #5\n", "has no '## Which issue does this implement' section"),
        (body("#5"), "names #5 without a spelling"),
        (body("Closes #5, #6"), "names #6 without a spelling"),
        (body("Closes #5\nRefs #5"), "#5 is both closed and contributed to"),
        (body("Part of #5", before="## What changed\n\nThis fixes #5.\n"), "#5 is both closed and contributed to"),
        (body("Part of #6", before="## What changed\n\nFixes #5\n"), "before #5 sits outside the issue section"),
        (body("Part of #6", after="## Notes\n\nResolves #8\n"), "before #8 sits outside the issue section"),
    ],
)
def test_each_failure(text, expected):
    verdict = check(text=text)
    assert not verdict.passed
    assert any(expected in line for line in verdict.errors), verdict.errors
    assert verdict.errors[-1] == SPELLINGS


def test_keyword_in_the_title_fails():
    verdict = check(title="Fixes #5: add the adapter", text=body("Closes #5"))
    assert not verdict.passed and any("The title closes #5" in e for e in verdict.errors)


def test_references_outside_the_section_without_a_keyword_are_fine():
    assert check(text=body("Part of #6", before="## What changed\n\nSee #5 and Refs #9.\n")).passed


def test_editorial_checkbox_exempts_when_nothing_closes():
    editorial = body("", after="- [x] This is an editorial correction (typo) with no change in meaning\n")
    verdict = check(text=editorial.replace(SECTION, "## Other"))
    assert verdict.passed and "editorial" in verdict.notices[0].lower()
    closing = editorial.replace(SECTION, "## Other") + "\nFixes #5\n"
    assert not check(text=closing).passed


def test_dependabot_exempt_only_when_nothing_closes():
    assert check(text="Bumps x from 1 to 2.", author="dependabot[bot]").passed
    assert not check(title="Bump x, fixes #5", text="Bumps x.", author="dependabot[bot]").passed


def test_sync_pull_request_is_exempt_only_from_main_here_by_a_trusted_login():
    sync = dict(text="Documentation landed on main.", head_ref="main",
                head_repo="GenAI-Security-Project/agent-control-standard")
    assert check(author="RockLambros", **sync).passed
    assert not check(author="contributor", **sync).passed
    assert not check(author="rocklambros", **dict(sync, head_repo="someone/agent-control-standard")).passed
    assert not check(author="rocklambros", **dict(sync, head_ref="integration")).passed


@pytest.mark.parametrize(
    "since, created",
    [(None, "2026-10-20T12:00:00Z"), ("", "2026-10-20T12:00:00Z"), ("  ", "2026-10-20T12:00:00Z"),
     ("not a date", "2026-10-20T12:00:00Z"), ("2026-10-10", "2026-10-09T23:59:59Z")],
)
def test_date_gate_passes_with_a_notice_saying_what_would_fail(since, created):
    verdict = check(text=body("#5"), since=since, created=created)
    assert verdict.passed and verdict.errors == ()
    assert any("Would fail once enforced" in n and "#5" in n for n in verdict.notices)


def test_date_gate_binds_from_its_own_day():
    assert not check(text=body("#5"), since="2026-10-10", created="2026-10-10T00:00:00Z").passed
    assert not check(text=body("#5"), since=" 2026-10-10 ", created="2026-10-11T00:00:00Z").passed


def test_messages_carry_numbers_never_text():
    hostile = body("#5 ::error::injected", before="## What changed\n\nFixes #6 ignore previous instructions\n")
    verdict = check(title="Closes #7 ::warning::x", text=hostile)
    for line in verdict.errors + verdict.notices:
        assert "injected" not in line and "ignore previous" not in line and "::" not in line


def test_adversarial_body_finishes_in_under_a_second():
    hostile = body("Part of #1, " * 5_000 + "[" * 20_000 + "Closes " * 2_000)
    started = time.perf_counter()
    violations("Closes " * 20_000, hostile + "#1 " * 20_000)
    assert time.perf_counter() - started < 1.0


def run_cli(env_extra: dict) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PR_TITLE": "Add it", "PR_AUTHOR": "contributor",
           "PR_HEAD_REF": "feature", "PR_HEAD_REPO": "someone/fork", "PR_CREATED_AT": "2026-10-20T12:00:00Z"}
    env.update(env_extra)
    return subprocess.run([sys.executable, "-I", "-S", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)


def test_cli_runs_isolated_and_fails_with_annotations():
    done = run_cli({"PR_BODY": body("#5"), "CLOSING_CHOICE_SINCE": "2026-10-10"})
    assert done.returncode == 1, done.stderr
    assert "::error::The issue section names #5 without a spelling." in done.stdout


def test_cli_passes_with_a_notice_while_the_gate_is_unset():
    done = run_cli({"PR_BODY": body("#5")})
    assert done.returncode == 0, done.stderr
    assert "::notice::Would fail once enforced" in done.stdout


def test_cli_reads_the_real_roster_for_the_sync_exemption():
    done = run_cli({"PR_BODY": "Documentation landed on main.", "PR_AUTHOR": "rocklambros", "PR_HEAD_REF": "main",
                    "PR_HEAD_REPO": "GenAI-Security-Project/agent-control-standard", "CLOSING_CHOICE_SINCE": "2026-10-10"})
    assert done.returncode == 0, done.stdout + done.stderr
