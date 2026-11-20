"""The page's real app.js, run against a stub DOM and a scripted server (final review R11).

The repository's tooling already requires bun, for the reference implementations' CI, so the test runs the harness
under bun, or node when bun is absent. With neither on the machine it skips, and test_static's source-text check of
the reset still stands.
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from conftest import VIEWER_DIR

HARNESS = VIEWER_DIR / "tests" / "page_harness.mjs"
APP = VIEWER_DIR / "static" / "app.js"


def runtime() -> list[str]:
    bun = shutil.which("bun")
    if bun:
        # --no-install keeps bun from fetching anything a bare import names.
        return [bun, "--no-install"]
    node = shutil.which("node")
    if node:
        return [node]
    pytest.skip("neither bun nor node is installed, so the page can't be run here")


def run(*extra: str) -> dict:
    done = subprocess.run([*runtime(), str(HARNESS), str(APP), *extra], capture_output=True, text=True, timeout=60,
                          cwd=HARNESS.parent, check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_an_open_page_shows_the_restarted_servers_marks():
    # Server B holds one row under a new id, so only that row may be on the page (final review R13).
    seen = run()
    assert seen["onA"] == [["echo", "allow", "verified"], ["rm", "deny", "verified"]]
    assert seen["onB"] == [["rm", "DENY", "failed"]]


def test_the_harness_catches_a_page_without_the_reset():
    # The same run with the instance check taken out keeps server A's verified marks, the stale view R5 fixed.
    seen = run("--without-reset")
    assert seen["onB"] == [["echo", "allow", "verified"], ["rm", "deny", "verified"]]


def test_the_harness_catches_a_reset_that_keeps_the_old_rows():
    # Review m-1: a reset that redraws but keeps A's rows still shows A's verified marks beside B's row.
    seen = run("--keep-rows")
    assert ["rm", "deny", "verified"] in seen["onB"]
    assert seen["onB"] != [["rm", "DENY", "failed"]]
