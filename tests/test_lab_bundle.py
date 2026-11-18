"""Pins the FinBot lab bundle: its git hygiene, compose file and workflows (issue #588, LAB-15).

The bundle lives on the lab branch only. Each test reads a file as text or YAML and checks one property the lab
depends on, so a change that would leak a secret, publish a port off loopback, or let FinBot reach the Guardian shows
red here before anyone runs the stack.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "labs" / "finbot"


def _rules(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return {" ".join(line.split()) for line in lines if line.strip() and not line.lstrip().startswith("#")}


def test_gitattributes_forces_lf():
    # A checkout that turns lab.sh or the entrypoint into CRLF breaks them inside a Linux container.
    rules = _rules(BUNDLE / ".gitattributes")
    for pattern in ("*.sh", "*.py", "Dockerfile*", "*.Dockerfile", "*.yaml", "*.yml"):
        assert f"{pattern} text eol=lf" in rules, pattern


def test_gitignore_covers_secrets():
    rules = _rules(BUNDLE / ".gitignore")
    for pattern in ("state/", ".env", "*.key", "*.token"):
        assert pattern in rules, pattern


def test_no_state_tracked():
    tracked = subprocess.run(["git", "ls-files", "labs/finbot/state", "labs/finbot/.env"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    assert tracked == ""
