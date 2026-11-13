"""Shared builders for the tests that read the built docs or the rendered landing page.

One session-scoped build serves every test that reads the docs at DOCS_BASE, so the
suite pays for a single mkdocs build instead of one per module. Tests that need a
different GITHUB_PAGES_URL call build_docs() themselves.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from render_landing import read_nav_config, render  # noqa: E402

DOCS_BASE = "https://example.org/agent-control-standard/docs/"


def build_docs(out: Path, base: str = DOCS_BASE) -> Path:
    """Build the docs strictly into out and return it, failing with the build output."""
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = base
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


def render_landing_page() -> str:
    """Render the landing page from the repository's real files."""
    landing = REPO / "landing"
    return render(
        (landing / "index.html").read_text(encoding="utf-8"),
        REPO / "specification",
        (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        (landing / "assets" / "starburst.svg").read_text(encoding="utf-8"),
        read_nav_config(REPO / "mkdocs.yml"),
        (REPO / "version.txt").read_text(encoding="utf-8"),
    )
