"""Regression guard on the built documentation site.

Verified before this change: with GOOGLE_ANALYTICS_KEY empty, and also with the variable
unset entirely, Material emitted <script src=".../gtag/js?id=">. No env value suppressed
it, so the analytics block had to be removed. Removing it alone was not enough: the theme
also fetched Roboto from fonts.googleapis.com on all 37 pages.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# The canonical URL the test build is given. Anything else is a third party.
SELF_HOSTS = {"example.org"}


@pytest.fixture(scope="module")
def built_site(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site")
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = "https://example.org/"
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


def test_mkdocs_config_declares_no_analytics():
    assert "analytics" not in (REPO / "mkdocs.yml").read_text(encoding="utf-8")


def test_mkdocs_config_disables_theme_fonts():
    """Material fetches Roboto from Google unless font is false."""
    assert re.search(r"^\s*font:\s*false\s*$", (REPO / "mkdocs.yml").read_text(encoding="utf-8"), re.M)


def test_built_site_loads_nothing_from_google(built_site):
    for page in built_site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        assert "googletagmanager" not in text
        assert "fonts.googleapis.com" not in text
        assert "fonts.gstatic.com" not in text


def test_built_site_loads_no_third_party_resource(built_site):
    """The site must fetch nothing it does not serve itself.

    Stylesheets are scanned as well as markup. A url() in a stylesheet every page loads
    reaches a third party without any script, and an HTML-only scan cannot see it.
    """
    from conftest import stylesheet_hosts, third_party_hosts

    offenders: dict[str, str] = {}
    for asset in built_site.rglob("*.html"):
        for host in third_party_hosts(asset.read_text(encoding="utf-8"), SELF_HOSTS):
            offenders.setdefault(host, asset.name)
    for asset in built_site.rglob("*.css"):
        for host in stylesheet_hosts(asset.read_text(encoding="utf-8"), SELF_HOSTS):
            offenders.setdefault(host, asset.name)
    assert not offenders, f"third-party resource loads: {offenders}"


def test_only_scripts_the_pinned_theme_ships_reach_the_site(built_site):
    """Every script must be one the installed theme installs.

    A path check cannot tell our own file from the theme's, because mkdocs copies
    docs/assets/ into the same output directory, so docs/assets/javascripts/x.js
    lands beside the theme's own bundle. Comparing against the package's manifest
    can, which puts a first-party script in front of a human wherever it is placed.
    """
    from conftest import stray_scripts

    stray = stray_scripts(built_site)
    assert stray == [], f"script not shipped by the pinned theme: {stray}"
