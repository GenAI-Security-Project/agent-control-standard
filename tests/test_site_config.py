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


# Package CDNs exist to serve executable code. A licence link or a documentation link
# never points at one, so any occurrence in built JavaScript is a runtime fetch that
# puts third-party code in a reader's browser.
#
# This guard exists because that is exactly what happened and nothing caught it. The
# theme's bundle lazily fetched mermaid from unpkg on every page carrying a diagram,
# and the third-party guard passed, because it allowlists the theme bundle by digest
# and never reads what is inside it.
CODE_CDN_HOSTS = (
    "unpkg.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "esm.sh",
    "cdn.skypack.dev",
    "ajax.googleapis.com",
)

# Occurrences reviewed and accepted, by host. The theme bundle is vendored byte for
# byte from the pinned mkdocs-material package and is proven so by the digest check
# above, so editing it out is not available without breaking that proof.
#
# unpkg.com appears three times, none of which can fire:
#   - two mermaid loader references, dead because this project's diagram fences carry
#     class `acs-diagram` rather than `mermaid`, so the theme never recognises a
#     diagram and never reaches its loader
#   - one ResizeObserver polyfill, guarded by `typeof ResizeObserver == "undefined"`,
#     which no browser this site supports satisfies
REVIEWED_CDN_OCCURRENCES = {"unpkg.com": 3}


def test_no_unreviewed_package_cdn_reference_in_built_javascript(built_site):
    """Fail when built JavaScript gains a package-CDN reference nobody reviewed."""
    import re

    counts: dict[str, int] = {}
    for path in built_site.rglob("*.js"):
        if path.name.endswith(".map"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for host in CODE_CDN_HOSTS:
            found = len(re.findall(re.escape(host), text))
            if found:
                counts[host] = counts.get(host, 0) + found

    assert counts == REVIEWED_CDN_OCCURRENCES, (
        "package-CDN references in built JavaScript changed.\n"
        f"  found:    {counts}\n"
        f"  reviewed: {REVIEWED_CDN_OCCURRENCES}\n"
        "Every one of these loads executable code from a third party at runtime. "
        "Confirm the new reference cannot fire, or remove it, then update "
        "REVIEWED_CDN_OCCURRENCES with the reason."
    )


# Any scheme a script can open a connection with. A host a script names is not proof
# that it fetches, so each one below was read in place and recorded per file.
_SCRIPT_URL = re.compile(r"""\b(?:https?|wss?)://([^\s/?#'"),<>]+)""", re.I)
_HOSTNAME = re.compile(r"^[a-z0-9.-]+$")

# Licence banners, documentation links, and comments name most of these. The lunr
# language packs all carry the same four.
_LUNR_LANGUAGE_HOSTS = frozenset({"code.google.com", "github.com", "snowball.tartarus.org", "www.mozilla.org"})
REVIEWED_SCRIPT_HOSTS = {
    "assets/javascripts/bundle.min.js": {"api.github.com", "clipboardjs.com", "unpkg.com"},
    **{
        f"assets/javascripts/lunr/min/lunr.{language}.min.js": _LUNR_LANGUAGE_HOSTS
        for language in ("da", "de", "du", "es", "fi", "fr", "hu", "it", "nl", "no", "pt", "ro", "ru", "sv", "tr")
    },
    "assets/javascripts/lunr/tinyseg.js": {"chasen.org", "github.com"},
    "assets/javascripts/lunr/wordcut.js": {
        "developer.mozilla.org", "docs.python.org", "en.wikipedia.org", "github.com",
        "msdn.microsoft.com", "narwhaljs.org", "people.mozilla.org", "underscorejs.org",
        "wiki.commonjs.org", "wiki.ecmascript.org",
    },
    "assets/javascripts/mermaid-init.js": {"unpkg.com"},
    "assets/javascripts/mermaid.min.js": {
        "chevrotain.io", "en.wikipedia.org", "engelschall.com", "github.com", "jquery.org",
        "langium.org", "lodash.com", "openjsf.org", "opensource.org", "tldrlegal.com",
        "underscorejs.org", "www.w3.org",
    },
    "assets/javascripts/workers/search.min.js": {"bit.ly", "lunrjs.com", "tartarus.org"},
}
# A URL built at runtime, such as `https://${e}`, names no host this scan can read. The
# count pins how many the bundle carries, so a new one is read before it ships.
RUNTIME_HOSTS = {"assets/javascripts/bundle.min.js": 1}
# The theme names its bundles by content hash, so every release renames them. Dropping
# the hash keys both maps on the file's role, and a theme bump fails this test only
# when a host or the runtime count changes.
_CONTENT_HASH = re.compile(r"\.[0-9a-f]{8}(?=\.min\.js$)")


def test_built_javascript_names_only_reviewed_hosts(built_site):
    """Fail when a built script names a host nobody recorded for that file.

    This catches literal hosts only. A script that assembles a host from pieces, or
    reads one from the page, passes this scan, which is why RUNTIME_HOSTS counts the
    template-literal URLs it can see.
    """
    found: dict[str, set[str]] = {}
    runtime: dict[str, int] = {}
    for path in sorted(built_site.rglob("*.js")):
        rel = _CONTENT_HASH.sub("", path.relative_to(built_site).as_posix())
        for match in _SCRIPT_URL.finditer(path.read_text(encoding="utf-8", errors="replace")):
            host = match.group(1)
            if _HOSTNAME.match(host):
                found.setdefault(rel, set()).add(host)
            else:
                runtime[rel] = runtime.get(rel, 0) + 1
    added = {rel: sorted(hosts - REVIEWED_SCRIPT_HOSTS.get(rel, set())) for rel, hosts in found.items()}
    removed = {rel: sorted(hosts - found.get(rel, set())) for rel, hosts in REVIEWED_SCRIPT_HOSTS.items()}
    assert found == REVIEWED_SCRIPT_HOSTS, (
        "hosts named in built JavaScript changed. Read each new one where the script uses "
        "it before recording it in REVIEWED_SCRIPT_HOSTS.\n"
        f"  added:   { {rel: hosts for rel, hosts in added.items() if hosts} }\n"
        f"  removed: { {rel: hosts for rel, hosts in removed.items() if hosts} }"
    )
    assert runtime == RUNTIME_HOSTS, f"runtime-built URLs in built JavaScript changed: {runtime}"


# Each value names a bundle component the theme wires to the page. Recorded from the
# build on 2026-10-29.
RECORDED_MD_COMPONENTS = frozenset({
    "announce", "container", "content", "dialog", "header", "header-title", "header-topic",
    "logo", "main", "palette", "search", "search-query", "search-result", "search-suggest",
    "sidebar", "skip", "toc",
})
_MD_COMPONENT = re.compile(r"""data-md-component=["']?([^"'\s>]+)""")


def test_built_pages_use_only_recorded_md_components(built_site):
    components: set[str] = set()
    for page in built_site.rglob("*.html"):
        components |= set(_MD_COMPONENT.findall(page.read_text(encoding="utf-8")))
    assert components == RECORDED_MD_COMPONENTS, (
        "a theme partial started binding a new bundle component. Read what the bundle does "
        "with it before recording it here. `overrides/partials/source.html` exists because "
        "`source` fetches api.github.com.\n"
        f"  added:   {sorted(components - RECORDED_MD_COMPONENTS)}\n"
        f"  removed: {sorted(RECORDED_MD_COMPONENTS - components)}"
    )
