"""Pins the live navigation check that runs after each deploy and every six hours.

The check reads three served pages. Each test here stands in for the network with a
fake fetch, so the suite never reaches the published site.
"""
from __future__ import annotations

import email.message
import io
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import verify_site_nav  # noqa: E402

BASE = "https://example.org/acs/"
NONCE = "7-1"
MISSING = f"{BASE}docs/does-not-exist-{NONCE}/"


def _landing(docs_href: str = "docs/") -> str:
    return (
        '<nav aria-label="Navigation"><ul>'
        f'<li><a href="{docs_href}">ACS</a></li>'
        '<li><a href="docs/topics/faq/">FAQ</a></li>'
        "</ul></nav>"
    )


def _docs(front_href: str, faq_href: str) -> str:
    return (
        '<nav class="md-nav md-nav--primary" aria-label="Navigation">'
        '<ul class="md-nav__list">'
        f'<li class="md-nav__item"><a class="md-nav__link" href="{front_href}">ACS</a></li>'
        f'<li class="md-nav__item"><a class="md-nav__link" href="{faq_href}">FAQ</a></li>'
        "</ul></nav>"
    )


# The docs front page links relative to itself. The 404 page links from the site root,
# because Pages serves it at whatever address missed.
DOCS_FRONT = _docs("./", "topics/faq/")
NOT_FOUND = _docs("/acs/docs/", "/acs/docs/topics/faq/")
GITHUB_404 = "<html><body><h1>404</h1><p>File not found</p></body></html>"


def _serve(monkeypatch, pages: dict[str, tuple[int, str]]) -> list[str]:
    asked: list[str] = []

    def fake(url: str) -> tuple[int, str]:
        asked.append(url)
        return pages[url]

    monkeypatch.setattr(verify_site_nav, "fetch_text", fake)
    return asked


def _site(**overrides: tuple[int, str]) -> dict[str, tuple[int, str]]:
    pages = {
        BASE: (200, _landing()),
        f"{BASE}docs/": (200, DOCS_FRONT),
        MISSING: (404, NOT_FOUND),
    }
    pages.update({{"front": BASE, "docs": f"{BASE}docs/", "missing": MISSING}[key]: value
                  for key, value in overrides.items()})
    return pages


def test_check_passes_on_matching_panes(monkeypatch):
    asked = _serve(monkeypatch, _site())
    assert verify_site_nav.check(BASE.rstrip("/"), NONCE) == []
    assert asked == [BASE, f"{BASE}docs/", MISSING]


def test_fetch_text_returns_the_body_of_a_404(monkeypatch):
    url = MISSING

    def raise_404(request, timeout):
        assert request.get_header("User-agent") == "acs-verify-site-nav"
        assert timeout == 20
        raise urllib.error.HTTPError(
            url, 404, "Not Found", email.message.Message(),
            io.BytesIO(b'<nav aria-label="Navigation"></nav>'),
        )

    monkeypatch.setattr(verify_site_nav.urllib.request, "urlopen", raise_404)
    assert verify_site_nav.fetch_text(url) == (404, '<nav aria-label="Navigation"></nav>')


def test_fetch_text_lets_a_network_error_propagate(monkeypatch):
    def refuse(request, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(verify_site_nav.urllib.request, "urlopen", refuse)
    with pytest.raises(urllib.error.URLError):
        verify_site_nav.fetch_text(BASE)


def test_check_reports_a_github_default_404(monkeypatch):
    _serve(monkeypatch, _site(missing=(404, GITHUB_404)))
    problems = verify_site_nav.check(BASE, NONCE)
    assert problems and MISSING in problems[0] and "404" in problems[0]
    assert "GitHub" in problems[0]


def test_check_reports_a_404_on_the_docs_front(monkeypatch):
    _serve(monkeypatch, _site(docs=(404, NOT_FOUND)))
    problems = verify_site_nav.check(BASE, NONCE)
    assert problems and f"{BASE}docs/" in problems[0] and "404" in problems[0]


def test_check_reports_a_row_mismatch(monkeypatch):
    _serve(monkeypatch, _site(front=(200, _landing("docs/other/"))))
    problems = verify_site_nav.check(BASE, NONCE)
    assert any("rows differ" in problem for problem in problems)
    assert any("docs/other/" in problem for problem in problems)


def test_main_retries_a_row_mismatch_and_then_passes(monkeypatch):
    stale = _site(front=(200, _landing("docs/other/")))
    fresh = _site()
    served = iter([stale, stale, fresh])
    current: dict[str, tuple[int, str]] = {}

    def fake(url: str) -> tuple[int, str]:
        if url == BASE:
            current.clear()
            current.update(next(served))
        return current[url]

    monkeypatch.setattr(verify_site_nav, "fetch_text", fake)
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    sleeps: list[float] = []
    assert verify_site_nav.main(["verify_site_nav.py", BASE], sleep=sleeps.append) == 0
    assert sleeps == [verify_site_nav.DELAY_SECONDS] * 2


def test_main_fails_a_wrong_status_without_retrying(monkeypatch, tmp_path):
    _serve(monkeypatch, _site(docs=(404, NOT_FOUND)))
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    sleeps: list[float] = []
    assert verify_site_nav.main(["verify_site_nav.py", BASE], sleep=sleeps.append) == 1
    assert sleeps == []
    assert "404" in summary.read_text(encoding="utf-8")


def test_main_fails_a_missing_landmark_after_the_second_attempt(monkeypatch):
    _serve(monkeypatch, _site(missing=(404, GITHUB_404)))
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    sleeps: list[float] = []
    assert verify_site_nav.main(["verify_site_nav.py", BASE], sleep=sleeps.append) == 1
    assert sleeps == [verify_site_nav.DELAY_SECONDS]


def test_main_retries_a_server_error_and_a_network_error(monkeypatch):
    outcomes = iter(["error", 503, "ok"])
    pages = _site()

    def fake(url: str) -> tuple[int, str]:
        if url == BASE:
            outcome = next(outcomes)
            if outcome == "error":
                raise urllib.error.URLError("connection reset")
            if outcome == 503:
                return 503, "unavailable"
        return pages[url]

    monkeypatch.setattr(verify_site_nav, "fetch_text", fake)
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    sleeps: list[float] = []
    assert verify_site_nav.main(["verify_site_nav.py", BASE], sleep=sleeps.append) == 0
    assert len(sleeps) == 2


def test_main_gives_up_after_thirteen_attempts_and_writes_the_row_diff(monkeypatch, tmp_path):
    _serve(monkeypatch, _site(front=(200, _landing("docs/other/"))))
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    sleeps: list[float] = []
    assert verify_site_nav.main(["verify_site_nav.py", BASE], sleep=sleeps.append) == 1
    assert len(sleeps) == verify_site_nav.ATTEMPTS - 1 == 12
    text = summary.read_text(encoding="utf-8")
    assert "docs/other/" in text and "@@" in text


def test_nonce_falls_back_to_the_clock_outside_actions(monkeypatch):
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.delenv("GITHUB_RUN_ATTEMPT", raising=False)
    assert verify_site_nav.nonce().isdigit()
    monkeypatch.setenv("GITHUB_RUN_ID", "41")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    assert verify_site_nav.nonce() == "41-2"


def test_verifier_runs_on_the_bare_interpreter():
    imported = subprocess.run(
        [sys.executable, "-I", "-S", "-c", "import sys; sys.path.insert(0, 'tools'); import site_nav"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert imported.returncode == 0, imported.stderr
    usage = subprocess.run(
        [sys.executable, "-I", "-S", "tools/verify_site_nav.py"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert usage.returncode == 2, usage.stderr
    assert "usage" in usage.stderr
