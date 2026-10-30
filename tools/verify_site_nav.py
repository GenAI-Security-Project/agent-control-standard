#!/usr/bin/env python3
"""Assert that the published site serves one navigation pane on every surface.

Three pages are read: the landing page, the docs front page, and an address under the
docs that does not exist. The third must be the docs 404 page served with status 404.
GitHub Pages serves only a root-level 404.html, so a missed address under /docs/ gets
the site root's 404.html. When that page lacks the pane landmark, Pages is serving its
own default page and the deploy's copy step did not reach the artifact.

The pane is walked into rows on each page and the three row lists must be equal. Each
docs page resolves its links against its own address, and the 404 page links from the
site root, so equal rows mean every link lands in the same place from every surface.

Pages fronts the site with a CDN. Measured on 2026-10-29 the responses carry
`cache-control: max-age=600`, and a request with `Cache-Control: no-cache`, with
`Pragma: no-cache`, or with a query string was still answered as a cache `HIT`. No
request header clears the edge, so only time does. That is why a row mismatch is
retried for thirteen minutes, past the ten-minute lifetime, rather than failed at once.
The missing address carries a nonce so no earlier run's cached 404 can answer it.

This runs on the deploy runner's bare interpreter, so it imports the standard library
and the sibling site_nav module only. It reads no secret and sends nothing but GETs.
"""
from __future__ import annotations

import difflib
import http.client
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_nav import PANE_LABEL, Row, WalkError, walk_docs, walk_landing  # noqa: E402

ATTEMPTS = 13
DELAY_SECONDS = 60
# A 200 page with no landmark may be the edge's stale copy from before the pane existed,
# so it gets the full window like a row mismatch. The 404 address carries a nonce, so no
# cache can hold an old copy of it. A 404 with no landmark is GitHub's own page, and
# waiting thirteen minutes would only delay a failure that a repair has to fix. One
# retry covers a slow deploy.
DEFAULT_404_ATTEMPTS = 2
LANDMARK = f'aria-label="{PANE_LABEL}"'
MAX_BYTES = 5_000_000
USER_AGENT = "acs-verify-site-nav"


def fetch_text(url: str) -> tuple[int, str]:
    """Return the status and body. An HTTP error status is a result here, not a failure,
    because the third page is a 404 by design. Any other error propagates."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read(MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(MAX_BYTES).decode("utf-8", "replace")


@dataclass
class Outcome:
    """What one pass over the three pages found, and whether waiting could change it."""

    problems: list[str] = field(default_factory=list)
    retryable: bool = False
    default_404: bool = False
    rows: dict[str, list[Row]] = field(default_factory=dict)


def inspect(base: str, nonce: str) -> Outcome:
    base = base.rstrip("/") + "/"
    pages = [
        ("landing", base, 200, walk_landing),
        ("docs", base + "docs/", 200, walk_docs),
        ("not found", base + f"docs/does-not-exist-{nonce}/", 404, walk_docs),
    ]
    outcome = Outcome()
    for name, url, expected, walk in pages:
        status, markup = fetch_text(url)
        if status >= 500:
            outcome.problems.append(f"{url} returned {status}, a server error")
            outcome.retryable = True
            continue
        if status != expected:
            outcome.problems.append(f"{url} returned {status}, expected {expected}")
            continue
        if LANDMARK not in markup:
            if expected == 404:
                outcome.default_404 = True
                outcome.problems.append(
                    f"{url} returned {status} with no {LANDMARK} landmark. This is GitHub's "
                    "default 404 page, so _site/404.html did not reach the artifact."
                )
            else:
                outcome.retryable = True
                outcome.problems.append(f"{url} returned {status} with no {LANDMARK} landmark")
            continue
        try:
            outcome.rows[name] = walk(markup, url)
        except WalkError as error:
            outcome.problems.append(f"{url} returned {status} and its pane does not walk: {error}")
    if outcome.problems:
        return outcome
    want = [repr(row) for row in outcome.rows["landing"]]
    for name in ("docs", "not found"):
        got = [repr(row) for row in outcome.rows[name]]
        if got != want:
            diff = "\n".join(difflib.unified_diff(want, got, "landing", name, lineterm=""))
            outcome.problems.append(f"rows differ between the landing page and the {name} page\n{diff}")
            outcome.retryable = True
    return outcome


def check(base: str, nonce: str) -> list[str]:
    """Return every problem with the three served panes, or an empty list."""
    return inspect(base, nonce).problems


def nonce() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        return f"{run_id}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
    return str(int(time.time()))


def _write_summary(outcome: Outcome) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["## The published navigation does not match", ""]
    lines += [f"- {problem.splitlines()[0]}" for problem in outcome.problems]
    want = [repr(row) for row in outcome.rows.get("landing", [])]
    for name in ("docs", "not found"):
        if name in outcome.rows:
            got = [repr(row) for row in outcome.rows[name]]
            diff = list(difflib.unified_diff(want, got, "landing", name, lineterm=""))
            if diff:
                lines += ["", "```diff", *diff, "```"]
    with open(path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


def main(argv: list[str], sleep: Callable[[float], None] = time.sleep) -> int:
    if len(argv) != 2:
        print("usage: verify_site_nav.py <site-base-url>", file=sys.stderr)
        return 2
    base, run_nonce = argv[1], nonce()
    outcome = Outcome()
    for attempt in range(1, ATTEMPTS + 1):
        try:
            outcome = inspect(base, run_nonce)
        # A read timeout or a dropped connection can surface from http.client below
        # urllib's wrapper, so the raw exceptions are caught here too. URLError is an
        # OSError, and TimeoutError is one as well.
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            outcome = Outcome([f"network error: {error!r}"], retryable=True)
        if not outcome.problems:
            print(f"ok: the landing, docs, and 404 panes under {base} match")
            return 0
        print(f"attempt {attempt}/{ATTEMPTS}: " + "; ".join(p.splitlines()[0] for p in outcome.problems))
        if outcome.default_404:
            retry = attempt < DEFAULT_404_ATTEMPTS
        else:
            retry = outcome.retryable
        if not retry or attempt == ATTEMPTS:
            break
        sleep(DELAY_SECONDS)
    for problem in outcome.problems:
        print(f"::error::{problem.splitlines()[0]}")
        if "\n" in problem:
            print(problem.split("\n", 1)[1])
    _write_summary(outcome)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
