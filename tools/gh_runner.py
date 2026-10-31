#!/usr/bin/env python3
"""Run `gh` for the repository's automation, with every argv checked against an allowlist.

Version 1.0. Owner: ACS project leads. Spec: design/2026-10-29-pr-intake-rules-design.md.

The pull request intake tool, the roadmap health renderer, and the roadmap monitor share
this runner. They handle text a pull request author controls: titles, bodies, paths, and
logins. The property this module exists for is that none of that text ever reaches `gh`
argv, a `--jq` program, or a shell. Request bodies travel on stdin as JSON, and every argv
must match one fixed shape below, element by element, before any process starts.

No shape admits a free-text flag (`-f`, `-F`, `--jq`, `-q`, `-t`, `--template`) in any
position, because each element is a literal or a pattern that cannot match one. Paths are
anchored to this repository, so a caller cannot reach another repository or the user API.
Every pattern is linear, with no nested quantifiers.

The process itself gets an absolute `gh`, an environment of six keys, and a 60 second
timeout. A timeout or a missing binary returns a failure tuple instead of raising, so the
caller classifies it like any other failed call. Error messages raised here carry fixed
text only, never gh's stderr, which can echo a token.

It runs under `python3 -I -S` and is standard library only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable

from roadmap_model import REPO

GH = "/usr/bin/gh"
TIMEOUT_SECONDS = 60

Runner = Callable[[list[str], "str | None"], tuple[int, str, str]]


class RunnerError(RuntimeError):
    """An argv outside the allowlist, or a response a helper here cannot read."""


_REPO = re.escape(REPO)
PATH = re.compile(
    rf"^repos/{_REPO}/(pulls|issues)(/[0-9]{{1,9}})?(/(files|reviews|comments|timeline|labels))?(\?[A-Za-z0-9_=&%.-]*)?$"
)
RUNS_PATH = re.compile(rf"^repos/{_REPO}/actions/workflows/pr-intake\.yml/runs\?[A-Za-z0-9_=&]*$")
COMMENT_PATH = re.compile(rf"^repos/{_REPO}/issues/comments/[0-9]{{1,9}}$")
COMMENTS_PATH = re.compile(rf"^repos/{_REPO}/issues/[0-9]{{1,9}}/comments$")
LABELS_PATH = re.compile(rf"^repos/{_REPO}/issues/[0-9]{{1,9}}/labels$")
LABEL_PATH = re.compile(rf"^repos/{_REPO}/issues/[0-9]{{1,9}}/labels/status%3Aneeds-triage$")
DIGITS = re.compile(r"^[0-9]{1,9}$")

# Every write carries -i so the status line and headers come back on stdout, which lets
# the caller tell a rejected write from a successful one without parsing stderr.
ALLOWLIST: tuple[tuple[str | re.Pattern[str], ...], ...] = (
    ("api", "-i", PATH),
    ("api", "--paginate", "--slurp", PATH),
    ("api", "-i", RUNS_PATH),
    ("api", "rate_limit"),
    ("api", "-i", "graphql", "--input", "-"),
    ("api", "-i", "-X", "PATCH", COMMENT_PATH, "--input", "-"),
    ("api", "-i", "-X", "POST", COMMENTS_PATH, "--input", "-"),
    ("api", "-i", "-X", "POST", LABELS_PATH, "--input", "-"),
    ("api", "-i", "-X", "DELETE", LABEL_PATH),
    ("pr", "merge", DIGITS, "--disable-auto", "--repo", REPO),
    ("pr", "ready", DIGITS, "--undo", "--repo", REPO),
)


def _matches(shape: tuple[str | re.Pattern[str], ...], args: list[str]) -> bool:
    if len(shape) != len(args):
        return False
    for expected, actual in zip(shape, args):
        if not isinstance(actual, str):
            return False
        if isinstance(expected, str) and actual != expected:
            return False
        # fullmatch, so the `$` in a pattern cannot accept a trailing newline.
        if isinstance(expected, re.Pattern) and not expected.fullmatch(actual):
            return False
    return True


def _check_allowlist(args: list[str]) -> None:
    if not isinstance(args, list) or not any(_matches(shape, args) for shape in ALLOWLIST):
        raise RunnerError("gh argv is outside the allowlist")


def make_runner(gh: str = GH, token: str | None = None) -> Runner:
    """Build a runner for one process lifetime. The token defaults to GH_TOKEN."""
    if token is None:
        token = os.environ.get("GH_TOKEN", "")
    # A fresh HOME and nothing inherited, so no earlier step can point gh at another host,
    # config directory, or repository, or preload code into it.
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": tempfile.mkdtemp(prefix="acs-gh-"),
        "GH_TOKEN": token,
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
    }

    def run(args: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        _check_allowlist(args)
        if not token:
            # Without a token gh would prompt or fall back to ambient credentials. A synthetic
            # 401 classifies as a permission failure, which no caller retries.
            return 0, "HTTP/2.0 401 Unauthorized\r\n\r\n{}", ""
        try:
            done = subprocess.run(
                [gh, *args], input=stdin, env=env, capture_output=True, text=True, timeout=TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired:
            return 124, "", "gh timed out"
        except OSError as exc:
            return 127, "", f"could not run {gh}: {exc.strerror}"
        return done.returncode, done.stdout, done.stderr

    return run


def paginate(run: Runner, path: str) -> list:
    """Every item from every page of a list endpoint, flattened into one list."""
    code, stdout, _stderr = run(["api", "--paginate", "--slurp", path], None)
    if code != 0:
        raise RunnerError(f"gh api --paginate exited {code}")
    try:
        pages = json.loads(stdout)
    except ValueError:
        raise RunnerError("gh api --paginate returned non-JSON output") from None
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise RunnerError("gh api --paginate returned a page that is not a list")
    return [item for page in pages for item in page]


def split_http(stdout: str) -> tuple[int, dict[str, str], str]:
    """Split `gh api -i` output into its status, lowercased headers, and body."""
    normalized = stdout.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise RunnerError("response had no HTTP status line") from None
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return status, headers, body


def remaining(run: Runner) -> int | None:
    """The core rate limit budget left, or None when it cannot be read.

    The field is read here rather than with --jq, because no shape admits a jq program.
    """
    code, stdout, _stderr = run(["api", "rate_limit"], None)
    if code != 0:
        return None
    try:
        value = json.loads(stdout)["resources"]["core"]["remaining"]
    except (ValueError, KeyError, TypeError):
        return None
    # bool is an int subclass, and True is not a budget.
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
