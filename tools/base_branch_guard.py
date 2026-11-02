"""Let only promotions reach the publishing branch.

`main` publishes the site and all 44 schema $id URIs on every merge. Every change lands on
`integration` first and reaches `main` only as a promotion, so `main` never holds content
`integration` lacks. The guard checks the result of the merge, not the branch's own
history, because that result is what publishes:

- A full promotion, from `integration` or from a `promote/full-*` branch that
  tools/promote_pr.py builds when the plain merge would conflict. After the merge,
  `main`'s whole tree must equal `integration`'s. That also catches a change reverted on
  `integration` after it reached `main` some other way, because the merge would keep it.
- A single pull request promotion, from a `promote/*` or `release/*` branch. Every path
  the merge changes must equal `integration`, and release files are refused, because a
  release goes through a full promotion.

Every other pull request into `main` fails, forks included. The documentation lane that
once let editorial pull requests target `main` was removed on 2026-11-01: every change
merged that way left `integration` behind, and the workflow meant to sync it back cannot
open a pull request under the organization's Actions policy.

The workflow runs this from `main`'s own checkout under pull_request_target and treats
the pull request's head as data, so a pull request cannot change the check that judges
it. Nothing here executes code from the pull request.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass

PUBLISHING_BRANCH = "main"

FULL_HEADS = frozenset({"integration"})
FULL_PREFIX = "promote/full-"
SINGLE_PREFIXES = ("promote/", "release/")

# A release bumps these together, and tag-release.yml tags main when version.txt changes.
# Promoting them alone would tag a main that lacks the release's other work.
RELEASE_FILES = frozenset({"version.txt", "pyproject.toml", "uv.lock"})

GitRunner = Callable[[list[str]], tuple[int, bytes]]


def git_runner(args: list[str]) -> tuple[int, bytes]:
    """Run git with replace refs ignored, and return its exit status and raw stdout.

    GIT_NO_REPLACE_OBJECTS stops a refs/replace object from changing what a commit
    appears to contain while it is being compared.
    """
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    completed = subprocess.run(["git", *args], capture_output=True, check=False, env=env)
    return completed.returncode, completed.stdout


def promotion_kind(head_ref: str, head_repo: str, base_repo: str) -> str | None:
    """Return "full", "single", or None when the head is not a promotion.

    The repository test runs first and is not optional. A head ref is a branch name the
    contributor chose, and a fork may name a branch anything.
    """
    if head_repo != base_repo:
        return None
    if head_ref in FULL_HEADS or head_ref.startswith(FULL_PREFIX):
        return "full"
    if head_ref.startswith(SINGLE_PREFIXES):
        return "single"
    return None


def _nul_paths(out: bytes) -> list[str]:
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


@dataclass(frozen=True)
class Verdict:
    conflicted: bool
    differing: list[str]
    release_files: list[str]


def check(kind: str, main: str, head: str, integration: str, run: GitRunner) -> Verdict:
    """Merge `head` into `main` in memory and compare the result with `integration`.

    Paths come from git with -z, never from a quoted listing, so a file name with a
    non-ASCII character, a tab, or a quote is compared like any other.
    """
    code, out = run(["merge-tree", "--write-tree", main, head])
    if code not in (0, 1):
        raise RuntimeError("git merge-tree failed")
    if code == 1:
        return Verdict(True, [], [])
    merged = out.split(b"\n", 1)[0].decode("ascii").strip()

    code, out = run(["diff", "-z", "--name-only", "--no-renames", merged, integration])
    if code != 0:
        raise RuntimeError("git diff against integration failed")
    against_integration = set(_nul_paths(out))
    if kind == "full":
        return Verdict(False, sorted(against_integration), [])

    code, out = run(["diff", "-z", "--name-only", "--no-renames", main, merged])
    if code != 0:
        raise RuntimeError("git diff against main failed")
    changed = set(_nul_paths(out))
    return Verdict(False, sorted(changed & against_integration), sorted(changed & RELEASE_FILES))


RETARGET = (
    f"`{PUBLISHING_BRANCH}` publishes the site and all 44 schema $id URIs on merge, so every "
    "change lands on `integration` first and reaches it only as a promotion. Retarget this "
    "pull request at `integration`. To publish one merged pull request before the next full "
    "promotion, a project lead runs `uv run python tools/promote_pr.py <number>`. "
    "See CONTRIBUTING.md."
)


def listing(paths: list[str]) -> str:
    return "\n".join(f"  {path!r}" if not path.isprintable() else f"  {path}" for path in paths)


def decide(
    base_ref: str,
    head_ref: str,
    head_repo: str,
    base_repo: str,
    verdict: Callable[[str], Verdict] | None,
) -> tuple[int, str]:
    """Return an exit status and the message to print.

    `verdict` takes the promotion kind and returns the result of `check`. A promotion
    with no way to check its content fails rather than passing unchecked.
    """
    if base_ref != PUBLISHING_BRANCH:
        return 0, f"Base branch is {base_ref!r}, not {PUBLISHING_BRANCH!r}. Nothing to check."
    kind = promotion_kind(head_ref, head_repo, base_repo)
    if kind is None:
        return 1, f"Only promotions may target `{PUBLISHING_BRANCH}`. {RETARGET}"
    if verdict is None:
        return 1, "This promotion could not be checked against `integration`, so it does not pass."
    result = verdict(kind)
    if result.conflicted:
        return 1, (
            f"This promotion conflicts with `{PUBLISHING_BRANCH}`. A project lead runs "
            "`uv run python tools/promote_pr.py --full`, which builds a promotion whose tree "
            "is exactly `integration`'s. See CONTRIBUTING.md."
        )
    if result.release_files:
        return 1, (
            "A single pull request promotion may not change release files, because a release "
            f"goes through a full promotion:\n{listing(result.release_files)}"
        )
    if result.differing:
        if kind == "full":
            return 1, (
                f"After this merge `{PUBLISHING_BRANCH}` would still differ from "
                f"`integration` at:\n{listing(result.differing)}\n\n"
                f"`{PUBLISHING_BRANCH}` holds content `integration` lacks there, usually a "
                "change reverted on `integration` after it was promoted. A project lead runs "
                "`uv run python tools/promote_pr.py --full`, which makes `integration` win."
            )
        return 1, (
            "A single pull request promotion may carry only content `integration` already "
            f"holds. These paths would differ from `integration`:\n{listing(result.differing)}\n\n"
            "Rebuild the branch with tools/promote_pr.py, or land the change on `integration` first."
        )
    if kind == "full":
        return 0, f"Promotion from {head_ref!r}. After the merge, `{PUBLISHING_BRANCH}` equals `integration`."
    return 0, f"Promotion from {head_ref!r}. Every path it changes matches `integration`."


def main(argv: list[str]) -> int:
    """Read the refs from the environment and judge the pull request."""
    if len(argv) != 1:
        print("usage: base_branch_guard.py  (reads BASE_REF, HEAD_REF, HEAD_REPO, BASE_REPO, "
              "MAIN_REF, HEAD_SHA, INTEGRATION_REF)", file=sys.stderr)
        return 2
    env = os.environ
    head_sha = env.get("HEAD_SHA", "")
    main_ref = env.get("MAIN_REF", "origin/main")
    integration = env.get("INTEGRATION_REF", "origin/integration")

    def verdict(kind: str) -> Verdict:
        if not head_sha:
            raise RuntimeError("HEAD_SHA is not set")
        return check(kind, main_ref, head_sha, integration, git_runner)

    try:
        status, message = decide(env.get("BASE_REF", ""), env.get("HEAD_REF", ""),
                                 env.get("HEAD_REPO", ""), env.get("BASE_REPO", ""), verdict)
    except (RuntimeError, ValueError) as error:
        status, message = 1, f"The content check could not run ({error}), so this does not pass."
    print(message, file=sys.stderr if status else sys.stdout)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
