"""Keep everything off the publishing branch except promotions.

`main` publishes the site and all 44 schema $id URIs on every merge. Every change lands on
`integration` first, and reaches `main` only as a promotion. Two kinds exist:

- A full promotion, a pull request from `integration` (or a `release/*` branch) in this
  repository.
- A single pull request promotion, from a `promote/*` branch in this repository whose every
  changed path is byte-for-byte identical to `integration`. `tools/promote_pr.py` builds
  one. It cannot carry anything `integration` does not already hold, so `main` never gets
  ahead of `integration`.

Nothing else may target `main`. There used to be a documentation lane that let editorial
pull requests go straight to `main`. It was removed on 2026-11-01 because every change
merged that way left `integration` behind, and the workflow meant to sync it back cannot
open a pull request under the organization's Actions policy.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Iterable

PUBLISHING_BRANCH = "main"

# Branches a full promotion comes from.
PROMOTION_HEADS = frozenset({"integration"})
PROMOTION_HEAD_PREFIXES = ("release/",)

# Branches a single pull request promotion comes from. tools/promote_pr.py names them.
SINGLE_PROMOTION_PREFIX = "promote/"

# The ref the content check compares against when the workflow does not name one.
DEFAULT_INTEGRATION_REF = "origin/integration"

GitRunner = Callable[[list[str]], tuple[int, bytes]]


def is_promotion(head_ref: str, head_repo: str, base_repo: str) -> bool:
    """True when this is a full promotion from a branch inside this repository.

    The repository test is not optional and runs first. A pull request's head ref is a
    branch name the contributor chose, and a fork may name a branch anything, so
    exempting on the ref alone would let somebody fork, create a branch called
    `integration`, and walk a specification change onto the publishing branch.
    """
    if head_repo != base_repo:
        return False
    return head_ref in PROMOTION_HEADS or head_ref.startswith(PROMOTION_HEAD_PREFIXES)


def is_single_promotion(head_ref: str, head_repo: str, base_repo: str) -> bool:
    """True when the head is a `promote/*` branch inside this repository."""
    return head_repo == base_repo and head_ref.startswith(SINGLE_PROMOTION_PREFIX)


# Statuses from `git diff --name-status` that put a path into the tree. A rename or copy
# carries a similarity score after its letter, as in R100. The workflow passes
# --no-renames, so a rename reaches this script as a delete plus an add and both paths
# are compared. R and C stay here so a listing produced without that flag still counts
# the new path as an addition.
ADDING_STATUSES = ("A", "R", "C")


def parse_name_status(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split `git diff --name-status` output into changed paths and added paths.

    Each line is a status, a tab, and a path. A rename or copy names the old path and
    then the new one, and only the new path is a change here, the same path
    `--name-only` reports. A line with no tab is a bare path from an older listing and
    counts as changed, not added.
    """
    changed: list[str] = []
    added: list[str] = []
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if "\t" not in line:
            changed.append(line.strip())
            continue
        fields = line.split("\t")
        status, path = fields[0].strip(), fields[-1]
        changed.append(path)
        if status.startswith(ADDING_STATUSES):
            added.append(path)
    return changed, added


def git_runner(args: list[str]) -> tuple[int, bytes]:
    """Run git and return its exit status and raw stdout."""
    completed = subprocess.run(["git", *args], capture_output=True, check=False)
    return completed.returncode, completed.stdout


def tree_entries(ref: str, paths: list[str], run: GitRunner) -> dict[str, tuple[str, str]]:
    """Map each path that exists at `ref` to its (mode, object id).

    --literal-pathspecs makes git read every path as a file name. Without it, a path that
    starts with a colon or holds a glob character is a pattern, and a crafted file name
    could make the listing match files the pull request never touched. -z keeps a file
    name with a newline or a quote intact.
    """
    if not paths:
        return {}
    code, out = run(["--literal-pathspecs", "ls-tree", "-r", "-z", "--full-tree", ref, "--", *paths])
    if code != 0:
        raise RuntimeError(f"git ls-tree {ref} failed")
    entries: dict[str, tuple[str, str]] = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        mode, _kind, oid = meta.decode("ascii").split(" ")
        entries[path.decode("utf-8", "surrogateescape")] = (mode, oid)
    return entries


def paths_differing_from(paths: Iterable[str], head: str, integration: str, run: GitRunner) -> list[str]:
    """Return every path whose file at `head` is not identical to `integration`.

    A path absent from both is identical, which is how a deletion that already happened
    on `integration` passes. The mode counts, so promoting a file can't change whether it
    is executable.
    """
    wanted = sorted(set(paths))
    at_head = tree_entries(head, wanted, run)
    at_integration = tree_entries(integration, wanted, run)
    return [path for path in wanted if at_head.get(path) != at_integration.get(path)]


RETARGET = (
    f"`{PUBLISHING_BRANCH}` publishes the site and all 44 schema $id URIs on merge, so every "
    "change lands on `integration` first and reaches it only as a promotion. Retarget this "
    "pull request at `integration`. To publish one merged pull request before the next full "
    "promotion, a project lead runs `uv run python tools/promote_pr.py <number>`. "
    "See CONTRIBUTING.md."
)


def decide(
    paths: Iterable[str],
    base_ref: str,
    head_ref: str,
    head_repo: str,
    base_repo: str,
    differing: Callable[[list[str]], list[str]] | None = None,
) -> tuple[int, str]:
    """Return an exit status and the message to print.

    `differing` takes the changed paths and returns the ones whose content differs from
    `integration`. It is consulted only for a single pull request promotion, and a
    promotion with no way to check its content fails rather than passing unchecked.
    """
    if base_ref != PUBLISHING_BRANCH:
        return 0, f"Base branch is {base_ref!r}, not {PUBLISHING_BRANCH!r}. Nothing to check."
    if is_promotion(head_ref, head_repo, base_repo):
        return 0, f"Promotion from {head_ref!r}."
    if not is_single_promotion(head_ref, head_repo, base_repo):
        return 1, f"Only promotions may target `{PUBLISHING_BRANCH}`. {RETARGET}"
    changed = sorted(set(paths))
    if differing is None:
        return 1, "This promotion could not be checked against `integration`, so it does not pass."
    offenders = differing(changed)
    if offenders:
        listing = "\n".join(f"  {path}" for path in offenders)
        return 1, (
            f"A single pull request promotion may carry only content `integration` already "
            f"holds. These paths differ from `integration`:\n{listing}\n\n"
            "Rebuild the branch with tools/promote_pr.py, which copies each file from "
            "`integration`, or land the change on `integration` first."
        )
    return 0, f"Promotion from {head_ref!r}. Every changed path matches `integration`."


def main(argv: list[str]) -> int:
    """Read the changed paths from a file and the refs from the environment."""
    if len(argv) != 2:
        print("usage: base_branch_guard.py <git-diff-name-status-listing>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        paths, _added = parse_name_status(handle)
    head_sha = os.environ.get("HEAD_SHA", "")
    integration = os.environ.get("INTEGRATION_REF", DEFAULT_INTEGRATION_REF)

    def differing(changed: list[str]) -> list[str]:
        if not head_sha:
            raise RuntimeError("HEAD_SHA is not set")
        return paths_differing_from(changed, head_sha, integration, git_runner)

    try:
        status, message = decide(
            paths,
            os.environ.get("BASE_REF", ""),
            os.environ.get("HEAD_REF", ""),
            os.environ.get("HEAD_REPO", ""),
            os.environ.get("BASE_REPO", ""),
            differing,
        )
    except RuntimeError as error:
        status, message = 1, f"The content check could not run ({error}), so this does not pass."
    print(message, file=sys.stderr if status else sys.stdout)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
