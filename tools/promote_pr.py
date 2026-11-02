"""Promote one merged pull request from `integration` to `main`.

    uv run python tools/promote_pr.py <number> [--dry-run]

A full promotion merges all of `integration` into `main`. This publishes one pull request
sooner. It cuts `promote/pr-<number>` from `main`, copies the `integration` version of
every file that pull request changed (deleting the ones `integration` no longer has),
checks the result with the same content rule the base-branch guard enforces, pushes the
branch, and opens a pull request into `main`.

Whole files are copied, not commits. When a later pull request on `integration` edited
the same file, its edit comes along too, and the pull request body names it so reviewers
see everything that publishes. Copying keeps the branch identical to `integration` by
construction, which is the one property the guard checks.

Run it from a clone of this repository with `gh` signed in as a project lead. It runs
locally because the organization's Actions policy does not let a workflow open a pull
request. It works in a temporary worktree, so the checkout you run it from is untouched.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base_branch_guard import paths_differing_from  # noqa: E402

REPO = "GenAI-Security-Project/agent-control-standard"
REMOTE = "origin"
MAIN = f"{REMOTE}/main"
INTEGRATION = f"{REMOTE}/integration"
BRANCH_PREFIX = "promote/pr-"
# GitHub's pull request files endpoint stops at 3000 files. A larger pull request would be
# promoted partially and silently, so it is refused instead.
FILES_LIMIT = 3000

Runner = Callable[[list[str], str | None], tuple[int, str]]


class PromotionError(Exception):
    """A precondition failed. The message says what to do."""


def run_command(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    completed = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return completed.returncode, completed.stdout


@dataclass(frozen=True)
class Pull:
    number: int
    title: str
    merge_commit: str
    paths: tuple[str, ...]


def must(run: Runner, cmd: list[str], what: str, cwd: str | None = None) -> str:
    code, out = run(cmd, cwd)
    if code != 0:
        raise PromotionError(f"{what} failed: {' '.join(cmd[:3])}")
    return out


def git(*args: str) -> list[str]:
    """A git command that reads every path argument as a file name, never a pattern."""
    return ["git", "--literal-pathspecs", *args]


def fetch_pull(number: int, run: Runner) -> Pull:
    """Read the pull request and every path it changed, and check it can be promoted."""
    data = json.loads(must(run, ["gh", "api", f"repos/{REPO}/pulls/{number}"], "reading the pull request"))
    if not data.get("merged_at"):
        raise PromotionError(f"PR #{number} is not merged. Only merged work on integration can be promoted.")
    if data.get("base", {}).get("ref") != "integration":
        raise PromotionError(f"PR #{number} did not merge into integration.")
    if int(data.get("changed_files", 0)) > FILES_LIMIT:
        raise PromotionError(f"PR #{number} changes more than {FILES_LIMIT} files. Use a full promotion.")
    listing = must(
        run,
        ["gh", "api", "--paginate", f"repos/{REPO}/pulls/{number}/files",
         "--jq", '.[] | [.filename, (.previous_filename // "")] | @json'],
        "listing the pull request's files",
    )
    paths: set[str] = set()
    for line in listing.splitlines():
        if line.strip():
            for name in json.loads(line):
                if name:
                    paths.add(name)
    if not paths:
        raise PromotionError(f"PR #{number} changed no files.")
    return Pull(number, str(data.get("title", "")), str(data["merge_commit_sha"]), tuple(sorted(paths)))


def other_changes(pull: Pull, run: Runner) -> list[str]:
    """Subjects of other unpromoted integration commits that touched the same files."""
    out = must(
        run,
        git("log", "--format=%H %s", f"{MAIN}..{INTEGRATION}", "--", *pull.paths),
        "listing other changes to the same files",
    )
    subjects = []
    for line in out.splitlines():
        oid, _, subject = line.partition(" ")
        if oid and oid != pull.merge_commit:
            subjects.append(subject)
    return subjects


def body(pull: Pull, integration_sha: str, others: list[str]) -> str:
    files = "\n".join(f"- `{path}`" for path in pull.paths)
    carried = "\n".join(f"- {subject}" for subject in others) or "- None"
    # No closing keyword: the issues PR #N closes were closed when it merged into
    # integration, and this pull request publishes that work rather than completing it.
    return (
        f"Promotes PR #{pull.number} ({pull.title}) from `integration` to `main` ahead of the "
        "next full promotion.\n\n"
        f"Each file below is copied from `integration` at `{integration_sha[:12]}`, so this "
        "carries nothing `integration` does not already hold. The base-branch guard checks "
        "that again before this can merge.\n\n"
        f"Files:\n{files}\n\n"
        "Other unpromoted changes on `integration` to these same files, which publish with "
        f"this one:\n{carried}\n\n"
        "The roadmap counts an issue as delivered when its own commit reaches `main` by "
        "ancestry, so the issues this work closes show as delivered at the next full "
        "promotion, not at this merge."
    )


def promote(number: int, dry_run: bool, run: Runner = run_command, workdir: str | None = None) -> str:
    """Build and open the promotion. Returns the pull request URL, or a summary on a dry run."""
    branch = f"{BRANCH_PREFIX}{number}"
    pull = fetch_pull(number, run)
    must(run, ["git", "fetch", "--quiet", REMOTE, "main", "integration"], "fetching main and integration")
    code, _ = run(["git", "merge-base", "--is-ancestor", pull.merge_commit, INTEGRATION], None)
    if code != 0:
        raise PromotionError(f"PR #{number}'s merge commit is not on integration.")
    code, _ = run(["git", "ls-remote", "--exit-code", "--heads", REMOTE, branch], None)
    if code == 0:
        raise PromotionError(f"{branch} already exists on {REMOTE}. Merge or delete it first.")
    integration_sha = must(run, ["git", "rev-parse", INTEGRATION], "reading integration").strip()
    others = other_changes(pull, run)

    with tempfile.TemporaryDirectory(dir=workdir) as scratch:
        tree = str(Path(scratch) / "promote")
        must(run, ["git", "worktree", "add", "--quiet", "-b", branch, tree, MAIN], "creating the worktree")
        try:
            for path in pull.paths:
                code, _ = run(["git", "cat-file", "-e", f"{integration_sha}:{path}"], tree)
                if code == 0:
                    must(run, git("checkout", integration_sha, "--", path), f"copying {path}", tree)
                else:
                    code, _ = run(["git", "cat-file", "-e", f"HEAD:{path}"], tree)
                    if code == 0:
                        must(run, git("rm", "--quiet", "--", path), f"removing {path}", tree)
            code, _ = run(["git", "diff", "--cached", "--quiet"], tree)
            if code == 0:
                return f"main already holds PR #{number}'s content. Nothing to promote."

            def in_tree(args: list[str]) -> tuple[int, bytes]:
                completed = subprocess.run(["git", "-C", tree, *args], capture_output=True, check=False)
                return completed.returncode, completed.stdout

            must(run, ["git", "commit", "--quiet", "-s", "-m", f"Promote PR #{number}: {pull.title}",
                       "-m", f"Copies the integration versions of the files PR #{number} changed."],
                 "committing", tree)
            differing = paths_differing_from(list(pull.paths), "HEAD", integration_sha, in_tree)
            if differing:
                raise PromotionError("The promotion branch differs from integration at: " + ", ".join(differing))
            if dry_run:
                stat = must(run, ["git", "diff", "--stat", f"{MAIN}..HEAD"], "summarizing", tree)
                return f"Dry run. {branch} would publish:\n{stat}"
            must(run, ["git", "push", "--quiet", REMOTE, f"HEAD:refs/heads/{branch}"], "pushing", tree)
            url = must(
                run,
                ["gh", "pr", "create", "--repo", REPO, "--base", "main", "--head", branch,
                 "--title", f"Promote PR #{number}: {pull.title}",
                 "--body", body(pull, integration_sha, others)],
                "opening the pull request",
            )
            return url.strip()
        finally:
            run(["git", "worktree", "remove", "--force", tree], None)
            run(["git", "branch", "-D", branch], None)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--dry-run"]
    if len(args) != 1 or not args[0].isdigit():
        print("usage: promote_pr.py <pull request number> [--dry-run]", file=sys.stderr)
        return 2
    try:
        print(promote(int(args[0]), "--dry-run" in argv[1:]))
    except PromotionError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
