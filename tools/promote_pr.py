"""Open a promotion from `integration` to `main`.

    uv run python tools/promote_pr.py <number> [--dry-run]   one merged pull request
    uv run python tools/promote_pr.py --full [--dry-run]     all of integration

A single pull request promotion publishes one merged pull request before the next full
promotion. It cuts `promote/pr-<number>` from `main`, copies the `integration` version of
every file that pull request changed (removing the ones `integration` no longer has),
checks the result with the base-branch guard's own rule, pushes, and opens a pull request
into `main`. Whole files are copied, so when a later pull request on `integration` edited
the same file its edit publishes too, and the description names it.

A full promotion is normally the pull request from `integration` itself. It conflicts, or
the guard rejects it, when `main` holds a copy `integration` has since changed or
reverted. `--full` fixes that: it builds `promote/full-<sha>` from `integration` and
merges `main` into it with the `ours` strategy, so the result is exactly `integration`'s
tree with `main` as an ancestor. `integration` wins every difference, which is right,
because `main` never holds anything that did not come from `integration`.

Run it from a clone whose `origin` is this repository, with `gh` signed in as a project
lead. It runs locally because the organization's Actions policy does not let a workflow
open a pull request. It works in a temporary worktree with git hooks off, so the checkout
you run it from is untouched.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base_branch_guard import RELEASE_FILES, check  # noqa: E402

REPO = "GenAI-Security-Project/agent-control-standard"
REMOTE = "origin"
MAIN = f"{REMOTE}/main"
INTEGRATION = f"{REMOTE}/integration"
SINGLE_PREFIX = "promote/pr-"
FULL_PREFIX = "promote/full-"
# Matches this repository's URL over HTTPS or SSH. A fork or a mirror as origin would read
# the wrong integration and push to the wrong place.
ORIGIN_URL = re.compile(r"github\.com[:/]GenAI-Security-Project/agent-control-standard(?:\.git)?/?$", re.I)
# Checking one of these out runs filters, submodule logic, or LFS configuration on the
# lead's machine, so a pull request that changes one goes through a full promotion.
CHECKOUT_SENSITIVE = frozenset({".gitmodules", ".lfsconfig"})
FETCH_REFSPECS = (f"+refs/heads/main:refs/remotes/{MAIN}", f"+refs/heads/integration:refs/remotes/{INTEGRATION}")
# Hooks off for every git call that writes, so a hook in the lead's clone or in a copied
# file never runs.
QUIET_GIT = ["git", "-c", "core.hooksPath=/dev/null", "--literal-pathspecs"]

Runner = Callable[[list[str], str | None], tuple[int, str]]


class PromotionError(Exception):
    """A precondition failed. The message says what to do."""


def run_command(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    # Hooks off for every git call, not only the ones that write: worktree add fires
    # post-checkout and push fires pre-push.
    if cmd and cmd[0] == "git" and cmd[1:3] != ["-c", "core.hooksPath=/dev/null"]:
        cmd = ["git", "-c", "core.hooksPath=/dev/null", *cmd[1:]]
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    completed = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, env=env)
    return completed.returncode, completed.stdout


def must(run: Runner, cmd: list[str], what: str, cwd: str | None = None) -> str:
    code, out = run(cmd, cwd)
    if code != 0:
        raise PromotionError(f"{what} failed.")
    return out


def nul_paths(out: str) -> list[str]:
    return [p for p in out.split("\0") if p]


def code_span(text: str) -> str:
    """Contributor text as an inline code span, so it cannot close an issue or mention anyone."""
    return "`" + " ".join(text.replace("`", "'").split()) + "`"


@dataclass(frozen=True)
class Pull:
    number: int
    title: str
    merge_commit: str
    paths: tuple[str, ...]


def prepare(run: Runner) -> str:
    """Check origin, fetch main and integration, and return integration's commit."""
    url = must(run, ["git", "remote", "get-url", REMOTE], f"reading the {REMOTE} remote").strip()
    if not ORIGIN_URL.search(url):
        raise PromotionError(f"{REMOTE} is {url}, not {REPO}. Run this from a clone of {REPO}.")
    must(run, ["git", "fetch", "--quiet", "--no-tags", REMOTE, *FETCH_REFSPECS], "fetching main and integration")
    return must(run, ["git", "rev-parse", f"{INTEGRATION}^{{commit}}"], "reading integration").strip()


def refuse_existing(branch: str, run: Runner) -> None:
    code, _ = run(["git", "ls-remote", "--exit-code", "--heads", REMOTE, branch], None)
    if code == 0:
        raise PromotionError(f"{branch} already exists on {REMOTE}. Merge its pull request or delete it first.")


def read_pull(number: int, run: Runner) -> Pull:
    """Read the pull request from GitHub and the files it changed from git."""
    data = json.loads(must(run, ["gh", "api", f"repos/{REPO}/pulls/{number}"], "reading the pull request"))
    if not data.get("merged_at"):
        raise PromotionError(f"PR #{number} is not merged. Only merged work on integration can be promoted.")
    if data.get("base", {}).get("ref") != "integration":
        raise PromotionError(f"PR #{number} did not merge into integration.")
    merge = str(data.get("merge_commit_sha") or "")
    code, _ = run(["git", "merge-base", "--is-ancestor", merge, INTEGRATION], None)
    if not merge or code != 0:
        raise PromotionError(f"PR #{number}'s merge commit is not on integration.")
    # The squash commit against its parent is exactly what the pull request changed, read
    # from git with -z so every file name survives intact. No API page limit applies.
    out = must(run, ["git", "diff", "-z", "--name-only", "--no-renames", f"{merge}^1", merge],
               "listing the pull request's files")
    paths = tuple(sorted(set(nul_paths(out))))
    if not paths:
        raise PromotionError(f"PR #{number} changed no files.")
    return Pull(number, str(data.get("title") or ""), merge, paths)


def refuse_unsafe(paths: tuple[str, ...]) -> None:
    blocked = sorted(p for p in paths if p in RELEASE_FILES or p in CHECKOUT_SENSITIVE
                     or Path(p).name == ".gitattributes")
    if blocked:
        raise PromotionError("These files go through a full promotion (tools/promote_pr.py --full): "
                             + ", ".join(blocked))


def other_changes(pull: Pull, run: Runner) -> list[str]:
    """Subjects of other unpromoted integration commits that touched the same files."""
    out = must(run, ["git", "--literal-pathspecs", "log", "-z", "--format=%H %s", f"{MAIN}..{INTEGRATION}",
                     "--", *pull.paths], "listing other changes to the same files")
    subjects = []
    for record in nul_paths(out):
        oid, _, subject = record.strip().partition(" ")
        if oid != pull.merge_commit:
            subjects.append(subject)
    return subjects


def single_body(pull: Pull, integration_sha: str, others: list[str]) -> str:
    files = "\n".join(pull.paths)
    carried = "\n".join(f"- {code_span(s)}" for s in others) or "- None"
    # No closing keyword: the issues this work closes closed when it merged into
    # integration, and this publishes that work rather than completing it.
    return (
        f"Promotes PR #{pull.number} ({code_span(pull.title)}) from `integration` to `main` "
        "ahead of the next full promotion.\n\n"
        f"Each file below is copied from `integration` at `{integration_sha[:12]}`, so this "
        "carries nothing `integration` does not already hold. The base-branch guard checks "
        "that again before this can merge.\n\n"
        f"Files:\n\n```text\n{files}\n```\n\n"
        "Other unpromoted changes on `integration` to these same files, which publish with "
        f"this one:\n\n{carried}\n\n"
        "The roadmap counts an issue as delivered when its own commit reaches `main` by "
        "ancestry, so the issues this work closes show as delivered at the next full "
        "promotion, not at this merge.\n\n"
        "Merge with a merge commit. The person who ran tools/promote_pr.py pushed this "
        "branch, so a different code owner approves it."
    )


def full_body(integration_sha: str, overridden: list[str]) -> str:
    listing = "\n".join(overridden) or "(none)"
    return (
        f"Promotes all of `integration` at `{integration_sha[:12]}` to `main`.\n\n"
        "Built by `tools/promote_pr.py --full`: `integration` with `main` merged in using the "
        "`ours` strategy, so after this merges `main` equals `integration` exactly. Where the "
        "two differed, `integration` wins. These paths are where `main` held something "
        f"`integration` no longer does:\n\n```text\n{listing}\n```\n\n"
        "Merge with a merge commit, not a squash: squashing flattens the specification history "
        "that makes a schema change reviewable later. The person who ran the script pushed "
        "this branch, so a different code owner approves it."
    )


def publish(branch: str, title: str, text: str, tree: str, run: Runner) -> str:
    """Push the branch and open the pull request. Remove the branch if the second step fails."""
    must(run, ["git", "push", "--quiet", REMOTE, f"HEAD:refs/heads/{branch}"], "pushing", tree)
    code, url = run(["gh", "pr", "create", "--repo", REPO, "--base", "main", "--head", branch,
                     "--title", title, "--body", text], None)
    if code != 0:
        run(["git", "push", "--quiet", REMOTE, "--delete", branch], tree)
        raise PromotionError("Opening the pull request failed, so the pushed branch was deleted. Run it again.")
    return url.strip()


def guard_runner(tree: str):
    def run(args: list[str]) -> tuple[int, bytes]:
        env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
        completed = subprocess.run(["git", "-C", tree, *args], capture_output=True, check=False, env=env)
        return completed.returncode, completed.stdout
    return run


def promote_single(number: int, dry_run: bool, run: Runner = run_command, workdir: str | None = None) -> str:
    branch = f"{SINGLE_PREFIX}{number}"
    integration_sha = prepare(run)
    pull = read_pull(number, run)
    refuse_unsafe(pull.paths)
    refuse_existing(branch, run)
    others = other_changes(pull, run)

    with tempfile.TemporaryDirectory(dir=workdir) as scratch:
        tree = str(Path(scratch) / "promote")
        must(run, ["git", "worktree", "add", "--quiet", "-b", branch, tree, MAIN], "creating the worktree")
        try:
            on_integration = []
            for path in pull.paths:
                code, _ = run(["git", "cat-file", "-e", f"{integration_sha}:{path}"], tree)
                if code == 0:
                    on_integration.append(path)
                else:
                    # Removals first, so a file that replaces a directory, or the other way
                    # round, never meets the old shape still in the index.
                    must(run, [*QUIET_GIT, "rm", "-r", "--quiet", "--ignore-unmatch", "--", path],
                         f"removing {path}", tree)
            for path in on_integration:
                must(run, [*QUIET_GIT, "checkout", integration_sha, "--", path], f"copying {path}", tree)
            code, _ = run(["git", "diff", "--cached", "--quiet"], tree)
            if code == 0:
                return f"main already holds PR #{number}'s content. Nothing to promote."
            must(run, [*QUIET_GIT, "commit", "--quiet", "-s",
                       "-m", f"Promote PR #{number}: {' '.join(pull.title.split())}",
                       "-m", f"Copies the integration versions of the files PR #{number} changed."],
                 "committing", tree)

            changed = set(nul_paths(must(run, ["git", "diff", "-z", "--name-only", "--no-renames", MAIN, "HEAD"],
                                         "listing the branch's changes", tree)))
            extra = sorted(changed - set(pull.paths))
            verdict = check("single", MAIN, "HEAD", integration_sha, guard_runner(tree))
            if extra or verdict.conflicted or verdict.differing or verdict.release_files:
                raise PromotionError("The promotion branch failed its own check: "
                                     + ", ".join(extra + verdict.differing + verdict.release_files or ["conflict"]))
            if dry_run:
                stat = must(run, ["git", "diff", "--stat", MAIN, "HEAD"], "summarizing", tree)
                return f"Dry run. {branch} would publish:\n{stat}"
            title = f"Promote PR #{number}: {' '.join(pull.title.split())}"
            return publish(branch, title, single_body(pull, integration_sha, others), tree, run)
        finally:
            run(["git", "worktree", "remove", "--force", tree], None)
            run(["git", "branch", "-D", branch], None)


def promote_full(dry_run: bool, run: Runner = run_command, workdir: str | None = None) -> str:
    integration_sha = prepare(run)
    branch = f"{FULL_PREFIX}{integration_sha[:12]}"
    code, _ = run(["git", "merge-base", "--is-ancestor", MAIN, INTEGRATION], None)
    if code == 0:
        return ("integration already contains main, so the plain promotion from integration merges "
                "cleanly. Open it with the command the roadmap health issue prints.")
    refuse_existing(branch, run)
    overridden = nul_paths(must(run, ["git", "diff", "-z", "--name-only", "--no-renames", INTEGRATION, MAIN],
                                "listing where main differs"))

    with tempfile.TemporaryDirectory(dir=workdir) as scratch:
        tree = str(Path(scratch) / "promote")
        must(run, ["git", "worktree", "add", "--quiet", "-b", branch, tree, integration_sha], "creating the worktree")
        try:
            must(run, [*QUIET_GIT, "merge", "--quiet", "-s", "ours", "--no-edit", "--signoff",
                       "-m", "Promote integration to main", MAIN], "merging main with the ours strategy", tree)
            verdict = check("full", MAIN, "HEAD", integration_sha, guard_runner(tree))
            if verdict.conflicted or verdict.differing:
                raise PromotionError("The full promotion branch failed its own check: "
                                     + (", ".join(verdict.differing) or "conflict"))
            if dry_run:
                return f"Dry run. {branch} would make main equal integration. integration wins at:\n" + (
                    "\n".join(overridden) or "(nothing)")
            return publish(branch, "Promote integration to main", full_body(integration_sha, overridden), tree, run)
        finally:
            run(["git", "worktree", "remove", "--force", tree], None)
            run(["git", "branch", "-D", branch], None)


USAGE = "usage: promote_pr.py <pull request number> [--dry-run]\n       promote_pr.py --full [--dry-run]"


def main(argv: list[str]) -> int:
    flags = {a for a in argv[1:] if a.startswith("--")}
    args = [a for a in argv[1:] if not a.startswith("--")]
    if flags - {"--dry-run", "--full"}:
        print(USAGE, file=sys.stderr)
        return 2
    dry_run = "--dry-run" in flags
    try:
        if "--full" in flags:
            if args:
                print(USAGE, file=sys.stderr)
                return 2
            print(promote_full(dry_run))
        else:
            if len(args) != 1 or not args[0].isdigit():
                print(USAGE, file=sys.stderr)
                return 2
            print(promote_single(int(args[0]), dry_run))
    except PromotionError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
