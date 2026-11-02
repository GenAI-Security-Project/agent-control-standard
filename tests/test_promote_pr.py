"""Promotions, against a real git origin with GitHub faked.

GitHub is the only thing faked. Every git step runs for real against a local bare
repository standing in for origin, so the tests show what the branch contains,
not what the script meant to do.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import promote_pr  # noqa: E402
from base_branch_guard import check  # noqa: E402
from promote_pr import PromotionError, promote_full, promote_single  # noqa: E402


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def exists(repo: Path, spec: str) -> bool:
    return subprocess.run(["git", "-C", str(repo), "cat-file", "-e", spec]).returncode == 0


def commit(repo: Path, files: dict[str, str | None], message: str) -> str:
    for name, content in files.items():
        if content is None:
            git(repo, "rm", "-rq", "--", name)
        else:
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(content)
            git(repo, "add", "--", name)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def on_integration(clone: Path, files: dict[str, str | None], message: str) -> str:
    git(clone, "checkout", "-q", "integration")
    sha = commit(clone, files, message)
    git(clone, "push", "-q", "origin", "integration")
    git(clone, "checkout", "-q", "main")
    return sha


@pytest.fixture
def origin(tmp_path, monkeypatch):
    """A bare origin with main, and integration two squash commits ahead.

    PR #10 edits a.md and deletes old.md. PR #11 later edits a.md again and adds b.md.
    """
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(bare), str(clone)], check=True, capture_output=True)
    git(clone, "config", "user.email", "lead@example.com")
    git(clone, "config", "user.name", "Lead")
    commit(clone, {"a.md": "one\n", "old.md": "old\n", "keep.md": "keep\n", "dir/inner.md": "inner\n"}, "base")
    git(clone, "push", "-q", "origin", "HEAD:main")
    git(clone, "checkout", "-q", "-b", "integration")
    git(clone, "push", "-q", "origin", "integration")
    git(clone, "checkout", "-q", "main")
    pr10 = on_integration(clone, {"a.md": "two\n", "old.md": None}, "Edit a and drop old (#10)")
    on_integration(clone, {"a.md": "three\n", "b.md": "b\n"}, "Edit a again and add b (#11)")
    monkeypatch.chdir(clone)
    # The bare repository's path is not a GitHub URL. Every other check runs unchanged.
    monkeypatch.setattr(promote_pr, "ORIGIN_URL", re.compile(r"origin\.git$"))
    return {"bare": bare, "clone": clone, "pr10": pr10}


def meta(sha: str, **overrides) -> dict:
    data = {"merged_at": "2026-11-01T00:00:00Z", "base": {"ref": "integration"},
            "merge_commit_sha": sha, "title": "Edit a and drop old"}
    data.update(overrides)
    return data


def fake_github(pulls: dict[int, dict], calls: list, create_fails: bool = False):
    """A runner that answers gh from `pulls` and runs git for real."""
    def run(cmd, cwd=None):
        if cmd[0] != "gh":
            return promote_pr.run_command(cmd, cwd)
        calls.append(cmd)
        if cmd[1] == "api":
            return 0, json.dumps(pulls[int(cmd[2].rsplit("/", 1)[1])])
        if cmd[1:3] == ["pr", "create"]:
            return (1, "") if create_fails else (0, "https://github.com/example/pull/99\n")
        return 1, ""
    return run


def created(calls: list) -> list:
    return next(c for c in calls if c[1:3] == ["pr", "create"])


BRANCH = "refs/heads/promote/pr-10"


def test_promotes_whole_files_from_integration_and_opens_a_pull_request(origin):
    calls = []
    url = promote_single(10, False, fake_github({10: meta(origin["pr10"])}, calls))
    assert url == "https://github.com/example/pull/99"
    bare = origin["bare"]
    assert git(bare, "show", f"{BRANCH}:a.md") == "three"  # integration's current a.md
    assert not exists(bare, f"{BRANCH}:old.md")
    assert not exists(bare, f"{BRANCH}:b.md")  # PR #10 never touched b.md
    assert git(bare, "rev-list", "--count", f"main..{BRANCH}") == "1"
    assert git(bare, "diff", "--name-only", "main", BRANCH).splitlines() == ["a.md", "old.md"]
    assert "Signed-off-by: Lead <lead@example.com>" in git(bare, "log", "-1", "--format=%B", BRANCH)
    create = created(calls)
    assert create[create.index("--base") + 1] == "main"
    body = create[create.index("--body") + 1]
    assert "`Edit a again and add b (#11)`" in body
    for keyword in ("Closes", "Fixes", "Resolves"):
        assert keyword not in body


def test_the_body_quotes_contributor_text_so_it_cannot_close_or_mention(origin):
    calls = []
    title = "Fix `x` closes #12 @org/team"
    promote_single(10, False, fake_github({10: meta(origin["pr10"], title=title)}, calls))
    body = created(calls)[created(calls).index("--body") + 1]
    assert "(`Fix 'x' closes #12 @org/team`)" in body


def test_leaves_no_worktree_or_local_branch_behind(origin):
    promote_single(10, False, fake_github({10: meta(origin["pr10"])}, []))
    clone = origin["clone"]
    assert len(git(clone, "worktree", "list").splitlines()) == 1
    assert "promote/" not in git(clone, "branch", "--list")


def test_git_hooks_do_not_run(origin):
    hooks = origin["clone"] / ".git" / "hooks"
    marker = origin["clone"].parent / "hook-ran"
    for name in ("pre-commit", "commit-msg", "post-checkout"):
        (hooks / name).write_text(f"#!/bin/sh\ntouch {marker}\n")
        (hooks / name).chmod(0o755)
    promote_single(10, False, fake_github({10: meta(origin["pr10"])}, []))
    assert not marker.exists()


def test_dry_run_pushes_nothing_and_opens_nothing(origin):
    calls = []
    summary = promote_single(10, True, fake_github({10: meta(origin["pr10"])}, calls))
    assert "Dry run" in summary and "a.md" in summary
    assert not any(c[1:3] == ["pr", "create"] for c in calls)
    assert git(origin["bare"], "branch", "--list", "promote/*") == ""


@pytest.mark.parametrize("override,needle", [
    ({"merged_at": None}, "not merged"),
    ({"base": {"ref": "main"}}, "did not merge into integration"),
    ({"merge_commit_sha": "0" * 40}, "not on integration"),
])
def test_refuses_what_cannot_be_promoted(origin, override, needle):
    with pytest.raises(PromotionError, match=needle):
        promote_single(10, False, fake_github({10: meta(origin["pr10"], **override)}, []))


def test_refuses_an_origin_that_is_not_this_repository(origin, monkeypatch):
    monkeypatch.setattr(promote_pr, "ORIGIN_URL", re.compile(r"github\.com/GenAI-Security-Project/"))
    with pytest.raises(PromotionError, match="Run this from a clone"):
        promote_single(10, False, fake_github({10: meta(origin["pr10"])}, []))


def test_refuses_when_the_branch_already_exists(origin):
    git(origin["clone"], "push", "-q", "origin", "main:refs/heads/promote/pr-10")
    with pytest.raises(PromotionError, match="already exists"):
        promote_single(10, False, fake_github({10: meta(origin["pr10"])}, []))


@pytest.mark.parametrize("path", ["version.txt", "docs/.gitattributes", ".gitmodules"])
def test_refuses_release_and_checkout_sensitive_files(origin, path):
    sha = on_integration(origin["clone"], {path: "x\n"}, "sensitive (#13)")
    with pytest.raises(PromotionError, match="full promotion"):
        promote_single(13, False, fake_github({13: meta(sha)}, []))


def test_reports_nothing_to_do_when_main_already_matches(origin):
    clone = origin["clone"]
    git(clone, "checkout", "-q", "origin/integration", "--", "a.md")
    git(clone, "rm", "-q", "old.md")
    git(clone, "commit", "-q", "-m", "already promoted")
    git(clone, "push", "-q", "origin", "HEAD:main")
    calls = []
    assert "Nothing to promote" in promote_single(10, False, fake_github({10: meta(origin["pr10"])}, calls))
    assert not any(c[1:3] == ["pr", "create"] for c in calls)


def test_a_rename_copies_the_new_path_and_removes_the_old(origin):
    clone = origin["clone"]
    git(clone, "checkout", "-q", "integration")
    git(clone, "mv", "keep.md", "kept.md")
    git(clone, "commit", "-q", "-m", "Rename keep (#12)")
    git(clone, "push", "-q", "origin", "integration")
    sha = git(clone, "rev-parse", "HEAD")
    git(clone, "checkout", "-q", "main")
    promote_single(12, False, fake_github({12: meta(sha)}, []))
    branch = "refs/heads/promote/pr-12"
    assert git(origin["bare"], "show", f"{branch}:kept.md") == "keep"
    assert not exists(origin["bare"], f"{branch}:keep.md")


def test_a_directory_replaced_by_a_file_promotes(origin):
    sha = on_integration(origin["clone"], {"dir": None}, "drop dir")
    sha = on_integration(origin["clone"], {"dir": "now a file\n"}, "dir becomes a file (#14)")
    clone = origin["clone"]
    # Promote both as one pull request: the squash of #14 relative to before the drop.
    git(clone, "checkout", "-q", "integration")
    git(clone, "reset", "-q", "--soft", "HEAD~2")
    git(clone, "commit", "-q", "-m", "dir becomes a file (#14)")
    git(clone, "push", "-q", "-f", "origin", "integration")
    sha = git(clone, "rev-parse", "HEAD")
    git(clone, "checkout", "-q", "main")
    promote_single(14, False, fake_github({14: meta(sha)}, []))
    branch = "refs/heads/promote/pr-14"
    assert git(origin["bare"], "show", f"{branch}:dir") == "now a file"
    assert not exists(origin["bare"], f"{branch}:dir/inner.md")


def test_a_crafted_file_name_promotes_only_itself(origin):
    """Read as a pattern, `*.md` would copy every markdown file on integration."""
    sha = on_integration(origin["clone"], {"*.md": "star\n"}, "Add a star file (#15)")
    promote_single(15, False, fake_github({15: meta(sha)}, []))
    branch = "refs/heads/promote/pr-15"
    assert git(origin["bare"], "diff", "--name-only", "main", branch).splitlines() == ["*.md"]


def test_a_non_ascii_file_name_promotes(origin):
    sha = on_integration(origin["clone"], {"café.md": "accent\n"}, "Add café (#16)")
    promote_single(16, False, fake_github({16: meta(sha)}, []))
    assert git(origin["bare"], "show", "refs/heads/promote/pr-16:café.md") == "accent"


def test_a_failed_pull_request_removes_the_pushed_branch(origin):
    with pytest.raises(PromotionError, match="deleted"):
        promote_single(10, False, fake_github({10: meta(origin["pr10"])}, [], create_fails=True))
    assert git(origin["bare"], "branch", "--list", "promote/*") == ""
    # A rerun is not blocked by an orphan branch.
    assert promote_single(10, False, fake_github({10: meta(origin["pr10"])}, [])).startswith("https://")


def test_the_post_commit_check_catches_a_copy_that_went_wrong(origin):
    """If the copied tree differs from integration, nothing is pushed."""
    calls = []
    real = fake_github({10: meta(origin["pr10"])}, calls)

    def tamper(cmd, cwd=None):
        code, out = real(cmd, cwd)
        if cmd[:3] == promote_pr.QUIET_GIT[:3] and "checkout" in cmd and cwd:
            Path(cwd, "a.md").write_text("tampered\n")
            subprocess.run(["git", "-C", cwd, "add", "a.md"], check=True)
        return code, out
    with pytest.raises(PromotionError, match="failed its own check"):
        promote_single(10, False, tamper)
    assert not any(c[1:3] == ["pr", "create"] for c in calls)
    assert git(origin["bare"], "branch", "--list", "promote/*") == ""


def test_the_post_commit_check_catches_a_file_the_pull_request_never_touched(origin):
    """An extra file copied from integration matches integration, so only the check against
    the pull request's own file list can see it."""
    calls = []
    real = fake_github({10: meta(origin["pr10"])}, calls)

    def widen(cmd, cwd=None):
        code, out = real(cmd, cwd)
        if cmd[:3] == promote_pr.QUIET_GIT[:3] and "checkout" in cmd and cwd:
            subprocess.run(["git", "-C", cwd, "checkout", "origin/integration", "--", "b.md"], check=True)
        return code, out
    with pytest.raises(PromotionError, match="b.md"):
        promote_single(10, False, widen)
    assert not any(c[1:3] == ["pr", "create"] for c in calls)


def test_refuses_a_merge_commit_that_is_not_this_pull_requests_squash(origin):
    """A rebase merge leaves the last commit as merge_commit_sha, which holds only part of
    the work. Its subject does not end in the pull request number."""
    sha = on_integration(origin["clone"], {"c.md": "c\n"}, "Part three of a rebase merge")
    with pytest.raises(PromotionError, match="squash-merged"):
        promote_single(18, False, fake_github({18: meta(sha)}, []))


def test_warns_when_mkdocs_yml_is_copied_whole(origin):
    sha = on_integration(origin["clone"], {"mkdocs.yml": "nav: []\n"}, "Add a nav (#19)")
    calls = []
    promote_single(19, False, fake_github({19: meta(sha)}, calls))
    body = created(calls)[created(calls).index("--body") + 1]
    assert promote_pr.NAV_WARNING in body


# ---- full promotion ------------------------------------------------------------------------


def single_promoted_then_edited_again(origin) -> None:
    """The conflict trap: a.md is promoted alone, then integration edits it again."""
    promote_single(10, False, fake_github({10: meta(origin["pr10"])}, []))
    bare, clone = origin["bare"], origin["clone"]
    git(clone, "fetch", "-q", "origin")
    git(clone, "checkout", "-q", "main")
    git(clone, "reset", "-q", "--hard", "origin/main")
    git(clone, "merge", "-q", "--no-ff", "--no-edit", "origin/promote/pr-10")
    git(clone, "push", "-q", "origin", "HEAD:main")
    on_integration(clone, {"a.md": "four\n"}, "Edit a once more (#17)")
    git(clone, "fetch", "-q", "origin")
    code = subprocess.run(["git", "-C", str(bare), "merge-tree", "--write-tree", "main", "integration"],
                          capture_output=True).returncode
    assert code == 1  # the plain promotion conflicts


def test_full_promotion_makes_main_equal_integration_where_the_plain_merge_conflicts(origin):
    single_promoted_then_edited_again(origin)
    calls = []
    url = promote_full(False, fake_github({}, calls))
    assert url.startswith("https://")
    bare = origin["bare"]
    branch = next(b.strip("* ") for b in git(bare, "branch", "--list", "promote/full-*").splitlines())
    # integration and main are both ancestors, and the tree is integration's.
    assert subprocess.run(["git", "-C", str(bare), "merge-base", "--is-ancestor", "integration", branch]).returncode == 0
    assert subprocess.run(["git", "-C", str(bare), "merge-base", "--is-ancestor", "main", branch]).returncode == 0
    assert git(bare, "rev-parse", f"{branch}^{{tree}}") == git(bare, "rev-parse", "integration^{tree}")

    def bare_run(args):
        done = subprocess.run(["git", "-C", str(bare), *args], capture_output=True)
        return done.returncode, done.stdout
    assert check("full", "main", branch, "integration", bare_run).differing == []
    body = created(calls)[created(calls).index("--body") + 1]
    listed = body.split("```text\n", 1)[1].split("\n```", 1)[0].splitlines()
    # Only where main changed something integration does not match, not new integration work.
    assert listed == ["a.md"]


def test_full_promotion_says_so_when_the_plain_promotion_is_enough(origin):
    assert "plain promotion" in promote_full(False, fake_github({}, []))


def test_full_dry_run_pushes_nothing(origin):
    single_promoted_then_edited_again(origin)
    calls = []
    assert "Dry run" in promote_full(True, fake_github({}, calls))
    assert git(origin["bare"], "branch", "--list", "promote/full-*") == ""
    assert not calls


def test_main_rejects_bad_arguments():
    for argv in (["x"], ["x", "abc"], ["x", "--full", "3"], ["x", "--bogus"]):
        assert promote_pr.main(argv) == 2
