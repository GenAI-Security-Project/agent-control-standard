"""Single pull request promotion, against a real git origin with GitHub faked.

GitHub is the only thing faked. Every git step runs for real against a local bare
repository standing in for origin, so the tests show what the branch actually contains,
not what the script meant to do.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import promote_pr  # noqa: E402
from promote_pr import PromotionError, body, promote  # noqa: E402


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo: Path, files: dict[str, str | None], message: str) -> str:
    for name, content in files.items():
        path = repo / name
        if content is None:
            git(repo, "rm", "-q", "--", name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            git(repo, "add", "--", name)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def origin(tmp_path, monkeypatch):
    """A bare origin with main, and integration two pull requests ahead of it.

    PR #10 edits a.md and deletes old.md. PR #11 later edits a.md again and adds b.md.
    """
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(bare), str(clone)], check=True, capture_output=True)
    git(clone, "config", "user.email", "lead@example.com")
    git(clone, "config", "user.name", "Lead")
    commit(clone, {"a.md": "one\n", "old.md": "old\n", "keep.md": "keep\n"}, "base")
    git(clone, "push", "-q", "origin", "HEAD:main")
    git(clone, "checkout", "-q", "-b", "integration")
    pr10 = commit(clone, {"a.md": "two\n", "old.md": None}, "Edit a and drop old (#10)")
    commit(clone, {"a.md": "three\n", "b.md": "b\n"}, "Edit a again and add b (#11)")
    git(clone, "push", "-q", "origin", "integration")
    git(clone, "checkout", "-q", "main")
    monkeypatch.chdir(clone)
    return {"bare": bare, "clone": clone, "pr10": pr10}


def fake_github(pulls: dict[int, dict], calls: list):
    """A runner that answers gh from `pulls` and runs git for real."""
    def run(cmd, cwd=None):
        if cmd[0] != "gh":
            completed = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
            return completed.returncode, completed.stdout
        calls.append(cmd)
        if cmd[1] == "api" and cmd[-1].endswith("/files") is False and "--paginate" not in cmd:
            number = int(cmd[2].rsplit("/", 1)[1])
            return 0, json.dumps(pulls[number]["meta"])
        if cmd[1] == "api" and "--paginate" in cmd:
            number = int(cmd[3].split("/")[-2])
            return 0, "\n".join(json.dumps(pair) for pair in pulls[number]["files"])
        if cmd[1:3] == ["pr", "create"]:
            return 0, "https://github.com/example/pull/99\n"
        return 1, ""
    return run


def pr10(origin, **overrides):
    meta = {"merged_at": "2026-11-01T00:00:00Z", "base": {"ref": "integration"},
            "merge_commit_sha": origin["pr10"], "title": "Edit a and drop old", "changed_files": 2}
    meta.update(overrides)
    return {10: {"meta": meta, "files": [["a.md", ""], ["old.md", ""]]}}


def test_promotes_whole_files_from_integration_and_opens_a_pull_request(origin):
    calls = []
    url = promote(10, False, fake_github(pr10(origin), calls))
    assert url == "https://github.com/example/pull/99"
    bare = origin["bare"]
    branch = "refs/heads/promote/pr-10"
    # a.md is integration's current version, PR #11's later edit included.
    assert git(bare, "show", f"{branch}:a.md") == "three"
    # old.md is deleted, as on integration. b.md, which PR #10 never touched, stays out.
    assert subprocess.run(["git", "-C", str(bare), "cat-file", "-e", f"{branch}:old.md"]).returncode != 0
    assert subprocess.run(["git", "-C", str(bare), "cat-file", "-e", f"{branch}:b.md"]).returncode != 0
    assert git(bare, "show", f"{branch}:keep.md") == "keep"
    # The branch is cut from main and adds one signed commit.
    assert git(bare, "rev-list", "--count", f"main..{branch}") == "1"
    assert "Signed-off-by: Lead <lead@example.com>" in git(bare, "log", "-1", "--format=%B", branch)
    create = next(c for c in calls if c[1:3] == ["pr", "create"])
    text = create[create.index("--body") + 1]
    assert "--base" in create and create[create.index("--base") + 1] == "main"
    assert "Edit a again and add b (#11)" in text
    assert "Closes" not in text and "Fixes" not in text and "Resolves" not in text


def test_leaves_no_worktree_or_local_branch_behind(origin):
    promote(10, False, fake_github(pr10(origin), []))
    clone = origin["clone"]
    assert len(git(clone, "worktree", "list").splitlines()) == 1
    assert "promote/pr-10" not in git(clone, "branch", "--list")


def test_dry_run_pushes_nothing_and_opens_nothing(origin):
    calls = []
    summary = promote(10, True, fake_github(pr10(origin), calls))
    assert "Dry run" in summary and "a.md" in summary
    assert not any(c[1:3] == ["pr", "create"] for c in calls)
    assert git(origin["bare"], "branch", "--list", "promote/*") == ""


@pytest.mark.parametrize("override,needle", [
    ({"merged_at": None}, "not merged"),
    ({"base": {"ref": "main"}}, "did not merge into integration"),
    ({"changed_files": 3001}, "full promotion"),
])
def test_refuses_what_cannot_be_promoted(origin, override, needle):
    with pytest.raises(PromotionError, match=needle):
        promote(10, False, fake_github(pr10(origin, **override), []))


def test_refuses_a_merge_commit_that_is_not_on_integration(origin):
    with pytest.raises(PromotionError, match="not on integration"):
        promote(10, False, fake_github(pr10(origin, merge_commit_sha="0" * 40), []))


def test_refuses_when_the_branch_already_exists(origin):
    git(origin["clone"], "push", "-q", "origin", "main:refs/heads/promote/pr-10")
    with pytest.raises(PromotionError, match="already exists"):
        promote(10, False, fake_github(pr10(origin), []))


def test_reports_nothing_to_do_when_main_already_matches(origin):
    clone = origin["clone"]
    git(clone, "checkout", "-q", "origin/integration", "--", "a.md")
    git(clone, "rm", "-q", "old.md")
    git(clone, "commit", "-q", "-m", "already promoted")
    git(clone, "push", "-q", "origin", "HEAD:main")
    calls = []
    assert "Nothing to promote" in promote(10, False, fake_github(pr10(origin), calls))
    assert not any(c[1:3] == ["pr", "create"] for c in calls)


def test_a_rename_copies_the_new_path_and_removes_the_old(origin):
    clone = origin["clone"]
    git(clone, "checkout", "-q", "integration")
    git(clone, "mv", "keep.md", "kept.md")
    git(clone, "commit", "-q", "-m", "Rename keep (#12)")
    sha = git(clone, "rev-parse", "HEAD")
    git(clone, "push", "-q", "origin", "integration")
    git(clone, "checkout", "-q", "main")
    pulls = {12: {"meta": {"merged_at": "x", "base": {"ref": "integration"}, "merge_commit_sha": sha,
                           "title": "Rename keep", "changed_files": 1},
                  "files": [["kept.md", "keep.md"]]}}
    promote(12, False, fake_github(pulls, []))
    branch = "refs/heads/promote/pr-12"
    assert git(origin["bare"], "show", f"{branch}:kept.md") == "keep"
    assert subprocess.run(["git", "-C", str(origin["bare"]), "cat-file", "-e", f"{branch}:keep.md"]).returncode != 0


def test_body_names_files_and_carried_changes_without_closing_anything():
    pull = promote_pr.Pull(5, "Fix x", "a" * 40, ("a.md", "b.md"))
    text = body(pull, "b" * 40, ["Other change (#6)"])
    assert "PR #5" in text and "`a.md`" in text and "Other change (#6)" in text
    assert "bbbbbbbbbbbb" in text
    for keyword in ("Closes", "Fixes", "Resolves"):
        assert keyword not in text


def test_main_rejects_bad_arguments(capsys):
    assert promote_pr.main(["promote_pr.py"]) == 2
    assert promote_pr.main(["promote_pr.py", "abc"]) == 2
