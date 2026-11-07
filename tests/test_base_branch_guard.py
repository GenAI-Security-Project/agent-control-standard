"""Guards for the rule that only promotions reach the publishing branch.

The guard judges the result of merging a pull request into `main`, compared with
`integration`. Every content case below runs against a real repository, because the
failures that matter live in git's own behavior: how it names unusual files, what a
three-way merge keeps, and what a conflict looks like.
"""

import subprocess
import sys
from pathlib import Path

import pytest

# Matches the import style the other tools tests use, in test_publish_schemas.py:12.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from base_branch_guard import (  # noqa: E402
    PUBLISHING_BRANCH,
    Verdict,
    check,
    decide,
    main,
    promotion_kind,
)

REPO = "GenAI-Security-Project/agent-control-standard"
FORK = "someone/agent-control-standard"
WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "pr-base-guard.yml"

CLEAN = Verdict(False, [], [])


def test_promotion_kinds_inside_this_repository():
    assert promotion_kind("integration", REPO, REPO) == "full"
    assert promotion_kind("promote/full-abc123", REPO, REPO) == "full"
    assert promotion_kind("promote/pr-7", REPO, REPO) == "single"
    # A release is a pull request into integration plus a full promotion.
    assert promotion_kind("release/v0.2.0", REPO, REPO) is None
    assert promotion_kind("docs/faq", REPO, REPO) is None


def test_a_fork_branch_named_like_a_promotion_is_not_one():
    """head.ref is a name the contributor chose. Only the repository check is trustworthy."""
    for ref in ("integration", "promote/full-x", "promote/pr-1", "release/v1"):
        assert promotion_kind(ref, FORK, REPO) is None


def test_any_other_base_passes_without_checking():
    status, message = decide("integration", "spec/x", FORK, REPO, None)
    assert status == 0
    assert "Nothing to check" in message


def test_a_documentation_pull_request_to_main_fails():
    """The documentation lane is gone. Docs land on integration like everything else."""
    status, message = decide(PUBLISHING_BRANCH, "docs/faq", FORK, REPO, None)
    assert status == 1
    assert "integration" in message and "promote_pr.py" in message


def test_a_fork_promotion_fails_without_consulting_content():
    def explode(_kind):
        raise AssertionError("content must not be consulted for a fork")
    assert decide(PUBLISHING_BRANCH, "integration", FORK, REPO, explode)[0] == 1


def test_a_promotion_without_a_content_check_fails_closed():
    assert decide(PUBLISHING_BRANCH, "promote/pr-1", REPO, REPO, None)[0] == 1


def test_verdicts_map_to_messages():
    single = lambda v: decide(PUBLISHING_BRANCH, "promote/pr-1", REPO, REPO, lambda _k: v)  # noqa: E731
    full = lambda v: decide(PUBLISHING_BRANCH, "integration", REPO, REPO, lambda _k: v)  # noqa: E731
    assert single(CLEAN)[0] == 0
    assert full(CLEAN)[0] == 0
    status, message = single(Verdict(True, [], []))
    assert status == 1 and "--full" in message
    status, message = single(Verdict(False, [], ["version.txt"]))
    assert status == 1 and "version.txt" in message
    status, message = single(Verdict(False, ["a.md"], []))
    assert status == 1 and "a.md" in message
    status, message = full(Verdict(False, ["a.md"], []))
    assert status == 1 and "--full" in message and "a.md" in message


# ---- content, against real repositories ------------------------------------------------


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def write(repo: Path, files: dict[str, str | None], message: str) -> None:
    for name, content in files.items():
        if content is None:
            git(repo, "rm", "-q", "--", name)
        else:
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(content)
            git(repo, "add", "--", name)
    git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path):
    """main has a.md and keep.md. integration is one commit ahead: a.md edited, b.md added."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    write(root, {"a.md": "one\n", "keep.md": "keep\n", "version.txt": "0.1.4\n"}, "base")
    git(root, "checkout", "-q", "-b", "integration")
    write(root, {"a.md": "two\n", "b.md": "b\n"}, "integration work")
    git(root, "checkout", "-q", "main")
    return root


def run_in(repo: Path):
    def run(args):
        completed = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
        return completed.returncode, completed.stdout
    return run


def promote_branch(repo: Path, files: dict[str, str | None], name: str = "promote/pr-1") -> str:
    git(repo, "checkout", "-q", "-b", name, "main")
    write(repo, files, "promote")
    git(repo, "checkout", "-q", "main")
    return name


def verdict(repo: Path, kind: str, head: str) -> Verdict:
    return check(kind, "main", head, "integration", run_in(repo))


def test_a_full_promotion_from_integration_passes(repo):
    assert verdict(repo, "full", "integration") == CLEAN


def test_a_single_promotion_of_integration_content_passes(repo):
    head = promote_branch(repo, {"a.md": "two\n"})
    assert verdict(repo, "single", head) == CLEAN


def test_a_single_promotion_with_content_integration_lacks_fails(repo):
    head = promote_branch(repo, {"a.md": "two\n", "extra.md": "not on integration\n"})
    assert verdict(repo, "single", head).differing == ["extra.md"]


@pytest.mark.parametrize("name", ["café.md", "tab\tname.md", 'quo"te.md', "back\\slash.md"])
def test_a_file_name_git_would_quote_is_still_compared(repo, name):
    """Without -z git writes these names in quotes, and a quoted name matches no file, so a
    check built on that listing compared nothing and passed. This reproduces the bypass."""
    head = promote_branch(repo, {"a.md": "two\n", name: "smuggled\n"})
    assert verdict(repo, "single", head).differing == [name]


def test_a_mode_change_integration_lacks_fails(repo):
    git(repo, "checkout", "-q", "-b", "promote/mode", "main")
    (repo / "keep.md").chmod(0o755)
    git(repo, "add", "keep.md")
    git(repo, "commit", "-q", "-m", "chmod")
    git(repo, "checkout", "-q", "main")
    assert verdict(repo, "single", "promote/mode").differing == ["keep.md"]


def test_a_deletion_integration_lacks_fails(repo):
    head = promote_branch(repo, {"keep.md": None})
    assert verdict(repo, "single", head).differing == ["keep.md"]


def test_a_single_promotion_may_not_carry_release_files(repo):
    git(repo, "checkout", "-q", "integration")
    write(repo, {"version.txt": "0.1.5\n"}, "release")
    git(repo, "checkout", "-q", "main")
    head = promote_branch(repo, {"version.txt": "0.1.5\n"})
    assert verdict(repo, "single", head).release_files == ["version.txt"]


def test_a_promotion_behind_main_is_judged_on_the_merge_result(repo):
    """main's checks are not strict, so a branch can be behind main when it merges. Only
    the paths the merge itself changes count."""
    head = promote_branch(repo, {"a.md": "two\n"})
    git(repo, "checkout", "-q", "integration")
    write(repo, {"keep.md": "kept\n"}, "more integration work")
    git(repo, "checkout", "-q", "main")
    git(repo, "checkout", "-q", "integration", "--", "keep.md")
    git(repo, "commit", "-q", "-m", "keep.md promoted separately")
    assert verdict(repo, "single", head) == CLEAN


def test_a_full_promotion_fails_when_main_kept_a_change_integration_reverted(repo):
    """A single promotion publishes a.md, integration then reverts it, and a plain merge
    keeps main's copy because integration's side looks unchanged. The full check sees it."""
    head = promote_branch(repo, {"a.md": "two\n"})
    git(repo, "merge", "-q", "--no-ff", "--no-edit", head)
    git(repo, "checkout", "-q", "integration")
    write(repo, {"a.md": "one\n"}, "revert a")
    git(repo, "checkout", "-q", "main")
    assert verdict(repo, "full", "integration").differing == ["a.md"]


def test_a_full_promotion_that_conflicts_is_reported_as_a_conflict(repo):
    head = promote_branch(repo, {"a.md": "two\n"})
    git(repo, "merge", "-q", "--no-ff", "--no-edit", head)
    git(repo, "checkout", "-q", "integration")
    write(repo, {"a.md": "three\n"}, "edit a again")
    git(repo, "checkout", "-q", "main")
    assert verdict(repo, "full", "integration").conflicted


def test_a_full_promotion_built_with_ours_passes_where_the_plain_one_conflicts(repo):
    """promote_pr.py --full merges main into integration with -s ours. The result is
    integration's tree with main as an ancestor, so the merge into main is clean."""
    head = promote_branch(repo, {"a.md": "two\n"})
    git(repo, "merge", "-q", "--no-ff", "--no-edit", head)
    git(repo, "checkout", "-q", "integration")
    write(repo, {"a.md": "three\n"}, "edit a again")
    git(repo, "checkout", "-q", "-b", "promote/full-x")
    git(repo, "merge", "-q", "-s", "ours", "--no-edit", "main")
    git(repo, "checkout", "-q", "main")
    assert verdict(repo, "full", "promote/full-x") == CLEAN


def environment(monkeypatch, repo, head_ref, head_sha, integration="integration"):
    monkeypatch.chdir(repo)
    for name, value in {"BASE_REF": PUBLISHING_BRANCH, "HEAD_REF": head_ref, "HEAD_REPO": REPO,
                        "BASE_REPO": REPO, "HEAD_SHA": head_sha, "MAIN_REF": "main",
                        "INTEGRATION_REF": integration}.items():
        monkeypatch.setenv(name, value)


def test_main_passes_and_fails_end_to_end(repo, monkeypatch, capsys):
    good = promote_branch(repo, {"a.md": "two\n"}, "promote/pr-1")
    environment(monkeypatch, repo, good, git(repo, "rev-parse", good))
    assert main(["base_branch_guard.py"]) == 0
    bad = promote_branch(repo, {"café.md": "x\n"}, "promote/pr-2")
    environment(monkeypatch, repo, bad, git(repo, "rev-parse", bad))
    assert main(["base_branch_guard.py"]) == 1
    assert "caf" in capsys.readouterr().err


@pytest.mark.parametrize("head_sha,integration", [("", "integration"), (None, "origin/missing")])
def test_main_fails_closed_when_the_check_cannot_run(repo, monkeypatch, capsys, head_sha, integration):
    head = promote_branch(repo, {"a.md": "two\n"})
    sha = git(repo, "rev-parse", head) if head_sha is None else head_sha
    environment(monkeypatch, repo, head, sha, integration)
    assert main(["base_branch_guard.py"]) == 1
    assert "could not run" in capsys.readouterr().err


# ---- the workflow wiring ----------------------------------------------------------------


def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_runs_mains_guard_not_the_pull_requests():
    """A pull request must not be able to rewrite the check that judges it."""
    text = workflow()
    assert "pull_request_target:" in text
    assert "\n          ref: main\n" in text
    assert "persist-credentials: false" in text


def test_workflow_reruns_when_a_base_is_changed_to_main():
    assert "types: [opened, edited, synchronize, reopened]" in workflow()


def test_workflow_passes_live_tips_and_the_head_to_the_guard():
    text = workflow()
    for line in ("HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
                 "MAIN_REF: origin/main", "INTEGRATION_REF: origin/integration"):
        assert line in text


def test_workflow_never_lists_paths_in_quoted_form():
    """The guard computes paths itself with -z. A text listing is how the bypass got in."""
    assert "--name-status" not in workflow()
    assert "--name-only" not in workflow()


def test_workflow_keeps_the_required_check_name():
    """protect-main requires a check named base-branch-guard. Renaming the job leaves a
    required check that never reports, which blocks every pull request to main."""
    assert "\n  base-branch-guard:\n" in workflow()


def test_the_sync_workflow_is_gone():
    """It opened a pull request from main into integration, which the organization's
    Actions policy forbids, so it failed on every run. Nothing reaches main except a
    promotion now, so there is nothing to sync back."""
    assert not (WORKFLOW.parent / "sync-integration.yml").exists()


def test_the_guard_reruns_when_main_or_integration_moves():
    """The guard reads live tips, so a promotion's green check goes stale when either one
    moves. A revert on integration would otherwise publish behind that check."""
    rerun = (WORKFLOW.parent / "rerun-base-guard.yml").read_text(encoding="utf-8")
    assert 'branches: ["main", "integration"]' in rerun
    assert "actions: write" in rerun and "contents: write" not in rerun
    assert "pr-base-guard.yml/runs?event=pull_request_target" in rerun
    # Runs are matched by head commit and repository, passed to jq only as --arg data.
    assert '--arg sha "$sha"' in rerun and '--arg repo "$REPO"' in rerun
    # A run GitHub will not re-run fails the job instead of passing it quietly.
    assert "29 days ago" in rerun and "exit 1" in rerun and "|| echo" not in rerun
