"""Guards for the rule that only promotions reach the publishing branch.

Two kinds of promotion pass: a full one from `integration` in this repository, and a
single pull request promotion from a `promote/*` branch in this repository whose every
changed path matches `integration` byte for byte. The interesting cases are the ones a
contributor controls: a fork can name its branch anything, and a file can be named
anything, so neither a branch name nor a path may be trusted on its own.
"""

import subprocess
import sys
from pathlib import Path

import pytest

# Matches the import style the other tools tests use, in test_publish_schemas.py:12.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from base_branch_guard import (  # noqa: E402
    PUBLISHING_BRANCH,
    decide,
    git_runner,
    is_promotion,
    is_single_promotion,
    main,
    parse_name_status,
    paths_differing_from,
)

REPO = "GenAI-Security-Project/agent-control-standard"
FORK = "someone/agent-control-standard"
WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def same(_paths):
    return []


def test_promotion_from_integration_in_this_repository():
    assert is_promotion("integration", REPO, REPO)


def test_promotion_from_a_release_branch_in_this_repository():
    assert is_promotion("release/v0.2.0", REPO, REPO)


def test_a_fork_branch_named_like_a_promotion_is_not_one():
    """head.ref is a name the contributor chose. Only the repository check is trustworthy."""
    assert not is_promotion("integration", FORK, REPO)
    assert not is_promotion("release/v0.2.0", FORK, REPO)
    assert not is_single_promotion("promote/pr-1", FORK, REPO)


def test_full_promotion_passes_with_any_paths():
    status, message = decide(["specification/a.json"], PUBLISHING_BRANCH, "integration", REPO, REPO)
    assert status == 0
    assert "Promotion" in message


def test_any_other_base_passes_without_checking():
    status, message = decide(["specification/a.json"], "integration", "spec/x", FORK, REPO)
    assert status == 0
    assert "Nothing to check" in message


def test_a_documentation_pull_request_to_main_now_fails():
    """The documentation lane is gone. Docs land on integration like everything else."""
    status, message = decide(["docs/topics/faq.md"], PUBLISHING_BRANCH, "docs/faq", FORK, REPO)
    assert status == 1
    assert "integration" in message
    assert "promote_pr.py" in message


def test_an_in_repository_branch_that_is_not_a_promotion_fails():
    status, _ = decide(["CONTRIBUTORS.md"], PUBLISHING_BRANCH, "docs/contributors", REPO, REPO, same)
    assert status == 1


def test_an_empty_diff_from_a_feature_branch_still_fails():
    status, _ = decide([], PUBLISHING_BRANCH, "empty", FORK, REPO)
    assert status == 1


def test_a_fork_promote_branch_fails_without_consulting_content():
    def explode(_paths):
        raise AssertionError("content must not be consulted for a fork")
    status, _ = decide(["CONTRIBUTORS.md"], PUBLISHING_BRANCH, "promote/pr-1", FORK, REPO, explode)
    assert status == 1


def test_single_promotion_passes_when_every_path_matches():
    status, message = decide(["CONTRIBUTORS.md", "docs/a.md"], PUBLISHING_BRANCH, "promote/pr-7", REPO, REPO, same)
    assert status == 0
    assert "matches `integration`" in message


def test_single_promotion_fails_and_lists_only_the_differing_paths():
    status, message = decide(
        ["CONTRIBUTORS.md", "specification/a.json"], PUBLISHING_BRANCH, "promote/pr-7", REPO, REPO,
        lambda paths: [p for p in paths if p.startswith("specification/")],
    )
    listing = message.split("\n\n")[0]
    assert status == 1
    assert "specification/a.json" in listing
    assert "CONTRIBUTORS.md" not in listing


def test_single_promotion_without_a_content_check_fails_closed():
    status, _ = decide(["CONTRIBUTORS.md"], PUBLISHING_BRANCH, "promote/pr-7", REPO, REPO, None)
    assert status == 1


def test_name_status_marks_adds_renames_and_copies_as_added():
    lines = [
        "M\tdocs/topics/faq.md\n",
        "A\tdocs/topics/new.md\n",
        "R100\tdocs/topics/old.md\tdocs/topics/moved.md\n",
        "C075\tdesign/a.md\tdesign/b.md\n",
        "D\tdocs/topics/gone.md\n",
        "\n",
    ]
    changed, added = parse_name_status(lines)
    assert changed == [
        "docs/topics/faq.md",
        "docs/topics/new.md",
        "docs/topics/moved.md",
        "design/b.md",
        "docs/topics/gone.md",
    ]
    assert added == ["docs/topics/new.md", "docs/topics/moved.md", "design/b.md"]


def test_name_status_accepts_a_bare_path_as_changed():
    assert parse_name_status(["CONTRIBUTORS.md\n"]) == (["CONTRIBUTORS.md"], [])


# ---- the content check, against real repositories ----------------------------------


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A repository with an `integration` branch and a `promote` branch cut from it."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "integration")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    (root / "a.md").write_text("one\n")
    (root / "a.md.bak").write_text("backup\n")
    (root / "gone.md").write_text("old\n")
    (root / "docs").mkdir()
    (root / "docs" / "page.md").write_text("page\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "rm", "-q", "gone.md")
    git(root, "commit", "-q", "-m", "delete on integration")
    git(root, "checkout", "-q", "-b", "promote")
    return root


def differing_in(repo: Path, paths: list[str]) -> list[str]:
    def run(args):
        completed = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
        return completed.returncode, completed.stdout
    return paths_differing_from(paths, "promote", "integration", run)


def test_identical_files_and_a_shared_deletion_match(repo):
    assert differing_in(repo, ["a.md", "docs/page.md", "gone.md"]) == []


def test_an_edited_file_differs(repo):
    (repo / "a.md").write_text("two\n")
    git(repo, "commit", "-q", "-am", "edit")
    assert differing_in(repo, ["a.md"]) == ["a.md"]


def test_a_matching_prefix_does_not_hide_a_differing_file(repo):
    """a.md must not be compared through a.md.bak, or the other way round."""
    (repo / "a.md.bak").write_text("changed\n")
    git(repo, "commit", "-q", "-am", "edit backup")
    assert differing_in(repo, ["a.md"]) == []
    assert differing_in(repo, ["a.md.bak"]) == ["a.md.bak"]


def test_a_mode_change_differs(repo):
    git(repo, "update-index", "--chmod=+x", "a.md")
    git(repo, "commit", "-q", "-m", "make executable")
    assert differing_in(repo, ["a.md"]) == ["a.md"]


def test_a_deletion_integration_does_not_have_differs(repo):
    git(repo, "rm", "-q", "a.md")
    git(repo, "commit", "-q", "-m", "delete")
    assert differing_in(repo, ["a.md"]) == ["a.md"]


def test_a_file_only_the_promotion_adds_differs(repo):
    (repo / "new.md").write_text("new\n")
    git(repo, "add", "new.md")
    git(repo, "commit", "-q", "-m", "add")
    assert differing_in(repo, ["new.md"]) == ["new.md"]


def test_a_directory_path_is_not_a_wildcard_for_its_files(repo):
    """Naming `docs` must not compare, and so excuse, every file under it."""
    (repo / "docs" / "page.md").write_text("edited\n")
    git(repo, "commit", "-q", "-am", "edit page")
    assert differing_in(repo, ["docs/page.md"]) == ["docs/page.md"]


@pytest.mark.parametrize("name", ["*.md", ":(glob)**", "[a].md"])
def test_a_crafted_file_name_is_read_literally(repo, name):
    """A pathspec pattern as a file name must match only itself, never other files."""
    (repo / name).write_text("crafted\n")
    git(repo, "add", "--", name)
    git(repo, "commit", "-q", "-m", "crafted name")
    (repo / "a.md").write_text("two\n")
    git(repo, "commit", "-q", "-am", "edit a")
    assert differing_in(repo, [name]) == [name]


def test_main_runs_the_content_check_end_to_end(repo, monkeypatch, capsys):
    """The workflow's environment, run against a real repository."""
    listing = repo.parent / "changed.txt"
    listing.write_text("M\ta.md\nD\tgone.md\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    for name, value in {"BASE_REF": PUBLISHING_BRANCH, "HEAD_REF": "promote/pr-1",
                        "HEAD_REPO": REPO, "BASE_REPO": REPO, "HEAD_SHA": "promote",
                        "INTEGRATION_REF": "integration"}.items():
        monkeypatch.setenv(name, value)
    assert main(["base_branch_guard.py", str(listing)]) == 0
    (repo / "a.md").write_text("two\n")
    git(repo, "commit", "-q", "-am", "edit")
    assert main(["base_branch_guard.py", str(listing)]) == 1
    assert "a.md" in capsys.readouterr().err


def test_main_fails_closed_when_the_head_is_missing(repo, monkeypatch, capsys):
    listing = repo.parent / "changed.txt"
    listing.write_text("M\ta.md\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    for name, value in {"BASE_REF": PUBLISHING_BRANCH, "HEAD_REF": "promote/pr-1",
                        "HEAD_REPO": REPO, "BASE_REPO": REPO, "HEAD_SHA": "",
                        "INTEGRATION_REF": "integration"}.items():
        monkeypatch.setenv(name, value)
    assert main(["base_branch_guard.py", str(listing)]) == 1
    assert "could not run" in capsys.readouterr().err


def test_git_runner_reports_failure_rather_than_raising():
    code, _ = git_runner(["rev-parse", "--verify", "refs/heads/does-not-exist-anywhere"])
    assert code != 0


# ---- the workflow wiring ----------------------------------------------------------------


def test_workflow_lists_a_rename_as_a_delete_plus_an_add():
    """With rename detection on, moving a file lists only its new path, so the old one
    would never reach the content check. The workflow turns it off."""
    workflow = (WORKFLOWS / "pr-base-guard.yml").read_text(encoding="utf-8")
    diff_lines = [line for line in workflow.splitlines() if "git diff --name-status" in line]
    assert len(diff_lines) == 1
    assert "--no-renames" in diff_lines[0]


def test_workflow_passes_the_head_and_integration_to_the_guard():
    workflow = (WORKFLOWS / "pr-base-guard.yml").read_text(encoding="utf-8")
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in workflow
    assert "INTEGRATION_REF: origin/integration" in workflow


def test_workflow_keeps_the_required_check_name():
    """protect-main requires a check named base-branch-guard. Renaming the job leaves a
    required check that never reports, which blocks every pull request to main."""
    workflow = (WORKFLOWS / "pr-base-guard.yml").read_text(encoding="utf-8")
    assert "\n  base-branch-guard:\n" in workflow


def test_the_sync_workflow_is_gone():
    """It opened a pull request from main into integration, which the organization's
    Actions policy forbids, so it failed on every run. Nothing reaches main except a
    promotion now, so there is nothing to sync back."""
    assert not (WORKFLOWS / "sync-integration.yml").exists()
