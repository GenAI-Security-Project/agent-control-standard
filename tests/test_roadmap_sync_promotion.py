"""Tests for the health issue's promotion and bypass sections.

Both read git history, so each case builds a small repository shaped like this one: squash
merges on integration, promotion by merge commit on main, and a sync from main that lands
on integration as a squash.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fetch_roadmap  # noqa: E402
from roadmap_sync import (  # noqa: E402
    PROMOTION_BODY,
    PROMOTION_TITLE,
    SyncError,
    promotion_pending,
    render_health,
)

GIT = shutil.which("git") or "/usr/bin/git"
OPEN_PROMOTION = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "open-promotion.yml"


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str, when: str = "2026-10-01T12:00:00Z") -> str:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
        return subprocess.run([GIT, *args], cwd=self.root, env=env, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, name: str, text: str, message: str, when: str = "2026-10-01T12:00:00Z") -> str:
        (self.root / name).write_text(text, encoding="utf-8")
        self.git("add", name)
        self.git("commit", "-q", "-m", message, when=when)
        return self.git("rev-parse", "HEAD")

    def publish(self) -> None:
        for branch in ("main", "integration"):
            self.git("update-ref", f"refs/remotes/origin/{branch}", branch)

    def runner(self):
        return fetch_roadmap._git_runner(GIT, str(self.root))


@pytest.fixture
def repo(tmp_path) -> Repo:
    made = Repo(tmp_path / "repo")
    made.commit("README.md", "base\n", "Base", when="2026-09-01T00:00:00Z")
    made.git("branch", "integration")
    return made


def test_nothing_ahead_is_not_pending(repo):
    repo.publish()
    assert promotion_pending(repo.runner()) is None


def test_integration_work_is_pending_from_its_oldest_commit(repo):
    repo.git("checkout", "-q", "integration")
    repo.commit("spec.md", "one\n", "Add one (#12)", when="2026-09-28T09:00:00Z")
    repo.commit("spec.md", "two\n", "Add two (#13)", when="2026-10-02T09:00:00Z")
    repo.publish()
    assert promotion_pending(repo.runner()) == ("2026-09-28", 2)


def test_squashed_sync_from_main_is_not_pending(repo):
    repo.commit("docs.md", "fixed\n", "Fix a typo (#40)")
    repo.git("checkout", "-q", "integration")
    repo.commit("docs.md", "fixed\n", "Sync integration from main (#41)")
    repo.publish()
    assert promotion_pending(repo.runner()) is None


def test_conflicting_integration_work_is_pending(repo):
    repo.commit("spec.md", "main\n", "Main change (#50)")
    repo.git("checkout", "-q", "integration")
    repo.commit("spec.md", "integration\n", "Integration change (#51)", when="2026-09-30T00:00:00Z")
    repo.publish()
    assert promotion_pending(repo.runner()) == ("2026-09-30", 1)


def test_unreadable_history_raises_sync_error(tmp_path):
    with pytest.raises(SyncError):
        promotion_pending(fetch_roadmap._git_runner(GIT, str(tmp_path)))


def health(report: dict) -> str:
    return render_health(report, "ok", "2026-10-04T04:10:00Z", "1", [])


def test_promotion_line_names_an_open_pull_request():
    body = health({"promotion": ["2026-09-28", 2, 210]})
    assert "Promotion pending since 2026-09-28." in body
    assert "Promotion pull request #210 is open." in body and "gh pr create" not in body


def test_promotion_command_uses_the_open_promotion_title_and_body():
    body = health({"promotion": ["2026-09-28", 2, None]})
    expected = (
        f"gh pr create --repo GenAI-Security-Project/agent-control-standard --base main --head integration "
        f"--title '{PROMOTION_TITLE}' --body '{PROMOTION_BODY.format(ahead=2)}'"
    )
    assert expected in body
    run = yaml.safe_load(OPEN_PROMOTION.read_text(encoding="utf-8"))["jobs"]["promote"]["steps"][1]["run"]
    assert f'--title "{PROMOTION_TITLE}"' in run
    workflow_body = re.search(r'--body "(.*)"', run).group(1)
    assert workflow_body.replace("\\$", "$").replace("${AHEAD}", "{ahead}") == PROMOTION_BODY


def test_open_promotion_runs_on_dispatch_only():
    # PyYAML reads the key `on` as the boolean True.
    assert yaml.safe_load(OPEN_PROMOTION.read_text(encoding="utf-8"))[True] == {"workflow_dispatch": None}
