"""Pins sync-release.yml, which carries integration's fixes into the open release branch.

The job holds a pull-requests: write token, so its triggers and permissions are fixed here.
The script is run against a scratch repository to show it opens a pull request only when
integration is not an ancestor of the release branch."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "sync-release.yml"


def load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_triggers_and_permissions_are_fixed():
    wf = load()
    # PyYAML reads the key `on` as the boolean True.
    assert wf[True] == {"push": {"branches": ["integration"]}, "workflow_dispatch": None}
    assert wf["permissions"] == {}
    job = wf["jobs"]["sync"]
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert job["env"] == {"RELEASE_BRANCH": "release/0.2"}
    checkout = job["steps"][0]
    assert checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert checkout["with"] == {"persist-credentials": False, "fetch-depth": 0}


def run_script(repo: Path, bindir: Path) -> subprocess.CompletedProcess:
    script = load()["jobs"]["sync"]["steps"][1]["run"]
    env = {**os.environ, "RELEASE_BRANCH": "release/0.2", "GH_TOKEN": "x",
           "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(["bash", "-e", "-c", script], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=60)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   cwd=repo, check=True, capture_output=True)


def scratch(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A repository whose remote-tracking refs stand in for origin, and a fake gh that
    records each call and reports no open pull request."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "integration")
    (repo / "f").write_text("a\n")
    git(repo, "add", "f")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "update-ref", "refs/remotes/origin/integration", "HEAD")
    git(repo, "update-ref", "refs/remotes/origin/release/0.2", "HEAD")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "gh.log"
    gh = bindir / "gh"
    gh.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n'
                  'case "$1 $2" in "pr list") echo 0 ;; esac\n')
    gh.chmod(0o755)
    return repo, bindir, log


def test_does_nothing_when_the_release_branch_carries_integration(tmp_path):
    repo, bindir, log = scratch(tmp_path)
    done = run_script(repo, bindir)
    assert done.returncode == 0, done.stderr
    assert "Nothing to sync" in done.stdout
    assert not log.exists()


def test_opens_a_pull_request_when_integration_moves_ahead(tmp_path):
    repo, bindir, log = scratch(tmp_path)
    (repo / "f").write_text("b\n")
    git(repo, "commit", "-q", "-am", "fix")
    git(repo, "update-ref", "refs/remotes/origin/integration", "HEAD")
    done = run_script(repo, bindir)
    assert done.returncode == 0, done.stderr
    calls = log.read_text().splitlines()
    assert calls[-1].startswith("pr create --base release/0.2 --head integration")


def test_exits_quietly_once_the_release_branch_is_gone(tmp_path):
    repo, bindir, log = scratch(tmp_path)
    git(repo, "update-ref", "-d", "refs/remotes/origin/release/0.2")
    done = run_script(repo, bindir)
    assert done.returncode == 0, done.stderr
    assert "does not exist" in done.stdout
    assert not log.exists()
