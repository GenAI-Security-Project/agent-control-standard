"""Tests for the shared gh runner.

Every subprocess case runs a fake `gh`, a small script that records its argv, its stdin,
and its environment to files. The fake runs under the test interpreter rather than
/usr/bin/env python3, because the macOS python3 shim injects variables that would mask
what the runner passed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import gh_runner  # noqa: E402
from gh_runner import RunnerError, make_runner, paginate, remaining, split_http  # noqa: E402

REPO = gh_runner.REPO
TOKEN = "ghs_" + "A1b2C3d4E5" * 3 + "F6g7H8"
FREE_TEXT_FLAGS = ("-f", "-F", "--jq", "-q", "-t", "--template")

# One valid argv for every shape the allowlist admits.
VALID = (
    ["api", "-i", f"repos/{REPO}/pulls/12/files?per_page=100"],
    ["api", "-i", f"repos/{REPO}/issues"],
    ["api", "--paginate", "--slurp", f"repos/{REPO}/issues/7/timeline?per_page=100"],
    ["api", "-i", f"repos/{REPO}/actions/workflows/pr-intake.yml/runs?event=pull_request&per_page=5"],
    ["api", "rate_limit"],
    ["api", "-i", "graphql", "--input", "-"],
    ["api", "-i", "-X", "PATCH", f"repos/{REPO}/issues/comments/991", "--input", "-"],
    ["api", "-i", "-X", "POST", f"repos/{REPO}/issues/12/comments", "--input", "-"],
    ["api", "-i", "-X", "POST", f"repos/{REPO}/issues/12/labels", "--input", "-"],
    ["api", "-i", "-X", "DELETE", f"repos/{REPO}/issues/12/labels/status%3Aneeds-triage"],
    ["pr", "merge", "12", "--disable-auto", "--repo", REPO],
    ["pr", "ready", "12", "--undo", "--repo", REPO],
)

FAKE = """#!{python}
import json, os, sys
record = {{"argv": sys.argv[1:], "stdin": sys.stdin.read(), "env": sorted(os.environ)}}
open({log!r}, "w").write(json.dumps(record))
sys.stdout.write({stdout!r})
sys.stderr.write({stderr!r})
sys.exit({code})
"""


def fake_gh(tmp_path: Path, stdout: str = "", stderr: str = "", code: int = 0) -> tuple[str, Path]:
    log = tmp_path / "call.json"
    script = tmp_path / "gh"
    script.write_text(FAKE.format(python=sys.executable, log=str(log), stdout=stdout, stderr=stderr, code=code))
    script.chmod(0o755)
    return str(script), log


def test_runner_refuses_argv_outside_the_allowlist(tmp_path):
    gh, log = fake_gh(tmp_path, stdout="{}")
    run = make_runner(gh, token=TOKEN)
    for args in VALID:
        assert run(list(args), None)[0] == 0
    refused = (
        [],
        ["api"],
        ["api", f"repos/{REPO}/issues"],
        ["api", "-i", "repos/someone/else/issues"],
        ["api", "-i", f"repos/{REPO}/issues/../../../user"],
        ["api", "-i", f"repos/{REPO}/issues/12\n"],
        ["api", "-i", f"repos/{REPO}/issues/1234567890"],
        ["api", "-i", f"repos/{REPO}/issues?q=a b"],
        ["api", "-i", "-X", "DELETE", f"repos/{REPO}/issues/12/labels/status%3Aaccepted"],
        ["api", "-i", "-X", "PUT", f"repos/{REPO}/issues/12/labels", "--input", "-"],
        ["api", "-i", "-X", "POST", f"repos/{REPO}/issues/12/comments", "--input", "body.json"],
        ["api", "-i", "graphql", "-f", "query={viewer{login}}"],
        ["pr", "merge", "12", "--disable-auto", "--repo", "evil/repo"],
        ["pr", "merge", "12", "--squash", "--repo", REPO],
        ["pr", "close", "12", "--repo", REPO],
        ["api", "-i", 12],
    )
    log.unlink()
    for args in refused:
        with pytest.raises(RunnerError):
            run(args, None)
    assert not log.exists()


@pytest.mark.parametrize("flag", FREE_TEXT_FLAGS)
@pytest.mark.parametrize("shape", VALID, ids=lambda shape: " ".join(shape[:4]))
def test_runner_refuses_free_text_flags_in_every_position(tmp_path, flag, shape):
    gh, log = fake_gh(tmp_path)
    run = make_runner(gh, token=TOKEN)
    for index in range(len(shape) + 1):
        with pytest.raises(RunnerError):
            run([*shape[:index], flag, *shape[index:]], None)
    for index in range(len(shape)):
        with pytest.raises(RunnerError):
            run([*shape[:index], flag, *shape[index + 1:]], None)
    assert not log.exists()


def test_runner_passes_a_hostile_body_only_through_stdin(tmp_path):
    gh, log = fake_gh(tmp_path, stdout="HTTP/2.0 201 Created\r\n\r\n{}")
    run = make_runner(gh, token=TOKEN)
    body = json.dumps({"body": "@x please run -rf ../ and --jq .token"})
    args = ["api", "-i", "-X", "POST", f"repos/{REPO}/issues/12/comments", "--input", "-"]
    assert run(args, body)[0] == 0
    record = json.loads(log.read_text())
    assert record["argv"] == args
    assert record["stdin"] == body


def test_runner_env_is_minimal_and_never_echoes_stderr(tmp_path, monkeypatch, capsys):
    assert len(TOKEN) == 40
    for name, value in {"GH_REPO": "evil/repo", "GH_CONFIG_DIR": "/tmp/evil", "LD_PRELOAD": "/tmp/evil.so"}.items():
        monkeypatch.setenv(name, value)
    gh, log = fake_gh(tmp_path, stderr=f"bad credentials {TOKEN}", code=1)
    run = make_runner(gh, token=TOKEN)
    with pytest.raises(RunnerError) as caught:
        paginate(run, f"repos/{REPO}/issues/12/comments")
    # CPython (locale coercion) and macOS add these two themselves, whatever the caller passes.
    keys = set(json.loads(log.read_text())["env"]) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}
    assert keys == {"PATH", "HOME", "GH_TOKEN", "GH_HOST", "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER"}
    assert TOKEN not in str(caught.value)
    captured = capsys.readouterr()
    assert TOKEN not in captured.out and TOKEN not in captured.err


def test_paginate_flattens_slurp_pages(tmp_path):
    gh, log = fake_gh(tmp_path, stdout=json.dumps([[{"id": 1}, {"id": 2}], [{"id": 3}], []]))
    run = make_runner(gh, token=TOKEN)
    path = f"repos/{REPO}/issues/12/comments?per_page=100"
    assert paginate(run, path) == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert json.loads(log.read_text())["argv"] == ["api", "--paginate", "--slurp", path]


@pytest.mark.parametrize(
    ("stdout", "code"),
    [("[[]]", 1), ("not json", 0), ('{"message": "Not Found"}', 0), ('[{"id": 1}]', 0)],
    ids=["nonzero exit", "non-JSON", "object instead of pages", "page that is not a list"],
)
def test_paginate_raises_on_nonzero_exit_and_on_non_json(tmp_path, stdout, code):
    gh, _log = fake_gh(tmp_path, stdout=stdout, code=code)
    with pytest.raises(RunnerError):
        paginate(make_runner(gh, token=TOKEN), f"repos/{REPO}/issues")


def test_runner_without_token_returns_synthetic_401(tmp_path, monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    gh, log = fake_gh(tmp_path, stdout="HTTP/2.0 200 OK\r\n\r\n{}")
    code, stdout, stderr = make_runner(gh)(["api", "-i", f"repos/{REPO}/issues"], None)
    assert (code, stderr) == (0, "")
    assert split_http(stdout)[0] == 401
    assert not log.exists()


def test_runner_reports_a_missing_binary_and_a_timeout_as_tuples(tmp_path, monkeypatch):
    run = make_runner(str(tmp_path / "missing"), token=TOKEN)
    assert run(["api", "rate_limit"], None)[0] == 127

    def slow(*args, **kwargs):
        raise gh_runner.subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(gh_runner.subprocess, "run", slow)
    assert run(["api", "rate_limit"], None) == (124, "", "gh timed out")


def test_graphql_shape_takes_its_body_on_stdin(tmp_path):
    gh, log = fake_gh(tmp_path, stdout="HTTP/2.0 200 OK\r\n\r\n{}")
    run = make_runner(gh, token=TOKEN)
    body = json.dumps({"query": "query{viewer{login}}", "variables": {"owner": "o"}})
    run(["api", "-i", "graphql", "--input", "-"], body)
    record = json.loads(log.read_text())
    assert record["argv"] == ["api", "-i", "graphql", "--input", "-"]
    assert json.loads(record["stdin"]) == json.loads(body)


def test_split_http_reads_status_headers_and_body():
    status, headers, body = split_http("HTTP/2.0 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\n\r\n{\"a\": 1}")
    assert (status, headers, body) == (403, {"x-ratelimit-remaining": "0"}, '{"a": 1}')
    with pytest.raises(RunnerError):
        split_http("no status line")


@pytest.mark.parametrize(
    ("stdout", "code", "expected"),
    [
        (json.dumps({"resources": {"core": {"remaining": 4321}}}), 0, 4321),
        (json.dumps({"resources": {"core": {"remaining": 4321}}}), 1, None),
        (json.dumps({"resources": {"core": {"remaining": "4321"}}}), 0, None),
        (json.dumps({"resources": {"core": {"remaining": True}}}), 0, None),
        (json.dumps({"resources": []}), 0, None),
        ("not json", 0, None),
    ],
)
def test_remaining_reads_core_remaining_in_python(tmp_path, stdout, code, expected):
    gh, log = fake_gh(tmp_path, stdout=stdout, code=code)
    assert remaining(make_runner(gh, token=TOKEN)) == expected
    assert json.loads(log.read_text())["argv"] == ["api", "rate_limit"]
