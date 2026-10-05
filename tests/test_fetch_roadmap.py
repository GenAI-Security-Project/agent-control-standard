"""Tests for the roadmap fetch.

Every case runs against a fake `gh`. The subprocess cases run the script exactly as the
workflow does, under `python3 -I -S`, so an accidental import from tools/ fails here
rather than on the first push to main.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fetch_roadmap  # noqa: E402
from fetch_roadmap import FetchFailure, classify_response, fetch, node_bound  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "fetch_roadmap.py"


def http(status: int, body: dict | str, headers: dict | None = None) -> str:
    lines = [f"HTTP/2.0 {status} X"] + [f"{k}: {v}" for k, v in (headers or {}).items()]
    text = body if isinstance(body, str) else json.dumps(body)
    return "\r\n".join(lines) + "\r\n\r\n" + text


MILESTONES = {"data": {"repository": {"milestones": {
    "pageInfo": {"hasNextPage": False, "endCursor": None},
    "nodes": [{"number": 3, "title": "M", "description": "d", "state": "OPEN",
               "dueOn": "2026-12-31T00:00:00Z", "url": "u", "issues": {"totalCount": 1}}],
}}}}
ISSUES = {"data": {"repository": {"milestone": {"issues": {
    "pageInfo": {"hasNextPage": False, "endCursor": None},
    "nodes": [{"number": 9, "state": "CLOSED", "stateReason": "COMPLETED", "author": {"login": "a"},
               "labels": {"totalCount": 1, "nodes": [{"name": "status:accepted"}]},
               "timelineItems": {"nodes": [{"actor": {"login": "rocklambros"}}]}}],
}}}}}


def fake_run(responses):
    calls = []

    def run(args):
        calls.append(args)
        query = next(a for a in args if a.startswith("query="))
        key = "issues" if "milestone(number" in query else "milestones"
        out = responses[key].pop(0) if isinstance(responses[key], list) else responses[key]
        return 0, out, ""

    return run, calls


def test_fetch_ok_normalizes():
    run, _ = fake_run({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["status"] == "ok"
    issue = result["milestones"][0]["issues"][0]
    assert issue == {"number": 9, "state": "CLOSED", "stateReason": "COMPLETED", "author": "a",
                     "labels": ["status:accepted"], "closedBy": "rocklambros"}


def test_mismatch_retries_then_fails():
    short = json.loads(json.dumps(MILESTONES))
    short["data"]["repository"]["milestones"]["nodes"][0]["issues"]["totalCount"] = 2
    run, calls = fake_run({"milestones": http(200, short), "issues": http(200, ISSUES)})
    sleeps = []
    result = fetch(run, "o/n", 240, sleep=sleeps.append, clock=lambda: 0.0)
    assert result["status"] == "failed" and result["class"] == "mismatch"
    assert sleeps == [20, 20]


@pytest.mark.parametrize(
    "status, headers, body, expected",
    [
        (403, {"x-ratelimit-remaining": "0"}, "{}", "rate_limit"),
        (429, {"retry-after": "60"}, "{}", "rate_limit"),
        (403, {}, '{"message": "API rate limit exceeded"}', "rate_limit"),
        (403, {}, '{"message": "Resource not accessible by integration"}', "permission"),
        (401, {}, "{}", "permission"),
        (502, {}, "{}", "server"),
        (200, {}, '{"errors": [{"type": "RATE_LIMITED"}]}', "rate_limit"),
        (200, {}, '{"errors": [{"type": "MAX_NODE_LIMIT_EXCEEDED"}]}', "code_defect"),
        (200, {}, '{"errors": [{"type": "NOT_FOUND"}]}', "data"),
        (200, {}, '{"errors": [{"type": "FORBIDDEN"}]}', "permission"),
        (200, {}, '{"errors": [{"type": "INSUFFICIENT_SCOPES"}]}', "permission"),
        (200, {}, '{"errors": [{"type": "UNAUTHORIZED"}]}', "permission"),
        (429, {}, "{}", "rate_limit"),
        (200, {}, "not json", "data"),
    ],
)
def test_classify_response(status, headers, body, expected):
    with pytest.raises(FetchFailure) as caught:
        classify_response(1 if status != 200 else 0, http(status, body, headers), "")
    assert caught.value.cls == expected


def test_empty_output_is_transport():
    with pytest.raises(FetchFailure) as caught:
        classify_response(1, "", "dial tcp: timeout")
    assert caught.value.cls == "transport"


def test_permission_is_not_retried():
    run, calls = fake_run({"milestones": http(403, {"message": "nope"}), "issues": ""})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["class"] == "permission" and len(calls) == 1


def test_deadline():
    ticks = iter([0.0, 300.0, 300.0, 300.0])
    run, _ = fake_run({"milestones": http(502, {}), "issues": ""})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: next(ticks))
    assert result["class"] == "timeout"


def test_deadline_is_checked_before_every_call():
    clock = iter([0.0, 0.0, 0.0, 500.0] + [500.0] * 20)
    run, calls = fake_run({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: next(clock))
    assert result["class"] == "timeout"
    assert len(calls) == 1


def test_node_bound_under_github_limit():
    assert node_bound() <= 100_000


STUB = """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
data = json.load(open({path!r}))
query = next(a for a in args if a.startswith("query="))
key = "issues" if "milestone(number" in query else "milestones"
sys.stdout.write(data[key])
"""


def test_runs_isolated_as_a_subprocess(tmp_path):
    fixture = tmp_path / "responses.json"
    fixture.write_text(json.dumps({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)}))
    stub = tmp_path / "gh"
    stub.write_text(STUB.format(path=str(fixture)))
    stub.chmod(0o755)
    out = tmp_path / "out.json"
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), "--out", str(out), "--gh", str(stub)],
        capture_output=True, text=True, timeout=60, env={**os.environ, "GH_TOKEN": "t"},
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(out.read_text())["status"] == "ok"


def test_unexpected_exception_still_writes_a_record(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bad")
    monkeypatch.setattr(fetch_roadmap, "fetch", boom)
    out = tmp_path / "out.json"
    assert fetch_roadmap.main(["--out", str(out)]) == 0
    record = json.loads(out.read_text())
    assert record["status"] == "failed" and record["class"] == "code_defect"


def test_empty_token_is_permission_and_not_retried(monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    calls = []
    inner = fetch_roadmap._runner("/nonexistent/gh")

    def run(args):
        calls.append(args)
        return inner(args)

    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["class"] == "permission" and len(calls) == 1


ENV_STUB = """#!/usr/bin/env python3
import json, os, sys
open({dump!r}, "w").write(json.dumps(sorted(os.environ)))
data = json.load(open({path!r}))
query = next(a for a in sys.argv[1:] if a.startswith("query="))
sys.stdout.write(data["issues" if "milestone(number" in query else "milestones"])
"""


def test_gh_environment_is_exactly_the_minimal_set(tmp_path):
    fixture = tmp_path / "responses.json"
    fixture.write_text(json.dumps({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)}))
    dump = tmp_path / "env.json"
    stub = tmp_path / "gh"
    # Use the real interpreter in the shebang. The macOS /usr/bin/python3 shim injects SDKROOT,
    # CPATH and similar variables, which would mask what the script passed.
    body = ENV_STUB.format(dump=str(dump), path=str(fixture)).replace("/usr/bin/env python3", sys.executable, 1)
    stub.write_text(body)
    stub.chmod(0o755)
    poisoned = {**os.environ, "GH_TOKEN": "t", "GH_REPO": "evil/repo", "GH_CONFIG_DIR": "/tmp/evil",
                "LD_PRELOAD": "/tmp/evil.so"}
    subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "--out", str(tmp_path / "o.json"),
                    "--gh", str(stub)], capture_output=True, text=True, timeout=60, env=poisoned)
    # CPython (locale coercion) and macOS add these two themselves, whatever the caller passes.
    keys = set(json.loads(dump.read_text())) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}
    assert keys == {"PATH", "HOME", "GH_TOKEN", "GH_HOST"}


def page(nodes, more, cursor):
    return {"data": {"repository": {"milestone": {"issues": {
        "pageInfo": {"hasNextPage": more, "endCursor": cursor}, "nodes": nodes}}}}}


def issue_node(number=9, label_count=1):
    return {"number": number, "state": "OPEN", "stateReason": None, "author": {"login": "a"},
            "labels": {"totalCount": label_count, "nodes": [{"name": "x"}]},
            "timelineItems": {"nodes": []}}


def test_issue_pages_carry_cursor_and_dedupe():
    pages = [http(200, page([issue_node(9)], True, "c1")), http(200, page([issue_node(9)], False, None))]
    run, calls = fake_run({"milestones": http(200, MILESTONES), "issues": pages})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["status"] == "ok" and len(result["milestones"][0]["issues"]) == 1
    assert "cursor=c1" in calls[2]
    assert "cursor=c1" not in calls[1]


def test_max_pages_overflow_is_code_defect(monkeypatch):
    monkeypatch.setattr(fetch_roadmap, "MAX_PAGES", 2)
    run, _ = fake_run({"milestones": http(200, MILESTONES),
                       "issues": http(200, page([issue_node(9)], True, "c"))})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["class"] == "code_defect"


def test_too_many_labels_is_code_defect():
    run, _ = fake_run({"milestones": http(200, MILESTONES),
                       "issues": http(200, page([issue_node(9, label_count=51)], False, None))})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0)
    assert result["class"] == "code_defect"


def test_unwritable_output_still_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fetch_roadmap, "fetch", lambda *a, **k: {"status": "ok", "milestones": []})
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert fetch_roadmap.main(["--out", str(blocker / "sub" / "out.json")]) == 0
    assert "failed write_error" in capsys.readouterr().out


def test_output_creates_parent_and_leaves_no_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch_roadmap, "fetch", lambda *a, **k: {"status": "ok", "milestones": []})
    out = tmp_path / "new" / "out.json"
    assert fetch_roadmap.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text())["status"] == "ok"
    assert not (tmp_path / "new" / "out.json.tmp").exists()
