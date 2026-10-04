"""Tests for the roadmap fetch.

Every case runs against a fake `gh`. The subprocess cases run the script exactly as the
workflow does, under `python3 -I -S`, so an accidental import from tools/ fails here
rather than on the first push to main.
"""
from __future__ import annotations

import json
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
        capture_output=True, text=True, timeout=60,
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
