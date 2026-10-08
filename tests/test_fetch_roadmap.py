"""Tests for the roadmap fetch.

Every case runs against a fake `gh`. The subprocess cases run the script exactly as the
workflow does, under `python3 -I -S`, so an accidental import from tools/ fails here
rather than on the first push to main.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fetch_roadmap  # noqa: E402
from closing_choice import declared_closes  # noqa: E402
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
OID = "a" * 40
CLOSER = {"__typename": "PullRequest", "number": 12, "merged": True, "repository": {"nameWithOwner": "o/n"},
          "mergeCommit": {"oid": OID, "message": "Add the adapter (#12)\n\nCloses #9. SECRET MESSAGE"}}
ISSUES = {"data": {"repository": {"milestone": {"issues": {
    "pageInfo": {"hasNextPage": False, "endCursor": None},
    "nodes": [{"number": 9, "state": "CLOSED", "stateReason": "COMPLETED", "author": {"login": "a"},
               "labels": {"totalCount": 1, "nodes": [{"name": "status:accepted"}]},
               "closes": {"nodes": [{"actor": {"login": "rocklambros"}, "closer": CLOSER}]},
               "references": {"totalCount": 1, "nodes": [{"source": {
                   "__typename": "PullRequest", "number": 12, "merged": True,
                   "repository": {"nameWithOwner": "o/n"}, "mergeCommit": {"oid": OID}}}]}}],
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


def test_fetch_ok_normalizes_and_drops_every_message():
    run, _ = fake_run({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)})
    result = fetch(run, "o/n", 240, sleep=lambda s: None, clock=lambda: 0.0, parse=declared_closes)
    assert result["status"] == "ok"
    issue = result["milestones"][0]["issues"][0]
    assert issue == {"number": 9, "state": "CLOSED", "stateReason": "COMPLETED", "author": "a",
                     "labels": ["status:accepted"], "closedBy": "rocklambros", "closerKind": "pull_request",
                     "closerInRepo": True, "declaresClose": True, "declaresContribution": False, "unparsed": False,
                     "_verify": {"closer": [12, OID], "references": [[12, OID]]}}
    assert "SECRET" not in json.dumps(result) and "adapter" not in json.dumps(result)


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


GIT = shutil.which("git") or "/usr/bin/git"


def git(cwd: Path, *args: str) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run([GIT, *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def make_history(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A repository shaped like this one: squash merges on integration, promoted to main by
    a merge commit, a side branch never promoted, and two reverts on main."""
    root = tmp_path / "history"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")

    def commit(message: str) -> str:
        git(root, "commit", "-q", "--allow-empty", "-m", message)
        return git(root, "rev-parse", "HEAD")

    oids = {"base": commit("Base")}
    git(root, "checkout", "-q", "-b", "integration")
    oids["squash"] = commit("Add the adapter (#12)\n\nCloses #9")
    git(root, "checkout", "-q", "-b", "feature")
    oids["side"] = commit("Never promoted (#30)")
    git(root, "checkout", "-q", "main")
    git(root, "merge", "-q", "--no-ff", "-m", "Merge pull request #20 from o/integration", "integration")
    oids["reverted"] = commit("Change one (#13)")
    commit(f'Revert "Change one (#13)"\n\nThis reverts commit {oids["reverted"]}.')
    oids["reverted_by_pull"] = commit("Change two (#14)")
    commit('Revert "Change two (#14)" (#15)\n\nReverts o/n#14')
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    return root, oids


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
    root, _oids = make_history(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), "--out", str(out), "--gh", str(stub), "--git", GIT,
         "--repo-root", str(root), "--repo", "o/n"],
        capture_output=True, text=True, timeout=60, env={**os.environ, "GH_TOKEN": "t"},
    )
    assert completed.returncode == 0, completed.stderr
    record = json.loads(out.read_text())
    assert record["status"] == "ok", record
    issue = record["milestones"][0]["issues"][0]
    # OID is not in the temporary history, so the close cannot be on main.
    assert issue["declaresClose"] is True and issue["closerLanding"] == "not_on_main"
    assert "_verify" not in issue and "SECRET" not in out.read_text()


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
            "closes": {"nodes": []}, "references": {"totalCount": 0, "nodes": []}}


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
    root, _oids = make_history(tmp_path)
    assert fetch_roadmap.main(["--out", str(out), "--git", GIT, "--repo-root", str(root)]) == 0
    assert json.loads(out.read_text())["status"] == "ok"
    assert not (tmp_path / "new" / "out.json.tmp").exists()



# --- Close facts against a real git history --------------------------------------------

def git_runner(root: Path):
    return fetch_roadmap._git_runner(GIT, str(root))


def test_landing_reads_ancestry_and_reverts(tmp_path):
    root, oids = make_history(tmp_path)
    run = git_runner(root)
    reverted = fetch_roadmap.revert_index(run, "o/n")
    assert fetch_roadmap.landing(run, oids["squash"], 12, reverted) == "on_main"
    assert fetch_roadmap.landing(run, oids["side"], 30, reverted) == "not_on_main"
    assert fetch_roadmap.landing(run, oids["reverted"], 13, reverted) == "reverted"
    assert fetch_roadmap.landing(run, oids["reverted_by_pull"], 14, reverted) == "reverted"


@pytest.mark.parametrize("oid", ["f" * 40, None, "", "A" * 40, "abc123", "a" * 41, "a" * 39 + "\n"])
def test_missing_or_malformed_commit_is_not_on_main(tmp_path, oid):
    root, _oids = make_history(tmp_path)
    run = git_runner(root)
    assert fetch_roadmap.landing(run, oid, None, (frozenset(), frozenset())) == "not_on_main"


def test_uppercase_spelling_of_a_real_commit_is_not_on_main(tmp_path):
    root, oids = make_history(tmp_path)
    run = git_runner(root)
    assert fetch_roadmap.landing(run, oids["squash"].upper(), None, (frozenset(), frozenset())) == "not_on_main"


def test_shallow_clone_fails_verification(tmp_path):
    root, _oids = make_history(tmp_path)
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", f"file://{root}", str(shallow))
    with pytest.raises(FetchFailure) as caught:
        fetch_roadmap.verify_clone(git_runner(shallow))
    assert caught.value.cls == "verification"


def test_missing_main_ref_fails_verification(tmp_path):
    root, _oids = make_history(tmp_path)
    git(root, "update-ref", "-d", "refs/remotes/origin/main")
    with pytest.raises(FetchFailure) as caught:
        fetch_roadmap.verify_clone(git_runner(root))
    assert caught.value.cls == "verification"


def test_not_a_repository_fails_verification(tmp_path):
    with pytest.raises(FetchFailure) as caught:
        fetch_roadmap.verify_clone(git_runner(tmp_path))
    assert caught.value.cls == "verification"


def closed(number=9, reason="COMPLETED", closer=None, references=()):
    return {"number": number, "state": "CLOSED", "stateReason": reason,
            "_verify": {"closer": closer, "references": [list(pair) for pair in references]}}


def test_attach_facts_sets_landings_and_drops_commit_ids(tmp_path):
    root, oids = make_history(tmp_path)
    result = {"status": "ok", "milestones": [{"issues": [
        closed(1, closer=[12, oids["squash"]], references=[(12, oids["squash"])]),
        # A lead's hand close with an unpromoted pull request behind it.
        closed(2, references=[(30, oids["side"])]),
        closed(3, closer=[13, oids["reverted"]]),
        closed(4, reason="NOT_PLANNED", closer=[30, oids["side"]]),
        {"number": 5, "state": "OPEN", "stateReason": None, "_verify": {"closer": None, "references": []}},
    ]}]}
    issues = fetch_roadmap.attach_facts(result, git_runner(root), "o/n")["milestones"][0]["issues"]
    facts = {i["number"]: (i["closerLanding"], i["referencesLanding"]) for i in issues}
    assert facts == {
        1: ("on_main", "on_main"),
        2: (None, "not_on_main"),
        3: ("reverted", "on_main"),
        4: (None, "on_main"),
        5: (None, "on_main"),
    }
    assert all("_verify" not in issue for issue in issues)


def issue_with(closer, references=None, number=9):
    node = dict(ISSUES["data"]["repository"]["milestone"]["issues"]["nodes"][0])
    node["number"] = number
    node["closes"] = {"nodes": [{"actor": {"login": "rocklambros"}, "closer": closer}]}
    node["references"] = references or {"totalCount": 0, "nodes": []}
    return fetch_roadmap._issue(node, "o/n", declared_closes)


def test_closer_kinds():
    commit = {"__typename": "Commit", "oid": OID, "message": "Part of #9", "repository": {"nameWithOwner": "O/N"}}
    facts = issue_with(commit)
    assert (facts["closerKind"], facts["closerInRepo"], facts["declaresClose"], facts["declaresContribution"]) == (
        "commit", True, False, True)
    elsewhere = dict(CLOSER, repository={"nameWithOwner": "other/repo"})
    facts = issue_with(elsewhere)
    assert facts["closerKind"] == "pull_request" and facts["closerInRepo"] is False
    assert facts["declaresClose"] is False and facts["_verify"]["closer"] is None
    assert issue_with(None)["closerKind"] == "none"
    assert issue_with({"__typename": "ProjectV2"})["closerKind"] == "unknown"
    unmerged = dict(CLOSER, merged=False)
    assert issue_with(unmerged)["_verify"]["closer"] == [12, None]


def test_closed_issue_with_no_close_event_is_unknown():
    node = dict(ISSUES["data"]["repository"]["milestone"]["issues"]["nodes"][0], closes={"nodes": []})
    assert fetch_roadmap._issue(node, "o/n", declared_closes)["closerKind"] == "unknown"


def test_unreadable_message_marks_the_issue_unparsed():
    def boom(message, number):
        raise ValueError("bad")

    node = ISSUES["data"]["repository"]["milestone"]["issues"]["nodes"][0]
    facts = fetch_roadmap._issue(node, "o/n", boom)
    assert facts["unparsed"] is True and facts["declaresClose"] is False
    assert fetch_roadmap._issue(node, "o/n", None)["unparsed"] is True


def test_references_keep_merged_pull_requests_here_only():
    nodes = [
        {"source": {"__typename": "PullRequest", "number": 12, "merged": True, "repository": {"nameWithOwner": "o/n"}, "mergeCommit": {"oid": OID}}},
        {"source": {"__typename": "PullRequest", "number": 13, "merged": False, "repository": {"nameWithOwner": "o/n"}, "mergeCommit": None}},
        {"source": {"__typename": "PullRequest", "number": 14, "merged": True, "repository": {"nameWithOwner": "x/y"}, "mergeCommit": {"oid": OID}}},
        {"source": {"__typename": "Issue"}},
        {},
    ]
    facts = issue_with(CLOSER, {"totalCount": len(nodes), "nodes": nodes})
    assert facts["_verify"]["references"] == [[12, OID]]


def test_too_many_cross_references_is_code_defect():
    with pytest.raises(FetchFailure) as caught:
        issue_with(CLOSER, {"totalCount": 101, "nodes": []})
    assert caught.value.cls == "code_defect"


def test_main_writes_a_verification_failure_for_a_shallow_checkout(tmp_path):
    fixture = tmp_path / "responses.json"
    fixture.write_text(json.dumps({"milestones": http(200, MILESTONES), "issues": http(200, ISSUES)}))
    stub = tmp_path / "gh"
    stub.write_text(STUB.format(path=str(fixture)))
    stub.chmod(0o755)
    root, _oids = make_history(tmp_path)
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", f"file://{root}", str(shallow))
    out = tmp_path / "out.json"
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), "--out", str(out), "--gh", str(stub), "--git", GIT,
         "--repo-root", str(shallow)],
        capture_output=True, text=True, timeout=60, env={**os.environ, "GH_TOKEN": "t"},
    )
    assert completed.returncode == 0
    record = json.loads(out.read_text())
    assert record["status"] == "failed" and record["class"] == "verification"


def test_import_failure_still_writes_a_record(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "closing_choice", None)
    out = tmp_path / "out.json"
    assert fetch_roadmap.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text())["class"] == "code_defect"


def test_reverting_a_promotion_reverts_every_commit_it_brought_in(tmp_path):
    """A promotion lands as a merge commit, so its revert names the merge, not the squash
    commits that closed issues. Each of those must still read as reverted."""
    for how in ("commit", "pull"):
        root = tmp_path / how
        root.mkdir()
        git(root, "init", "-q", "-b", "main")

        def commit(message: str) -> str:
            git(root, "commit", "-q", "--allow-empty", "-m", message)
            return git(root, "rev-parse", "HEAD")

        commit("Base")
        git(root, "checkout", "-q", "-b", "integration")
        first = commit("Add the adapter (#12)\n\nCloses #9")
        second = commit("Add the guardian (#13)\n\nCloses #10")
        git(root, "checkout", "-q", "main")
        git(root, "merge", "-q", "--no-ff", "-m", "Promote integration to main (#20)", "integration")
        merge = git(root, "rev-parse", "HEAD")
        if how == "commit":
            commit(f'Revert "Promote integration to main (#20)"\n\nThis reverts commit {merge}, reversing\nchanges made to {first}.')
        else:
            commit('Revert "Promote integration to main" (#21)\n\nReverts o/n#20')
        git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
        run = git_runner(root)
        reverted = fetch_roadmap.revert_index(run, "o/n")
        assert fetch_roadmap.landing(run, first, 12, reverted) == "reverted", how
        assert fetch_roadmap.landing(run, second, 13, reverted) == "reverted", how
