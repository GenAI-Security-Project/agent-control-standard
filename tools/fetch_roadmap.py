#!/usr/bin/env python3
"""Fetch milestone and issue data, plus the facts that verify each close, for the roadmap.

Version 1.1. Owner: ACS project leads. Spec: design/2026-10-04-roadmap-page-design.md, and
design/2026-10-04-roadmap-rollout-design.md, package D, "What the fetch reads".

This runs as the first tool step of the deploy build job, before any package is installed,
under `python3 -I -S`. It is standard library only. `-I` drops the script's own directory
from the import path, so `main` adds tools/ back inside its `try` and imports only
closing_choice, which is standard library only too. An import failure therefore still
writes the failure record. It calls `gh` and `git` by absolute path with explicit minimal
environments, so nothing an earlier step wrote into the environment can redirect them.

Every closing message is parsed for two booleans and then discarded. No message, title, or
body text reaches the output file.

It always exits 0 and always writes its output file, holding either the data or a failure
record with a class. The next step reads that file. No step outcome or job dependency carries
the result, so nothing downstream can be skipped silently.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

REPO = "GenAI-Security-Project/agent-control-standard"
GH = "/usr/bin/gh"
GIT = "/usr/bin/git"
GIT_TIMEOUT_SECONDS = 10
MAIN_REF = "refs/remotes/origin/main"
DEADLINE_SECONDS = 240
ATTEMPTS = 3
RETRY_SECONDS = 20
ISSUE_PAGE = 50
LABEL_PAGE = 50
REFERENCE_PAGE = 100
PERMISSION_TYPES = frozenset({"FORBIDDEN", "INSUFFICIENT_SCOPES", "UNAUTHORIZED"})
TRANSIENT = frozenset({"transport", "server", "rate_limit", "mismatch"})

MILESTONES_QUERY = (
    "query($owner:String!,$name:String!,$cursor:String){repository(owner:$owner,name:$name)"
    "{milestones(first:50,after:$cursor,states:[OPEN,CLOSED]){pageInfo{hasNextPage endCursor}"
    "nodes{number title description state dueOn url issues{totalCount}}}}}"
)
# The close event carries its closer: a pull request, a commit, or nothing for a hand close.
# The cross references list the pull requests that mention the issue. Messages are read
# only to be parsed by closing_choice.declared_closes, then dropped.
ISSUES_QUERY = (
    "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name)"
    "{milestone(number:$number){issues(first:%d,after:$cursor){pageInfo{hasNextPage endCursor}"
    "nodes{number state stateReason author{login} labels(first:%d){totalCount nodes{name}}"
    "closes:timelineItems(itemTypes:[CLOSED_EVENT],last:1){nodes{... on ClosedEvent{actor{login}"
    "closer{__typename ... on PullRequest{number merged repository{nameWithOwner} mergeCommit{oid message}}"
    " ... on Commit{oid message repository{nameWithOwner}}}}}}"
    "references:timelineItems(itemTypes:[CROSS_REFERENCED_EVENT],first:%d){totalCount"
    " nodes{... on CrossReferencedEvent{source{__typename"
    " ... on PullRequest{number merged repository{nameWithOwner} mergeCommit{oid}}}}}}}}}}}"
) % (ISSUE_PAGE, LABEL_PAGE, REFERENCE_PAGE)


def node_bound() -> int:
    """GitHub's node count for the larger query: issues, labels, close event, references.

    One query over every milestone at page size 100 measured about 1.23 million nodes,
    above GitHub's 500,000 limit, which is why issues are fetched one milestone at a time.
    """
    return ISSUE_PAGE + ISSUE_PAGE * LABEL_PAGE + ISSUE_PAGE * 1 + ISSUE_PAGE * REFERENCE_PAGE


class FetchFailure(Exception):
    def __init__(self, cls: str, detail: str) -> None:
        super().__init__(f"{cls}: {detail}")
        self.cls = cls
        self.detail = detail[:300]


def _split_http(stdout: str) -> tuple[int, dict[str, str], str]:
    normalized = stdout.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise FetchFailure("data", "response had no HTTP status line") from None
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return status, headers, body


def classify_response(returncode: int, stdout: str, stderr: str) -> dict:
    """Turn one `gh api -i graphql` result into data, or raise a classified failure."""
    if not stdout.strip():
        raise FetchFailure("transport", stderr.strip() or f"gh exited {returncode} with no output")
    status, headers, body = _split_http(stdout)
    lowered = body.lower()
    # 429 is a rate limit by definition. 403 needs a marker to tell it from a permission denial.
    if status == 429 or (
        status == 403
        and (headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers or "rate limit" in lowered)
    ):
        raise FetchFailure("rate_limit", f"HTTP {status}")
    if status in (401, 403):
        raise FetchFailure("permission", f"HTTP {status}")
    if status >= 500:
        raise FetchFailure("server", f"HTTP {status}")
    if status != 200:
        raise FetchFailure("data", f"HTTP {status}")
    try:
        payload = json.loads(body)
    except ValueError:
        raise FetchFailure("data", "response body was not JSON") from None
    types = {error.get("type") for error in payload.get("errors") or []}
    if "RATE_LIMITED" in types:
        raise FetchFailure("rate_limit", "GraphQL RATE_LIMITED")
    if "MAX_NODE_LIMIT_EXCEEDED" in types:
        raise FetchFailure("code_defect", "GraphQL MAX_NODE_LIMIT_EXCEEDED")
    if types & PERMISSION_TYPES:
        raise FetchFailure("permission", f"GraphQL errors {sorted(str(t) for t in types)}")
    if types:
        raise FetchFailure("data", f"GraphQL errors {sorted(str(t) for t in types)}")
    return payload["data"]


def _graphql(run, query: str, variables: dict) -> dict:
    args = ["api", "-i", "graphql", "-f", f"query={query}"]
    for key, value in variables.items():
        if value is None:
            continue
        flag = "-F" if isinstance(value, int) else "-f"
        args += [flag, f"{key}={value}"]
    return classify_response(*run(args))


def _same_repo(block: dict | None, repo: str) -> bool:
    name = (block or {}).get("nameWithOwner")
    return isinstance(name, str) and name.casefold() == repo.casefold()


def _issue(node: dict, repo: str, parse) -> dict:
    """One issue, normalized. Closing messages become two booleans here and go no further.

    `parse` is closing_choice.declared_closes. Without it, every message-bearing close is
    marked unparsed, which can only make an issue unverified, never done.
    """
    labels = node.get("labels") or {}
    if (labels.get("totalCount") or 0) > LABEL_PAGE:
        raise FetchFailure("code_defect", f"issue {node.get('number')} has more than {LABEL_PAGE} labels")
    references = node.get("references") or {}
    if (references.get("totalCount") or 0) > REFERENCE_PAGE:
        raise FetchFailure("code_defect", f"issue {node.get('number')} has more than {REFERENCE_PAGE} cross references")
    events = (node.get("closes") or {}).get("nodes") or []
    event = (events[-1] or {}) if events else None
    actor = ((event or {}).get("actor") or {}).get("login")
    closer = (event or {}).get("closer")
    number = int(node["number"])
    kind, in_repo, oid, pull, message = "none", False, None, None, None
    if event is None:
        # A closed issue with no close event cannot be traced to anything.
        kind = "unknown" if node["state"] == "CLOSED" else "none"
    elif closer is not None:
        typename = closer.get("__typename")
        if typename == "PullRequest":
            kind, in_repo, pull = "pull_request", _same_repo(closer.get("repository"), repo), closer.get("number")
            commit = closer.get("mergeCommit") or {}
            oid = commit.get("oid") if closer.get("merged") else None
            message = commit.get("message")
        elif typename == "Commit":
            kind, in_repo = "commit", _same_repo(closer.get("repository"), repo)
            oid, message = closer.get("oid"), closer.get("message")
        else:
            kind = "unknown"
    closes, contributes, unparsed = False, False, False
    if kind in ("pull_request", "commit") and in_repo:
        if parse is None:
            unparsed = True
        else:
            try:
                closes, contributes = parse(message if isinstance(message, str) else "", number)
            except Exception:  # noqa: BLE001 - one unreadable message marks one issue, never the fetch
                unparsed = True
    merged = []
    for item in references.get("nodes") or []:
        source = (item or {}).get("source") or {}
        if source.get("__typename") == "PullRequest" and source.get("merged") and _same_repo(source.get("repository"), repo):
            merged.append([source.get("number"), (source.get("mergeCommit") or {}).get("oid")])
    return {
        "number": number,
        "state": node["state"],
        "stateReason": node.get("stateReason"),
        "author": (node.get("author") or {}).get("login"),
        "labels": [label["name"] for label in labels.get("nodes") or []],
        "closedBy": actor,
        "closerKind": kind,
        "closerInRepo": in_repo,
        "declaresClose": closes,
        "declaresContribution": contributes,
        "unparsed": unparsed,
        # Commit ids and pull request numbers only. attach_facts turns them into landings.
        "_verify": {"closer": [pull, oid] if kind in ("pull_request", "commit") and in_repo else None, "references": merged},
    }


MAX_PAGES = 200


def _fetch_once(run, repo: str, check=lambda: None, parse=None) -> list[dict]:
    """`check` raises a timeout FetchFailure once the deadline passes. It runs before every
    call, because one attempt makes a call per milestone and each may take up to a minute."""
    owner, name = repo.split("/", 1)
    milestones: list[dict] = []
    cursor = None
    pages = 0
    while True:
        check()
        pages += 1
        if pages > MAX_PAGES:
            raise FetchFailure("code_defect", "milestone pagination did not terminate")
        data = _graphql(run, MILESTONES_QUERY, {"owner": owner, "name": name, "cursor": cursor})
        block = data["repository"]["milestones"]
        milestones.extend(block["nodes"])
        if not block["pageInfo"]["hasNextPage"]:
            break
        cursor = block["pageInfo"]["endCursor"]
    result = []
    for milestone in milestones:
        issues: list[dict] = []
        cursor = None
        pages = 0
        while True:
            check()
            pages += 1
            if pages > MAX_PAGES:
                raise FetchFailure("code_defect", "issue pagination did not terminate")
            data = _graphql(
                run, ISSUES_QUERY, {"owner": owner, "name": name, "number": milestone["number"], "cursor": cursor}
            )
            block = data["repository"]["milestone"]["issues"]
            issues.extend(_issue(node, repo, parse) for node in block["nodes"])
            if not block["pageInfo"]["hasNextPage"]:
                break
            cursor = block["pageInfo"]["endCursor"]
        unique = {issue["number"]: issue for issue in issues}
        expected = milestone["issues"]["totalCount"]
        if len(unique) != expected:
            raise FetchFailure(
                "mismatch", f"milestone {milestone['number']}: fetched {len(unique)} issues, expected {expected}"
            )
        result.append(
            {
                "number": milestone["number"],
                "title": milestone["title"],
                "description": milestone.get("description"),
                "state": milestone["state"],
                "dueOn": milestone.get("dueOn"),
                "url": milestone["url"],
                "issues": sorted(unique.values(), key=lambda issue: issue["number"]),
            }
        )
    return result


def fetch(run, repo: str, deadline: float, sleep, clock, parse=None) -> dict:
    start = clock()

    def check() -> None:
        if clock() - start > deadline:
            raise FetchFailure("timeout", f"exceeded {deadline:.0f}s")

    for attempt in range(ATTEMPTS):
        try:
            check()
            return {"status": "ok", "milestones": _fetch_once(run, repo, check, parse)}
        except FetchFailure as failure:
            if failure.cls == "timeout" or failure.cls not in TRANSIENT or attempt == ATTEMPTS - 1:
                return {"status": "failed", "class": failure.cls, "detail": failure.detail}
            sleep(RETRY_SECONDS)
    return {"status": "failed", "class": "timeout", "detail": "no attempts left"}


_OID = re.compile(r"^[0-9a-f]{40}$")


def _git_runner(git: str, repo_root: str):
    """Run git in the checkout with a minimal environment and a ten-second limit per call."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": tempfile.mkdtemp(prefix="roadmap-git-"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def run(args: list[str]) -> tuple[int, str]:
        try:
            done = subprocess.run(
                [git, *args], cwd=repo_root, env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired:
            raise FetchFailure("verification", f"git {args[0]} timed out") from None
        except OSError as exc:
            raise FetchFailure("verification", f"could not run git: {exc.strerror}") from None
        return done.returncode, done.stdout

    return run


def verify_clone(git) -> None:
    """A shallow clone or a missing main makes every ancestry answer wrong, so stop here."""
    code, out = git(["rev-parse", "--is-shallow-repository"])
    if code != 0 or out.strip() != "false":
        raise FetchFailure("verification", "the checkout is shallow or not a git repository")
    code, _out = git(["rev-parse", "--verify", "--quiet", f"{MAIN_REF}^{{commit}}"])
    if code != 0:
        raise FetchFailure("verification", f"{MAIN_REF} does not resolve")


def revert_index(git, repo: str) -> tuple[frozenset[str], frozenset[int]]:
    """Commit ids and pull request numbers that a commit on main says it reverts."""
    code, out = git(["log", MAIN_REF, "--format=%B"])
    if code != 0:
        raise FetchFailure("verification", "git log of main failed")
    named = set(re.findall(r"This reverts commit ([0-9a-f]{40})", out))
    pulls = frozenset(int(n) for n in re.findall(rf"Reverts {re.escape(repo)}#([0-9]{{1,9}})", out, re.IGNORECASE))
    # A promotion lands as a merge commit, so reverting it names the merge or the
    # promotion's pull request, never the squash commits that closed issues. Map each
    # reverted pull request to its first-parent commit on main, then widen every reverted
    # merge to the commits it brought in.
    code, subjects = git(["log", MAIN_REF, "--first-parent", "--format=%H %s"])
    if code != 0:
        raise FetchFailure("verification", "git log of main failed")
    for line in subjects.splitlines():
        oid, _, subject = line.partition(" ")
        match = re.search(r"\(#([0-9]{1,9})\)$", subject) or re.match(r"Merge pull request #([0-9]{1,9}) ", subject)
        if match and int(match.group(1)) in pulls:
            named.add(oid)
    commits = set(named)
    for oid in named:
        code, brought = git(["rev-list", f"{oid}^1..{oid}"])
        if code == 0:
            commits.update(brought.split())
    return frozenset(commits), pulls


def landing(git, oid: object, pull: object, reverted: tuple[frozenset[str], frozenset[int]]) -> str:
    """Where one commit stands: on_main, not_on_main, or reverted."""
    if not isinstance(oid, str) or not _OID.fullmatch(oid):
        return "not_on_main"
    code, _out = git(["cat-file", "-e", f"{oid}^{{commit}}"])
    if code != 0:
        return "not_on_main"
    code, _out = git(["merge-base", "--is-ancestor", oid, MAIN_REF])
    if code == 1:
        return "not_on_main"
    if code != 0:
        raise FetchFailure("verification", "git merge-base failed")
    if oid in reverted[0] or (isinstance(pull, int) and pull in reverted[1]):
        return "reverted"
    return "on_main"


def _worst(landings: list[str]) -> str:
    for value in ("reverted", "not_on_main"):
        if value in landings:
            return value
    return "on_main"


def attach_facts(result: dict, git, repo: str) -> dict:
    """Replace each issue's commit ids with where those commits stand against main.

    Only closes as completed are checked, since no other close can count as done. Each
    commit is checked once per run.
    """
    verify_clone(git)
    reverted = revert_index(git, repo)
    seen: dict[tuple, str] = {}

    def check(pair: list) -> str:
        key = (pair[0], pair[1])
        if key not in seen:
            seen[key] = landing(git, pair[1], pair[0], reverted)
        return seen[key]

    for milestone in result["milestones"]:
        for issue in milestone["issues"]:
            verify = issue.pop("_verify", None) or {"closer": None, "references": []}
            if issue["state"] != "CLOSED" or issue["stateReason"] != "COMPLETED":
                issue["closerLanding"], issue["referencesLanding"] = None, "on_main"
                continue
            issue["closerLanding"] = check(verify["closer"]) if verify["closer"] else None
            issue["referencesLanding"] = _worst([check(pair) for pair in verify["references"]])
    return result


def _runner(gh: str):
    token = os.environ.get("GH_TOKEN", "")
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": tempfile.mkdtemp(prefix="roadmap-gh-"),
        "GH_TOKEN": token,
        "GH_HOST": "github.com",
    }

    def run(args: list[str]) -> tuple[int, str, str]:
        if not token:
            # Without a token gh would prompt or fall back to ambient credentials. A synthetic 401
            # classifies as permission, which is never retried.
            return 0, "HTTP/2.0 401 Unauthorized\r\n\r\n{}", ""
        try:
            done = subprocess.run([gh, *args], env=env, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return 124, "", "gh timed out"
        except OSError as exc:
            return 127, "", f"could not run {gh}: {exc.strerror}"
        return done.returncode, done.stdout, done.stderr

    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--repo", default=REPO)
    # Tests only. The workflow guard test asserts the deploy workflow never passes these.
    parser.add_argument("--gh", default=GH)
    parser.add_argument("--git", default=GIT)
    parser.add_argument("--repo-root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument("--deadline", type=float, default=DEADLINE_SECONDS)
    args = parser.parse_args(argv)
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import closing_choice

        result = fetch(
            _runner(args.gh), args.repo, args.deadline, time.sleep, time.monotonic, closing_choice.declared_closes
        )
        if result["status"] == "ok":
            result = attach_facts(result, _git_runner(args.git, args.repo_root), args.repo)
    except FetchFailure as failure:
        result = {"status": "failed", "class": failure.cls, "detail": failure.detail}
    except Exception as exc:  # noqa: BLE001 - the contract is a record, never a traceback
        result = {"status": "failed", "class": "code_defect", "detail": type(exc).__name__}
    result["fetched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        parent = os.path.dirname(os.path.abspath(args.out))
        os.makedirs(parent, exist_ok=True)
        # Write beside the target then rename, so a reader never sees a half-written file.
        temporary = f"{args.out}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(result, handle)
        os.replace(temporary, args.out)
    except OSError:
        print("roadmap fetch: failed write_error")
        return 0
    print(f"roadmap fetch: {result['status']} {result.get('class', '')}".rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
