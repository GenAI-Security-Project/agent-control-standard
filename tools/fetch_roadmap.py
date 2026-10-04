#!/usr/bin/env python3
"""Fetch milestone and issue data for the roadmap build.

Version 1.0. Owner: ACS project lead. Spec: design/2026-10-04-roadmap-page-design.md.

This runs as the first tool step of the deploy build job, before any package is installed,
under `python3 -I -S`. It is standard library only and imports nothing from tools/, because
`-I` drops the script's own directory from the import path. It calls `gh` by absolute path
with an explicit minimal environment, so nothing an earlier step wrote into the environment
can redirect it.

It always exits 0 and always writes its output file, holding either the data or a failure
record with a class. The next step reads that file. No step outcome or job dependency carries
the result, so nothing downstream can be skipped silently.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

REPO = "GenAI-Security-Project/agent-control-standard"
GH = "/usr/bin/gh"
DEADLINE_SECONDS = 240
ATTEMPTS = 3
RETRY_SECONDS = 20
ISSUE_PAGE = 50
LABEL_PAGE = 50
PERMISSION_TYPES = frozenset({"FORBIDDEN", "INSUFFICIENT_SCOPES", "UNAUTHORIZED"})
TRANSIENT = frozenset({"transport", "server", "rate_limit", "mismatch"})

MILESTONES_QUERY = (
    "query($owner:String!,$name:String!,$cursor:String){repository(owner:$owner,name:$name)"
    "{milestones(first:50,after:$cursor,states:[OPEN,CLOSED]){pageInfo{hasNextPage endCursor}"
    "nodes{number title description state dueOn url issues{totalCount}}}}}"
)
ISSUES_QUERY = (
    "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name)"
    "{milestone(number:$number){issues(first:%d,after:$cursor){pageInfo{hasNextPage endCursor}"
    "nodes{number state stateReason author{login} labels(first:%d){totalCount nodes{name}}"
    "timelineItems(itemTypes:[CLOSED_EVENT],last:1){nodes{... on ClosedEvent{actor{login}}}}}}}}}"
) % (ISSUE_PAGE, LABEL_PAGE)


def node_bound() -> int:
    """GitHub's node count for the larger query: issues, their labels, their close event.

    One query over every milestone at page size 100 measured about 1.23 million nodes,
    above GitHub's 500,000 limit, which is why issues are fetched one milestone at a time.
    """
    return ISSUE_PAGE + ISSUE_PAGE * LABEL_PAGE + ISSUE_PAGE * 1


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


def _issue(node: dict) -> dict:
    labels = node.get("labels") or {}
    if (labels.get("totalCount") or 0) > LABEL_PAGE:
        raise FetchFailure("code_defect", f"issue {node.get('number')} has more than {LABEL_PAGE} labels")
    closers = (node.get("timelineItems") or {}).get("nodes") or []
    actor = (closers[-1] or {}).get("actor") if closers else None
    return {
        "number": node["number"],
        "state": node["state"],
        "stateReason": node.get("stateReason"),
        "author": (node.get("author") or {}).get("login"),
        "labels": [label["name"] for label in labels.get("nodes") or []],
        "closedBy": (actor or {}).get("login"),
    }


MAX_PAGES = 200


def _fetch_once(run, repo: str, check=lambda: None) -> list[dict]:
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
            issues.extend(_issue(node) for node in block["nodes"])
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


def fetch(run, repo: str, deadline: float, sleep, clock) -> dict:
    start = clock()

    def check() -> None:
        if clock() - start > deadline:
            raise FetchFailure("timeout", f"exceeded {deadline:.0f}s")

    for attempt in range(ATTEMPTS):
        try:
            check()
            return {"status": "ok", "milestones": _fetch_once(run, repo, check)}
        except FetchFailure as failure:
            if failure.cls == "timeout" or failure.cls not in TRANSIENT or attempt == ATTEMPTS - 1:
                return {"status": "failed", "class": failure.cls, "detail": failure.detail}
            sleep(RETRY_SECONDS)
    return {"status": "failed", "class": "timeout", "detail": "no attempts left"}


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
    # Tests only. The workflow guard test asserts the deploy workflow never passes it.
    parser.add_argument("--gh", default=GH)
    parser.add_argument("--deadline", type=float, default=DEADLINE_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = fetch(_runner(args.gh), args.repo, args.deadline, time.sleep, time.monotonic)
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
