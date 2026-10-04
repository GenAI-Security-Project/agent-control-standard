#!/usr/bin/env python3
"""Keep roadmap milestones true: accept milestoned issues, and report drift nightly.

Version 1.0. Owner: ACS project lead. Spec: design/2026-10-04-roadmap-page-design.md,
"Keeping milestones synced" and "Health reporting".

The workflow runs this as `python3 -I -S tools/roadmap_sync.py`, which drops the script's
own directory from the import path, so the directory is added back explicitly below. It is
standard library only and no sync job installs packages, so no third-party code runs beside
the write token.

The automation never closes, reopens, sets, or clears a milestone outside the one-time
migration command, never removes a label other than status:needs-triage, never touches a
pull request, and never quotes fetched issue text into anything it writes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
from dataclasses import dataclass  # noqa: E402

import fetch_roadmap  # noqa: E402
import roadmap_model as model  # noqa: E402


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class Action:
    kind: str
    issue: int
    labels: tuple[str, ...] = ()
    milestone: int | None = None


def _labels(issue: dict) -> set[str]:
    return {label["name"] for label in issue.get("labels") or ()}


def plan_event(issue: dict) -> list[Action]:
    """Spec "The event job". Acts only on an open issue whose milestone is still set and open."""
    if "pull_request" in issue or issue.get("state") != "open":
        return []
    milestone = issue.get("milestone")
    if not milestone or milestone.get("state") != "open":
        return []
    # Decision 3: with the switch off the event job accepts nothing.
    if not model.MILESTONE_ACCEPTS:
        return []
    names = _labels(issue)
    if names & model.DECLINE_LABELS:
        return []
    number = int(issue["number"])
    actions: list[Action] = []
    if model.ACCEPTED not in names:
        add = [model.ACCEPTED]
        if model.ADD_IN_FOCUS_ON_ACCEPT and not any(name.startswith(model.SCOPE_PREFIX) for name in names):
            add.append(model.IN_FOCUS)
        actions.append(Action("add_labels", number, tuple(add)))
    if model.NEEDS_TRIAGE in names:
        actions.append(Action("remove_label", number, (model.NEEDS_TRIAGE,)))
    return actions


class GitHub:
    def __init__(self, repo: str = model.REPO) -> None:
        self.repo = repo

    def call(self, *args: str) -> tuple[int, str, str]:
        done = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
        return done.returncode, done.stdout, done.stderr

    def call_list(self, args: list[str]) -> tuple[int, str, str]:
        """The runner signature fetch_roadmap.fetch expects."""
        return self.call(*args)

    def _check(self, result: tuple[int, str, str], what: str) -> str:
        code, out, err = result
        if code != 0:
            raise SyncError(f"{what} failed: {err.strip()[:300]}")
        return out

    def get(self, path: str) -> object:
        return json.loads(self._check(self.call("api", path), path))

    def paginate(self, path: str) -> list:
        pages = json.loads(self._check(self.call("api", "--paginate", "--slurp", path), path))
        return [item for page in pages for item in page]


def execute(gh, actions: list[Action], pace: float = 0.0, sleep=time.sleep) -> None:
    for action in actions:
        base = f"repos/{model.REPO}/issues/{action.issue}"
        if action.kind == "add_labels":
            args = ["api", "-X", "POST", f"{base}/labels"]
            for label in action.labels:
                args += ["-f", f"labels[]={label}"]
        elif action.kind == "remove_label":
            quoted = urllib.parse.quote(action.labels[0], safe="")
            args = ["api", "-X", "DELETE", f"{base}/labels/{quoted}"]
        elif action.kind == "set_milestone":
            args = ["api", "-X", "PATCH", base, "-F", f"milestone={action.milestone}"]
        else:
            raise SyncError(f"unknown action {action.kind}")
        code, _out, err = gh.call(*args)
        # A label already gone is the state this removal wanted.
        if code != 0 and not (action.kind == "remove_label" and "404" in err):
            if "rate limit" in err.lower():
                # The same advice apply_governance.py gives. Every action is idempotent.
                raise SyncError(
                    "GitHub rate limited this run. A burst of writes trips a secondary limit even "
                    "when the hourly quota is full. Wait a few minutes and run again. A partly "
                    "applied run resumes safely."
                )
            raise SyncError(f"{action.kind} on #{action.issue} failed: {err.strip()[:300]}")
        if pace:
            sleep(pace)


def plan_migration(table: dict, milestones: list[dict], issues: dict[int, dict]) -> tuple[list[Action], list[str]]:
    """Spec "Milestone migration" step 4, as a plan. Empty once everything has landed."""
    by_title = {m["title"]: m for m in milestones if m.get("state") == "open"}
    actions: list[Action] = []
    refusals: list[str] = []
    seen: set = set()
    for title, numbers in table["assignments"].items():
        milestone = by_title.get(title)
        if milestone is None:
            refusals.append(f"milestone {title!r} does not exist or is closed. Create it first.")
            continue
        for number in numbers:
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                refusals.append(f"{number!r} is not an issue number")
                continue
            if number in seen:
                refusals.append(f"#{number} appears under more than one milestone")
                continue
            seen.add(number)
            issue = issues.get(number)
            if issue is None:
                refusals.append(f"#{number} could not be read")
                continue
            if "pull_request" in issue:
                refusals.append(f"#{number} is a pull request. The roadmap counts issues only.")
                continue
            if issue.get("state") != "open":
                refusals.append(f"#{number} is closed. Migration places open work only.")
                continue
            current = (issue.get("milestone") or {}).get("number")
            if current != milestone["number"]:
                actions.append(Action("set_milestone", number, milestone=milestone["number"]))
            landed = dict(issue, milestone={"number": milestone["number"], "state": "open"})
            actions.extend(plan_event(landed))
    return actions, refusals


CROSS_REFERENCES = (
    "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name)"
    "{issue(number:$number){timelineItems(itemTypes:[CROSS_REFERENCED_EVENT],first:50)"
    "{nodes{... on CrossReferencedEvent{source{... on PullRequest{number merged}}}}}}}}"
)


def delivered_by(nodes: list[dict]) -> list[int]:
    """Merged pull requests that reference an issue, so it may already be delivered."""
    found = {
        int((node.get("source") or {})["number"])
        for node in nodes
        if (node.get("source") or {}).get("merged") and "number" in (node.get("source") or {})
    }
    return sorted(found)


def missing_acceptance(milestoned: list[dict]) -> list[int]:
    """Open milestoned issues the event job would have accepted but has not, for example
    issues milestoned while the sync switch was off during rollout."""
    return sorted(
        int(issue["number"]) for issue in milestoned
        if "pull_request" not in issue and issue.get("state") == "open"
        and model.ACCEPTED not in _labels(issue) and not _labels(issue) & model.DECLINE_LABELS
    )


def _print_actions(actions: list[Action]) -> None:
    for action in actions:
        detail = f"milestone {action.milestone}" if action.kind == "set_milestone" else ", ".join(action.labels)
        print(f"  #{action.issue}: {action.kind} {detail}")
    if not actions:
        print("  nothing to do")


def cmd_event(args) -> int:
    gh = GitHub()
    issue = gh.get(f"repos/{model.REPO}/issues/{int(args.issue)}")
    actions = plan_event(issue)
    _print_actions(actions)
    if args.apply:
        execute(gh, actions)
    return 0


def cmd_migrate(args) -> int:
    gh = GitHub()
    table = json.loads(Path(args.table).read_text(encoding="utf-8"))
    milestones = gh.paginate(f"repos/{model.REPO}/milestones?state=all&per_page=100")
    numbers = sorted({n for ns in table["assignments"].values() for n in ns if isinstance(n, int) and not isinstance(n, bool) and n > 0})
    issues = {}
    for number in numbers:
        try:
            issues[number] = gh.get(f"repos/{model.REPO}/issues/{number}")
        except SyncError:
            pass
    for number in numbers:
        issue = issues.get(number)
        if issue:
            labels = sorted(n for n in _labels(issue) if n.startswith(("scope:", "status:")))
            kind = "pull request" if "pull_request" in issue else "issue"
            author = (issue.get("user") or {}).get("login")
            # The URL, not the title. A title is author-editable text, and whoever reads this
            # output may be an agent about to run --apply.
            print(f"#{number} {kind} by {author} {issue.get('state')} {labels} {issue.get('html_url')}")
            declined = sorted(_labels(issue) & model.DECLINE_LABELS)
            if declined:
                print(f"DECLINED #{number} {', '.join(declined)}")
    owner, name = model.REPO.split("/", 1)
    for number in numbers:
        issue = issues.get(number)
        if not issue or issue.get("state") != "open" or "pull_request" in issue:
            continue
        code, out, _err = gh.call(
            "api", "graphql", "-f", f"query={CROSS_REFERENCES}",
            "-f", f"owner={owner}", "-f", f"name={name}", "-F", f"number={number}",
        )
        if code == 0:
            nodes = json.loads(out)["data"]["repository"]["issue"]["timelineItems"]["nodes"]
            prs = delivered_by(nodes)
            if prs:
                print(f"POSSIBLY DELIVERED #{number} by merged pull request {', '.join(f'#{p}' for p in prs)}")
    milestoned = gh.paginate(f"repos/{model.REPO}/issues?milestone=*&state=open&per_page=100")
    for number in missing_acceptance(milestoned):
        print(f"MILESTONED WITHOUT ACCEPTANCE #{number}")
    actions, refusals = plan_migration(table, milestones, issues)
    for refusal in refusals:
        print(f"REFUSED {refusal}")
    print("Plan:")
    _print_actions(actions)
    if args.apply:
        if refusals:
            print("Refusing to apply while any entry is refused. Fix the table first.")
            return 1
        # One write a second keeps a migration of about fifty issues under the secondary limit.
        execute(gh, actions, pace=1.0)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    event = sub.add_parser("event")
    event.add_argument("--issue", required=True)
    event.add_argument("--apply", action="store_true")
    migrate = sub.add_parser("migrate")
    migrate.add_argument("table")
    migrate.add_argument("--apply", action="store_true")
    return parser


COMMANDS = {"event": cmd_event, "migrate": cmd_migrate}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except SyncError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
