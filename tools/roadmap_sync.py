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
        if code != 0:
            print(f"COULD NOT CHECK #{number}")
            continue
        try:
            nodes = json.loads(out)["data"]["repository"]["issue"]["timelineItems"]["nodes"]
            prs = delivered_by(nodes)
        except (ValueError, KeyError, TypeError, AttributeError):
            print(f"COULD NOT CHECK #{number}")
            continue
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


import os  # noqa: E402
from datetime import date, datetime, timedelta, timezone  # noqa: E402

SECTION_TITLES = (
    ("ready_to_publish", "Ready to publish", "Work complete. Verify each milestone's work is on main by hand, then close it."),
    ("closed_with_open_work", "Closed with open work", "Closed milestones that still hold remaining issues."),
    ("closed_nothing_done", "Closed with open work and nothing done", "Closed milestones with no done issues but remaining ones. They show as withdrawn. Reopen any closed by mistake."),
    ("target_passed", "Target passed", "Open milestones past their committed date or quarter."),
    ("untriaged_in_milestone", "Untriaged in a milestone", "Open issues in a milestone with no acceptance decision."),
    ("declined_by_triage_label", "Milestoned against a triage decision", "The event job declined these because of a standing triage label."),
    ("awaiting_confirmation", "Awaiting maintainer confirmation", "Closed by someone outside the roster. A maintainer reopens and recloses to confirm."),
    ("in_focus_without_milestone", "In focus without a milestone", "Open in-focus issues not yet placed on the roadmap."),
    ("accepted_without_milestone", "Accepted without a milestone", "Open accepted issues not yet placed on the roadmap."),
    ("accepted_this_week", "Accepted by milestone this week", "Issues the bot accepted in the last eight days, with who set the milestone."),
    ("unknown_close_reasons", "Unknown close reasons", "Closed with a reason this version does not know."),
    ("off_quarter_dates", "Off-quarter dates", "Milestones whose due date is not the last day of a quarter."),
    ("missing_description_lines", "Missing description lines", "Milestones without a valid Workstream or Type line."),
    ("switches", "Switches", "Roadmap variables holding something other than true or false."),
)


def record_from_rest(issue: dict, facts: dict | None) -> model.IssueRecord:
    """A REST issue plus the close facts the fetch wrote for it.

    Missing facts mean the fetch did not see the issue, so every close fact takes the
    reading that verifies nothing and the issue can only count as unverified.
    """
    reason = issue.get("state_reason")
    facts = facts or {}
    return model.IssueRecord(
        number=int(issue["number"]),
        state=str(issue["state"]).upper(),
        state_reason=reason.upper() if reason else None,
        labels=frozenset(_labels(issue)),
        author=(issue.get("user") or {}).get("login"),
        closed_by=facts.get("closedBy"),
        **model.closer_facts(facts),
    )


def build_report(
    snapshot: dict,
    trusted: frozenset[str],
    leads: frozenset[str],
    workstream_names: set[str],
    today: date,
    switches: dict[str, str],
) -> dict:
    """Spec "Health reporting", sections. Numbers, reason codes, and maintainer logins only."""
    report: dict[str, list] = {key: [] for key, _title, _note in SECTION_TITLES}
    by_milestone: dict[int, list[model.IssueRecord]] = {}
    for raw in snapshot["milestoned"]:
        record = record_from_rest(raw, snapshot["facts"].get(int(raw["number"])))
        by_milestone.setdefault(int(raw["milestone"]["number"]), []).append(record)
        cls = model.classify(record, trusted, leads)
        if record.state == "OPEN" and record.labels & model.DECLINE_LABELS - {model.DEFERRED}:
            report["declined_by_triage_label"].append(record.number)
        elif cls == "untriaged":
            report["untriaged_in_milestone"].append(record.number)
        if cls == "unverified":
            report["awaiting_confirmation"].append(record.number)
        if model.unknown_reason(record):
            report["unknown_close_reasons"].append(record.number)
    for milestone in snapshot["milestones"]:
        number = int(milestone["number"])
        records = by_milestone.get(number, [])
        counts = {name: 0 for name in model.CLASSES}
        for record in records:
            counts[model.classify(record, trusted, leads)] += 1
        due = model.due_date(milestone.get("due_on"))
        description = model.parse_description(milestone.get("description"), workstream_names)
        closed = milestone.get("state") == "closed"
        state = model.milestone_state(closed, due is not None, counts)
        if state == "ready":
            report["ready_to_publish"].append(number)
        if state == "closed_with_open_work":
            report["closed_with_open_work"].append(number)
        if closed and counts["done"] == 0 and model.remaining(counts) > 0:
            report["closed_nothing_done"].append(number)
        if not closed and model.target_passed(due, description.committed, today) and state != "skipped":
            report["target_passed"].append(number)
        if due is not None and not model.is_quarter_end(due) and not closed:
            report["off_quarter_dates"].append(number)
        if not closed and {"workstream", "type"} & set(description.errors):
            report["missing_description_lines"].append(number)
    for raw in snapshot["unmilestoned_open"]:
        names = _labels(raw)
        if model.IN_FOCUS in names:
            report["in_focus_without_milestone"].append(int(raw["number"]))
        if model.ACCEPTED in names:
            report["accepted_without_milestone"].append(int(raw["number"]))
    report["accepted_this_week"] = [list(pair) for pair in snapshot["bot_accepted"]]
    # Every switch is listed, so the weekly call sees that rendering is off, not only that a
    # value is odd. The third element flags anything other than true or false.
    report["switches"] = [[name, value, value not in ("true", "false")] for name, value in sorted(switches.items())]
    for key in report:
        if key not in ("accepted_this_week", "switches"):
            report[key] = sorted(set(report[key]))
    return report


def status_line(status: str, stamp: str, run_id: str, failed: list[str]) -> str:
    tail = f" {' '.join(failed)}" if failed else ""
    return f"<!-- acs-sweep: {status} {stamp} run {run_id}{tail} -->"


def render_health(report: dict, status: str, stamp: str, run_id: str, failed: list[str]) -> str:
    repo_url = f"https://github.com/{model.REPO}"
    lines = [
        status_line(status, stamp, run_id, failed),
        model.HEALTH_MARKER,
        "",
        "This issue is rewritten every night by the roadmap sweep. It is the weekly call's "
        "triage agenda. Fix what it lists in GitHub, and the next sweep clears the line.",
        "",
        f"Written {stamp}, run [{run_id}]({repo_url}/actions/runs/{run_id}), rules {model.RULES_VERSION}.",
    ]
    for key, title, note in SECTION_TITLES:
        lines += ["", f"## {title}", "", note, ""]
        if key in failed:
            lines.append("Could not be read on this run.")
            continue
        items = report.get(key) or []
        if not items:
            lines.append("None.")
        elif key == "accepted_this_week":
            lines += [f"- #{number}, milestone set by `{login}`" for number, login in items]
        elif key == "switches":
            for name, value, odd in items:
                shown = f"`{value}`" if value else "unset"
                lines.append(f"- `{name}` is {shown}" + (" (only `true` turns it on)" if odd else ""))
        elif key in ("ready_to_publish", "closed_with_open_work", "target_passed", "off_quarter_dates", "missing_description_lines"):
            lines += [f"- [milestone {number}]({repo_url}/milestone/{number})" for number in items]
        else:
            lines += [f"- #{number}" for number in items]
    return "\n".join(lines) + "\n"


def choose_health_issue(candidates: list[dict]) -> dict | None:
    """Bot-authored and marked, or nothing. A marked issue by anyone else is ignored."""
    matches = [
        issue for issue in candidates
        if "pull_request" not in issue
        and (issue.get("user") or {}).get("login") == model.BOT_LOGIN
        and model.HEALTH_MARKER in (issue.get("body") or "")
    ]
    if len(matches) > 1:
        raise SyncError(f"more than one health issue: {sorted(i['number'] for i in matches)}. Close the extras.")
    return matches[0] if matches else None


def _snapshot(gh: GitHub, today: date, failed: list[str]) -> dict:
    base = f"repos/{model.REPO}"
    snapshot = {"milestones": [], "milestoned": [], "unmilestoned_open": [], "facts": {}, "bot_accepted": []}
    snapshot["milestones"] = gh.paginate(f"{base}/milestones?state=all&per_page=100")
    snapshot["milestoned"] = [i for i in gh.paginate(f"{base}/issues?milestone=*&state=all&per_page=100") if "pull_request" not in i]
    # Closers come from the same GraphQL ClosedEvent.actor the build uses, through the same
    # fetch code, so the health issue and roadmap.json never classify an issue differently.
    # It is also one query per milestone rather than one request per closed issue.
    fetched = fetch_roadmap.fetch(gh.call_list, model.REPO, 240, time.sleep, time.monotonic)
    if fetched["status"] != "ok":
        raise SyncError(f"closer fetch failed: {fetched['class']}")
    for milestone in fetched["milestones"]:
        for item in milestone["issues"]:
            snapshot["facts"][int(item["number"])] = item
    try:
        snapshot["unmilestoned_open"] = [
            i for i in gh.paginate(f"{base}/issues?milestone=none&state=open&per_page=100") if "pull_request" not in i
        ]
    except SyncError:
        failed += ["in_focus_without_milestone", "accepted_without_milestone"]
    cutoff = datetime.combine(today - timedelta(days=8), datetime.min.time(), timezone.utc)
    try:
        for raw in snapshot["milestoned"]:
            if raw["state"] != "open" or model.ACCEPTED not in _labels(raw):
                continue
            if datetime.fromisoformat(raw["updated_at"].replace("Z", "+00:00")) < cutoff:
                continue
            events = gh.paginate(f"{base}/issues/{raw['number']}/events?per_page=100")
            accepted_by_bot = any(
                e.get("event") == "labeled" and (e.get("label") or {}).get("name") == model.ACCEPTED
                and (e.get("actor") or {}).get("login") == model.BOT_LOGIN
                and datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")) >= cutoff
                for e in events
            )
            setters = [(e.get("actor") or {}).get("login") for e in events if e.get("event") == "milestoned"]
            if accepted_by_bot and setters and setters[-1]:
                snapshot["bot_accepted"].append([int(raw["number"]), setters[-1]])
    except SyncError:
        failed.append("accepted_this_week")
    return snapshot


# The creator filter must be spelled exactly. A wrong value returns an empty list with
# status 200, which would create a duplicate health issue every night.
HEALTH_LISTING = f"repos/{model.REPO}/issues?creator=github-actions%5Bbot%5D&state=all&per_page=100"


def _degraded() -> tuple[list[str], dict]:
    # The switches come from the environment, not from GitHub, so they still render.
    rows = [[name, value, value not in ("true", "false")] for name, value in sorted(_switches().items())]
    failed = [key for key, _title, _note in SECTION_TITLES if key != "switches"]
    return failed, {"switches": rows}


def _switches() -> dict[str, str]:
    names = ("ROADMAP_RENDER_ENABLED", "ROADMAP_REFRESH_ENABLED", "ROADMAP_SYNC_ENABLED")
    return {name: os.environ.get(name, "") for name in names}


def _sweep(apply: bool) -> int:
    gh = GitHub()
    repo_root = Path(__file__).resolve().parents[1]
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = os.environ.get("RUN_ID", "local")
    failed: list[str] = []
    try:
        # Inside the try, so a GOVERNANCE.md that does not parse degrades the health issue
        # rather than crashing the job before it writes anything.
        trusted = model.trusted_logins(repo_root)
        roster = model.parse_governance((repo_root / "GOVERNANCE.md").read_text(encoding="utf-8"))
        leads = model.project_lead_logins(roster)
        snapshot = _snapshot(gh, now.date(), failed)
        report = build_report(snapshot, trusted, leads, set(roster.workstreams), now.date(), _switches())
    except SyncError as exc:
        print(f"::warning::{exc}")
        failed, report = _degraded()
    except Exception as exc:  # noqa: BLE001 - the health issue write must happen even on a code defect
        # Only the type name is printed. The message can carry fetched text.
        print(f"::warning::sweep failed: {type(exc).__name__}")
        failed, report = _degraded()
    status = "degraded" if failed else "ok"
    body = render_health(report, status, stamp, run_id, failed)
    if not apply:
        print(body)
        return 1 if failed else 0
    target = _health_issue(gh)
    base = f"repos/{model.REPO}/issues"
    if target is None:
        created = json.loads(gh._check(
            gh.call("api", "-X", "POST", base, "-f", "title=Roadmap health", "-f", f"body={body}"), "create health issue"
        ))
        number = int(created["number"])
        message = f"Created the health issue #{number}. Set the repository variable ROADMAP_HEALTH_ISSUE to {number} and pin the issue."
        print(f"::notice::{message}")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(message + "\n")
    else:
        number = int(target["number"])
        gh._check(gh.call("api", "-X", "PATCH", f"{base}/{number}", "-f", f"body={body}", "-f", "state=open"), "update health issue")
    gh._check(gh.call("api", "-X", "PUT", f"{base}/{number}/lock", "-f", "lock_reason=resolved"), "lock health issue")
    return 1 if failed else 0


def _health_issue(gh: GitHub) -> dict | None:
    configured = os.environ.get("ROADMAP_HEALTH_ISSUE", "").strip()
    if configured:
        if not configured.isdigit():
            raise SyncError(f"ROADMAP_HEALTH_ISSUE is {configured!r}, not an issue number")
        issue = gh.get(f"repos/{model.REPO}/issues/{configured}")
        chosen = choose_health_issue([issue])
        if chosen is None:
            raise SyncError(f"issue #{configured} is not a bot-authored health issue")
        return chosen
    return choose_health_issue(gh.paginate(HEALTH_LISTING))


def cmd_sweep(args) -> int:
    return _sweep(args.apply)


def cmd_dryrun(args) -> int:
    code = _sweep(False)
    if args.issue:
        cmd_event(argparse.Namespace(issue=args.issue, apply=False))
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    event = sub.add_parser("event")
    event.add_argument("--issue", required=True)
    event.add_argument("--apply", action="store_true")
    migrate = sub.add_parser("migrate")
    migrate.add_argument("table")
    migrate.add_argument("--apply", action="store_true")
    sweep = sub.add_parser("sweep")
    sweep.add_argument("--apply", action="store_true")
    dryrun = sub.add_parser("dryrun")
    dryrun.add_argument("--issue", default="")
    return parser


COMMANDS = {"event": cmd_event, "migrate": cmd_migrate, "sweep": cmd_sweep, "dryrun": cmd_dryrun}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except SyncError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
