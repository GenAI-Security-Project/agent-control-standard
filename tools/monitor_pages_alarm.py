#!/usr/bin/env python3
"""Open or update the issue that says a scheduled site monitor run failed.

Version 1.0. Owner: ACS project leads.

A failed scheduled run emails only whoever last edited the cron line, so this is the last
job of monitor-pages.yml. It follows the roadmap monitor's alarm: the first failure mentions
every project lead, and later failures add a comment without mentions. It closes nothing.
A lead closes the issue once the site is healthy.

Everything it writes is fixed text, job ids from the workflow, and the run's own URL.
Nothing fetched reaches the issue, and no value passes through a shell.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json  # noqa: E402
import os  # noqa: E402

import check_origin_cert  # noqa: E402
import monitor_roadmap  # noqa: E402
import roadmap_model as model  # noqa: E402

TITLE = "Site monitor failing"
# A job that hits its timeout-minutes reports cancelled, not failure, and a real outage is
# what drives the schema check past its limit.
FAILED_RESULTS = frozenset({"failure", "cancelled"})
# Bot-authored only, so an issue anyone opens with this title cannot absorb the alarm. The
# creator value must be spelled exactly: a wrong one returns an empty list with status 200,
# which would open a duplicate on every failed run.
OPEN_ISSUES = f"repos/{model.REPO}/issues?creator=github-actions%5Bbot%5D&state=open&per_page=100"


def failed_jobs(results: str) -> list[str]:
    """The job ids that failed, from the toJSON(needs) value the workflow passes."""
    return sorted(name for name, job in json.loads(results).items() if job.get("result") in FAILED_RESULTS)


def report(failed: list[str], run_url: str) -> str:
    lines = [f"Failed jobs: {', '.join(failed)}.", f"Run: {run_url}"]
    if "origin-cert" in failed:
        # The check also fails when the edge is down, and the proxy is not the fix for that.
        lines.append(f"If the `origin-cert` log reports the certificate: {check_origin_cert.REMEDY}")
    return "\n\n".join(lines)


def open_issue(gh) -> int | None:
    """The oldest open alarm issue. A failed read raises, so it can never open a duplicate."""
    pages = json.loads(monitor_roadmap._call(gh, ["api", "--paginate", "--slurp", OPEN_ISSUES], "listing open issues"))
    return min(
        (
            int(issue["number"]) for page in pages for issue in page
            if issue.get("title") == TITLE and "pull_request" not in issue
        ),
        default=None,
    )


def sound(gh, failed: list[str], run_url: str, leads: list[str]) -> str:
    base = f"repos/{model.REPO}/issues"
    text = report(failed, run_url)
    number = open_issue(gh)
    if number is not None:
        monitor_roadmap._call(gh, ["api", "-X", "POST", f"{base}/{number}/comments", "-f", f"body={text}"], "commenting on the issue")
        return f"commented on #{number}"
    mentions = " ".join(f"@{login}" for login in leads)
    body = f"{mentions} The site monitor failed on a scheduled run.\n\n{text}".lstrip()
    monitor_roadmap._call(gh, ["api", "-X", "POST", base, "-f", f"title={TITLE}", "-f", f"body={body}"], "opening the issue")
    return "opened the issue"


def main() -> int:
    try:
        failed = failed_jobs(os.environ["JOB_RESULTS"])
        try:
            leads = monitor_roadmap.project_lead_logins(Path(__file__).resolve().parents[1])
        except (model.RosterError, OSError):
            # An issue without mentions beats no issue.
            print("::warning::Could not read the project leads, so the issue mentions nobody.")
            leads = []
        print(f"site monitor alarm: {sound(monitor_roadmap._gh, failed, os.environ['RUN_URL'], leads)}")
    except monitor_roadmap.AlarmError as exc:
        print(f"::error::The site monitor alarm did not post: {exc}.")
        return 1
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"::error::The site monitor alarm did not post: {type(exc).__name__}.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
