#!/usr/bin/env python3
"""Fail loudly when the published roadmap or the health issue goes stale.

Version 1.0. Owner: ACS project lead. Spec: design/2026-10-04-roadmap-page-design.md,
"The roadmap monitor".

Separate from monitor-pages.yml, so the schema contract's alarm never shares a red or green
result with roadmap noise. Each check runs only while the switch it watches is on. It reads
the sweep's own status line, never the issue's updated_at, which a comment also moves.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import urllib.request  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import roadmap_model as model  # noqa: E402

PAGE_MAX_AGE = timedelta(hours=36)
HEALTH_MAX_AGE = timedelta(hours=50)
CLOCK_SKEW = timedelta(minutes=10)
STATUS = re.compile(r"<!-- acs-sweep: (ok|degraded) (\S+) run (\S+)")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_page(doc: dict | None, now: datetime) -> list[str]:
    if doc is None:
        return ["roadmap.json could not be read"]
    if doc.get("status") != "ok":
        return [f"roadmap.json status is {doc.get('status')!r}"]
    try:
        age = now - _time(doc["generated"])
    except (KeyError, ValueError):
        return ["roadmap.json has no readable generated time"]
    return [f"roadmap.json is {age} old"] if age > PAGE_MAX_AGE else []


def check_health(configured: str, issue: dict | None, now: datetime) -> list[str]:
    if not configured.strip().isdigit():
        return [f"ROADMAP_HEALTH_ISSUE is {configured!r}, not an issue number"]
    if issue is None:
        return [f"health issue #{configured} could not be read"]
    if (issue.get("user") or {}).get("login") != model.BOT_LOGIN:
        return [f"health issue #{configured} is not authored by {model.BOT_LOGIN}"]
    body = issue.get("body") or ""
    if model.HEALTH_MARKER not in body:
        return [f"health issue #{configured} lacks the marker"]
    match = STATUS.search(body)
    if not match:
        return [f"health issue #{configured} has no status line"]
    problems = []
    if match.group(1) == "degraded":
        problems.append("the last sweep was degraded")
    try:
        written = _time(match.group(2))
    except ValueError:
        return problems + ["the status line time does not parse"]
    if written > now + CLOCK_SKEW:
        problems.append("the status line time is in the future")
    elif now - written > HEALTH_MAX_AGE:
        problems.append(f"the last sweep wrote {now - written} ago")
    return problems


def _read_json(url: str) -> dict | None:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "acs-roadmap"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - unreadable is reported as a problem by check_page
        return None


def _read_issue(number: str) -> dict | None:
    done = subprocess.run(
        ["gh", "api", f"repos/{model.REPO}/issues/{number}"], capture_output=True, text=True, timeout=60
    )
    if done.returncode != 0:
        return None
    return json.loads(done.stdout)


def evaluate(env: dict, read_json, read_issue, now: datetime) -> list[str]:
    """Each check runs only while the switch it watches is on."""
    problems: list[str] = []
    if env.get("ROADMAP_RENDER_ENABLED") == "true":
        base = env.get("PAGE_URL", "https://genai-security-project.github.io/agent-control-standard")
        problems += check_page(read_json(f"{base.rstrip('/')}/roadmap/roadmap.json"), now)
    if env.get("ROADMAP_SYNC_ENABLED") == "true":
        configured = env.get("ROADMAP_HEALTH_ISSUE", "")
        issue = read_issue(configured) if configured.strip().isdigit() else None
        problems += check_health(configured, issue, now)
    return problems


def main() -> int:
    problems = evaluate(dict(os.environ), _read_json, _read_issue, datetime.now(timezone.utc))
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print("roadmap monitor: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
