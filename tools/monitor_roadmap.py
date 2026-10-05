#!/usr/bin/env python3
"""Fail loudly when the published roadmap or the health issue goes stale, and tell the leads.

Version 1.1. Owner: ACS project leads. Spec: design/2026-10-04-roadmap-page-design.md,
"The roadmap monitor", and design/2026-10-04-roadmap-rollout-design.md, "Alerting the
project leads".

Separate from monitor-pages.yml, so the schema contract's alarm never shares a red or green
result with roadmap noise. Each check runs only while the switch it watches is on. It reads
the sweep's own status line, never the issue's updated_at, which a comment also moves.

A failed run emails only whoever last edited the cron line. So when the result changes,
the monitor comments on the health issue: once with an @mention of every project lead when
it starts failing, and once without mentions when it recovers. The comment holds fixed text
and fixed check names. Nothing fetched reaches it.
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


SAFE_STATUSES = {"unavailable", "disabled", "placeholder"}


def _time(value: str) -> datetime:
    """Parse an ISO time. A time without a zone cannot be compared to now, so it is a ValueError."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("no timezone")
    return parsed


def _issue_number(configured: str) -> str | None:
    """The stripped ASCII issue number, or None. str.isdigit alone accepts non-ASCII digits."""
    stripped = configured.strip()
    return stripped if stripped.isascii() and stripped.isdigit() else None


def check_page(doc: dict | None, now: datetime) -> list[str]:
    if not isinstance(doc, dict):
        return ["roadmap.json could not be read"]
    status = doc.get("status")
    if status != "ok":
        # Fetched text never reaches the log. Only a known status word is echoed.
        if isinstance(status, str) and status in SAFE_STATUSES:
            return [f"roadmap.json status is {status!r}"]
        return ["roadmap.json status is not ok"]
    try:
        age = now - _time(doc["generated"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return ["roadmap.json has no readable generated time"]
    return [f"roadmap.json is {age} old"] if age > PAGE_MAX_AGE else []


def check_health(configured: str, issue: dict | None, now: datetime) -> list[str]:
    number = _issue_number(configured)
    if number is None:
        return [f"ROADMAP_HEALTH_ISSUE is {configured!r}, not an issue number"]
    configured = number
    if not isinstance(issue, dict):
        return [f"health issue #{configured} could not be read"]
    user = issue.get("user")
    if not isinstance(user, dict) or user.get("login") != model.BOT_LOGIN:
        return [f"health issue #{configured} is not authored by {model.BOT_LOGIN}"]
    body = issue.get("body")
    body = body if isinstance(body, str) else ""
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
            data = json.loads(response.read().decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - unreadable is reported as a problem by check_page
        return None


def _read_issue(number: str) -> dict | None:
    try:
        done = subprocess.run(
            ["gh", "api", f"repos/{model.REPO}/issues/{number}"], capture_output=True, text=True, timeout=60
        )
        if done.returncode != 0:
            return None
        data = json.loads(done.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


# The fixed names a comment may carry, keyed by check.
CHECK_NAMES = {"page": "the published roadmap.json", "health": "the roadmap health issue"}


def evaluate_checks(env: dict, read_json, read_issue, now: datetime) -> dict[str, list[str]]:
    """Problems per check. Each check runs only while the switch it watches is on."""
    checks: dict[str, list[str]] = {}
    if env.get("ROADMAP_RENDER_ENABLED") == "true":
        base = env.get("PAGE_URL", "https://genai-security-project.github.io/agent-control-standard")
        checks["page"] = check_page(read_json(f"{base.rstrip('/')}/roadmap/roadmap.json"), now)
    if env.get("ROADMAP_SYNC_ENABLED") == "true":
        configured = env.get("ROADMAP_HEALTH_ISSUE", "")
        number = _issue_number(configured)
        issue = read_issue(number) if number else None
        checks["health"] = check_health(configured, issue, now)
    return checks


def evaluate(env: dict, read_json, read_issue, now: datetime) -> list[str]:
    return [problem for problems in evaluate_checks(env, read_json, read_issue, now).values() for problem in problems]


# --- The alarm ------------------------------------------------------------------------

ALARM = re.compile(r"<!-- acs-roadmap-alarm: (failing|passing) -->")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


class AlarmError(RuntimeError):
    pass


def last_alarm(comments: list) -> str | None:
    """The state in the bot's most recent alarm comment. Anyone else's marker is ignored."""
    state = None
    for comment in comments:
        if not isinstance(comment, dict) or (comment.get("user") or {}).get("login") != model.BOT_LOGIN:
            continue
        match = ALARM.search(comment.get("body") or "")
        if match:
            state = match.group(1)
    return state


def alarm_body(state: str, names: list[str], leads: list[str]) -> str:
    marker = f"<!-- acs-roadmap-alarm: {state} -->"
    if state == "failing":
        mentions = " ".join(f"@{login}" for login in leads)
        checks = ", ".join(names) or "an unnamed check"
        return (
            f"{marker}\n{mentions} The roadmap monitor started failing. Failing checks: {checks}. "
            "The monitor's run log names each problem."
        )
    return f"{marker}\nThe roadmap monitor passes again."


def project_lead_logins(repo_root: Path) -> list[str]:
    """Project lead logins from GOVERNANCE.md, kept only when they match the login pattern."""
    roster = model.parse_governance((repo_root / "GOVERNANCE.md").read_text(encoding="utf-8"))
    return [login for _name, login in roster.project_leads if LOGIN.fullmatch(login)]


def _call(gh, args: list[str], what: str) -> str:
    code, out, _err = gh(args)
    if code != 0:
        raise AlarmError(f"{what} failed")
    return out


def post(gh, number: str, state: str, names: list[str], leads: list[str]) -> None:
    """Unlock, comment, relock. The sweep locks the health issue nightly, and GitHub refuses
    a comment on a locked issue even from the Actions token. Only the comment must succeed:
    an issue already unlocked refuses the unlock, and the next sweep relocks the issue if
    the relock fails."""
    base = f"repos/{model.REPO}/issues/{number}"
    gh(["api", "-X", "DELETE", f"{base}/lock"])
    _call(gh, ["api", "-X", "POST", f"{base}/comments", "-f", f"body={alarm_body(state, names, leads)}"], "commenting on the health issue")
    code, _out, _err = gh(["api", "-X", "PUT", f"{base}/lock", "-f", "lock_reason=resolved"])
    if code != 0:
        print("::warning::Could not relock the health issue. The next sweep relocks it.")


def sound(gh, number: str, failing: bool, names: list[str], leads: list[str], test: bool = False) -> list[str]:
    """Comment only when the result differs from the last alarm comment. Returns the states posted.

    With no earlier alarm comment the last state reads as passing, so a first passing run
    posts nothing and a first failing run posts the alarm.
    """
    posted: list[str] = []
    if test:
        post(gh, number, "failing", ["an alarm test"], leads)
        post(gh, number, "passing", [], leads)
        posted += ["failing", "passing"]
    pages = json.loads(_call(
        gh, ["api", "--paginate", "--slurp", f"repos/{model.REPO}/issues/{number}/comments?per_page=100"],
        "reading the health issue comments",
    ))
    flat = [comment for page in pages if isinstance(page, list) for comment in page]
    current = "failing" if failing else "passing"
    if (last_alarm(flat) or "passing") != current:
        post(gh, number, current, names, leads)
        posted.append(current)
    return posted


def _gh(args: list[str]) -> tuple[int, str, str]:
    try:
        done = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return 1, "", "gh failed"
    return done.returncode, done.stdout, done.stderr


def main() -> int:
    env = dict(os.environ)
    checks = evaluate_checks(env, _read_json, _read_issue, datetime.now(timezone.utc))
    problems = [problem for found in checks.values() for problem in found]
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print("roadmap monitor: ok")
    code = 1 if problems else 0
    test = env.get("TEST_ALARM") == "true"
    number = _issue_number(env.get("ROADMAP_HEALTH_ISSUE", ""))
    if number is None:
        # No issue to comment on. A failing run still fails, so the cron editor's email is
        # the fallback.
        if test:
            print("::error::ROADMAP_HEALTH_ISSUE is not set, so the alarm test cannot comment.")
            return 1
        return code
    names = [CHECK_NAMES[key] for key, found in checks.items() if found]
    try:
        leads = project_lead_logins(Path(__file__).resolve().parents[1])
        posted = sound(_gh, number, bool(problems), names, leads, test)
    except AlarmError as exc:
        print(f"::error::The lead alarm did not post: {exc}.")
        return 1
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print(f"::error::The lead alarm did not post: {type(exc).__name__}.")
        return 1
    for state in posted:
        print(f"roadmap monitor: posted the {state} alarm comment")
    return code


if __name__ == "__main__":
    sys.exit(main())
