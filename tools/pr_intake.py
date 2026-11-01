#!/usr/bin/env python3
"""Flag a pull request no lead asked for, so the queue is visible.

Version 1.0. Owner: ACS project leads.

A pull request is flagged when its author is not a lead in GOVERNANCE.md, no lead assigned
them on an issue the description references, and no lead reviewed it. A flag is the
status:needs-triage label and one comment. It blocks nothing, and it always exits 0.

The workflow runs this under `python3 -I -S` from the base commit, never the pull request's
head. The description is untrusted, so only digits are taken from it and nothing from it
is printed. Disable the workflow in the Actions tab to turn this off.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

LABEL = "status:needs-triage"
# The queue comment has always carried this phrase, so a pull request commented on before
# this check existed is not commented on again, and a lead's removal of the label sticks.
SEEN = "queued rather than ignored"
COMMENT = (
    f"Thanks for this. It is {SEEN}. No lead has assigned you to a referenced issue or "
    "reviewed this pull request yet, so a lead will pick it up in triage. You don't need "
    "to do anything, and nothing here is rejected."
)
REFERENCE = re.compile(r"(?:#|/issues/)(\d{1,7})\b")
HANDLE = re.compile(r"github\.com/([A-Za-z0-9-]+)")


def gh(*args: str) -> str:
    done = subprocess.run(
        ["gh", *args], capture_output=True, encoding="utf-8", errors="replace", check=True, timeout=60
    )
    return done.stdout


def rows(path: str, fields: str) -> list:
    """List an endpoint, one JSON value per item."""
    lines = gh("api", "--paginate", path, "--jq", f".[] | {fields} | tojson").splitlines()
    return [json.loads(line) for line in lines]


def leads(governance: str) -> set[str]:
    """Return the lowercased handles in every section whose heading ends in 'leads'."""
    sections = re.split(r"^## +", governance, flags=re.MULTILINE)[1:]
    wanted = (s for s in sections if s.partition("\n")[0].strip().lower().endswith("leads"))
    return {handle.lower() for section in wanted for handle in HANDLE.findall(section)}


def reviewed_by_lead(repo: str, number: str, roster: set[str]) -> bool:
    reviewers = rows(f"repos/{repo}/pulls/{number}/reviews?per_page=100", ".user.login")
    return any((login or "").lower() in roster for login in reviewers)


def assigned_by_lead(repo: str, author: str, body: str, roster: set[str]) -> bool:
    # The author's own assignments are listed first, so a description naming hundreds of
    # issues costs one call. The body cannot grow this list, because assigning takes triage.
    path = f"repos/{repo}/issues?assignee={author}&state=all&per_page=100"
    held = {str(number) for number in rows(path, ".number")}
    for issue in held & set(REFERENCE.findall(body)):
        events = rows(
            f"repos/{repo}/issues/{issue}/events?per_page=100",
            "[.event, .assignee.login, .assigner.login]",
        )
        for event, assignee, assigner in events:
            if event == "assigned" and (assignee or "").lower() == author.lower():
                if (assigner or "").lower() in roster:
                    return True
    return False


def asked_for(repo: str, number: str, author: str, body: str, roster: set[str]) -> bool:
    try:
        return reviewed_by_lead(repo, number, roster) or assigned_by_lead(repo, author, body, roster)
    except (subprocess.SubprocessError, OSError, ValueError):
        # A flag is cheap and a lead can clear it, so a failed lookup queues the pull request.
        print("::warning::Could not read the reviews or assignments. Treating as not asked for.")
        return False


def already_commented(repo: str, number: str) -> bool:
    comments = rows(f"repos/{repo}/issues/{number}/comments?per_page=100", "[.user.login, .body]")
    # Only the bot's comments count, so an author cannot suppress the flag by quoting it.
    return any((login or "").startswith("github-actions") and SEEN in (text or "") for login, text in comments)


def run(env: dict[str, str], governance: str) -> None:
    author = env.get("PR_AUTHOR", "")
    if not author or env.get("PR_AUTHOR_TYPE") == "Bot" or author.endswith("[bot]"):
        return
    roster = leads(governance)
    if not roster:
        print("::warning::Found no leads in GOVERNANCE.md, so nothing was flagged.")
        return
    repo, number, body = env["REPO"], env["PR_NUMBER"], env.get("PR_BODY", "")
    if author.lower() in roster or asked_for(repo, number, author, body, roster):
        return
    if already_commented(repo, number):
        return
    gh("pr", "edit", number, "--repo", repo, "--add-label", LABEL)
    gh("pr", "comment", number, "--repo", repo, "--body", COMMENT)


def main() -> int:
    try:
        run(dict(os.environ), Path("GOVERNANCE.md").read_text(encoding="utf-8"))
    except (subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
        # Only the type is printed, so no untrusted text reaches the log.
        print(f"::warning::PR intake stopped early: {type(error).__name__}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
