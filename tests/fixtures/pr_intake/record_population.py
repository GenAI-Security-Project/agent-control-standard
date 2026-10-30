#!/usr/bin/env python3
"""Record population.json: every open pull request's gate facts, with nothing that names anyone.

Version 1.0. Owner: ACS project leads. Read-only: it calls `gh api` reads only.

Usage, from the repository root:
    GH_TOKEN=$(gh auth token) python3 -I tests/fixtures/pr_intake/record_population.py --gh "$(command -v gh)"

It loads the shared listings and collects every open pull request's facts through
`pr_intake.collect_facts`, in enforced mode, exactly as a sweep would. Each row is then
made anonymous before it is written:

- Logins become `lead-N` for a roster login and `user-N` for anyone else. The two bots
  the gate names keep their logins, since the gate reads them.
- Pull request and issue numbers become `1001` upward, in the same order, so the held
  cap, which compares numbers, reads the same.
- SHAs become numbered hex strings, so a review's commit still matches the head or not.
- The title becomes `t`. The body becomes the template's ticked editorial line when the
  box is ticked and `b` otherwise, the one thing the gate reads in it.
- Paths become synthetic paths, on the documentation lane exactly when the real one is.

`expected` is `decide` on the anonymous facts, and the script refuses to write a row
whose anonymous decision differs from the decision on the real facts. The real numbers
are printed to the terminal for hand checks and never written to the file.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

import base_branch_guard  # noqa: E402
import gh_runner  # noqa: E402
import pr_intake  # noqa: E402
import roadmap_model  # noqa: E402

OUT = Path(__file__).resolve().parent / "population.json"
TICKED = "- [x] This is an editorial correction on the documentation lane (typo, grammar, link, formatting)"
KEPT = pr_intake.KNOWN_BOTS | {roadmap_model.BOT_LOGIN}


class Anonymizer:
    def __init__(self, roster: frozenset[str], numbers: list[int]) -> None:
        self.logins = {login: f"lead-{index}" for index, login in enumerate(sorted(roster), 1)}
        self.others = 0
        self.numbers = {number: 1001 + index for index, number in enumerate(sorted(set(numbers)))}
        self.shas: dict[str, str] = {}

    def login(self, login: str) -> str:
        if login in KEPT:
            return login
        if login not in self.logins:
            self.others += 1
            self.logins[login] = f"user-{self.others}"
        return self.logins[login]

    def sha(self, sha: str | None) -> str | None:
        if sha is None:
            return None
        if sha not in self.shas:
            self.shas[sha] = f"{len(self.shas) + 1:040x}"
        return self.shas[sha]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _paths(paths: tuple[str, ...]) -> list[str]:
    return [
        f"docs/topics/f{index}.md" if base_branch_guard.in_docs_lane(path) else f"tools/f{index}.py"
        for index, path in enumerate(paths)
    ]


def anonymous(facts: pr_intake.Facts, anon: Anonymizer) -> dict:
    if facts.bot_comment is not None and facts.bot_comment.data is not None:
        raise SystemExit("a bot comment carries a data line, which this script does not yet remap")
    n = anon.numbers
    return {
        "number": n[facts.number],
        "state": facts.state,
        "draft": facts.draft,
        "author": anon.login(facts.author),
        "author_is_bot": facts.author_is_bot,
        "title": "t",
        "body": TICKED if pr_intake.editorial_ticked(facts.body) else "b",
        "base": facts.base,
        "head_sha": anon.sha(facts.head_sha),
        "created_at": _iso(facts.created_at),
        "updated_at": _iso(facts.updated_at),
        "labels": sorted(facts.labels),
        "paths": _paths(facts.paths),
        "paths_truncated": facts.paths_truncated,
        "references": [
            {
                "number": n[ref.number], "kind": ref.kind, "is_pull": ref.is_pull, "state": ref.state,
                "labels": sorted(ref.labels), "assignees": sorted(anon.login(a) for a in ref.assignees),
                "milestoned": ref.milestoned, "author_commented_at": _iso(ref.author_commented_at),
                "unresolved": ref.unresolved,
            }
            for ref in facts.references
        ],
        "references_dropped": facts.references_dropped,
        "reviews": [
            {
                "login": anon.login(r.login), "state": r.state, "association": r.association,
                "submitted_at": _iso(r.submitted_at), "commit_id": anon.sha(r.commit_id),
            }
            for r in facts.reviews
        ],
        "last_unlabel": None if facts.last_unlabel is None else [
            anon.login(facts.last_unlabel[0]), _iso(facts.last_unlabel[1])
        ],
        "last_author_comment_at": _iso(facts.last_author_comment_at),
        "bot_comment": None if facts.bot_comment is None else {
            "id": 1, "body": "", "data": None, "legacy": facts.bot_comment.legacy
        },
        "auto_merge": facts.auto_merge,
        "author_record": facts.author_record,
        "held_use": {str(n[k]): [n[v] for v in vs] for k, vs in sorted(facts.held_use.items())},
        "roster": sorted(anon.login(login) for login in facts.roster),
        "mode": facts.mode,
        "sweep": facts.sweep,
        "event_action": facts.event_action,
    }


def restore(row: dict) -> pr_intake.Facts:
    """The anonymous row as Facts, read the way the population test reads it."""
    def when(value):
        return None if value is None else datetime.fromisoformat(value)

    return pr_intake.Facts(**{
        **row,
        "created_at": when(row["created_at"]), "updated_at": when(row["updated_at"]),
        "last_author_comment_at": when(row["last_author_comment_at"]),
        "labels": frozenset(row["labels"]), "roster": frozenset(row["roster"]), "paths": tuple(row["paths"]),
        "references": tuple(
            pr_intake.Reference(**{**r, "labels": frozenset(r["labels"]), "assignees": frozenset(r["assignees"]),
                                   "author_commented_at": when(r["author_commented_at"])})
            for r in row["references"]
        ),
        "reviews": tuple(pr_intake.Review(**{**r, "submitted_at": when(r["submitted_at"])}) for r in row["reviews"]),
        "last_unlabel": None if row["last_unlabel"] is None else (row["last_unlabel"][0], when(row["last_unlabel"][1])),
        "held_use": {int(k): tuple(v) for k, v in row["held_use"].items()},
        "bot_comment": None if row["bot_comment"] is None else pr_intake.BotComment(**row["bot_comment"]),
    })


def outcome(decision: pr_intake.Decision) -> dict:
    return {"outcome": decision.outcome, "route": decision.route, "reasons": list(decision.reasons)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gh", default=gh_runner.GH)
    args = parser.parse_args()
    run = gh_runner.make_runner(args.gh)
    today = date.today()
    roster = roadmap_model.trusted_logins(ROOT)
    listings = pr_intake.load_listings(run)
    counter = pr_intake.CallCounter(limit=5_000)
    collected = [
        pr_intake.collect_facts(run, int(pull["number"]), listings=listings, roster=roster, mode="enforced",
                                sweep=True, event_action=None, counter=counter)
        for pull in sorted(listings.open_pulls, key=lambda pull: pull["number"])
    ]
    numbers = [f.number for f in collected]
    for f in collected:
        numbers.extend(ref.number for ref in f.references)
        for issue, pulls in f.held_use.items():
            numbers.append(issue)
            numbers.extend(pulls)
    anon = Anonymizer(roster, numbers)
    rows = []
    for f in collected:
        row = anonymous(f, anon)
        real = outcome(pr_intake.decide(f, today))
        if outcome(pr_intake.decide(restore(row), today)) != real:
            raise SystemExit(f"#{f.number}: the anonymous facts decide differently from the real ones")
        rows.append({"facts": row, "today": today.isoformat(), "expected": real})
        print(f"#{f.number} -> {row['number']}: {real['outcome']} route={real['route']} reasons={real['reasons']}")
    document = {
        "generated_by": "tests/fixtures/pr_intake/record_population.py",
        "recorded": today.isoformat(),
        "rows": rows,
    }
    OUT.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
