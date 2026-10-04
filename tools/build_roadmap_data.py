#!/usr/bin/env python3
"""Write /roadmap/roadmap.json into the built site, following the spec's failure table.

Version 1.0. Owner: ACS project lead. Spec: design/2026-10-04-roadmap-page-design.md,
"Phase 0" and "Failure behavior".

The roadmap must never stop a schema from publishing or a pull request from merging. So
this step fails the build in two cases only: a pull request whose committed fixture no
longer builds, which is a code defect, and a nightly refresh whose data failed while the
site already serves this commit, where failing keeps yesterday's good file.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import roadmap_model as model


class DataFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def published_commit(url: str, opener=urllib.request.urlopen) -> str | None:
    """The commit the live site's roadmap.json reports, or None when it cannot be read.

    Every failure means "not this commit", so a first deploy, a 404, or an outage that
    also broke the page read degrades rather than failing closed.
    """
    try:
        request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "acs-roadmap"})
        with opener(request, timeout=10) as response:
            value = json.loads(response.read(2_000_000).decode("utf-8")).get("commit")
    except Exception:  # noqa: BLE001 - any failure to read means not the same commit
        return None
    return value if isinstance(value, str) else None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: str, doc: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build(data: dict, repo_root: Path, today, generated: str, commit: str, run_id: str) -> dict:
    roster = model.parse_governance((repo_root / "GOVERNANCE.md").read_text(encoding="utf-8"))
    trusted = model.trusted_logins(repo_root)
    return model.build_roadmap(data["milestones"], roster, trusted, today, generated, commit, run_id)


def _summary(path: str | None, doc: dict) -> None:
    if not path:
        return
    # Counts only, so rollout step 3 can confirm closers resolved under the build token
    # without any fetched text reaching the run summary.
    lines = [
        f"Roadmap data: status `{doc['status']}`", "",
        "| Milestone | State | Done | Unverified | Planned | Deferred |", "| --- | --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {m['number']} | {m['state']} | {m['counts']['done']} | {m['counts']['unverified']} "
        f"| {m['counts']['planned']} | {m['counts']['deferred']} |"
        for m in doc["milestones"]
    ]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def run(args: argparse.Namespace, opener=urllib.request.urlopen, now: datetime | None = None) -> int:
    moment = now or datetime.now(timezone.utc)
    generated = _stamp(moment)
    repo_root = Path(args.repo_root)
    if args.render_enabled not in ("true", "false", ""):
        print(f"::warning::ROADMAP_RENDER_ENABLED is {args.render_enabled!r}. Only 'true' turns it on.")

    if args.event == "pull_request":
        # Fixture data and a frozen time, so a quarter boundary cannot change the result.
        fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        frozen = datetime.fromisoformat(fixture["frozen_now"].replace("Z", "+00:00"))
        doc = _build(fixture, repo_root, frozen.date(), _stamp(frozen), args.commit, args.run)
        _write(args.out, doc)
        return 0

    if args.render_enabled != "true" and args.preview != "true":
        _write(args.out, model.empty_roadmap("disabled", generated, args.commit, args.run))
        return 0

    try:
        path = Path(args.data)
        if not path.exists():
            raise DataFailure("missing")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") != "ok":
            raise DataFailure(str(data.get("class", "unknown")))
        doc = _build(data, repo_root, moment.date(), generated, args.commit, args.run)
    except Exception as exc:  # noqa: BLE001 - every failure is classed, never a traceback
        reason = exc.reason if isinstance(exc, DataFailure) else "code_defect"
        if args.source == "nightly" and published_commit(args.published_url, opener) == args.commit:
            print(f"::error::Roadmap data failed ({reason}) and the site already serves this commit. Keeping it.")
            return 1
        print(f"::warning::Roadmap data failed ({reason}). Publishing status 'unavailable'.")
        _write(args.out, model.empty_roadmap("unavailable", generated, args.commit, args.run, reason=reason))
        return 0

    _write(args.out, doc)
    _summary(args.summary, doc)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("data", "fixture", "out", "repo-root", "event", "commit", "run", "published-url"):
        parser.add_argument(f"--{name}", required=True)
    for name in ("source", "preview", "render-enabled"):
        parser.add_argument(f"--{name}", default="")
    parser.add_argument("--summary", default=None)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
