"""Every run a guide asks for has a recording the gateway can serve (issue #589, LAB-16 Task 5).

Version 1.0.0. Owner: Rock Lambros. Runs in the gateway's environment, because it loads each recording with the
gateway's own loader, so a file the gateway would refuse at startup fails here first:

    uv run --project adapters/gateway --locked --group test python -m pytest labs/finbot/replay/tests -v

test_every_guide_run_has_a_recording stays red, naming every missing recording, until Task 15 copies in the owner's
captures. Task 15 adds its hygiene and size tests to this file.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from acs_gateway.upstream import RecordingStore

REPLAY = Path(__file__).resolve().parents[1]
RECORDINGS = REPLAY / "recordings"
MANIFEST = REPLAY.parent / "scenarios" / "manifest.json"
# Off and shadow runs forward every tool call, so each step's branch token is always "a" (A.8) and two such runs of
# one scenario send the model the same thing.
ALWAYS_ALLOW = {"off", "shadow"}


def manifest_runs() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["runs"]


def recording_problems(stem: str, directory: Path = RECORDINGS) -> list[str]:
    path = directory / f"{stem}.jsonl"
    if path.is_symlink():
        return [f"{stem}: replay/recordings/{stem}.jsonl is a symlink, and a shipped recording is a plain file"]
    if not path.is_file():
        return [f"{stem}: replay/recordings/{stem}.jsonl is missing. Record it with ./lab.sh record"]
    try:
        store = RecordingStore.load(directory, stem)
    except ValueError as e:
        return [f"{stem}: the gateway can't load it: {e}"]
    lines = [r for recordings in store.files for r in recordings]
    if not lines:
        return [f"{stem}: the file holds no recording lines"]
    wrong = sorted({r.scenario for r in lines if r.scenario != stem})
    return [f"{stem}: lines name the scenario {', '.join(wrong)}, not {stem}"] if wrong else []


def test_every_guide_run_has_a_recording():
    stems = sorted({run["recording"] for run in manifest_runs()})
    problems = [p for stem in stems for p in recording_problems(stem)]
    assert not problems, f"{len(problems)} of {len(stems)} recordings aren't ready:\n" + "\n".join(problems)


def test_shared_recordings_are_safe():
    by_stem: dict[str, list[dict]] = defaultdict(list)
    for run in manifest_runs():
        by_stem[run["recording"]].append(run)
    unsafe = [f"{stem}: {run['run']} ({run['mode']}) shares it without \"shared_proof\": \"acceptance\""
              for stem, runs in by_stem.items() if len(runs) > 1
              for run in runs if run["mode"] not in ALWAYS_ALLOW and run.get("shared_proof") != "acceptance"]
    assert not unsafe, "\n".join(unsafe)


def test_the_missing_recording_rule_names_what_is_wrong(tmp_path):
    assert "missing" in recording_problems("s1__off", tmp_path)[0]
    path = tmp_path / "s1__off.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    assert "can't load" in recording_problems("s1__off", tmp_path)[0]
    path.write_text("", encoding="utf-8")
    assert "no recording lines" in recording_problems("s1__off", tmp_path)[0]
