"""Plays the attendee guides on a live lab with no model key and no network out, and fails on anything an attendee
would see go wrong (issue #589, LAB-16 Task 16).

Version 1.0.0. Owner: Rock Lambros. Standard library only, like guide_sim.py, which it reads the guides through.

Run from anywhere, with Docker running and nothing else using the acs-finbot-lab project:

    python3 labs/finbot/modules/tests/acceptance.py [--modules 1,3,7]

Steps:
1. Every guide asked for must exist and pass guide_sim.simulate, before Docker is touched.
2. `./lab.sh reset --delete-model-key` when state/ exists, so the run starts from a fresh bundle with no key. A fresh
   clone has nothing to reset.
3. Each guide's commands run in order, exactly as written, from labs/finbot. When the first guide doesn't open with
   `init`, this runs `./lab.sh init` and `./lab.sh up` before its first step.
4. Every Docker call lab.sh makes goes through a shim that adds compose.offline.yaml after compose.yaml, so upstream-net
   is internal too and no service on the model path can reach outside the stack. test_lab_bundle.py holds lab.sh to
   starting every compose call with `-f compose.yaml`, which is what the shim keys on.

It fails, and stops, on the first of these:
- a command that doesn't exit 0. The module 7 verbs forge, verify and downgrade may also exit 1, since a NOT YET line
  can be the lesson. Exit 2, a broken environment, fails every verb.
- a `replay_miss` line in state/audit.log.
- a run record that isn't completed, counts a replay miss, ran on an upstream other than replay, or carries a FinBot
  namespace that appears in a recording. A run in a capture's own namespace would hide replay answers keyed to the
  wrong FinBot record (LAB-16 plan, risk 1).
- acs-gateway or FinBot joined to a network that isn't internal, checked after every step that recreates either.
- a model key in state/secrets or an openai upstream in .env at the end.

The lab stays up afterward, so its logs can be read. `./lab.sh down` stops it.
Exit 0 when everything passes, 1 on the first failure, 2 when Docker is missing.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import guide_sim  # noqa: E402

BUNDLE = guide_sim.BUNDLE
OFFLINE = TESTS_DIR / "compose.offline.yaml"
PROJECT = "acs-finbot-lab"
STATE = BUNDLE / "state"
AUDIT_LOG = STATE / "audit.log"
RUNS_DIR = STATE / "runs"
RECORDINGS_DIR = BUNDLE / "replay" / "recordings"
MISS_MARK = '"acs_audit_event": "replay_miss"'
# The module 7 kit prints NOT YET for a forgery that fails, which is the point of the lesson.
LESSON_VERBS = {"forge", "verify", "downgrade"}
# Verbs after which acs-gateway or FinBot is freshly created, so its networks are checked again.
RECREATES = {"up", "mode", "sign", "upstream", "traces", "run"}
# The services on the model path. Each must join only internal networks.
MODEL_PATH = ("acs-gateway", "finbot")

SHIM = """#!/bin/sh
# Adds the acceptance run's offline override after compose.yaml in each compose call lab.sh makes.
if [ "$1" = compose ] && [ "$2" = -f ] && [ "$3" = compose.yaml ]; then
    shift 3
    exec {real} compose -f compose.yaml -f {offline} "$@"
fi
exec {real} "$@"
"""


class NotYet(Exception):
    """One failure, named for the reader. The run stops on the first."""


def write_docker_shim(directory: Path, real_docker: str, offline: Path = OFFLINE) -> Path:
    """directory/docker, which lab.sh finds first on PATH."""
    shim = directory / "docker"
    shim.write_text(SHIM.format(real=shlex.quote(real_docker), offline=shlex.quote(str(offline))), encoding="utf-8")
    shim.chmod(0o755)
    return shim


def new_audit_misses(path: Path, offset: int) -> tuple[int, list[str]]:
    """The replay_miss lines written since offset, and the new offset. A log shorter than offset was wiped by a
    reset, so it is read from the start."""
    if not path.is_file():
        return 0, []
    data = path.read_bytes()
    if len(data) < offset:
        offset = 0
    lines = data[offset:].decode("utf-8", errors="replace").splitlines()
    return len(data), [line for line in lines if MISS_MARK in line]


def record_problems(name: str, record: object, recordings: dict[str, str]) -> list[str]:
    """Why one run record fails acceptance, or nothing. recordings maps a recording's file name to its text."""
    if not isinstance(record, dict):
        return [f"run record {name} isn't a JSON object"]
    problems = []
    if record.get("result") != "completed":
        problems.append(f"run record {name} says {record.get('result')!r}: {record.get('error')}")
    if record.get("replay_misses") != 0:
        problems.append(f"run record {name} counts {record.get('replay_misses')!r} replay misses")
    if record.get("upstream") != "replay":
        problems.append(f"run record {name} ran on the {record.get('upstream')!r} upstream, not replay")
    finbot = record.get("finbot")
    namespace = finbot.get("namespace") if isinstance(finbot, dict) else None
    if not isinstance(namespace, str) or not namespace:
        problems.append(f"run record {name} has no FinBot namespace")
    else:
        problems.extend(f"run record {name} ran in FinBot namespace {namespace}, which recording {stem} holds"
                        for stem, text in sorted(recordings.items()) if namespace in text)
    return problems


def _docker(*args: str) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise NotYet(f"docker {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def network_problems() -> list[str]:
    """Each model-path service's networks that aren't internal."""
    problems = []
    for service in MODEL_PATH:
        ids = _docker("ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
                      "--filter", f"label=com.docker.compose.service={service}").split()
        if not ids:
            problems.append(f"{service} isn't running, so its networks can't be checked")
            continue
        for container in ids:
            networks = json.loads(_docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", container))
            for network in sorted(networks):
                if _docker("network", "inspect", "--format", "{{.Internal}}", network) != "true":
                    problems.append(f"{service} joins {network}, which isn't internal, so a call could leave the stack")
    return problems


def _say(line: str) -> None:
    print(line, flush=True)


def _run(argv: tuple[str, ...], env: dict[str, str]) -> tuple[int, str]:
    """Runs one lab.sh command from the bundle, echoing its output as it comes. Returns the exit code and the last
    DONE or NOT YET line it printed."""
    _say(f"==> {' '.join(argv)}")
    process = subprocess.Popen(list(argv), cwd=BUNDLE, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors="replace")
    verdict = ""
    assert process.stdout is not None
    for line in process.stdout:
        sys.stdout.write(f"    {line}")
        if line.startswith(("DONE", "NOT YET")):
            verdict = line.strip()
    sys.stdout.flush()
    return process.wait(), verdict


class Acceptance:
    def __init__(self, modules: list[int], guide_dir: Path, env: dict[str, str]) -> None:
        self.modules = modules
        self.guide_dir = guide_dir
        self.env = env
        self.audit_offset = 0
        self.seen_runs: set[str] = set()
        self.checked = 0
        self.runs = 0
        self.recordings = {p.name: p.read_text(encoding="utf-8", errors="replace")
                           for p in sorted(RECORDINGS_DIR.glob("*.jsonl"))} if RECORDINGS_DIR.is_dir() else {}

    def command(self, argv: tuple[str, ...]) -> None:
        verb = argv[1]
        code, verdict = _run(argv, self.env)
        allowed = (0, 1) if verb in LESSON_VERBS else (0,)
        if code not in allowed:
            raise NotYet(f"{' '.join(argv)} exited {code}" + (f": {verdict}" if verdict else ""))
        self.audit_offset, misses = new_audit_misses(AUDIT_LOG, self.audit_offset)
        if misses:
            raise NotYet(f"{' '.join(argv)} left {len(misses)} replay_miss lines in state/audit.log, the first: "
                         f"{misses[0]}")
        if verb == "run":
            self.read_new_runs(argv)
        if verb == "check":
            self.checked += 1
            _say(f"DONE: {' '.join(argv)} exited 0")
        if verb in RECREATES:
            problems = network_problems()
            if problems:
                raise NotYet(problems[0])

    def read_new_runs(self, argv: tuple[str, ...]) -> None:
        names = sorted(p.name for p in RUNS_DIR.glob("*.json")) if RUNS_DIR.is_dir() else []
        new = [n for n in names if n not in self.seen_runs]
        if not new:
            raise NotYet(f"{' '.join(argv)} exited 0 and left no run record in state/runs")
        for name in new:
            self.seen_runs.add(name)
            try:
                record = json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise NotYet(f"run record {name} can't be read: {e}") from None
            problems = record_problems(name, record, self.recordings)
            if problems:
                raise NotYet(problems[0])
            self.runs += 1

    def play(self) -> None:
        guides = {n: self.guide_dir / f"{n}.md" for n in self.modules}
        missing = [f"modules/{p.name}" for p in guides.values() if not p.is_file()]
        if missing:
            raise NotYet(f"no guide yet at {', '.join(missing)}")
        try:
            guide_sim.simulate(self.guide_dir, self.modules)
            plans = {n: guide_sim.find_commands(path, n) for n, path in guides.items()}
        except guide_sim.GuideError as e:
            raise NotYet(f"the guides don't pass the simulator: {e}") from None
        _say(f"DONE: guides {', '.join(map(str, self.modules))} pass the simulator")

        if STATE.exists():
            self.command(("./lab.sh", "reset", "--delete-model-key"))
            self.seen_runs.clear()
        set_up = False
        for n, commands in plans.items():
            _say(f"--- modules/{n}.md")
            for c in commands:
                verb = c.argv[1]
                if not set_up and verb not in guide_sim.SETUP and verb != "help":
                    # The guides before this one aren't played, so the lab they would have set up is set up here.
                    self.command(("./lab.sh", "init"))
                    self.command(("./lab.sh", "up"))
                    set_up = True
                self.command(c.argv)
                if verb == "reset":
                    set_up = False
                elif verb == "up":
                    set_up = True

        if (STATE / "secrets" / "openai.key").exists():
            raise NotYet("state/secrets/openai.key holds a model key, and attendees run with none")
        env_file = BUNDLE / ".env"
        if env_file.is_file() and "ACS_UPSTREAM=openai" in env_file.read_text(encoding="utf-8").splitlines():
            raise NotYet(".env sets the openai upstream, and attendees run on replay")
        if not self.checked:
            raise NotYet("the guides ran no check")
        _say(f"DONE: {self.checked} checks passed over {self.runs} runs, offline, with no replay miss and no run "
             f"in a recording's namespace")


def _modules(text: str) -> list[int]:
    try:
        chosen = sorted({int(part) for part in text.split(",") if part.strip()})
    except ValueError:
        raise argparse.ArgumentTypeError(f"--modules takes numbers 1 to 7 separated by commas, got {text!r}") from None
    if not chosen or any(n not in guide_sim.MODULES for n in chosen):
        raise argparse.ArgumentTypeError(f"--modules takes numbers 1 to 7 separated by commas, got {text!r}")
    return chosen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--modules", type=_modules, default=list(guide_sim.MODULES),
                        help="the guides to play, in order, for example 1,3,7 (default: 1 to 7)")
    args = parser.parse_args(argv)
    real_docker = shutil.which("docker")
    if not real_docker:
        _say("NOT YET: Docker isn't installed, and the acceptance run plays the guides on a live lab.")
        return 2
    with tempfile.TemporaryDirectory(prefix="acs-lab-acceptance.") as shim_dir:
        write_docker_shim(Path(shim_dir), real_docker)
        env = {**os.environ, "PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
        try:
            Acceptance(args.modules, guide_sim.MODULES_DIR, env).play()
        except NotYet as e:
            _say(f"NOT YET: {e}")
            _say("The lab is still up for its logs: ./lab.sh logs, then ./lab.sh down.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
