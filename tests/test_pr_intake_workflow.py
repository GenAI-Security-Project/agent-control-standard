"""Pins pr-intake.yml and runs its one step end to end against a fake gh.

The workflow runs under pull_request_target with a write token, so every key that bounds
what runs beside that token is pinned here: the triggers, the base ref guard, the
checkout, the permissions, the concurrency group, the env, and the run line.

The step is then run as the runner would run it. `run_tool` builds the environment from
the step's own `env` block, substituting each `${{ }}` value from a mapping the test
controls, and executes the tool with `--gh` pointed at a fake. The fake serves the
recorded fixtures under tests/fixtures/pr_intake, records every call, and refuses any argv
outside gh_runner's allowlist, as `runner_from_fixtures` does in-process.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from test_pr_intake import listing_mapping, pull_mapping, slurp, with_body

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pr-intake.yml"
ROADMAP_SYNC = REPO_ROOT / ".github" / "workflows" / "roadmap-sync.yml"
TOOLS = REPO_ROOT / "tools"
API = "repos/GenAI-Security-Project/agent-control-standard"
ACCEPTED_LISTING = f"{API}/issues?labels=status%3Aaccepted&state=all&per_page=100"
OPEN_PULLS = f"{API}/pulls?state=open&per_page=100"
RATE_LIMIT = json.dumps({"resources": {"core": {"remaining": 5000}}})

IF = (
    "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
    "((github.event.pull_request.base.ref == 'main' || github.event.pull_request.base.ref == 'integration' || "
    "startsWith(github.event.pull_request.base.ref, 'release/')) && "
    "(github.event.action != 'edited' || github.event.changes.body || github.event.changes.title || "
    "github.event.changes.base))"
)
STEP_ENV = {
    "GH_TOKEN": "${{ github.token }}",
    "PR_NUMBER": "${{ github.event.pull_request.number || inputs.pr_number }}",
    "INTAKE_MODE": "${{ inputs.mode || 'evaluate' }}",
    "INTAKE_AUTHORS": "${{ inputs.authors || 'all' }}",
    "EVENT_NAME": "${{ github.event_name }}",
    "EVENT_ACTION": "${{ github.event.action }}",
    "PR_INTAKE_ENFORCED": "${{ vars.PR_INTAKE_ENFORCED }}",
    "PR_INTAKE_TOOL_SHA": "${{ vars.PR_INTAKE_TOOL_SHA }}",
    "PR_INTAKE_LANDED": "${{ vars.PR_INTAKE_LANDED }}",
}

# The fake gh. A shell wrapper starts it, because gh_runner hands the process an
# environment of six keys, so the fake's own paths are written into it, not passed in env.
FAKE_GH = r'''import json
import sys

sys.path.insert(0, TOOLS)
import gh_runner

args = sys.argv[1:]
stdin = sys.stdin.read() if "--input" in args else None
entry = {"args": args, "stdin": stdin}
try:
    gh_runner._check_allowlist(args)
except gh_runner.RunnerError:
    entry["refused"] = True
if args[0] == "pr":
    key, write = f"pr {args[1]}", True
elif "-X" in args:
    key, write = f"{args[3]} {args[4]}", True
else:
    key, write = args[-1], False
with open(STATE, encoding="utf-8") as handle:
    serve = json.load(handle)
if entry.get("refused"):
    code, out, err = 2, "", "outside the allowlist\n"
elif key in serve:
    value = serve[key]
    code, out, err = value if isinstance(value, list) else (0, value, "")
elif args[0] == "pr":
    code, out, err = 0, "", ""
elif write:
    created = args[3] == "POST" and args[4].endswith("/comments")
    status = "201 Created" if created else "200 OK"
    code, out, err = 0, "HTTP/2.0 " + status + "\r\n\r\n" + ('{"id": 1}' if created else "{}"), ""
else:
    entry["unexpected"] = True
    code, out, err = 1, "", "no fixture for this read\n"
with open(LOG, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry) + "\n")
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(code)
'''


def load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def job() -> dict:
    return load()["jobs"]["intake"]


def tool_step() -> dict:
    (step,) = [step for step in job()["steps"] if "run" in step]
    return step


def event(number: int, action: str = "opened", name: str = "pull_request_target") -> dict:
    """The expression values a pull request event renders into the step's env."""
    return {
        "github.token": "x",
        "github.event.pull_request.number || inputs.pr_number": str(number),
        "inputs.mode || 'evaluate'": "evaluate",
        "inputs.authors || 'all'": "all",
        "github.event_name": name,
        "github.event.action": action,
        "vars.PR_INTAKE_ENFORCED": "",
        "vars.PR_INTAKE_TOOL_SHA": "",
        "vars.PR_INTAKE_LANDED": "",
    }


def nightly() -> dict:
    """The expression values the schedule renders. Every pull request field is empty."""
    return {**event(0), "github.event.pull_request.number || inputs.pr_number": "", "github.event_name": "schedule",
            "github.event.action": ""}


def step_env(values: dict) -> dict:
    """The step's env block with each `${{ }}` value replaced from `values`.

    An expression `values` does not name fails the test, so a renamed expression in the
    workflow cannot pass by rendering empty.
    """
    rendered = {}
    for key, value in tool_step()["env"].items():
        match = re.fullmatch(r"\$\{\{ (.+) \}\}", value)
        rendered[key] = values[match.group(1)] if match else value
    return rendered


def run_tool(tmp_path: Path, env: dict, state: dict):
    """Run the step's tool with `--gh` pointed at a fake that serves `state`.

    `state` maps a read's path, or a write's `METHOD path` or `pr <subcommand>`, to stdout
    or a `[code, stdout, stderr]` list. A write it does not name succeeds. A read it does
    not name fails the call, and the test, so every read the tool makes is accounted for.
    """
    state_file, log = tmp_path / "state.json", tmp_path / "gh.log"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    script = tmp_path / "fake_gh.py"
    script.write_text(f"TOOLS = {str(TOOLS)!r}\nSTATE = {str(state_file)!r}\nLOG = {str(log)!r}\n" + FAKE_GH)
    fake = tmp_path / "gh"
    fake.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -S {shlex.quote(str(script))} \"$@\"\n")
    fake.chmod(0o755)
    summary = tmp_path / "summary.md"
    environ = {**step_env(env), "GITHUB_STEP_SUMMARY": str(summary)}
    done = subprocess.run(
        [sys.executable, "-I", "-S", "tools/pr_intake.py", "--gh", str(fake)],
        cwd=REPO_ROOT, env=environ, capture_output=True, text=True, timeout=300,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    assert not [call["args"] for call in calls if call.get("refused")], "an argv outside the allowlist reached gh"
    assert not [call["args"][-1] for call in calls if call.get("unexpected")], "a read had no fixture"
    return done, calls, summary.read_text() if summary.exists() else ""


def writes(calls) -> list[list[str]]:
    return [call["args"] for call in calls if call["args"][0] == "pr" or "-X" in call["args"]]


def stub_pull(number: int) -> dict:
    return {
        "number": number, "state": "open", "draft": False, "title": "Add a thing", "body": "b",
        "user": {"login": f"outsider-{number}", "type": "User"}, "base": {"ref": "integration"},
        "head": {"sha": f"{number:040d}"}, "created_at": "2026-10-20T12:00:00Z",
        "updated_at": "2026-10-21T01:00:00Z", "changed_files": 1, "labels": [], "auto_merge": None,
    }


def stub_reads(pull: dict) -> dict:
    return pull_mapping(pull["number"], pull=pull, files=[[{"filename": "tools/x.py"}]], reviews=[], comments=[],
                        timeline=[])


def sweep_state(pulls: list[dict]) -> dict:
    # The open listing arrives as two pages, so the sweep sees all of them only if it
    # flattens what --paginate --slurp returns. gh pr list stopped at 30 by default.
    state = {**listing_mapping(open_pulls=[]), OPEN_PULLS: slurp(pulls[:30], pulls[30:]), "rate_limit": RATE_LIMIT}
    for pull in pulls:
        state.update(stub_reads(pull))
    return state


def test_triggers_and_cron():
    on = load()[True]  # PyYAML reads the key `on` as the boolean True.
    assert on["pull_request_target"] == {"types": [
        "opened", "edited", "reopened", "ready_for_review", "synchronize", "unlabeled", "auto_merge_enabled",
    ]}
    assert on["pull_request_review"] == {"types": ["submitted", "dismissed"]}
    assert on["schedule"] == [{"cron": "10 3 * * *"}]
    inputs = on["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"pr_number", "mode", "authors"}
    assert inputs["pr_number"]["type"] == "string" and inputs["pr_number"]["required"] is False
    assert inputs["mode"]["type"] == "choice" and inputs["mode"]["options"] == ["evaluate", "dryrun", "retract"]
    assert inputs["mode"]["default"] == "evaluate"
    assert inputs["authors"]["type"] == "choice" and inputs["authors"]["options"] == ["all", "bots"]
    assert inputs["authors"]["default"] == "all"


def test_cron_runs_before_the_roadmap_sweep():
    def minutes(cron: str) -> int:
        minute, hour, *_ = cron.split()
        return int(hour) * 60 + int(minute)

    ours = minutes(load()[True]["schedule"][0]["cron"])
    roadmap = minutes(yaml.safe_load(ROADMAP_SYNC.read_text(encoding="utf-8"))[True]["schedule"][0]["cron"])
    assert ours < roadmap
    # Best effort only, which the header says, because the scheduler can start a run late.
    assert "best effort" in WORKFLOW.read_text(encoding="utf-8")


def test_checkout_is_the_base_ref_never_the_head():
    checkout = job()["steps"][0]
    assert checkout == {
        "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "with": {"persist-credentials": False, "ref": "${{ github.event.pull_request.base.ref || 'integration' }}"},
    }
    text = WORKFLOW.read_text(encoding="utf-8")
    for head in ("head.sha", "head.ref", "head.repo", "refs/pull", "merge_commit_sha"):
        assert head not in text
    assert [step.get("uses") for step in job()["steps"]].count(checkout["uses"]) == 1


def test_base_ref_guard_admits_only_protected_branches():
    assert job()["if"] == IF
    bases = re.findall(r"github\.event\.pull_request\.base\.ref == '([^']+)'", IF)
    assert bases == ["main", "integration"]
    assert re.findall(r"startsWith\(github\.event\.pull_request\.base\.ref, '([^']+)'\)", IF) == ["release/"]


def test_permissions_are_exactly_these():
    assert load()["permissions"] == {}
    assert job()["permissions"] == {"contents": "read", "pull-requests": "write", "issues": "read"}
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    for name in ("contents: read", "pull-requests: write", "issues: read"):
        (line,) = [line for line in lines if line.strip().startswith(name)]
        assert "# " in line, f"{name} carries no comment saying why"


def test_job_has_a_twenty_minute_timeout():
    assert job()["timeout-minutes"] == 20
    assert job()["name"] == "PR intake"
    assert list(load()["jobs"]) == ["intake"]


def test_concurrency_expression():
    assert load()["concurrency"] == {
        "group": (
            "${{ github.event.pull_request.number && format('pr-intake-{0}', github.event.pull_request.number)"
            " || inputs.pr_number && format('pr-intake-{0}', inputs.pr_number) || 'pr-intake-sweep' }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request_target' }}",
    }


def test_no_step_interpolates_into_run_in_any_job():
    for each in load()["jobs"].values():
        for step in each["steps"]:
            assert "${{" not in step.get("run", "")


def test_edited_guard_covers_body_title_and_base():
    guard = job()["if"]
    assert "(github.event.action != 'edited' || github.event.changes.body || github.event.changes.title || " \
        "github.event.changes.base)" in guard


def test_step_env_is_exactly_this():
    assert tool_step()["env"] == STEP_ENV
    # The token reaches the tool's step and no other.
    for step in job()["steps"]:
        if "run" not in step:
            assert "github.token" not in repr(step)


def test_run_line_is_exactly_this():
    assert tool_step()["run"] == "python3 -I -S tools/pr_intake.py"
    assert tool_step()["name"] == "Run the intake gate"
    assert len(job()["steps"]) == 2


def test_run_tool_against_fixtures_queues_and_comments(tmp_path):
    state = {**listing_mapping(), **pull_mapping(229, pull=with_body("Adds a thing."), comments=[])}
    done, calls, _ = run_tool(tmp_path, event(229), state)
    assert done.returncode == 0, done.stdout + done.stderr
    made = writes(calls)
    assert [args[3:5] for args in made] == [
        ["POST", f"{API}/issues/229/comments"], ["POST", f"{API}/issues/229/labels"],
    ]
    bodies = [json.loads(call["stdin"]) for call in calls if call["args"] in made]
    assert bodies[0]["body"].startswith("Thanks for this. It is queued rather than ignored.")
    assert bodies[1] == {"labels": ["status:needs-triage"]}
    assert "#229 wrote comment_post,label_set" in done.stdout.splitlines()


def test_sweep_pages_thirty_five_stubbed_pull_requests(tmp_path):
    pulls = [stub_pull(500 + n) for n in range(35)]
    done, calls, summary = run_tool(tmp_path, nightly(), sweep_state(pulls))
    assert done.returncode == 0, done.stdout + done.stderr
    assert [call["args"] for call in calls if call["args"][-1] == OPEN_PULLS] == [
        ["api", "--paginate", "--slurp", OPEN_PULLS],
    ]
    read = {call["args"][-1] for call in calls}
    assert all(f"{API}/pulls/{pull['number']}" in read for pull in pulls)
    assert " evaluated=35 " in summary.splitlines()[0] and " errors=0 " in summary.splitlines()[0]
    assert writes(calls) == []


def test_one_failed_evaluation_makes_the_sweep_red_with_its_error_line(tmp_path):
    pulls = [stub_pull(600 + n) for n in range(3)]
    state = sweep_state(pulls)
    state[f"{API}/pulls/601/files?per_page=100"] = [1, "", "HTTP 502: Bad Gateway\n"]
    done, calls, summary = run_tool(tmp_path, nightly(), state)
    assert done.returncode == 1
    lines = done.stdout.splitlines()
    assert "::error::#601: RunnerError" in lines
    assert [line for line in lines if line.startswith("::error::")] == ["::error::#601: RunnerError"]
    (line,) = [line for line in lines if line.startswith("mode=")]
    assert " evaluated=3 " in line and " errors=1 " in line
    assert summary.splitlines()[0] == line
    assert "Bad Gateway" not in done.stdout + done.stderr
    assert writes(calls) == []


def test_event_run_read_failure_exits_zero_with_no_write(tmp_path):
    state = {**listing_mapping(), **pull_mapping(229, pull=with_body("Adds a thing."), comments=[])}
    state[f"{API}/pulls/229/reviews?per_page=100"] = [1, "", "HTTP 502: Bad Gateway\n"]
    done, calls, _ = run_tool(tmp_path, event(229), state)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "::notice::#229: RunnerError, so nothing was written" in done.stdout.splitlines()
    assert writes(calls) == []


def test_accepted_lookup_is_one_call_whatever_the_body(tmp_path):
    body = " ".join(f"#{n}" for n in range(1, 400))
    state = {**listing_mapping(), **pull_mapping(229, pull=with_body(body), comments=[])}
    done, calls, _ = run_tool(tmp_path, event(229), state)
    assert done.returncode == 0, done.stdout + done.stderr
    assert sum(1 for call in calls if call["args"][-1] == ACCEPTED_LISTING) == 1
    assert not any(re.fullmatch(rf"{API}/issues/[0-9]+", call["args"][-1]) for call in calls)
