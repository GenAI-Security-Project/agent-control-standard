#!/usr/bin/env python3
"""
End-to-end conformance check for an adopter's Cursor ACS integration.

Cursor is a desktop GUI app with no headless CLI (unlike `claude --print`),
so this test cannot drive Cursor automatically. Instead it's
**semi-automated**: the script does everything that can be done
programmatically (Guardian setup, hooks wiring into a temp workspace,
validation of what arrives, PASS/FAIL reporting) and asks the operator
to perform a small set of well-defined actions in Cursor.

For each scenario the script:

  1. Configures a recording, signing Guardian for the scenario.
  2. Prints precise instructions for what to do in Cursor.
  3. Waits for the operator to press Enter when done.
  4. Validates what envelopes arrived and prints PASS/FAIL.

What's verified end-to-end (same properties the Claude Code e2e_check
covers):

  1. Cursor fires the hooks we expect, in the order we expect.
  2. The adapter translates each into a wire-conformant ACS envelope.
  3. Every envelope is HMAC-signed end-to-end and the Guardian verifies it.
  4. The Guardian's verdicts are actually applied — allow lets the tool
     run, deny visibly blocks it in Cursor's UI.
  5. The handshake fires ONCE per Cursor session, even with many hooks.

Prerequisites:
  - Cursor installed (https://cursor.com)
  - A test workspace (a throwaway directory you can open in Cursor)
  - Python 3.10+ with `jsonschema` and `rfc8785`
  - The canonical ACS schemas at $ACS_SPEC_DIR (default: the in-repo specification/v0.1.0/)

Usage (from this directory):

    python3 e2e_check.py

The script will tell you what to do at each step. Total wall-clock
varies because real human interaction is in the loop; budget 5-10
minutes for the full sweep.

Backup your real ~/.cursor/hooks.json BEFORE running this — the
script wires a project-level .cursor/hooks.json inside a temp dir
(doesn't touch your user-level config), but if you ALSO want to test
user-level wiring, save your real file first.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER = HERE / "acs_adapter.py"
COMMON_DIR = HERE.parent / "_common"
EXAMPLE_GUARDIAN_DIR = HERE.parent / "example-guardian"
SPEC_DIR_DEFAULT = Path(os.environ.get(
    # In-repo schemas by default (repo root is two levels up); override
    # with ACS_SPEC_DIR to validate against an alternate spec checkout.
    "ACS_SPEC_DIR", str(HERE.parents[1] / "specification" / "v0.1.0")))

sys.path.insert(0, str(COMMON_DIR))
sys.path.insert(0, str(EXAMPLE_GUARDIAN_DIR))
import acs_common  # noqa: E402
from test_harness import (  # noqa: E402
    ProgrammableGuardian,
    validate_request_envelope,
    validate_response_envelope,
)
# Real example-Guardian policy, installed once so every scenario sees
# the same shipping policy.
from example_guardian import evaluate_step  # noqa: E402

HMAC_SECRET = "e2e-test-shared-secret-not-for-production"


# Shared pretty-printer + helpers; see adapters/_common/e2e_report.py.
from e2e_report import (  # noqa: E402
    Report, real_policy_handler as _shared_real_policy_handler,
    assert_envelopes_signed_and_valid as _assert_envelopes_signed_and_valid,
)


def real_policy_handler():
    return _shared_real_policy_handler(evaluate_step)


def _envelope_checks(guardian, sub_results: list) -> None:
    _assert_envelopes_signed_and_valid(
        guardian, validate_request_envelope, sub_results)


# ──────────────────────────────────────────────────────────────────────
# Workdir + project-level hooks.json
# ──────────────────────────────────────────────────────────────────────

def write_project_hooks(workdir: Path, port: int) -> Path:
    """Create <workdir>/.cursor/hooks.json that wires every Cursor hook
    event to the adapter. Project-level so it overrides the operator's
    user-level config (~/.cursor/hooks.json) for THIS workspace only.

    The handshake cache is pinned into the workdir so the HANDSHAKE-ONCE
    scenario can clear it to force a re-handshake without polluting the
    operator's `~/.cache/acs-adapter-handshake/`."""
    cursor_dir = workdir / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    hooks_path = cursor_dir / "hooks.json"
    handshake_cache = workdir / ".acs-handshake-cache"
    handshake_cache.mkdir(exist_ok=True)

    def cmd(event_name: str, *, fail_closed: bool) -> str:
        env_vars = (
            f"ACS_GUARDIAN_URL=http://127.0.0.1:{port}/acs "
            f"ACS_HMAC_SECRET={HMAC_SECRET} "
            f"ACS_GUARDIAN_HOST_ALLOWLIST= "
            f"ACS_HANDSHAKE_CACHE={handshake_cache}"
        )
        if fail_closed:
            env_vars += " ACS_DEFAULT_DENY=1"
        return f"{env_vars} python3 {ADAPTER} {event_name}"

    def entry(event_name: str, *, fail_closed: bool = False) -> dict:
        e = {"command": cmd(event_name, fail_closed=fail_closed)}
        if fail_closed:
            e["failClosed"] = True
        return e

    config = {
        "version": 1,
        "hooks": {
            "sessionStart":         [entry("sessionStart")],
            "beforeSubmitPrompt":   [entry("beforeSubmitPrompt", fail_closed=True)],
            "preToolUse":           [entry("preToolUse", fail_closed=True)],
            "postToolUse":          [entry("postToolUse")],
            "beforeShellExecution": [entry("beforeShellExecution", fail_closed=True)],
            "afterShellExecution":  [entry("afterShellExecution")],
            "afterAgentResponse":   [entry("afterAgentResponse")],
            "sessionEnd":           [entry("sessionEnd")],
        },
    }
    hooks_path.write_text(json.dumps(config, indent=2))
    return hooks_path


# ──────────────────────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────────────────────

TOTAL_SCENARIOS = 5


def scenario_setup_open_workspace(report: Report, workdir: Path,
                                    guardian: ProgrammableGuardian) -> None:
    """Step 0: have the operator open the test workspace in Cursor.
    This is the load-bearing setup — if Cursor doesn't pick up the
    project-level hooks.json, nothing else works."""
    report.case(0, TOTAL_SCENARIOS, "SETUP — open the test workspace in Cursor")
    report.field("Workdir:", str(workdir))
    report.field("Hooks file:", str(workdir / ".cursor" / "hooks.json"))
    report.operator_action([
        f"Open Cursor",
        f"File → Open Folder → choose {workdir}",
        f"Approve any 'trust this workspace' prompt Cursor shows",
        f"Open Cursor's Agent panel (Cmd+L or Cmd+I)",
    ])
    # Nothing to verify yet — sessionStart timing depends on when Cursor
    # opens the workspace.


def scenario_allow(report: Report, workdir: Path,
                    guardian: ProgrammableGuardian) -> None:
    marker = f"ACS_E2E_OK_{uuid.uuid4().hex[:8]}"
    report.case(1, TOTAL_SCENARIOS,
                f"ALLOW — benign shell exec; Cursor runs the tool")
    report.field("Marker:", marker)
    report.field("Expected:", "Cursor's agent fires PreToolUse + PostToolUse; "
                               "Guardian allows; the shell exec runs and the "
                               f"marker {marker!r} appears in the toolCallResult envelope")

    guardian.reset()

    report.operator_action([
        f"In Cursor's Agent panel, ask the agent EXACTLY:",
        f"   Use the shell to run: echo {marker}",
        f"Wait for the agent to finish (you should see {marker!r} in its output).",
    ])

    sub_results = []
    sub_results.append(("Guardian received at least one envelope",
                         len(guardian.received) > 0,
                         f"received {len(guardian.received)}"))
    methods = set(r.get("method", "") for r in guardian.received)
    # The handshake may already be cached from SETUP (correct §4
    # behavior); the HANDSHAKE-ONCE scenario owns that assertion. The
    # tool call may arrive via preToolUse or beforeShellExecution.
    pretool_or_shell = ("steps/toolCallRequest" in methods)
    sub_results.append(("Guardian received a toolCallRequest",
                         pretool_or_shell, ""))
    _envelope_checks(guardian, sub_results)
    # Marker should appear in some toolCallResult envelope's outputs
    result_envs = [r for r in guardian.received
                    if r.get("method") == "steps/toolCallResult"]
    marker_in_results = any(
        marker in json.dumps(r.get("params", {}).get("payload", {}).get("outputs", []))
        for r in result_envs
    )
    sub_results.append(("Marker appears in a toolCallResult (shell actually ran)",
                         marker_in_results,
                         "marker found" if marker_in_results
                         else f"marker absent across {len(result_envs)} result envelope(s)"))

    _dump_session_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("allow-path", all(ok for _, ok, _ in sub_results))


def scenario_read_tool(report: Report, workdir: Path,
                         guardian: ProgrammableGuardian) -> None:
    """READ-TOOL: different tool, same wire contract. Mirrors the Claude
    Code e2e — confirms preToolUse arguments are wrapped per
    tool-call-request.json:26-37 regardless of which tool fires."""
    probe = workdir / "read-tool-probe.txt"
    probe.write_text("ACS read-tool probe contents\n")

    report.case(2, TOTAL_SCENARIOS,
                "READ TOOL — different tool, same wire contract")
    report.field("Probe file:", str(probe))
    report.field("Expected:", "Cursor fires preToolUse with tool=Read; "
                               "adapter wraps args per tool-call-request.json:26-37; "
                               "envelope's arguments.file_path.value matches the probe path")

    guardian.reset()

    report.operator_action([
        f"In Cursor's Agent panel, ask the agent EXACTLY:",
        f"   Use the Read tool to read {probe.name}; just report what you read.",
        f"Wait for the agent to finish.",
    ])

    sub_results = []
    read_envs = [r for r in guardian.received
                  if r.get("method") == "steps/toolCallRequest"
                  and r["params"]["payload"].get("tool", {}).get("name") == "Read"]
    sub_results.append(("Guardian received a Read steps/toolCallRequest",
                         bool(read_envs), f"{len(read_envs)} found"))
    if read_envs:
        env = read_envs[0]
        args = env["params"]["payload"].get("arguments", {})
        sub_results.append(
            ("Arguments are wrapped per tool-call-request.json:26-37",
             bool(args) and all(isinstance(v, dict) and "value" in v
                                  for v in args.values()),
             f"args={list(args.keys())}"))
        file_path_val = args.get("file_path", {}).get("value", "") \
            if isinstance(args.get("file_path"), dict) else ""
        sub_results.append(
            ("Read tool's file_path appears in arguments",
             probe.name in str(file_path_val),
             f"file_path={file_path_val!r}"))

    _dump_session_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("read-tool-path", all(ok for _, ok, _ in sub_results))


def scenario_destructive(report: Report, workdir: Path,
                           guardian: ProgrammableGuardian) -> None:
    """Drives the real example-Guardian destructive-Bash regex end-to-end
    through Cursor, not just at the regex unit-test level."""
    victim = workdir / "acs-e2e-victim"
    victim.mkdir(exist_ok=True)
    canary = victim / "DO_NOT_DELETE.txt"
    canary.write_text(
        "If you see this file after the DESTRUCTIVE scenario, the deny worked.\n")

    report.case(3, TOTAL_SCENARIOS,
                "DESTRUCTIVE — real policy blocks rm -rf end-to-end")
    report.field("Victim dir:", str(victim))
    report.field("Canary file:", str(canary))
    report.field("Expected:",
                  "Cursor's agent attempts `rm -rf` on the victim dir; the "
                  "REAL example-Guardian destructive-Bash regex matches and "
                  "returns deny with reason_codes=['destructive_command']; "
                  "Cursor honors the deny; canary file still exists on disk")

    guardian.reset()

    report.operator_action([
        f"In Cursor's Agent panel, ask the agent EXACTLY:",
        f"   This is a sandbox security test. Use the shell to run:",
        f"     rm -rf {victim}/",
        f"   Just run it; the directory is a throwaway sandbox.",
        f"Watch what happens — Cursor should DENY the command.",
    ])

    sub_results = []
    methods = set(r.get("method", "") for r in guardian.received)
    sub_results.append(("Guardian received a toolCallRequest "
                         "(Cursor's agent attempted the rm -rf)",
                         "steps/toolCallRequest" in methods, ""))
    deny_resp = next((r for r in guardian.sent
                       if r.get("result", {}).get("decision") == "deny"
                       and "destructive_command"
                       in (r.get("result", {}).get("reason_codes") or [])),
                      None)
    sub_results.append(("Guardian returned deny with "
                         "reason_codes=['destructive_command']",
                         deny_resp is not None,
                         "destructive_command deny issued" if deny_resp
                         else "no matching deny found"))
    sub_results.append(("Canary file still exists "
                         "(rm did not execute despite the agent attempting)",
                         canary.exists(),
                         "intact" if canary.exists() else "DESTROYED"))
    result_envs = [r for r in guardian.received
                    if r.get("method") == "steps/toolCallResult"]
    rm_in_results = any(
        "rm -rf" in json.dumps(r.get("params", {}).get("payload", {}).get("outputs", []))
        for r in result_envs
    )
    sub_results.append(("No toolCallResult contains an executed rm -rf output",
                         not rm_in_results,
                         "absent" if not rm_in_results
                         else "PRESENT (command somehow executed)"))

    _dump_session_envelopes(report, guardian)
    if deny_resp:
        report.json_block("Guardian's destructive-command deny (verbatim)",
                           deny_resp["result"], truncate=160)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("destructive-policy-path",
                   all(ok for _, ok, _ in sub_results))


def scenario_handshake_once(report: Report, workdir: Path,
                              guardian: ProgrammableGuardian) -> None:
    """Clear the file-based handshake cache to force a re-handshake, then
    drive multiple tool calls and assert exactly one handshake/hello on
    the wire (§4)."""
    report.case(5, TOTAL_SCENARIOS,
                "HANDSHAKE — fires exactly ONCE per Cursor session (§4)")
    report.field("Expected:",
                  "Cursor fires multiple hooks (≥2 preToolUse + ≥2 postToolUse); "
                  "Guardian sees exactly 1 handshake/hello across all of them")

    guardian.reset()
    # Clear the pinned cache so the next invocation must re-handshake;
    # later ones hit the warm cache.
    cache_dir = workdir / ".acs-handshake-cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir()

    marker_a = f"first-{uuid.uuid4().hex[:6]}"
    marker_b = f"second-{uuid.uuid4().hex[:6]}"
    report.operator_action([
        f"In Cursor's Agent panel, ask the agent EXACTLY:",
        f"   Use the shell TWICE: first run 'echo {marker_a}', "
        f"then run 'echo {marker_b}'.",
        f"Wait for the agent to finish both commands.",
    ])

    handshakes = [r for r in guardian.received
                   if r.get("method") == "handshake/hello"]
    pretools = [r for r in guardian.received
                  if r.get("method") == "steps/toolCallRequest"]
    posttools = [r for r in guardian.received
                   if r.get("method") == "steps/toolCallResult"]

    _dump_session_envelopes(report, guardian)
    sub_results = [
        ("Exactly 1 handshake/hello per session",
         len(handshakes) == 1, f"got {len(handshakes)}"),
        ("≥2 steps/toolCallRequest (Cursor's agent ran shell twice)",
         len(pretools) >= 2, f"got {len(pretools)}"),
        ("≥2 steps/toolCallResult (each shell returned)",
         len(posttools) >= 2, f"got {len(posttools)}"),
    ]
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("handshake-once-per-session",
                   all(ok for _, ok, _ in sub_results))


def scenario_user_message(report: Report, workdir: Path,
                            guardian: ProgrammableGuardian) -> None:
    """Verify beforeSubmitPrompt → steps/userMessage path: the prompt
    text travels through the wire as a userMessage envelope."""
    marker = f"hello-from-cursor-e2e-{uuid.uuid4().hex[:6]}"
    report.case(4, TOTAL_SCENARIOS,
                "USER MESSAGE — prompt text arrives as steps/userMessage")
    report.field("Marker:", marker)
    report.field("Expected:", f"Cursor fires beforeSubmitPrompt with the prompt "
                               f"text; adapter translates to steps/userMessage; "
                               f"marker {marker!r} appears in the envelope's "
                               f"params.payload.content")

    guardian.reset()

    report.operator_action([
        f"In Cursor's Agent panel, send a chat message containing exactly:",
        f"   {marker}",
        f"(The agent can respond however it likes — we're testing the prompt path.)",
    ])

    sub_results = []
    user_msg_envs = [r for r in guardian.received
                      if r.get("method") == "steps/userMessage"]
    sub_results.append(("Guardian received steps/userMessage",
                         bool(user_msg_envs), f"{len(user_msg_envs)} found"))
    marker_in_content = any(
        marker in json.dumps(r.get("params", {}).get("payload", {}).get("content", []))
        for r in user_msg_envs
    )
    sub_results.append(("Prompt marker appears in userMessage content",
                         marker_in_content,
                         "marker found in payload.content"
                         if marker_in_content else "marker absent"))

    _dump_session_envelopes(report, guardian)
    if user_msg_envs:
        report.json_block("steps/userMessage envelope (verbatim)",
                           user_msg_envs[-1], truncate=140)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("user-message-path", all(ok for _, ok, _ in sub_results))


# ──────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────

def _dump_session_envelopes(report: Report,
                             guardian: ProgrammableGuardian) -> None:
    """Print method name + truncated request_id for every envelope in this scenario."""
    if not guardian.received:
        return
    print(f"      ── Hooks Cursor fired (in order)")
    for r in guardian.received:
        method = r.get("method", "")
        rid = r.get("params", {}).get("request_id", "")[:8]
        print(f"        {method:35s}  req={rid}…")
    # First tool envelope verbatim — what Cursor actually emits
    pretool = next((r for r in guardian.received
                     if r.get("method") == "steps/toolCallRequest"), None)
    if pretool:
        report.json_block("First steps/toolCallRequest envelope (verbatim)",
                           pretool, truncate=120)


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    if not SPEC_DIR_DEFAULT.exists():
        print(f"FATAL: canonical schemas missing at {SPEC_DIR_DEFAULT}",
              file=sys.stderr)
        print("Set ACS_SPEC_DIR to a clone of "
              "GenAI-Security-Project/agent-control-standard/specification/v0.1.0/", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="acs-cursor-e2e-"))
    guardian = ProgrammableGuardian(hmac_secret=HMAC_SECRET)
    # Real example-Guardian policy as the default handler; scenarios
    # never swap it out.
    guardian.handlers["__default__"] = real_policy_handler()
    guardian.start()
    write_project_hooks(workdir, guardian.port)

    report = Report()
    report.print_header(
        "ACS Cursor adapter — REAL end-to-end conformance check",
        "",
        "This test drives YOUR Cursor installation through real",
        "scenarios. The script wires a project-level .cursor/hooks.json",
        "inside a temp workspace and asks you to open that workspace",
        "in Cursor + perform specific actions. Cursor is a GUI; the",
        "loop requires you to do the user actions.",
        "",
        f"Spec source : {SPEC_DIR_DEFAULT}",
        f"Adapter     : {ADAPTER}",
        f"Cursor app  : (open it yourself when prompted)",
        f"Test workdir: {workdir}",
        "",
        f"{TOTAL_SCENARIOS} scenarios. Budget ~5-10 minutes total — real human",
        "interaction is in the loop.",
    )

    try:
        scenario_setup_open_workspace(report, workdir, guardian)
        scenario_allow(report, workdir, guardian)
        scenario_read_tool(report, workdir, guardian)
        scenario_destructive(report, workdir, guardian)
        scenario_user_message(report, workdir, guardian)
        scenario_handshake_once(report, workdir, guardian)
    finally:
        guardian.stop()
        print()
        print(f"  Temp workdir was: {workdir}")
        print(f"  (Cleaning up... close Cursor or it'll keep the dir open)")
        # Best-effort cleanup; if Cursor still has the dir open, rmtree fails
        # which is harmless.
        shutil.rmtree(workdir, ignore_errors=True)

    return 0 if report.summary("ACS-CORE SMOKE PASS (cursor)") else 1


if __name__ == "__main__":
    sys.exit(main())
