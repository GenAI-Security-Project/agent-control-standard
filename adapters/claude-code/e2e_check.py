#!/usr/bin/env python3
"""
End-to-end conformance check for an adopter's Claude Code ACS integration.

This is NOT a synthetic adapter test. It drives a REAL `claude --print`
invocation against a freshly-wired `.claude/settings.json` and a
recording Guardian, and verifies that:

  1. Claude actually fires the hooks we expect, in the order we expect.
  2. The adapter translates each hook into a wire-conformant ACS envelope.
  3. Every envelope is HMAC-signed end-to-end and the Guardian verifies it.
  4. The Guardian's verdicts are actually applied by Claude — allow lets
     the tool run, deny visibly blocks it.
  5. The handshake fires ONCE per Claude session, even when many hooks
     fire within that session.

A developer integrating ACS runs this once after wiring the adapter to
confirm their installation works in production-like conditions.

Prerequisites:
  - `claude` CLI on PATH (Claude Code installed and authenticated)
  - Python 3.10+
  - The canonical ACS schemas at $ACS_SPEC_DIR (default: the in-repo specification/v0.1.0/)

Usage (from this directory):

    python3 e2e_check.py

Each scenario takes ~10-15 seconds because real Claude is in the loop.
Total wall-clock ~60-90 seconds. Add `--model` overrides via the
CLAUDE_MODEL env var if you want a different model than the default
(claude-haiku-4-5 — chosen for speed).
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
SPEC_DIR_DEFAULT = Path(os.environ.get(
    # In-repo schemas by default (repo root is two levels up); override
    # with ACS_SPEC_DIR to validate against an alternate spec checkout.
    "ACS_SPEC_DIR", str(HERE.parents[1] / "specification" / "v0.1.0")))

sys.path.insert(0, str(COMMON_DIR))
import acs_common  # noqa: E402
from test_harness import (  # noqa: E402
    ProgrammableGuardian,
    validate_request_envelope,
    validate_response_envelope,
)


HMAC_SECRET = "e2e-test-shared-secret-not-for-production"
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5")
PER_CALL_TIMEOUT_S = 120.0


# Shared pretty-printer + helpers; see adapters/_common/e2e_report.py.
from e2e_report import (  # noqa: E402
    Report,
    assert_envelopes_signed_and_valid as _assert_envelopes_signed_and_valid,
)


def _envelope_checks(guardian, sub_results: list) -> None:
    _assert_envelopes_signed_and_valid(
        guardian, validate_request_envelope, sub_results)


# ──────────────────────────────────────────────────────────────────────
# Workdir + settings.json
# ──────────────────────────────────────────────────────────────────────

def write_settings(workdir: Path, port: int) -> None:
    """Create .claude/settings.json that wires every Claude Code hook
    type to the adapter. Adapter is invoked once per hook event; it
    reads the framework-shaped event from stdin, builds an ACS envelope,
    POSTs to the Guardian, and writes the verdict back to stdout."""
    claude_dir = workdir / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    command = (
        f"ACS_GUARDIAN_URL=http://127.0.0.1:{port}/acs "
        f"ACS_HMAC_SECRET={HMAC_SECRET} "
        f"ACS_GUARDIAN_HOST_ALLOWLIST= "
        f"python3 {ADAPTER}"
    )

    def one(matcher: str = "*"):
        return {"matcher": matcher, "hooks": [{"type": "command", "command": command}]}

    settings = {
        "hooks": {
            "SessionStart":     [one()],
            "UserPromptSubmit": [one()],
            "PreToolUse":       [one()],
            "PostToolUse":      [one()],
            "Notification":     [one()],
            "Stop":             [one()],
            "SessionEnd":       [one()],
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings, indent=2))


def run_claude(prompt: str, *, workdir: Path,
                timeout: float = PER_CALL_TIMEOUT_S) -> tuple[int, str, str]:
    """Invoke `claude --print --model <CLAUDE_MODEL>` from workdir."""
    proc = subprocess.run(
        ["claude", "--print",
         "--model", CLAUDE_MODEL,
         "--permission-mode", "acceptEdits",
         prompt],
        cwd=str(workdir),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ──────────────────────────────────────────────────────────────────────
# Programmable disposition handlers for the Guardian
# ──────────────────────────────────────────────────────────────────────

def allow_unless(*, deny_when_command_contains: str | None = None,
                  deny_reason: str = "policy denies this") -> callable:
    """Build a Guardian handler that allows by default but denies when
    a Bash command's `command` argument contains a given substring."""
    def handler(req: dict) -> dict:
        result_base = {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "chain_hash": "0" * 64,
        }
        if deny_when_command_contains is not None:
            payload = req["params"].get("payload") or {}
            args = payload.get("arguments") or {}
            cmd_arg = args.get("command")
            cmd_str = ""
            if isinstance(cmd_arg, dict):
                cmd_str = str(cmd_arg.get("value", ""))
            elif isinstance(cmd_arg, str):
                cmd_str = cmd_arg
            if deny_when_command_contains in cmd_str:
                return {**result_base, "decision": "deny",
                        "reasoning": deny_reason,
                        "reason_codes": ["policy_deny"]}
        return {**result_base, "decision": "allow"}
    return handler


# ──────────────────────────────────────────────────────────────────────
# Scenario runner
# ──────────────────────────────────────────────────────────────────────

def header_for_scenario(report: Report, num: int, total: int, title: str,
                         prompt: str, expectation: str) -> None:
    report.case(num, total, title)
    report.field("Prompt:", f"\"{prompt}\"")
    report.field("Expected:", expectation)


def dump_session_envelopes(report: Report, guardian: ProgrammableGuardian,
                            session_id: str | None = None) -> None:
    """For every envelope received in this session, print method name +
    a one-line summary. For interesting ones (toolCallRequest), print the
    full JSON."""
    if session_id is None:
        envelopes = list(guardian.received)
    else:
        envelopes = [r for r in guardian.received
                      if r.get("params", {}).get("metadata", {}).get("session_id") == session_id]

    methods = [(r.get("method", ""), r.get("params", {}).get("request_id", "")[:8])
                for r in envelopes]
    print(f"      ── Hooks Claude fired (in order)")
    for method, rid in methods:
        print(f"        {method:35s}  req={rid}…")

    # Print the first toolCallRequest envelope verbatim — what Claude actually emits
    pretool = next((r for r in envelopes if r.get("method") == "steps/toolCallRequest"), None)
    if pretool:
        report.json_block("First steps/toolCallRequest envelope (verbatim)",
                           pretool, truncate=140)


# ──────────────────────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────────────────────

TOTAL_SCENARIOS = 4


def scenario_allow(report: Report, workdir: Path,
                    guardian: ProgrammableGuardian) -> None:
    marker = f"ACS_E2E_OK_{uuid.uuid4().hex[:8]}"
    prompt = f"Use the Bash tool exactly once to run: echo {marker}"
    header_for_scenario(
        report, 1, TOTAL_SCENARIOS,
        title="ALLOW — benign Bash; Claude runs the tool",
        prompt=prompt,
        expectation=(f"Claude fires PreToolUse(Bash); Guardian allows; "
                      f"the Bash tool actually executes; marker {marker!r} "
                      f"appears in the toolCallResult envelope"),
    )

    guardian.reset()
    guardian.handlers["steps/toolCallRequest"] = allow_unless()

    rc, stdout, stderr = run_claude(prompt, workdir=workdir)

    report.quote_block(f"Claude's stdout (rc={rc})", stdout, max_chars=300)

    sub_results = []
    sub_results.append(("Guardian received at least one envelope",
                         len(guardian.received) > 0,
                         f"received {len(guardian.received)}"))
    methods = set(r.get("method", "") for r in guardian.received)
    sub_results.append(("Guardian received handshake/hello",
                         "handshake/hello" in methods, ""))
    sub_results.append(("Guardian received steps/toolCallRequest",
                         "steps/toolCallRequest" in methods, ""))
    _envelope_checks(guardian, sub_results)
    # Assert on the toolCallResult envelope, not Claude's prose summary
    # — Claude may rephrase tool output.
    result_envs = [r for r in guardian.received
                    if r.get("method") == "steps/toolCallResult"]
    marker_in_tool_output = False
    for r in result_envs:
        outputs = r.get("params", {}).get("payload", {}).get("outputs", [])
        for o in outputs:
            value = o.get("value")
            if isinstance(value, dict):
                if marker in json.dumps(value):
                    marker_in_tool_output = True
                    break
            elif isinstance(value, str) and marker in value:
                marker_in_tool_output = True
                break
    sub_results.append(("Marker appears in the toolCallResult envelope (Bash actually ran)",
                         marker_in_tool_output,
                         "marker found in tool output" if marker_in_tool_output
                         else f"marker absent across {len(result_envs)} toolCallResult envelope(s)"))

    dump_session_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("allow-path", all(ok for _, ok, _ in sub_results))


def scenario_deny(report: Report, workdir: Path,
                   guardian: ProgrammableGuardian) -> None:
    marker = f"ACS_E2E_RAN_{uuid.uuid4().hex[:8]}"
    # Benign prompt: the Guardian, not Claude's own safety layer, does the blocking.
    prompt = f"Use the Bash tool exactly once to run: echo {marker}"
    header_for_scenario(
        report, 2, TOTAL_SCENARIOS,
        title="DENY — Guardian blocks a tool call; Claude does not run it",
        prompt=prompt,
        expectation=("Guardian returns DENY for the Bash call (forced via "
                      "Guardian config, not Claude's own safety layer); "
                      "Claude does NOT execute the command; "
                      f"marker {marker!r} is NOT in any toolCallResult"),
    )

    # Deny every Bash call so ACS enforcement is exercised apart from
    # Claude's own safety filters.
    def deny_all_bash(req: dict) -> dict:
        payload = req["params"].get("payload") or {}
        tool_name = payload.get("tool", {}).get("name", "")
        base = {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "chain_hash": "0" * 64,
        }
        if tool_name in ("Bash", "Shell"):
            return {**base, "decision": "deny",
                    "reasoning": "E2E test: Guardian configured to deny all Bash",
                    "reason_codes": ["e2e_force_deny"]}
        return {**base, "decision": "allow"}

    guardian.reset()
    guardian.handlers["steps/toolCallRequest"] = deny_all_bash

    rc, stdout, stderr = run_claude(prompt, workdir=workdir)

    report.quote_block(f"Claude's stdout (rc={rc})", stdout, max_chars=300)

    sub_results = []
    methods = set(r.get("method", "") for r in guardian.received)
    saw_pretool = "steps/toolCallRequest" in methods
    sub_results.append(("Guardian received steps/toolCallRequest "
                         "(Claude attempted the tool)",
                         saw_pretool, ""))
    deny_resp = next((r for r in guardian.sent
                       if r.get("result", {}).get("decision") == "deny"), None)
    sub_results.append(("Guardian returned a deny verdict",
                         deny_resp is not None,
                         "deny issued" if deny_resp else "no deny found"))
    # The marker must be absent from every toolCallResult output.
    result_envs = [r for r in guardian.received
                    if r.get("method") == "steps/toolCallResult"]
    marker_in_results = False
    for r in result_envs:
        outputs = r.get("params", {}).get("payload", {}).get("outputs", [])
        for o in outputs:
            value = o.get("value")
            if isinstance(value, dict) and marker in json.dumps(value):
                marker_in_results = True
                break
            elif isinstance(value, str) and marker in value:
                marker_in_results = True
                break
    sub_results.append(("Marker is NOT in any toolCallResult (command did not run)",
                         not marker_in_results,
                         "marker absent" if not marker_in_results else "MARKER PRESENT (command ran despite deny)"))

    dump_session_envelopes(report, guardian)
    if deny_resp:
        report.json_block("Guardian's deny verdict (verbatim)",
                           deny_resp["result"], truncate=140)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("deny-path", all(ok for _, ok, _ in sub_results))


def scenario_read_tool(report: Report, workdir: Path,
                        guardian: ProgrammableGuardian) -> None:
    prompt = "Use the Read tool to read the file /etc/hostname; just report what you read."
    header_for_scenario(
        report, 3, TOTAL_SCENARIOS,
        title="READ TOOL — different tool, same wire contract",
        prompt=prompt,
        expectation=("Claude fires PreToolUse(Read); envelope contains the "
                      "file_path argument wrapped per tool-call-request.json"),
    )

    guardian.reset()
    guardian.handlers["steps/toolCallRequest"] = allow_unless()

    rc, stdout, _ = run_claude(prompt, workdir=workdir)
    report.quote_block(f"Claude's stdout (rc={rc})", stdout, max_chars=200)

    sub_results = []
    read_envs = [r for r in guardian.received
                  if r.get("method") == "steps/toolCallRequest"
                  and r["params"]["payload"]["tool"]["name"] == "Read"]
    sub_results.append(("Guardian received a Read steps/toolCallRequest",
                         bool(read_envs), f"{len(read_envs)} found"))
    if read_envs:
        env = read_envs[0]
        args = env["params"]["payload"].get("arguments", {})
        # tool-call-request.json:26-37 — arguments wrapped as {value: ...}
        sub_results.append(
            ("Arguments are wrapped per tool-call-request.json:26-37",
             all(isinstance(v, dict) and "value" in v for v in args.values()),
             f"args={list(args.keys())}"))
        sub_results.append(
            ("Read tool's file_path appears in arguments",
             "file_path" in args, ""))

    dump_session_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("read-tool-path", all(ok for _, ok, _ in sub_results))


def scenario_handshake_once(report: Report, workdir: Path,
                              guardian: ProgrammableGuardian) -> None:
    prompt = ("Use the Bash tool exactly twice: first run "
               "'echo first-call', then run 'echo second-call'.")
    header_for_scenario(
        report, 4, TOTAL_SCENARIOS,
        title="HANDSHAKE — fires exactly ONCE per Claude session (§4)",
        prompt=prompt,
        expectation=("Claude fires multiple hooks (handshake at session "
                      "start, then ≥2 PreToolUse + PostToolUse pairs); "
                      "Guardian sees exactly 1 handshake/hello for the session"),
    )

    guardian.reset()
    guardian.handlers["steps/toolCallRequest"] = allow_unless()
    # Fresh handshake cache so this scenario's first envelope DOES handshake
    cache_dir = workdir / ".acs-handshake-cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir()
    os.environ["ACS_HANDSHAKE_CACHE"] = str(cache_dir)

    rc, stdout, _ = run_claude(prompt, workdir=workdir)
    report.quote_block(f"Claude's stdout (rc={rc})", stdout, max_chars=250)

    handshakes = [r for r in guardian.received if r.get("method") == "handshake/hello"]
    pretools = [r for r in guardian.received if r.get("method") == "steps/toolCallRequest"]
    posttools = [r for r in guardian.received if r.get("method") == "steps/toolCallResult"]
    methods_in_order = [r.get("method", "") for r in guardian.received]

    print(f"      ── Hooks Claude fired (in order)")
    for m in methods_in_order:
        print(f"        {m}")

    sub_results = [
        ("Exactly 1 handshake/hello per session", len(handshakes) == 1,
         f"got {len(handshakes)}"),
        ("≥2 steps/toolCallRequest (Claude did call Bash twice)",
         len(pretools) >= 2, f"got {len(pretools)}"),
        ("≥2 steps/toolCallResult (each Bash returned)",
         len(posttools) >= 2, f"got {len(posttools)}"),
    ]
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("handshake-once-per-session", all(ok for _, ok, _ in sub_results))


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    # Prereq: claude on PATH
    if shutil.which("claude") is None:
        print("FATAL: `claude` CLI not found on PATH.", file=sys.stderr)
        print("Install Claude Code first: https://docs.claude.com/claude-code",
              file=sys.stderr)
        return 1
    if not SPEC_DIR_DEFAULT.exists():
        print(f"FATAL: canonical schemas missing at {SPEC_DIR_DEFAULT}",
              file=sys.stderr)
        print("Set ACS_SPEC_DIR to a clone of "
              "GenAI-Security-Project/agent-control-standard/specification/v0.1.0/", file=sys.stderr)
        return 1

    report = Report()
    report.print_header(
        "ACS Claude Code adapter — REAL end-to-end conformance check",
        "",
        "This test drives a REAL `claude --print` invocation against",
        "the adapter you wired up. It is NOT synthetic — it verifies",
        "that YOUR installed Claude Code actually fires the hooks ACS",
        "expects, that they are correctly translated to wire envelopes,",
        "signed end-to-end, and applied by Claude when the Guardian decides.",
        "",
        f"Spec source : {SPEC_DIR_DEFAULT}",
        f"Adapter     : {ADAPTER}",
        f"Claude CLI  : {shutil.which('claude')}",
        f"Model       : {CLAUDE_MODEL}",
        "",
        f"{TOTAL_SCENARIOS} scenarios — each invokes real Claude (~10-15s each).",
        width=68,
    )

    # Programmable Guardian — records every envelope, signs every response
    # with the same HMAC secret the adapter uses, can be configured per
    # scenario to return specific dispositions.
    guardian = ProgrammableGuardian(hmac_secret=HMAC_SECRET)
    guardian.start()

    workdir = Path(tempfile.mkdtemp(prefix="acs-e2e-real-"))
    try:
        write_settings(workdir, guardian.port)
        scenario_allow(report, workdir, guardian)
        scenario_deny(report, workdir, guardian)
        scenario_read_tool(report, workdir, guardian)
        scenario_handshake_once(report, workdir, guardian)
    finally:
        guardian.stop()
        shutil.rmtree(workdir, ignore_errors=True)

    return 0 if report.summary("ACS-CORE SMOKE PASS (claude-code)", width=68) else 1


if __name__ == "__main__":
    sys.exit(main())
