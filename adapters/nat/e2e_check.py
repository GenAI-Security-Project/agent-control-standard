#!/usr/bin/env python3
"""
End-to-end conformance check for an adopter's NAT ACS integration.

Drives the real `ACSMiddleware` against a recording Guardian wired to
the real `example_guardian.evaluate_step` policy — every scenario sees
the same shipping policy, no synthetic per-scenario handlers.

Alongside `tests/test_live.py` (which asserts on side-effect counters),
this script asserts on the wire envelopes the Guardian receives: every
envelope HMAC-signed and valid against the canonical ACS JSON Schema,
arguments wrapped per tool-call-request.json:26-37, handshake once per
session, the 4 lifecycle boundary hooks on WORKFLOW_START/END. It also
runs the destructive scenario: `rm -rf` against a victim directory with
a canary file that must survive the deny.

Fully automated. NAT runs in-process, so unlike the Cursor e2e check
there is no operator-in-the-loop: just run and watch.

Prerequisites:
  - nvidia-nat-core installed (>= 1.7.0)
  - The canonical ACS schemas at $ACS_SPEC_DIR
    (default: the in-repo specification/v0.1.0/)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE
COMMON_DIR = HERE.parent / "_common"
EXAMPLE_GUARDIAN_DIR = HERE.parent / "example-guardian"
SPEC_DIR_DEFAULT = Path(os.environ.get(
    # In-repo schemas by default (repo root is two levels up); override
    # with ACS_SPEC_DIR to validate against an alternate spec checkout.
    "ACS_SPEC_DIR", str(HERE.parents[1] / "specification" / "v0.1.0")))

sys.path.insert(0, str(COMMON_DIR))
sys.path.insert(0, str(EXAMPLE_GUARDIAN_DIR))
sys.path.insert(0, str(ADAPTER_DIR))

import acs_common  # noqa: E402
from test_harness import (  # noqa: E402
    ProgrammableGuardian,
    validate_request_envelope,
)
from e2e_report import (  # noqa: E402
    Report, real_policy_handler,
    assert_envelopes_signed_and_valid as _assert_envelopes_signed_and_valid,
)
# Real example-Guardian policy, installed once for the whole run.
from example_guardian import evaluate_step  # noqa: E402

HMAC_SECRET = "e2e-test-shared-secret-not-for-production"

try:
    from nat.middleware.middleware import FunctionMiddlewareContext  # type: ignore[import-not-found]
    _NAT_OK = True
except ImportError:
    _NAT_OK = False


# ──────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────

def _build_middleware(guardian_url: str, *, default_deny: bool = True,
                       session_id: str | None = None):
    """Construct an ACSMiddleware with the same env the operator uses
    in production (HMAC secret on; signs every envelope)."""
    os.environ["ACS_HMAC_SECRET"] = HMAC_SECRET
    from acs_adapter import ACSMiddleware, ACSMiddlewareConfig  # noqa: E402
    return ACSMiddleware(ACSMiddlewareConfig(
        guardian_url=guardian_url,
        default_deny=default_deny,
        session_id=session_id or str(uuid.uuid4()),
    ))


def _ctx(tool_name: str):
    return FunctionMiddlewareContext(
        name=tool_name, config=None, description=None,
        input_schema=None,
        single_output_schema=type(None),
        stream_output_schema=type(None),
    )


# Bind the canonical-schema validator once so per-scenario callsites stay short.
def _envelope_checks(guardian, sub_results: list) -> None:
    _assert_envelopes_signed_and_valid(
        guardian, validate_request_envelope, sub_results)


# ──────────────────────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────────────────────

TOTAL_SCENARIOS = 5


def scenario_allow(report: Report, guardian: ProgrammableGuardian) -> None:
    marker = f"ACS_E2E_OK_{uuid.uuid4().hex[:8]}"
    report.case(1, TOTAL_SCENARIOS,
                f"ALLOW — benign Bash function executes; return value flows back")
    report.field("Marker:", marker)
    report.field("Expected:", "real policy allows; function executes once; "
                               "return value contains marker; "
                               "Guardian sees handshake + toolCallRequest + toolCallResult")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs", session_id="nat-e2e-allow")
    executed = {"count": 0, "got_command": None}

    async def target(command: str) -> str:
        executed["count"] += 1
        executed["got_command"] = command
        return f"executed: {command} -> {marker}"

    result = asyncio.run(mw.function_middleware_invoke(
        command=f"echo {marker}", call_next=target, context=_ctx("Bash")))

    methods = [r.get("method", "") for r in guardian.received]
    sub_results = []
    sub_results.append(("Function actually executed (counter = 1)",
                         executed["count"] == 1, f"count={executed['count']}"))
    sub_results.append(("Function received the expected command",
                         executed["got_command"] == f"echo {marker}",
                         f"got={executed['got_command']!r}"))
    sub_results.append(("Return value flows back through middleware",
                         marker in str(result), f"got={result!r}"))
    sub_results.append(("Guardian received handshake/hello",
                         "handshake/hello" in methods, ""))
    sub_results.append(("Guardian received steps/toolCallRequest",
                         "steps/toolCallRequest" in methods, ""))
    _envelope_checks(guardian, sub_results)

    _dump_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("allow-path", all(ok for _, ok, _ in sub_results))


def scenario_destructive(report: Report, guardian: ProgrammableGuardian) -> None:
    """The load-bearing scenario. The unit test asserts counter == 0; we
    additionally write a canary file inside a victim dir, then ask the
    middleware to rm -rf the victim. If the file vanishes despite the
    Guardian's deny, the enforcement failed silently — the counter check
    alone wouldn't catch it (counter == 0 if the function returns early
    for any reason, including a bug). The canary makes it impossible to
    false-pass."""
    victim = Path(tempfile.mkdtemp(prefix="acs-nat-e2e-victim-"))
    canary = victim / "DO_NOT_DELETE.txt"
    canary.write_text("if you see this after the scenario, the deny worked\n")

    report.case(2, TOTAL_SCENARIOS,
                "DESTRUCTIVE — real policy blocks rm -rf; canary survives")
    report.field("Victim dir:", str(victim))
    report.field("Canary:", str(canary))
    report.field("Expected:", "real policy denies via destructive_command regex; "
                               "function NOT executed; canary still on disk")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs", session_id="nat-e2e-destructive")
    executed = {"count": 0}

    async def target(command: str) -> str:
        executed["count"] += 1
        # If this ever runs despite the Guardian deny, it WILL delete the
        # victim dir — the canary check below catches it.
        import shutil
        shutil.rmtree(victim, ignore_errors=True)
        return "BUG: should not see this"

    from acs_adapter import ACSGuardianDenied  # noqa: E402
    raised = None
    try:
        asyncio.run(mw.function_middleware_invoke(
            command=f"rm -rf {victim}/",
            call_next=target,
            context=_ctx("Bash"),
        ))
    except ACSGuardianDenied as e:
        raised = e

    sub_results = []
    sub_results.append(("Function NOT executed (counter == 0)",
                         executed["count"] == 0,
                         f"count={executed['count']}"))
    sub_results.append(("ACSGuardianDenied raised (enforcement signaled)",
                         raised is not None,
                         f"raised={raised!r}"))
    sub_results.append(("Canary file still exists "
                         "(rm did NOT execute — counterproof)",
                         canary.exists(),
                         "intact" if canary.exists() else "DESTROYED"))
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
    _envelope_checks(guardian, sub_results)

    _dump_envelopes(report, guardian)
    if deny_resp:
        report.json_block("Guardian's destructive-command deny (verbatim)",
                           deny_resp["result"], truncate=160)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("destructive-policy-path",
                   all(ok for _, ok, _ in sub_results))

    # cleanup if still around
    if victim.exists():
        import shutil
        shutil.rmtree(victim, ignore_errors=True)


def scenario_read_tool(report: Report, guardian: ProgrammableGuardian) -> None:
    """READ-TOOL — different tool name, same wire contract. Confirms the
    adapter wraps every argument as {value: ...} per tool-call-request.json:26-37
    regardless of the tool. Rock-style: validate against the canonical
    schema, not against what we think the shape should be."""
    probe_dir = Path(tempfile.mkdtemp(prefix="acs-nat-e2e-read-"))
    probe = probe_dir / "probe.txt"
    probe.write_text("ACS NAT read-tool probe\n")

    report.case(3, TOTAL_SCENARIOS,
                "READ TOOL — different tool, same wire contract")
    report.field("Probe file:", str(probe))
    report.field("Expected:", "Read tool args wrapped per tool-call-request.json:26-37; "
                               "envelope.arguments.file_path.value matches probe path")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs", session_id="nat-e2e-read")
    executed = {"count": 0}

    async def target(file_path: str) -> str:
        executed["count"] += 1
        return Path(file_path).read_text()

    result = asyncio.run(mw.function_middleware_invoke(
        file_path=str(probe), call_next=target, context=_ctx("Read")))

    read_envs = [r for r in guardian.received
                  if r.get("method") == "steps/toolCallRequest"
                  and r["params"]["payload"].get("tool", {}).get("name") == "Read"]
    sub_results = []
    sub_results.append(("Function executed",
                         executed["count"] == 1, f"count={executed['count']}"))
    sub_results.append(("Guardian received a Read toolCallRequest",
                         bool(read_envs), f"{len(read_envs)} found"))
    if read_envs:
        args = read_envs[0]["params"]["payload"].get("arguments", {})
        sub_results.append(
            ("Arguments wrapped per tool-call-request.json:26-37",
             bool(args) and all(isinstance(v, dict) and "value" in v
                                  for v in args.values()),
             f"args={list(args.keys())}"))
        fp_value = args.get("file_path", {}).get("value", "") \
            if isinstance(args.get("file_path"), dict) else ""
        sub_results.append(
            ("file_path argument value matches probe path",
             str(fp_value) == str(probe),
             f"value={fp_value!r}"))
    _envelope_checks(guardian, sub_results)

    _dump_envelopes(report, guardian)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("read-tool-path", all(ok for _, ok, _ in sub_results))

    import shutil
    shutil.rmtree(probe_dir, ignore_errors=True)


def scenario_handshake_once(report: Report, guardian: ProgrammableGuardian) -> None:
    """HANDSHAKE — fires exactly ONCE per ACSMiddleware instance (§4).
    Reuse the SAME middleware across 3 invocations; assert exactly one
    handshake/hello envelope arrived. Subsequent calls must skip the
    round-trip (cached in process memory)."""
    report.case(4, TOTAL_SCENARIOS,
                "HANDSHAKE — fires exactly ONCE per middleware instance (§4)")
    report.field("Expected:",
                  "3 sequential function calls on the same middleware; "
                  "Guardian sees exactly 1 handshake/hello across all 3")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs", session_id="nat-e2e-handshake")
    executed = {"count": 0}

    async def target(command: str) -> str:
        executed["count"] += 1
        return f"ran #{executed['count']}: {command}"

    for i in range(3):
        asyncio.run(mw.function_middleware_invoke(
            command=f"echo call-{i}",
            call_next=target,
            context=_ctx("Bash"),
        ))

    handshakes = [r for r in guardian.received
                   if r.get("method") == "handshake/hello"]
    pretools = [r for r in guardian.received
                  if r.get("method") == "steps/toolCallRequest"]
    posttools = [r for r in guardian.received
                   if r.get("method") == "steps/toolCallResult"]

    _dump_envelopes(report, guardian)
    sub_results = [
        ("Exactly 1 handshake/hello across 3 invocations",
         len(handshakes) == 1, f"got {len(handshakes)}"),
        ("3 toolCallRequest envelopes (one per invocation)",
         len(pretools) == 3, f"got {len(pretools)}"),
        ("3 toolCallResult envelopes (one per invocation)",
         len(posttools) == 3, f"got {len(posttools)}"),
        ("All 3 function calls actually executed",
         executed["count"] == 3, f"count={executed['count']}"),
    ]
    _envelope_checks(guardian, sub_results)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("handshake-once-per-session",
                   all(ok for _, ok, _ in sub_results))


def scenario_lifecycle_observability(report: Report, guardian: ProgrammableGuardian) -> None:
    """LIFECYCLE — confirms the IntermediateStepManager subscription
    actually emits sessionStart + userMessage + agentResponse + sessionEnd
    on WORKFLOW_START / WORKFLOW_END.

    This is the OBSERVABILITY backstop we documented in the README: if
    YAML wiring misses a function, the lifecycle stream still surfaces
    the call to the Guardian. If THIS scenario fails, the backstop
    doesn't actually backstop — we'd be lying in the docs.
    """
    report.case(5, TOTAL_SCENARIOS,
                "LIFECYCLE — IntermediateStepManager emits boundary hooks")
    report.field("Expected:",
                  "WORKFLOW_START fires steps/sessionStart + steps/userMessage; "
                  "WORKFLOW_END fires steps/agentResponse + steps/sessionEnd")

    guardian.reset()

    # Subscribe _on_intermediate_step directly via ContextState.get();
    # Context._current_context is internal and unstable across NAT versions.
    try:
        from nat.builder.intermediate_step_manager import IntermediateStepManager  # type: ignore[import-not-found]
        from nat.builder.context import ContextState  # type: ignore[import-not-found]
        from nat.data_models.intermediate_step import (  # type: ignore[import-not-found]
            IntermediateStepPayload, IntermediateStepType, StreamEventData,
        )
    except ImportError as e:
        report.sub("nvidia-nat-core importable for lifecycle test",
                    False, f"missing: {e}")
        report.finish("lifecycle-observability", False)
        return

    workflow_input = f"hello-from-nat-e2e-{uuid.uuid4().hex[:6]}"
    workflow_output = f"acs-nat-output-{uuid.uuid4().hex[:6]}"

    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs",
                            session_id="nat-e2e-lifecycle")
    ctx_state = ContextState.get()
    mgr = IntermediateStepManager(ctx_state)
    sub = mgr.subscribe(on_next=mw._on_intermediate_step)
    try:
        wf_uuid = str(uuid.uuid4())
        # START and END of a span share the same UUID
        mgr.push_intermediate_step(IntermediateStepPayload(
            UUID=wf_uuid,
            event_type=IntermediateStepType.WORKFLOW_START,
            name="e2e-workflow",
            data=StreamEventData(input=workflow_input),
        ))
        mgr.push_intermediate_step(IntermediateStepPayload(
            UUID=wf_uuid,
            event_type=IntermediateStepType.WORKFLOW_END,
            name="e2e-workflow",
            data=StreamEventData(output=workflow_output),
        ))
    finally:
        try:
            sub.dispose()
        except Exception:  # noqa: BLE001
            pass

    # Give async pumps a moment to flush
    import time as _time
    _time.sleep(0.2)

    methods = [r.get("method", "") for r in guardian.received]
    session_start = [r for r in guardian.received
                      if r.get("method") == "steps/sessionStart"]
    user_msg = [r for r in guardian.received
                  if r.get("method") == "steps/userMessage"]
    agent_resp = [r for r in guardian.received
                    if r.get("method") == "steps/agentResponse"]
    session_end = [r for r in guardian.received
                     if r.get("method") == "steps/sessionEnd"]

    input_in_payload = any(
        workflow_input in json.dumps(r.get("params", {}).get("payload", {}))
        for r in user_msg)
    output_in_payload = any(
        workflow_output in json.dumps(r.get("params", {}).get("payload", {}))
        for r in agent_resp)

    _dump_envelopes(report, guardian)
    sub_results = [
        ("WORKFLOW_START emitted steps/sessionStart",
         bool(session_start), f"{len(session_start)} found"),
        ("WORKFLOW_START emitted steps/userMessage with input text",
         bool(user_msg) and input_in_payload,
         "input present" if input_in_payload else "input MISSING"),
        ("WORKFLOW_END emitted steps/agentResponse with output text",
         bool(agent_resp) and output_in_payload,
         "output present" if output_in_payload else "output MISSING"),
        ("WORKFLOW_END emitted steps/sessionEnd",
         bool(session_end), f"{len(session_end)} found"),
    ]
    _envelope_checks(guardian, sub_results)
    for label, ok, detail in sub_results:
        report.sub(label, ok, detail)
    report.finish("lifecycle-observability",
                   all(ok for _, ok, _ in sub_results))


# ──────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────

def _dump_envelopes(report: Report, guardian: ProgrammableGuardian) -> None:
    if not guardian.received:
        return
    print(f"      ── Envelopes received (in order)")
    for r in guardian.received:
        method = r.get("method", "")
        rid = r.get("params", {}).get("request_id", "")[:8]
        print(f"        {method:35s}  req={rid}…")


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    if not _NAT_OK:
        sys.stderr.write(
            "FATAL: nvidia-nat-core not installed.\n"
            "Install: pip install nvidia-nat-core\n")
        return 2
    if not SPEC_DIR_DEFAULT.exists():
        sys.stderr.write(
            f"FATAL: canonical schemas missing at {SPEC_DIR_DEFAULT}\n"
            "Set ACS_SPEC_DIR to a clone of "
            "GenAI-Security-Project/agent-control-standard/specification/v0.1.0/\n")
        return 2

    guardian = ProgrammableGuardian(hmac_secret=HMAC_SECRET)
    guardian.handlers["__default__"] = real_policy_handler(evaluate_step)
    guardian.start()

    report = Report()
    report.print_header(
        "ACS NAT adapter — REAL end-to-end conformance check",
        "",
        "Drives the real ACSMiddleware against a recording Guardian",
        "wired to the REAL example_guardian.evaluate_step policy.",
        "Fully automated — NAT runs in-process, no operator action.",
        "",
        f"Spec source : {SPEC_DIR_DEFAULT}",
        f"Adapter     : {ADAPTER_DIR}/acs_adapter.py",
        f"Guardian    : ProgrammableGuardian + real evaluate_step()",
        "",
        f"{TOTAL_SCENARIOS} scenarios.",
    )

    try:
        scenario_allow(report, guardian)
        scenario_destructive(report, guardian)
        scenario_read_tool(report, guardian)
        scenario_handshake_once(report, guardian)
        scenario_lifecycle_observability(report, guardian)
    finally:
        guardian.stop()

    return 0 if report.summary("ACS-CORE SMOKE PASS (nat)") else 1


if __name__ == "__main__":
    sys.exit(main())
