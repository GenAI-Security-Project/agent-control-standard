#!/usr/bin/env python3
"""Automated live check of a NAT ACS install: the real middleware against a recording Guardian running the shipped policy."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parents[2] / "src" / "acs" / "integrations" / "nat"
from acs.core import schemas_dir  # noqa: E402

SPEC_DIR_DEFAULT = schemas_dir(os.environ.get("ACS_SPEC_DIR"))


from acs.testing.harness import (  # noqa: E402
    ProgrammableGuardian,
    validate_request_envelope,
)
from acs.testing.e2e_report import (  # noqa: E402
    Report, real_policy_handler,
    assert_envelopes_signed_and_valid as _assert_envelopes_signed_and_valid,
)
from acs.guardian.example_guardian import evaluate_step  # noqa: E402

HMAC_SECRET = "e2e-test-shared-secret-not-for-production"

try:
    from nat.middleware.middleware import FunctionMiddlewareContext  # type: ignore[import-not-found]
    _NAT_OK = True
except ImportError:
    _NAT_OK = False


def _build_middleware(guardian_url: str, *, default_deny: bool = True):
    os.environ["ACS_HMAC_SECRET"] = HMAC_SECRET
    os.environ["ACS_HMAC_KEY_ID"] = "test-key"
    from acs.integrations.nat.adapter import ACSMiddleware, ACSMiddlewareConfig
    return ACSMiddleware(ACSMiddlewareConfig(
        guardian_url=guardian_url,
        default_deny=default_deny,
    ))


def _ctx(tool_name: str):
    return FunctionMiddlewareContext(
        name=tool_name, config=None, description=None,
        input_schema=None,
        single_output_schema=type(None),
        stream_output_schema=type(None),
    )


def _envelope_checks(guardian, sub_results: list) -> None:
    _assert_envelopes_signed_and_valid(
        guardian, validate_request_envelope, sub_results)


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
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs")
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
    """A canary in the victim dir must survive the deny; a zero call count alone also passes when the function returns early for any reason."""
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
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs")
    executed = {"count": 0}

    async def target(command: str) -> str:
        executed["count"] += 1
        # If this ever runs despite the Guardian deny, it WILL delete the
        # victim dir — the canary check below catches it.
        import shutil
        shutil.rmtree(victim, ignore_errors=True)
        return "BUG: should not see this"

    from acs.integrations.nat.adapter import ACSGuardianDenied
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

    if victim.exists():
        import shutil
        shutil.rmtree(victim, ignore_errors=True)


def scenario_read_tool(report: Report, guardian: ProgrammableGuardian) -> None:
    probe_dir = Path(tempfile.mkdtemp(prefix="acs-nat-e2e-read-"))
    probe = probe_dir / "probe.txt"
    probe.write_text("ACS NAT read-tool probe\n")

    report.case(3, TOTAL_SCENARIOS,
                "READ TOOL — different tool, same wire contract")
    report.field("Probe file:", str(probe))
    report.field("Expected:", "Read tool args wrapped per tool-call-request.json:26-37; "
                               "envelope.arguments.file_path.value matches probe path")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs")
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
    """§4: calls outside a Runner share the middleware's own session, so three calls bring one handshake."""
    report.case(4, TOTAL_SCENARIOS,
                "HANDSHAKE — fires exactly ONCE per middleware instance (§4)")
    report.field("Expected:",
                  "3 sequential function calls on the same middleware; "
                  "Guardian sees exactly 1 handshake/hello across all 3")

    guardian.reset()
    mw = _build_middleware(f"http://127.0.0.1:{guardian.port}/acs")
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
    """A Runner's WORKFLOW_START and WORKFLOW_END, reported by the middleware's exporter, send sessionStart, userMessage, agentResponse and sessionEnd."""
    report.case(5, TOTAL_SCENARIOS,
                "LIFECYCLE — a NAT run emits its boundary hooks")
    report.field("Expected:",
                  "WORKFLOW_START fires steps/sessionStart + steps/userMessage; "
                  "WORKFLOW_END fires steps/agentResponse + steps/sessionEnd")

    guardian.reset()

    try:
        from tests.integrations.nat._nat_runs import with_middleware
        from acs.integrations.nat.adapter import ACSMiddlewareConfig
    except ImportError as e:
        report.sub("nvidia-nat-core importable for lifecycle test",
                    False, f"missing: {e}")
        report.finish("lifecycle-observability", False)
        return

    workflow_input = f"hello-from-nat-e2e-{uuid.uuid4().hex[:6]}"
    workflow_output = f"acs-nat-output-{uuid.uuid4().hex[:6]}"
    os.environ["ACS_HMAC_SECRET"] = HMAC_SECRET
    os.environ["ACS_HMAC_KEY_ID"] = "test-key"

    async def body(middleware, run) -> None:
        async def entry(message: str) -> str:
            return workflow_output
        await run("e2e-workflow", entry, workflow_input)
    asyncio.run(with_middleware(ACSMiddlewareConfig(guardian_url=f"http://127.0.0.1:{guardian.port}/acs"), body))

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


def _dump_envelopes(report: Report, guardian: ProgrammableGuardian) -> None:
    if not guardian.received:
        return
    print(f"      ── Envelopes received (in order)")
    for r in guardian.received:
        method = r.get("method", "")
        rid = r.get("params", {}).get("request_id", "")[:8]
        print(f"        {method:35s}  req={rid}…")


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
        f"Adapter     : {ADAPTER_DIR}/adapter.py",
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
