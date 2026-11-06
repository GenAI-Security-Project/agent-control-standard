#!/usr/bin/env python3
"""Run the real Codex CLI with the installed acs-codex-hook and a signed test Guardian, against a scripted model on localhost.

No model account or external model call is needed. This tests host enforcement,
not model judgment. Run explicitly; it is not silently skipped in the unit gate.
The hook runs under the matcher and the exit-2 fallback from hooks.json.example,
so the check covers the configuration a deployment copies.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import acs
from acs.testing.capture_guardian import CaptureGuardian

HOOK = Path(sys.executable).parent / "acs-codex-hook"
EXAMPLE = Path(__file__).resolve().parents[3] / "docs" / "codex" / "hooks.json.example"
SUBAGENT_TASK = "ACS-SUBAGENT-TASK: create the marker"
REPLACEMENT_TASK = "ACS-SUBAGENT-TASK: create the replacement marker"
# A model in Codex's own catalog, named only so Codex offers it apply_patch; the local fixture still answers.
PATCH_MODEL = "gpt-5.5"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def example_hook() -> tuple[str, str]:
    """The example's PreToolUse matcher, and the fallback that follows the hook command inside its sh -c."""
    entry = json.loads(EXAMPLE.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]
    words = shlex.split(entry["hooks"][0]["command"])
    if words[:2] != ["sh", "-c"] or len(words) != 3 or " || " not in words[2]:
        raise SystemExit(f"{EXAMPLE} must run the hook as sh -c '<hook> || <fallback>'")
    return entry["matcher"], words[2].split(" || ", 1)[1]


def call(name: str, arguments: dict, call_id: str, namespace: str | None = None) -> dict:
    item = {"type": "function_call", "id": "fc_" + call_id, "call_id": call_id,
            "name": name, "arguments": json.dumps(arguments)}
    if namespace:
        item["namespace"] = namespace
    return item


def message(text: str) -> dict:
    return {"type": "message", "id": "msg_fixture", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}


def outputs(req: dict) -> list[dict]:
    return [item for item in req.get("input", [])
            if item.get("type") in ("function_call_output", "custom_tool_call_output")]


def patch_adding(name: str) -> str:
    return f"*** Begin Patch\n*** Add File: {name}\n+{name.split('.')[0]}\n*** End Patch\n"


def is_subagent(req: dict) -> bool:
    return any(item.get("type") == "message" and item.get("role") == "user"
               and "ACS-SUBAGENT-TASK" in json.dumps(item.get("content")) for item in req.get("input", []))


class ScriptedModel:
    """Answer each Responses request over SSE with the item decide(request) returns."""
    def __init__(self, decide):
        self.requests = []
        self.errors = []
        model = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                raw = b'{"models":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                # The local provider must not receive an account credential.
                if self.headers.get("Authorization") != "Bearer acs-local-fixture-no-credential":
                    model.errors.append("unexpected authorization header")
                model.requests.append(req)
                item = decide(req)
                resp = {"id": f"resp_{len(model.requests)}", "status": "completed", "output": [item],
                        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
                events = [{"type": "response.created", "response": {"id": resp["id"]}},
                          {"type": "response.output_item.done", "output_index": 0, "item": item},
                          {"type": "response.completed", "response": resp}]
                raw = "".join("data: " + json.dumps(ev) + "\n\n" for ev in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def tool_outputs(self) -> list[dict]:
        seen = {}
        for req in self.requests:
            seen.update((item["call_id"], item) for item in outputs(req))
        return list(seen.values())

    def advertised(self) -> set[str]:
        return {tool.get("name") for tool in self.requests[0].get("tools", [])} if self.requests else set()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def run_codex(codex: str, directory: Path, hook: str, decide, *, multi_agent: bool,
              name: str, evidence_dir: Path, model_name: str = "acs-fixture",
              ) -> tuple[subprocess.CompletedProcess, ScriptedModel]:
    matcher, fallback = example_hook()
    hook_command = shlex.join(["sh", "-c", hook + " || " + fallback])
    hook_config = ("hooks={PreToolUse=[{matcher=" + json.dumps(matcher) + ",hooks=[{type=\"command\",command="
                   + json.dumps(hook_command) + ",timeout=30}]}]}")
    with ScriptedModel(decide) as model:
        provider = ('model_providers.acs_fixture={name="ACS local fixture",base_url='
                    + json.dumps(f"http://127.0.0.1:{model.server.server_port}/v1")
                    + ',wire_api="responses",requires_openai_auth=false,env_key="ACS_FIXTURE_TOKEN",supports_websockets=false,'
                      'request_max_retries=0,stream_max_retries=0}')
        args = [codex, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "-C", str(directory),
                "--json", "--sandbox", "workspace-write", "-m", model_name,
                "-c", 'model_provider="acs_fixture"', "-c", provider,
                "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
                "-c", hook_config, "--enable", "hooks", "--enable", "unified_exec",
                "--enable" if multi_agent else "--disable", "multi_agent",
                "--disable", "plugins", "--disable", "apps", "--disable", "shell_snapshot",
                "--disable", "code_mode", "--disable", "code_mode_only",
                "Execute the fixture calls supplied by the local test server."]
        env = {key: value for key, value in os.environ.items() if not key.startswith("ACS_")}
        env["ACS_FIXTURE_TOKEN"] = "acs-local-fixture-no-credential"
        proc = subprocess.run(args, input="", env=env, text=True, capture_output=True, timeout=120)
    # Preserve diagnostic output even when an assertion fails.
    (evidence_dir / f"{name}.stdout.jsonl").write_text(proc.stdout)
    (evidence_dir / f"{name}.stderr.log").write_text(proc.stderr)
    (evidence_dir / f"{name}.model.json").write_text(json.dumps(model.requests, indent=2) + "\n")
    return proc, model


def hook_for(guardian: CaptureGuardian, directory: Path) -> str:
    """The hook as the example writes it: sh assignments, then the command, with no env process."""
    settings = {"ACS_GUARDIAN_URL": guardian.url(), "ACS_HMAC_SECRET": guardian.hmac_secret,
                "ACS_HMAC_KEY_ID": guardian.key_id, "ACS_HANDSHAKE_CACHE": str(directory / "cache"),
                "ACS_SESSION_STATE_DIR": str(directory / "state"), "ACS_DEFAULT_DENY": "1"}
    return " ".join([*(f"{key}={shlex.quote(value)}" for key, value in settings.items()), shlex.quote(str(HOOK))])


def decide_with(guardian: CaptureGuardian, decision: str, modifications: dict | None = None) -> None:
    def verdict(req):
        result = guardian._default_allow(req)
        if req["params"]["payload"]["tool"]["name"] != "spawn_agent" or decision == "allow":
            return result
        # response-envelope.json requires reasoning on a deny and a modify.
        result.update(decision=decision, reasoning="ACS live fixture decision")
        if modifications:
            result["modifications"] = modifications
        return result
    guardian.handlers["steps/toolCallRequest"] = verdict


def save_wire(guardian: CaptureGuardian, name: str, evidence_dir: Path) -> None:
    (evidence_dir / f"{name}.wire.json").write_text(json.dumps(
        {"requests": [r.parsed for r in guardian.captures], "responses": guardian.sent}, indent=2) + "\n")


def verify_bash(codex: str, decision: str, evidence_dir: Path) -> dict:
    check = unittest.TestCase()
    name = f"bash-{decision}"
    with tempfile.TemporaryDirectory(prefix="acs-codex-live-") as tmp, CaptureGuardian() as guardian:
        directory = Path(tmp)
        original = directory / "original.marker"
        replacement = directory / "replacement.marker"
        command = "printf original > " + shlex.quote(str(original))
        rewritten = "printf replacement > " + shlex.quote(str(replacement))

        def verdict(req):
            result = guardian._default_allow(req)
            # response-envelope.json requires reasoning on a deny and a modify.
            result.update(decision=decision, reasoning="ACS live fixture decision")
            if decision == "modify":
                result["modifications"] = {"parameter_overrides": {"command": rewritten}}
            return result
        guardian.handlers["steps/toolCallRequest"] = verdict

        def decide(req):
            if outputs(req):
                return message("Fixture completed.")
            return call("exec_command", {"cmd": command, "workdir": tmp, "login": False,
                                         "max_output_tokens": 200}, "call_fixture")
        proc, model = run_codex(codex, directory, hook_for(guardian, directory), decide,
                                multi_agent=False, name=name, evidence_dir=evidence_dir)
        check.assertEqual(proc.returncode, 0, proc.stderr)
        check.assertEqual(model.errors, [])
        check.assertIn("exec_command", model.advertised(), "Codex did not advertise exec_command")
        check.assertEqual(len(model.requests), 2, "fixture must invoke one tool, then finish")
        check.assertEqual(len(model.tool_outputs), 1, "host must return the tool result to the model")
        check.assertEqual(guardian.methods(), ["handshake/hello", "steps/toolCallRequest"])
        guardian.assert_all_valid(check)
        payload = guardian.payload_of("steps/toolCallRequest")
        check.assertEqual(payload["tool"]["name"], "Bash")
        check.assertEqual(payload["arguments"]["command"]["value"], command)
        check.assertEqual(original.exists(), decision == "allow")
        check.assertEqual(replacement.exists(), decision == "modify")
        if original.exists():
            check.assertEqual(original.read_text(), "original")
        if replacement.exists():
            check.assertEqual(replacement.read_text(), "replacement")
        if decision == "deny":
            check.assertIn("ACS live fixture decision", json.dumps(model.tool_outputs))
        save_wire(guardian, name, evidence_dir)
        return {"case": name, "original_created": original.exists(),
                "replacement_created": replacement.exists(), "signed_envelopes_valid": True,
                "guardian_methods": guardian.methods(), "model_requests": len(model.requests),
                "codex_exit_code": proc.returncode}


def verify_patch(codex: str, decision: str, evidence_dir: Path) -> dict:
    """Codex offers apply_patch only to a model its catalog says can use it, so this case names a catalog model."""
    check = unittest.TestCase()
    name = f"patch-{decision}"
    with tempfile.TemporaryDirectory(prefix="acs-codex-live-") as tmp, CaptureGuardian() as guardian:
        directory = Path(tmp)
        original, replacement = directory / "original.marker", directory / "replacement.marker"
        patch, rewritten = patch_adding(original.name), patch_adding(replacement.name)

        def verdict(req):
            result = guardian._default_allow(req)
            if decision != "allow":
                # response-envelope.json requires reasoning on a deny and a modify.
                result.update(decision=decision, reasoning="ACS live fixture decision")
            if decision == "modify":
                result["modifications"] = {"parameter_overrides": {"command": rewritten}}
            return result
        guardian.handlers["steps/toolCallRequest"] = verdict

        def decide(req):
            if outputs(req):
                return message("Fixture completed.")
            return {"type": "custom_tool_call", "id": "ctc_fixture", "call_id": "call_patch",
                    "name": "apply_patch", "input": patch}
        proc, model = run_codex(codex, directory, hook_for(guardian, directory), decide, multi_agent=False,
                                name=name, evidence_dir=evidence_dir, model_name=PATCH_MODEL)
        check.assertEqual(proc.returncode, 0, proc.stderr)
        check.assertEqual(model.errors, [])
        check.assertIn("apply_patch", model.advertised(), f"Codex did not offer apply_patch to {PATCH_MODEL}")
        check.assertEqual(len(model.tool_outputs), 1, "host must return the tool result to the model")
        check.assertEqual(guardian.methods(), ["handshake/hello", "steps/toolCallRequest"])
        guardian.assert_all_valid(check)
        payload = guardian.payload_of("steps/toolCallRequest")
        check.assertEqual(payload["tool"]["name"], "apply_patch")
        check.assertEqual(payload["arguments"]["command"]["value"], patch)
        check.assertEqual(original.exists(), decision == "allow")
        check.assertEqual(replacement.exists(), decision == "modify")
        if decision == "deny":
            check.assertIn("ACS live fixture decision", json.dumps(model.tool_outputs))
        save_wire(guardian, name, evidence_dir)
        return {"case": name, "original_created": original.exists(), "replacement_created": replacement.exists(),
                "signed_envelopes_valid": True, "guardian_methods": guardian.methods(),
                "model_requests": len(model.requests), "codex_exit_code": proc.returncode}


def verify_spawn(codex: str, decision: str, evidence_dir: Path) -> dict:
    """The parent spawns one subagent, whose only step creates the marker its task names, then waits for it."""
    check = unittest.TestCase()
    name = f"spawn-{decision}"
    with tempfile.TemporaryDirectory(prefix="acs-codex-live-") as tmp, CaptureGuardian() as guardian:
        directory = Path(tmp)
        marker = directory / "subagent.marker"
        replacement = directory / "replacement.marker"
        decide_with(guardian, decision, {"parameter_overrides": {"message": REPLACEMENT_TASK}}
                    if decision == "modify" else None)

        def decide(req):
            done = outputs(req)
            if is_subagent(req):
                target = replacement if REPLACEMENT_TASK in json.dumps(req.get("input")) else marker
                return message("Subagent completed.") if done else call(
                    "exec_command", {"cmd": "touch " + target.name, "workdir": tmp}, "call_sub")
            if not done:
                return call("spawn_agent", {"message": SUBAGENT_TASK}, "call_spawn", "multi_agent_v1")
            ids = UUID.findall(json.dumps(done[-1].get("output"))) if len(done) == 1 else []
            if ids:
                return call("wait_agent", {"targets": [ids[0]], "timeout_ms": 30000}, "call_wait", "multi_agent_v1")
            return message("Fixture completed.")
        proc, model = run_codex(codex, directory, hook_for(guardian, directory), decide,
                                multi_agent=True, name=name, evidence_dir=evidence_dir)
        check.assertEqual(proc.returncode, 0, proc.stderr)
        check.assertEqual(model.errors, [])
        check.assertIn("multi_agent_v1", model.advertised(), "Codex did not advertise multi-agent tools")
        guardian.assert_all_valid(check)
        steps = [c.parsed["params"]["payload"] for c in guardian.captures
                 if c.parsed["method"] == "steps/toolCallRequest"]
        check.assertEqual(steps[0]["tool"]["name"], "spawn_agent")
        check.assertEqual(steps[0]["arguments"]["message"]["value"], SUBAGENT_TASK)
        subagent_ran = any(is_subagent(req) for req in model.requests)
        if decision in ("allow", "modify"):
            check.assertTrue(subagent_ran, "the allowed subagent never started")
            check.assertEqual(marker.exists(), decision == "allow")
            check.assertEqual(replacement.exists(), decision == "modify", "the subagent did not get the rewritten task")
            # The subagent's own shell step goes through the same hook, and names the subagent.
            check.assertEqual([s["tool"]["name"] for s in steps], ["spawn_agent", "Bash"])
            spawn_meta, sub_meta = (c.parsed["params"]["metadata"] for c in guardian.captures
                                    if c.parsed["method"] == "steps/toolCallRequest")
            check.assertNotIn("codex_agent_id", spawn_meta)
            check.assertTrue(UUID.fullmatch(sub_meta.get("codex_agent_id", "")), sub_meta)
            check.assertEqual(sub_meta["session_id"], spawn_meta["session_id"])
        else:
            check.assertFalse(subagent_ran, "a denied subagent reached the model")
            check.assertFalse(marker.exists())
            check.assertEqual(len(steps), 1)
            check.assertIn("ACS live fixture decision", json.dumps(model.tool_outputs))
        save_wire(guardian, name, evidence_dir)
        return {"case": name, "subagent_started": subagent_ran, "marker_created": marker.exists(),
                "replacement_created": replacement.exists(),
                "signed_envelopes_valid": True, "guardian_methods": guardian.methods(),
                "model_requests": len(model.requests), "codex_exit_code": proc.returncode}


def verify_missing_hook(codex: str, evidence_dir: Path) -> dict:
    """A hook command that cannot run must block the call through the example's exit-2 fallback."""
    check = unittest.TestCase()
    name = "missing-hook"
    with tempfile.TemporaryDirectory(prefix="acs-codex-live-") as tmp:
        directory = Path(tmp)
        marker = directory / "original.marker"
        command = "printf original > " + shlex.quote(str(marker))

        def decide(req):
            if outputs(req):
                return message("Fixture completed.")
            return call("exec_command", {"cmd": command, "workdir": tmp}, "call_fixture")
        proc, model = run_codex(codex, directory, shlex.quote(str(directory / "missing" / "acs-codex-hook")),
                                decide, multi_agent=False, name=name, evidence_dir=evidence_dir)
        check.assertEqual(proc.returncode, 0, proc.stderr)
        check.assertEqual(model.errors, [])
        check.assertFalse(marker.exists(), "Codex ran the call when the hook command could not run")
        check.assertEqual(len(model.tool_outputs), 1, "host must return the block to the model")
        return {"case": name, "original_created": marker.exists(),
                "model_requests": len(model.requests), "codex_exit_code": proc.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    executable = shutil.which(args.codex)
    if executable is None:
        parser.error("Codex CLI is required; this check does not skip")
    if not HOOK.is_file():
        parser.error(f"{HOOK} is missing; install the adapters into this interpreter's environment")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([executable, "--version"], text=True).strip()
    results = []
    for decision in ("allow", "deny", "modify"):
        results.append(verify_bash(executable, decision, args.evidence_dir))
        print(json.dumps(results[-1]), flush=True)
    for decision in ("allow", "deny", "modify"):
        results.append(verify_patch(executable, decision, args.evidence_dir))
        print(json.dumps(results[-1]), flush=True)
    for decision in ("allow", "deny", "modify"):
        results.append(verify_spawn(executable, decision, args.evidence_dir))
        print(json.dumps(results[-1]), flush=True)
    results.append(verify_missing_hook(executable, args.evidence_dir))
    print(json.dumps(results[-1]), flush=True)
    matcher, _ = example_hook()
    report = {"codex_version": version, "adapter_version": acs.__version__,
              "model": "local scripted Responses fixture (no inference)", "matcher": matcher,
              "scope": "real CLI PreToolUse enforcement of exec_command/Bash, apply_patch and spawn_agent, "
                       "and the exit-2 fallback for a hook that cannot run", "cases": results}
    (args.evidence_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
