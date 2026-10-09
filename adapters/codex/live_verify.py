#!/usr/bin/env python3
"""Real Codex CLI + real adapter + signed test Guardian; scripted model on localhost.

No model account or external model call is needed. This tests host enforcement,
not model judgment. Run explicitly; it is not silently skipped in the unit gate.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "_common"))
from capture_guardian import CaptureGuardian


class ScriptedModel:
    """Emit one fixed exec_command call, then a final message over Responses SSE."""
    def __init__(self, command: str, directory: str):
        self.command = command
        self.directory = directory
        self.calls = 0
        self.tool_outputs = []
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
                model.calls += 1
                model.tool_outputs.extend(item for item in req.get("input", [])
                                          if item.get("type") == "function_call_output")
                if model.calls == 1:
                    names = {tool.get("name") for tool in req.get("tools", [])}
                    if "exec_command" not in names:
                        model.errors.append("Codex did not advertise exec_command")
                    item = {"type": "function_call", "id": "fc_fixture", "call_id": "call_fixture",
                            "name": "exec_command", "arguments": json.dumps({
                                "cmd": model.command, "workdir": model.directory,
                                "login": False, "max_output_tokens": 200})}
                else:
                    item = {"type": "message", "id": "msg_fixture", "role": "assistant",
                            "status": "completed", "content": [{"type": "output_text",
                            "text": "Fixture completed.", "annotations": []}]}
                resp = {"id": f"resp_{model.calls}", "status": "completed", "output": [item],
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

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def verify_case(codex: str, decision: str, evidence_dir: Path) -> dict:
    check = unittest.TestCase()
    with tempfile.TemporaryDirectory(prefix="acs-codex-live-") as tmp, CaptureGuardian() as guardian:
        directory = Path(tmp)
        original = directory / "original.marker"
        replacement = directory / "replacement.marker"
        command = "printf original > " + shlex.quote(str(original))
        rewritten = "printf replacement > " + shlex.quote(str(replacement))

        def verdict(req):
            result = guardian._default_allow(req)
            result.update(decision=decision, reasoning="ACS live fixture decision")
            if decision == "modify":
                result["modifications"] = {"parameter_overrides": {"command": rewritten}}
            return result
        guardian.handlers["steps/toolCallRequest"] = verdict
        hook_command = shlex.join([
            "env", "ACS_GUARDIAN_URL=" + guardian.url(), "ACS_HMAC_SECRET=" + guardian.hmac_secret,
            "ACS_HANDSHAKE_CACHE=" + str(directory / "cache"), "ACS_DEFAULT_DENY=1",
            sys.executable, str(HERE / "acs_adapter.py"),
        ])
        hook_config = ('hooks={PreToolUse=[{matcher="^Bash$",hooks=[{type="command",command='
                       + json.dumps(hook_command) + ',timeout=30}]}]}')
        with ScriptedModel(command, tmp) as model:
            provider = ('model_providers.acs_fixture={name="ACS local fixture",base_url='
                        + json.dumps(f"http://127.0.0.1:{model.server.server_port}/v1")
                        + ',wire_api="responses",requires_openai_auth=false,env_key="ACS_FIXTURE_TOKEN",supports_websockets=false,'
                          'request_max_retries=0,stream_max_retries=0}')
            args = [codex, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                    "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "-C", tmp,
                    "--json", "--sandbox", "workspace-write", "-m", "acs-fixture",
                    "-c", 'model_provider="acs_fixture"', "-c", provider,
                    "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
                    "-c", hook_config, "--enable", "hooks", "--enable", "unified_exec",
                    "--disable", "plugins", "--disable", "multi_agent", "--disable", "shell_snapshot",
                    "--disable", "code_mode", "--disable", "code_mode_only",
                    "Execute the single fixture command supplied by the local test server."]
            env = {key: value for key, value in os.environ.items() if not key.startswith("ACS_")}
            env["ACS_FIXTURE_TOKEN"] = "acs-local-fixture-no-credential"
            proc = subprocess.run(args, input="", env=env, text=True, capture_output=True, timeout=60)
            # Preserve diagnostic output even when an assertion fails.
            (evidence_dir / f"{decision}.stdout.jsonl").write_text(proc.stdout)
            (evidence_dir / f"{decision}.stderr.log").write_text(proc.stderr)
            check.assertEqual(proc.returncode, 0, proc.stderr)
            check.assertEqual(model.errors, [])
            check.assertEqual(model.calls, 2, "fixture must invoke one tool, then finish")
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
        result = {"decision": decision, "original_created": original.exists(),
                  "replacement_created": replacement.exists(), "signed_envelopes_valid": True,
                  "guardian_methods": guardian.methods(), "model_requests": model.calls,
                  "codex_exit_code": proc.returncode}
        (evidence_dir / f"{decision}.wire.json").write_text(json.dumps(
            {"requests": [r.parsed for r in guardian.captures], "responses": guardian.sent}, indent=2) + "\n")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    executable = shutil.which(args.codex)
    if executable is None:
        parser.error("Codex CLI is required; this check does not skip")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([executable, "--version"], text=True).strip()
    results = []
    for decision in ("allow", "deny", "modify"):
        results.append(verify_case(executable, decision, args.evidence_dir))
        print(json.dumps(results[-1]), flush=True)
    report = {"codex_version": version, "model": "local scripted Responses fixture (no inference)",
              "scope": "real CLI exec_command/Bash PreToolUse enforcement", "cases": results}
    (args.evidence_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
