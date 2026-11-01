"""Claude Code and Cursor run the tool when a hook crashes, so every unusable answer or file settles in the hook's shape with an audit line."""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from acs.testing.harness import seed_negotiated_session, signing_env

BIN = Path(sys.executable).parent

# What a stub Guardian at the configured address answers to every request, hello included.
ANSWERS = {
    "an empty list": (200, []),
    "null": (200, None),
    "a string": (200, "x"),
    "a string result": (200, "RESULT"),
    "a number as the signature": (200, "NUMBER_SIGNATURE"),
    "HTTP 500 with an error object": (500, {"error": "boom"}),
}


class _Stub(http.server.BaseHTTPRequestHandler):
    answer: tuple[int, object] = (200, None)

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        status, value = self.answer
        if value == "RESULT":
            value = {"jsonrpc": "2.0", "id": body.get("id"), "result": "x"}
        elif value == "NUMBER_SIGNATURE":
            value = {"jsonrpc": "2.0", "id": body.get("id"),
                     "result": {"decision": "allow", "request_id": body.get("params", {}).get("request_id"),
                                "signature": 5}}
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args) -> None:
        pass


class AnUnusableAnswerNeverCrashesAHook(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="acs-host-posture-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/acs"

    def _run(self, host: str, deny: str, *, seeded: bool, env_overrides: dict | None = None):
        session = str(uuid.uuid4())
        records = self.root / f"records-{uuid.uuid4().hex}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        env.update(signing_env(), ACS_GUARDIAN_URL=self.url, ACS_DEFAULT_DENY=deny,
                   ACS_HANDSHAKE_CACHE=str(records), ACS_SESSION_STATE_DIR=str(self.root / "state"),
                   ACS_HANDSHAKE_TIMEOUT_SECONDS="2")
        env.update(env_overrides or {})
        if host == "claude-code":
            argv = [str(BIN / "acs-claude-code-hook")]
            event = {"session_id": session, "cwd": "/tmp", "hook_event_name": "PreToolUse",
                     "tool_name": "Bash", "tool_input": {"command": "echo hi"}}
            hook_session = session
        else:
            from acs.core import coerce_uuid
            argv = [str(BIN / "acs-cursor-hook"), "preToolUse"]
            event = {"conversation_id": session, "workspace_roots": ["/tmp"],
                     "tool_name": "Bash", "tool_input": {"command": "echo hi"}}
            hook_session = coerce_uuid(session, namespace_prefix="cursor")
        if seeded:
            seed_negotiated_session(records, session_id=hook_session, guardian_url=self.url,
                                    hmac_secret=signing_env()["ACS_HMAC_SECRET"])
        p = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, timeout=30)
        out = json.loads(p.stdout) if p.stdout.strip() else {}
        denied = (out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny" if host == "claude-code"
                  else out.get("permission") == "deny")
        return p, denied

    def _assert_settled(self, p, denied: bool, deny: str, label: str) -> None:
        self.assertEqual(p.returncode, 0, f"{label}: a crash exits nonzero and the host runs the tool\n{p.stderr[-600:]}")
        self.assertIn("ACS_AUDIT ", p.stderr, f"{label}: settled with no audit line")
        if deny == "1":
            self.assertTrue(denied, f"{label}: fail-closed posture must deny\n{p.stdout}")

    def test_every_unusable_guardian_answer_settles_in_the_hooks_shape(self) -> None:
        for name, answer in ANSWERS.items():
            _Stub.answer = answer
            for host in ("claude-code", "cursor"):
                for deny in ("0", "1"):
                    for seeded in (False, True):
                        label = f"{host} deny={deny} {'step' if seeded else 'handshake'}: {name}"
                        with self.subTest(label):
                            p, denied = self._run(host, deny, seeded=seeded)
                            self._assert_settled(p, denied, deny, label)

    def test_an_unusable_key_file_or_session_record_settles_in_the_hooks_shape(self) -> None:
        _Stub.answer = (200, None)
        loose = self.root / "loose.key"
        loose.write_text("0" * 64)
        loose.chmod(0o644)
        cases = {"a key file with mode 0644": {"ACS_HMAC_SECRET": "", "ACS_HMAC_SECRET_FILE": str(loose)},
                 "a missing key file": {"ACS_HMAC_SECRET": "", "ACS_HMAC_SECRET_FILE": str(self.root / "absent.key")},
                 "an unparseable cache lifetime": {"ACS_HANDSHAKE_CACHE_TTL_SECONDS": "1h"}}
        for name, overrides in cases.items():
            for host in ("claude-code", "cursor"):
                for deny in ("0", "1"):
                    label = f"{host} deny={deny}: {name}"
                    with self.subTest(label):
                        p, denied = self._run(host, deny, seeded=False, env_overrides=overrides)
                        self._assert_settled(p, denied, deny, label)

    def test_a_session_record_the_agent_wrote_settles_in_the_hooks_shape(self) -> None:
        _Stub.answer = (200, None)
        from acs.client._handshake import _handshake_cache_path
        for host in ("claude-code", "cursor"):
            for deny in ("0", "1"):
                with self.subTest(host, deny=deny):
                    session = str(uuid.uuid4())
                    records = self.root / f"records-{uuid.uuid4().hex}"
                    records.mkdir()
                    if host == "cursor":
                        from acs.core import coerce_uuid
                        hook_session = coerce_uuid(session, namespace_prefix="cursor")
                    else:
                        hook_session = session
                    _handshake_cache_path(hook_session, self.url, records).write_text(
                        json.dumps({"result": {"signature": 1}}))
                    env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
                    env.update(signing_env(), ACS_GUARDIAN_URL=self.url, ACS_DEFAULT_DENY=deny,
                               ACS_HANDSHAKE_CACHE=str(records), ACS_SESSION_STATE_DIR=str(self.root / "state"))
                    if host == "claude-code":
                        argv = [str(BIN / "acs-claude-code-hook")]
                        event = {"session_id": session, "cwd": "/tmp", "hook_event_name": "PreToolUse",
                                 "tool_name": "Bash", "tool_input": {"command": "echo hi"}}
                    else:
                        argv = [str(BIN / "acs-cursor-hook"), "preToolUse"]
                        event = {"conversation_id": session, "workspace_roots": ["/tmp"],
                                 "tool_name": "Bash", "tool_input": {"command": "echo hi"}}
                    p = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, timeout=30)
                    out = json.loads(p.stdout) if p.stdout.strip() else {}
                    denied = (out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
                              if host == "claude-code" else out.get("permission") == "deny")
                    self._assert_settled(p, denied, "1", f"{host} deny={deny}: a record the agent wrote")


if __name__ == "__main__":
    unittest.main()
