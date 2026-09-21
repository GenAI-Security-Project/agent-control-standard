"""Real TypeScript wire-shape and unsigned-peer rejection coverage.

Run separately from the Python-only gate: this suite requires Bun and the
installed reference-implementations/agt workspace. Missing prerequisites fail.
The TypeScript Guardian currently does not sign responses; these tests do not
claim successful authenticated interoperability or disable signature checks.
"""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
TYPESCRIPT = ROOT / "reference-implementations" / "agt"
sys.path.insert(0, str(ROOT / "adapters" / "_common"))
import acs_common
from test_harness import build_local_resolver, make_envelope, validate_response_envelope
from jsonschema import Draft202012Validator


class TypeScriptGuardianInterop(unittest.TestCase):
    SECRET = b"typescript-interop-test-secret-not-for-production"

    def setUp(self):
        bun = shutil.which("bun")
        if bun is None:
            raise RuntimeError("Install Bun and the AGT workspace dependencies; see adapters/codex/README.md")
        temporary = tempfile.TemporaryDirectory(prefix="acs-typescript-interop-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.cache = self.directory / "cache"
        self.log = self.directory / "envelopes.jsonl"
        secret_file = self.directory / "test.key"
        secret_file.write_bytes(self.SECRET)
        secret_file.chmod(0o600)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("ACS_")}
        self.env.update(
            ACS_HMAC_SECRET_FILE=str(secret_file),
            ACS_HANDSHAKE_CACHE=str(self.cache),
            ACS_DEFAULT_DENY="1",
            ACS_GUARDIAN_PORT="0",
            ACS_GUARDIAN_HOST="127.0.0.1",
            ACS_ENVELOPE_LOG=str(self.log),
            ACS_SESSION_CONTEXT_LOG=str(self.directory / "session-context.jsonl"),
        )
        self.enterContext(mock.patch.dict(os.environ, self.env, clear=True))
        self.enterContext(mock.patch.object(acs_common, "_HANDSHAKE_CACHE_DIR", self.cache))
        # A configured but empty file would enable the shared library's unsigned
        # development mode, defeating the purpose of this negative test.
        self.assertEqual(acs_common.load_hmac_secret(), self.SECRET)
        stdout = self.directory / "guardian.stdout"
        stderr = self.directory / "guardian.stderr"
        out = self.enterContext(stdout.open("w"))
        err = self.enterContext(stderr.open("w"))
        self.guardian = subprocess.Popen(
            [bun, "run", "packages/guardian/src/main.ts"],
            cwd=TYPESCRIPT, env=self.env, stdout=out, stderr=err,
        )
        self.addCleanup(self._stop_guardian)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and self.guardian.poll() is None:
            match = re.search(r"Guardian listening at (http://localhost:\d+/acs)", stdout.read_text())
            if match:
                self.url = match.group(1)
                self.session = str(uuid.uuid4())
                return
            time.sleep(0.05)
        self.fail(f"TypeScript Guardian did not start: {stderr.read_text()[-2000:]}")

    def _stop_guardian(self):
        self.guardian.terminate()
        try:
            self.guardian.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.guardian.kill()
            self.guardian.wait(timeout=3)

    def _assert_exchange(self):
        """Inspect the actual server's log, including the request it received."""
        records = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([(r["direction"], r["method"]) for r in records],
                         [("request", "handshake/hello"), ("response", "handshake/hello")])
        request, response = [r["envelope"] for r in records]
        session = request["params"]["metadata"]["session_id"]
        self.assertIn("signature", request["params"])
        self.assertTrue(acs_common.verify_signature(request, session_id=session))
        self.assertEqual(response["id"], request["id"])
        self.assertEqual(validate_response_envelope(response), [])
        schema, resolver = build_local_resolver("handshake.json")
        Draft202012Validator(
            schema["$defs"]["ServerHello"], resolver=resolver,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(response["result"])
        self.assertNotIn("payload", response["result"])
        self.assertNotIn("signature", response["result"])
        self.assertFalse(acs_common.verify_signature(response, session_id=session))
        return response

    def test_live_response_is_a_direct_serverhello(self):
        request = make_envelope(
            "handshake/hello", session_id=self.session, sign_with_secret=self.SECRET,
            payload={
                "acs_versions_supported": [acs_common.ACS_VERSION],
                "methods_implemented": ["steps/toolCallRequest"],
                "transports_supported": ["http"],
                "max_payload_size_bytes": 1_000_000,
                "provenance_producer": "none",
                "profiles_supported": [],
                "signature_algorithms_supported": ["HMAC-SHA256"],
            },
        )
        wire = urllib.request.Request(
            self.url, data=json.dumps(request).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(wire, timeout=5) as reply:
            response = json.load(reply)
        self.assertEqual(response, self._assert_exchange())

    def test_signed_shared_helper_refuses_unsigned_response_without_caching_it(self):
        audit = io.StringIO()
        with redirect_stderr(audit):
            hello = acs_common.ensure_session_handshake(
                guardian_url=self.url, session_id=self.session,
                agent_id="typescript-interop", platform="test",
                methods_implemented=["steps/toolCallRequest"],
                profiles_supported=[], transports_supported=["http"], timeout=5,
            )
        self._assert_exchange()
        self.assertIsNone(hello)
        self.assertIn('"cause": "server_hello_signature_invalid"', audit.getvalue())
        self.assertFalse(acs_common._handshake_cache_path(self.session, self.url).exists())

    def test_codex_default_deny_refuses_unsigned_peer_before_tool_request(self):
        event = {
            "hook_event_name": "PreToolUse", "session_id": self.session,
            "turn_id": "turn-interop", "tool_use_id": "call-interop",
            "cwd": str(self.directory), "tool_name": "Bash",
            "tool_input": {"command": "printf harmless", "timeout_ms": 1000},
        }
        proc = subprocess.run(
            [sys.executable, str(ROOT / "adapters" / "codex" / "acs_adapter.py")],
            input=json.dumps(event), text=True, capture_output=True, timeout=15,
            env={**self.env, "ACS_GUARDIAN_URL": self.url},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        output = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("handshake_failed", output["permissionDecisionReason"])
        self.assertIn('"cause": "server_hello_signature_invalid"', proc.stderr)
        self._assert_exchange()  # No steps/toolCallRequest reached the server.
        self.assertEqual(list(self.cache.glob("*.json")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
