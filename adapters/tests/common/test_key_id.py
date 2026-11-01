"""§10's HMAC key derivation and key_id rules."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from acs import client
from acs.client import Config, SigningMaterialMissing, _exchange
from acs.client import _handshake
from acs.core import derive_session_key, sign_with_key
from acs.integrations.claude_code import wire as claude_wire
from acs.integrations.cursor import wire as cursor_wire
from acs.testing.harness import ProgrammableGuardian, launch_guardian, make_envelope

SPEC = Path(__file__).resolve().parents[3] / "docs" / "spec" / "instrument" / "specification.md"
SECRET = "key-id-test-secret-0123456789abcdef"
BIN = Path(sys.executable).parent


def _audits(text: str) -> list[dict]:
    return [json.loads(line[len("ACS_AUDIT "):]) for line in text.splitlines() if line.startswith("ACS_AUDIT ")]


class KeyDerivation(unittest.TestCase):
    def test_the_spec_example_derives_the_spec_key(self) -> None:
        example = re.search(r"the `session_id` `(?P<sid>[0-9a-f-]{36})` give the key `(?P<key>[0-9a-f]{64})`",
                            SPEC.read_text(encoding="utf-8"))
        self.assertIsNotNone(example, "§10 no longer carries the HKDF example in the expected form")
        self.assertEqual(derive_session_key(bytes(range(32)), example["sid"]).hex(), example["key"])
        for spelling in (example["sid"].upper(), f"urn:uuid:{example['sid']}"):
            self.assertNotEqual(derive_session_key(bytes(range(32)), spelling).hex(), example["key"],
                                "info is the session_id as sent, not normalized")


class ConfiguredLabel(unittest.TestCase):
    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        patcher = mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "2026-11"},
                                  clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.session = str(uuid.uuid4())
        self.key = derive_session_key(SECRET.encode(), self.session)

    def _response(self, label: str) -> dict:
        return sign_with_key({"jsonrpc": "2.0", "id": "rpc-1", "result": {"decision": "allow"}}, self.key, key_id=label)

    def test_requests_carry_the_configured_label(self) -> None:
        signed = client.sign_envelope(make_envelope("steps/toolCallRequest", session_id=self.session),
                                      session_id=self.session)
        self.assertEqual(signed["params"]["signature"]["key_id"], "2026-11")

    def test_there_is_no_default_label(self) -> None:
        with self.assertRaises(TypeError):
            sign_with_key({"jsonrpc": "2.0", "id": "x", "result": {}}, self.key)  # type: ignore[call-arg]
        del os.environ["ACS_HMAC_KEY_ID"]
        with self.assertRaisesRegex(SigningMaterialMissing, "ACS_HMAC_KEY_ID"):
            client.sign_envelope(make_envelope("steps/toolCallRequest", session_id=self.session),
                                 session_id=self.session)

    def test_a_response_under_another_label_fails_without_a_fallback(self) -> None:
        self.assertTrue(client.verify_signature(self._response("2026-11"), session_id=self.session))
        self.assertFalse(client.verify_signature(self._response("2026-10"), session_id=self.session),
                         "the right key under another label is still rejected")
        del os.environ["ACS_HMAC_KEY_ID"]
        self.assertFalse(client.verify_signature(self._response("2026-11"), session_id=self.session))

    def _open(self, records: str) -> tuple[client.Handshake, int]:
        with mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(records)), \
                mock.patch.object(_exchange, "_open") as network:
            session = client.open_session(config=Config.from_env({"ACS_GUARDIAN_URL": "http://127.0.0.1:9/acs"}),
                                          session_id=self.session, agent_id="key-id", platform="test",
                                          methods_implemented=["steps/toolCallRequest"])
        return session, network.call_count

    def test_a_secret_without_a_label_refuses_the_session_and_sends_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as records:
            del os.environ["ACS_HMAC_KEY_ID"]
            session, calls = self._open(records)
            self.assertEqual((session.cause, calls), ("key_id_missing", 0))

    def test_a_stored_session_is_refused_once_its_label_is_gone(self) -> None:
        with tempfile.TemporaryDirectory() as records:
            _handshake.store_session_decision(Path(records), self.session, "http://127.0.0.1:9/acs",
                                              client.Negotiated({"negotiated_version": "0.1.0"}), SECRET.encode())
            del os.environ["ACS_HMAC_KEY_ID"]
            session, calls = self._open(records)
            self.assertEqual((session.cause, calls), ("key_id_missing", 0),
                             "the label is checked before a stored session is followed")

    def test_a_missing_short_or_empty_secret_refuses_the_session_and_sends_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            empty = Path(d) / "empty.key"
            empty.write_text("")
            empty.chmod(0o600)
            cases = {"secret_missing": {"ACS_HMAC_SECRET": ""},
                     "secret_too_short": {"ACS_HMAC_SECRET": "x" * 31},
                     "secret_unavailable": {"ACS_HMAC_SECRET": "", "ACS_HMAC_SECRET_FILE": str(empty)}}
            for cause, env in cases.items():
                with self.subTest(cause), mock.patch.dict(os.environ, env), tempfile.TemporaryDirectory() as records:
                    session, calls = self._open(records)
                    self.assertEqual((session.cause, calls), (cause, 0))

    def test_an_unknown_label_at_the_guardian_never_runs_a_tool(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET, key_id="2026-10")
        guardian.start()
        self.addCleanup(guardian.stop)
        with tempfile.TemporaryDirectory() as root:
            env = {**os.environ, "ACS_GUARDIAN_URL": guardian.url(), "ACS_HANDSHAKE_CACHE": root,
                   "ACS_SESSION_STATE_DIR": root}
            event = {"session_id": self.session, "cwd": "/tmp", "hook_event_name": "PreToolUse",
                     "tool_name": "Bash", "tool_input": {"command": "rm -rf /srv"}}
            for _ in range(2):
                p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps(event),
                                   capture_output=True, text=True, env=env, timeout=30)
                self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "deny",
                                 "fail-open does not turn an unverifiable rejection into an allow")
        self.assertIn("key_id_rejected", [r.get("cause") for r in _audits(p.stderr)])
        self.assertEqual(guardian.methods_seen(), ["handshake/hello"], "the refusal holds; nothing more is sent")


class ExampleGuardianLabel(unittest.TestCase):
    def _guardian(self, **extra: str) -> str:
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        env = {**{k: v for k, v in os.environ.items() if not k.startswith("ACS_")},
               "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "2026-11", "ACS_GUARDIAN_STATE_DIR": state.name, **extra}
        proc, port = launch_guardian(env=env)
        self.addCleanup(proc.wait, 3)
        self.addCleanup(proc.terminate)
        return f"http://127.0.0.1:{port}/acs"

    def _post(self, url: str, label: str) -> dict:
        hello = {"acs_versions_supported": ["0.1.0"], "methods_implemented": ["steps/toolCallRequest"],
                 "transports_supported": ["http"], "provenance_producer": "none", "wrapped_protocols": [],
                 "profiles_supported": ["acs-core"]}
        envelope = make_envelope("handshake/hello", hello, sign_with_secret=SECRET, key_id=label)
        request = urllib.request.Request(url, data=json.dumps(envelope).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def test_an_unknown_label_gets_an_unsigned_signature_invalid(self) -> None:
        answer = self._post(self._guardian(), "2026-10")
        self.assertEqual(answer["error"]["code"], -32004)
        self.assertNotIn("signature", answer["error"], "no configured secret matches, so the error is unsigned")

    def test_a_malformed_step_under_an_unknown_label_still_gets_an_unsigned_signature_invalid(self) -> None:
        envelope = make_envelope("steps/toolCallRequest", {"not": "a toolCallRequest payload"},
                                 sign_with_secret=SECRET, key_id="2026-10")
        request = urllib.request.Request(self._guardian(), data=json.dumps(envelope).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            answer = json.loads(response.read())
        self.assertEqual(answer["error"]["code"], -32004, "the label is settled before the envelope's schema")
        self.assertNotIn("signature", answer["error"])

    def test_a_response_carries_the_requests_label(self) -> None:
        answer = self._post(self._guardian(), "2026-11")
        self.assertEqual(answer["result"]["signature"]["key_id"], "2026-11")

    def test_a_guardian_with_a_secret_and_no_label_does_not_start(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "ACS_HMAC_KEY_ID"):
            self._guardian(ACS_HMAC_KEY_ID="")


class WireToolsNameTheSecret(unittest.TestCase):
    def test_wiring_needs_a_secret(self) -> None:
        for name, module in (("claude-code", claude_wire), ("cursor", cursor_wire)):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                hook = Path(d) / "hook"
                hook.write_text("#!/bin/sh\n")
                hook.chmod(0o755)
                with mock.patch.dict(os.environ, {"HOME": d}), mock.patch("sys.stderr"), \
                        self.assertRaises(SystemExit) as stop:
                    module.main(["--guardian-url=http://127.0.0.1:8787/acs", f"--settings={d}/settings.json",
                                 f"--hook-command={hook}", "--write"])
                self.assertEqual(stop.exception.code, 2)
                self.assertFalse((Path(d) / "settings.json").exists())

    def test_a_secret_needs_a_label_and_the_command_carries_it(self) -> None:
        for name, module in (("claude-code", claude_wire), ("cursor", cursor_wire)):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                hook = Path(d) / "hook"
                hook.write_text("#!/bin/sh\n")
                hook.chmod(0o755)
                base = ["--guardian-url=http://127.0.0.1:8787/acs", f"--settings={d}/settings.json",
                        f"--hook-command={hook}", "--secret-env-inline=ab" * 1]
                with mock.patch.dict(os.environ, {"HOME": d}), mock.patch("sys.stderr"), \
                        self.assertRaises(SystemExit):
                    module.main(base)
                command = module.build_command(
                    hook_command=str(hook), guardian_url="http://127.0.0.1:8787/acs", secret_file=None,
                    secret_env="ab", key_id="2026-11", default_deny=False, host_allowlist=None,
                    **({"event_name": "preToolUse"} if module is cursor_wire else {}))
                self.assertIn("ACS_HMAC_KEY_ID=2026-11 ", command)


if __name__ == "__main__":
    unittest.main()
