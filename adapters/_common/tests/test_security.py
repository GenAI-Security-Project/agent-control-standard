"""
Security tests for the shared `acs_common` helpers and the Guardian
HTTP path. Each test names a specific attack and asserts the
mitigation that defeats it.

Spec context: ACS is a security project (the whole point is to police
agent behavior). Adapter and Guardian code that itself has security
holes undermines the standard. These tests are the falsifiers for the
mitigations documented in `adapters/SECURITY.md`.
"""
from __future__ import annotations

import binascii
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import acs_common  # noqa: E402
from test_harness import launch_guardian  # noqa: E402


HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "example-guardian" / "example_guardian.py"


# ----- 1. SSRF via Guardian URL -----

class GuardianUrlSchemeAllowlist(unittest.TestCase):
    """ACS_GUARDIAN_URL must be http/https; file://, ftp://, data://,
    etc. must be refused before the adapter calls urlopen — otherwise
    an attacker who controls the env var can read arbitrary files."""

    def test_file_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError) as cm:
            acs_common.validate_guardian_url("file:///etc/passwd")
        self.assertIn("scheme", str(cm.exception).lower())

    def test_ftp_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("ftp://example.com/x")

    def test_data_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("data:text/plain,evil")

    def test_javascript_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("javascript:alert(1)")

    def test_http_accepted(self) -> None:
        acs_common.validate_guardian_url("http://127.0.0.1:8787/acs")  # no raise

    def test_https_accepted(self) -> None:
        acs_common.validate_guardian_url("https://guardian.internal/acs")


# ----- 2. World-readable secret file -----

class HmacSecretFilePermissions(unittest.TestCase):
    """A secret file readable by group or world is a configuration mistake
    that must be refused — silently using a world-readable secret leaks
    the HMAC key to any local process."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.secret_path = Path(self.tmpdir) / "hmac.key"
        self.secret_path.write_bytes(b"super-secret-key-material" * 4)
        self._old_env = {
            "ACS_HMAC_SECRET_FILE": os.environ.get("ACS_HMAC_SECRET_FILE"),
            "ACS_HMAC_SECRET": os.environ.get("ACS_HMAC_SECRET"),
        }
        os.environ["ACS_HMAC_SECRET_FILE"] = str(self.secret_path)
        os.environ.pop("ACS_HMAC_SECRET", None)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_mode_0600_accepted(self) -> None:
        os.chmod(self.secret_path, 0o600)
        # Returns secret bytes; no raise
        self.assertTrue(acs_common.load_hmac_secret().startswith(b"super-secret"))

    def test_world_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o644)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()

    def test_group_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o640)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()

    def test_symlink_rejected(self) -> None:
        real = Path(self.tmpdir) / "real.key"
        real.write_bytes(b"x" * 32)
        os.chmod(real, 0o600)
        self.secret_path.unlink()
        os.symlink(real, self.secret_path)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()


# ----- 3. Guardian HTTP DoS via oversized body -----

class GuardianBodySizeCap(unittest.TestCase):
    """A POST with Content-Length > limit must be refused without reading
    the whole body. The Guardian's documented max_payload_size_bytes in
    the handshake is 1 MiB; the read path must enforce it."""

    @classmethod
    def setUpClass(cls) -> None:
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.proc, cls.port = launch_guardian(env=env)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def test_oversized_request_rejected(self) -> None:
        oversized = b"a" * (2 * 1024 * 1024)  # 2 MiB > 1 MiB cap
        req = urllib.request.Request(
            self.url, data=oversized,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        code = None
        connection_reset = False
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except urllib.error.URLError:
            # The Guardian sent its 413 response and closed the socket
            # before the client finished writing 2 MiB — manifests as a
            # connection reset / write error on the client side. That's
            # still a successful rejection: the body was never accepted.
            connection_reset = True
        # Any outcome that is NOT 200 OK proves the body was refused.
        self.assertFalse(code == 200,
            f"oversized request was accepted (status {code}) — DoS risk")
        if not connection_reset:
            self.assertIn(code, (400, 413),
                f"expected 413 Payload Too Large or 400 or connection reset; got {code}")


# ----- 4. Cache directory permissions -----

class CacheDirPermissions(unittest.TestCase):
    """save_session_state and the handshake cache must create files with
    mode 0600 and parent dirs with mode 0700 — otherwise a local
    attacker can read or poison adapter state."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp())
        self._old = os.environ.get("ACS_SESSION_STATE_DIR")
        os.environ["ACS_SESSION_STATE_DIR"] = str(self.tmpdir / "state")
        # Re-evaluate module-level dir
        import importlib
        importlib.reload(acs_common)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        if self._old is None:
            os.environ.pop("ACS_SESSION_STATE_DIR", None)
        else:
            os.environ["ACS_SESSION_STATE_DIR"] = self._old

    def test_session_state_file_is_0600(self) -> None:
        acs_common.save_session_state("test-session", {"x": 1})
        path = acs_common._session_state_path("test-session")
        self.assertTrue(path.exists())
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600,
            f"session-state file mode is {oct(mode)}, want 0o600")

    def test_session_state_dir_is_0700(self) -> None:
        acs_common.save_session_state("test-session", {"x": 1})
        d = acs_common._SESSION_STATE_DIR
        mode = stat.S_IMODE(os.stat(d).st_mode)
        self.assertEqual(mode, 0o700,
            f"session-state dir mode is {oct(mode)}, want 0o700")


# ----- 5. Regex DoS / oversized command input -----

class RegexInputSizeCap(unittest.TestCase):
    """Destructive-bash regex must not run on arbitrarily-large inputs.
    A multi-MB command crafted to trigger backtracking would freeze the
    Guardian; cap input length and audit the skip."""

    def test_oversized_command_is_short_circuited(self) -> None:
        # Construct a 64 KiB command that is benign but oversized
        large_cmd = "echo " + ("a" * (64 * 1024))
        # The destructive matcher should refuse to scan and return a
        # sentinel that the caller treats as "do not allow without
        # external review", not a False that allows the command.
        result = acs_common.scan_destructive_bash_safely(large_cmd, max_len=8192)
        self.assertEqual(result, "input_too_large",
            "oversized command MUST be flagged, not scanned, not silently allowed")

    def test_small_destructive_command_still_caught(self) -> None:
        # Use the Guardian's actual pattern set
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        for pat in example_guardian.DESTRUCTIVE_BASH_PATTERNS:
            if pat.search("rm -rf /home/x"):
                return
        self.fail("destructive pattern matching broken")

    def test_small_safe_command_returns_none(self) -> None:
        self.assertIsNone(
            acs_common.scan_destructive_bash_safely("ls -la", max_len=8192))


class Item13_DestructiveRmFlagVariants(unittest.TestCase):
    """Regression: every `rm` variant that combines recursive + force,
    no matter what other harmless flags are present (verbose, interactive,
    etc.), MUST be caught.

    Original Guardian regex used `\\b` after a fixed `-rf` match, so
    `rm -rfv /tmp/...` slipped through — the trailing `v` defeated the
    word boundary. A trivial single-letter extension defeating the
    policy is the worst class of regex bug for a security control."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        cls.eg = example_guardian

    def _assert_caught(self, cmd: str) -> None:
        match = self.eg._matches_destructive_bash(cmd)
        self.assertTrue(match,
            f"REGRESSION: destructive command not caught: {cmd!r}. "
            f"The Guardian's regex must match rm with recursive+force "
            f"flags regardless of additional harmless flags.")

    def _assert_allowed(self, cmd: str) -> None:
        match = self.eg._matches_destructive_bash(cmd)
        self.assertFalse(match,
            f"FALSE POSITIVE: benign command flagged as destructive: {cmd!r}")

    def test_rf_variants_caught(self) -> None:
        # Canonical
        self._assert_caught("rm -rf /home/x")
        self._assert_caught("rm -fr /home/x")
        self._assert_caught("rm --recursive --force /home/x")
        self._assert_caught("rm --force --recursive /home/x")

    def test_rf_with_trailing_letters_caught(self) -> None:
        # The bug Bar found: extra flag letters after r/f defeated the regex
        self._assert_caught("rm -rfv /home/x")
        self._assert_caught("rm -rfvi /home/x")
        self._assert_caught("rm -rfvI /home/x")
        self._assert_caught("rm -frv /home/x")

    def test_rf_with_middle_or_leading_letters_caught(self) -> None:
        self._assert_caught("rm -rvf /home/x")
        self._assert_caught("rm -vrf /home/x")
        self._assert_caught("rm -ivrf /home/x")

    def test_rf_with_trailing_slash_and_command_chain_caught(self) -> None:
        # Exact shape that Claude generated when Bar asked for an -rf test
        self._assert_caught("rm -rfv /tmp/this-is-a-fake-test-path-12345/")
        self._assert_caught("rm -rfv /tmp/foo/ ; echo done")

    def test_benign_rm_not_flagged(self) -> None:
        # rm WITHOUT both r and f is allowed
        self._assert_allowed("rm -v /home/x")
        self._assert_allowed("rm -i /home/x")
        self._assert_allowed("rm /home/x")
        self._assert_allowed("rmdir /home/x")
        # NOTE: `echo rm -rf /home/x` IS flagged by the regex (conservative
        # by design — wrapping a destructive command in `echo` and piping
        # to `sh` is a known evasion). Operators who want to allow it
        # disable the pattern in their policy bundle.


class Item14_ToolNameCaseInsensitive(unittest.TestCase):
    """Regression: the example Guardian's destructive-Bash policy was
    gated on `tool_name in ("Bash", "Shell")` — a case-sensitive string
    match. A NAT YAML key `shell` (lowercase) became the instance name,
    sailed past the check, and a real LLM-driven `rm -rf` against a
    sandbox directory ran to completion with the canary file deleted.
    The destructive regex was correct; the OUTER guard was too strict.

    Every reasonable shell tool name spelling MUST hit the same policy
    branch:
      - "Bash" (Claude Code adapter's PreToolUse tool name)
      - "Shell" (Cursor's beforeShellExecution synthesizes this name)
      - "shell" (NAT YAML key used as instance_name)
      - "bash" / "BASH" (paranoia — any caller-chosen casing)
    """

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        cls.eg = example_guardian

    def _call(self, tool_name: str, command: str) -> dict:
        params = {
            "request_id": "00000000-0000-4000-8000-000000000001",
            "chain_hash": "0" * 64,
            "metadata": {"session_id": "00000000-0000-4000-8000-000000000002"},
            "payload": {
                "tool": {"name": tool_name},
                "arguments": {"command": {"value": command}},
            },
        }
        return self.eg.evaluate_step(
            "steps/toolCallRequest", params,
            "00000000-0000-4000-8000-000000000001", "0" * 64)

    def test_every_reasonable_casing_denied(self) -> None:
        for name in ("Bash", "BASH", "bash", "Shell", "SHELL", "shell", "ShElL"):
            with self.subTest(tool_name=name):
                result = self._call(name, "rm -rf /tmp/x/")
                self.assertEqual(result.get("decision"), "deny",
                    f"tool name {name!r} should hit destructive-Bash branch")
                self.assertIn("destructive_command",
                                result.get("reason_codes", []))

    def test_unrelated_tool_unaffected(self) -> None:
        """Case-folding must not over-broaden — `read` is not a shell tool."""
        result = self._call("Read", "rm -rf /tmp/x/")
        # Read tool with a 'command' arg that LOOKS dangerous — not a
        # shell call, the destructive regex isn't applied here.
        self.assertEqual(result.get("decision"), "allow",
            "case-fold must not pull non-shell tools into shell policy")

    def test_task_subagent_gate_also_case_insensitive(self) -> None:
        """The Task tool deny was also case-sensitive; same case-fold."""
        # ALLOW_SUBAGENT defaults False so Task should be denied
        for name in ("Task", "task", "TASK"):
            with self.subTest(tool_name=name):
                result = self._call(name, "")
                self.assertEqual(result.get("decision"), "deny",
                    f"tool name {name!r} (Task variant) must hit subagent gate")
                self.assertIn("subagent_gated", result.get("reason_codes", []))


class Item15_VerifySignatureRobustToMalformedBase64(unittest.TestCase):
    """Regression: verify_signature() called base64.b64decode() directly
    without exception handling. A malformed signature value (truncation,
    garbage characters, wrong padding) raised binascii.Error / ValueError
    up to the request path instead of producing the spec's SIGNATURE_INVALID
    (-32004) response. The Guardian only caught GuardianError around
    signature checks, so the uncaught binascii.Error tore down the request
    on the wire as a 500 / disconnected handler — security control
    converted to a denial-of-service vector.

    Every form of unparseable base64 MUST return False (signature invalid),
    never crash."""

    BAD_VALUES = [
        "not-base64",                # raw garbage
        "this is not!base64@@@",     # non-base64 characters
        "!!!",                        # too short, illegal chars
        "===",                        # padding only
        "AB==CD",                    # padding mid-string
        "A" * 1000003,               # huge, no padding alignment
        "",                           # empty (this is "no signature" → False, no crash)
    ]

    def _make_envelope(self, sig_value):
        return {
            "params": {
                "request_id": "00000000-0000-4000-8000-000000000001",
                "metadata": {"session_id": "00000000-0000-4000-8000-000000000002"},
                "signature": {"algorithm": "HMAC-SHA256", "value": sig_value},
            }
        }

    def test_malformed_signature_returns_false_not_crashes(self) -> None:
        import os
        os.environ["ACS_HMAC_SECRET"] = "verify-sig-robustness-test-secret"
        try:
            for bad in self.BAD_VALUES:
                with self.subTest(signature=bad[:30]):
                    env = self._make_envelope(bad)
                    try:
                        result = acs_common.verify_signature(env)
                    except (binascii.Error, ValueError, TypeError) as e:
                        self.fail(
                            f"REGRESSION: malformed signature {bad[:30]!r} "
                            f"raised {type(e).__name__} instead of returning "
                            f"False; this turns SIGNATURE_INVALID into a "
                            f"crash on the request path")
                    self.assertFalse(
                        result,
                        f"malformed signature {bad[:30]!r} must verify as False")
        finally:
            os.environ.pop("ACS_HMAC_SECRET", None)


class Item16_ResponseRequestBinding(unittest.TestCase):
    """The per-session HMAC proves origin, not that a response answers
    THIS request. Binding = JSON-RPC `id` + `result.request_id`."""

    REQ = {"jsonrpc": "2.0", "id": "rpc-1", "method": "steps/toolCallRequest",
           "params": {"request_id": "11111111-1111-4111-8111-111111111111"}}

    def test_bound_response_accepted(self) -> None:
        resp = {"jsonrpc": "2.0", "id": "rpc-1",
                "result": {"request_id": "11111111-1111-4111-8111-111111111111",
                           "decision": "allow"}}
        self.assertTrue(acs_common.response_matches_request(self.REQ, resp))

    def test_wrong_jsonrpc_id_rejected(self) -> None:
        """A replayed response carries the OLD exchange's id."""
        resp = {"jsonrpc": "2.0", "id": "rpc-OTHER",
                "result": {"request_id": "11111111-1111-4111-8111-111111111111",
                           "decision": "allow"}}
        self.assertFalse(acs_common.response_matches_request(self.REQ, resp))

    def test_wrong_request_id_rejected(self) -> None:
        resp = {"jsonrpc": "2.0", "id": "rpc-1",
                "result": {"request_id": "99999999-9999-4999-8999-999999999999",
                           "decision": "allow"}}
        self.assertFalse(acs_common.response_matches_request(self.REQ, resp))

    def test_result_missing_request_id_rejected(self) -> None:
        """response-envelope.json requires request_id on every result;
        a result without one cannot be bound and must not be trusted."""
        resp = {"jsonrpc": "2.0", "id": "rpc-1",
                "result": {"decision": "allow"}}
        self.assertFalse(acs_common.response_matches_request(self.REQ, resp))

    def test_error_response_binds_by_id_alone(self) -> None:
        """Error responses carry no result — the JSON-RPC id is the
        only binding, and it must still match."""
        ok = {"jsonrpc": "2.0", "id": "rpc-1",
              "error": {"code": -32005, "message": "replay"}}
        bad = {"jsonrpc": "2.0", "id": "rpc-2",
               "error": {"code": -32005, "message": "replay"}}
        self.assertTrue(acs_common.response_matches_request(self.REQ, ok))
        self.assertFalse(acs_common.response_matches_request(self.REQ, bad))


class Item17_GuardianRefusalClassification(unittest.TestCase):
    """Refusal codes = the Guardian is ALIVE and REFUSED this envelope.
    Every one is attacker-reachable (oversize the body, replay the
    deterministic request_id, strip the signature), so adapters fail
    closed on them regardless of posture (spec issue #32)."""

    def test_refusal_codes(self) -> None:
        for code in (-32000, -32004, -32005, -32006, -32600, -32700):
            with self.subTest(code=code):
                self.assertTrue(acs_common.is_guardian_refusal(code))

    def test_non_refusal_codes_follow_posture(self) -> None:
        """Version/negotiation errors and unknowns are decision
        failures, not refusals — they follow the §6.4 posture."""
        for code in (None, -32001, -32002, -32003, -32099, 500):
            with self.subTest(code=code):
                self.assertFalse(acs_common.is_guardian_refusal(code))


class Item18_AuditFileSink(unittest.TestCase):
    """ACS_AUDIT_FILE gives §6.4's audit half somewhere durable to
    land; hook-process stderr alone is not collected."""

    def test_audit_event_appends_to_file_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            audit_path = os.path.join(d, "audit.log")
            os.environ["ACS_AUDIT_FILE"] = audit_path
            try:
                acs_common.audit_event("test_sink", foo="bar")
                acs_common.audit_event("test_sink_2", baz=1)
            finally:
                os.environ.pop("ACS_AUDIT_FILE", None)
            content = open(audit_path).read()
            self.assertIn("test_sink", content)
            self.assertIn("test_sink_2", content)
            self.assertEqual(len(content.strip().splitlines()), 2,
                "each audit_event appends exactly one line")
            mode = stat.S_IMODE(os.stat(audit_path).st_mode)
            self.assertEqual(mode, 0o600,
                f"audit file must be 0600, got {oct(mode)}")

    def test_unwritable_audit_file_does_not_crash_hook_path(self) -> None:
        os.environ["ACS_AUDIT_FILE"] = "/nonexistent-dir/audit.log"
        try:
            acs_common.audit_event("still_works")  # must not raise
        finally:
            os.environ.pop("ACS_AUDIT_FILE", None)


class Item19_SecretFileUnreadableRaises(unittest.TestCase):
    """A configured-but-unreadable ACS_HMAC_SECRET_FILE must raise,
    never silently downgrade to unsigned mode."""

    def test_missing_secret_file_raises(self) -> None:
        os.environ["ACS_HMAC_SECRET_FILE"] = "/nonexistent-secret-file"
        try:
            with self.assertRaises(acs_common.SecretFileUnreadableError):
                acs_common.load_hmac_secret()
        finally:
            os.environ.pop("ACS_HMAC_SECRET_FILE", None)

    def test_no_secret_at_all_is_still_devmode_empty(self) -> None:
        """No configuration at all stays dev-mode (b\"\") — only a
        CONFIGURED-and-broken path is an incident."""
        os.environ.pop("ACS_HMAC_SECRET_FILE", None)
        old = os.environ.pop("ACS_HMAC_SECRET", None)
        try:
            self.assertEqual(acs_common.load_hmac_secret(), b"")
        finally:
            if old is not None:
                os.environ["ACS_HMAC_SECRET"] = old


class Item20_HandshakeNegativeCache(unittest.TestCase):
    """Handshake failures are negative-cached for a short TTL so a dead
    Guardian costs one timeout, not one per hook event."""

    def test_second_failure_is_fast_and_cached(self) -> None:
        import time as _time
        with tempfile.TemporaryDirectory() as d:
            os.environ["ACS_HANDSHAKE_CACHE"] = d
            # Force module to re-read the cache dir env
            import importlib
            importlib.reload(acs_common)
            try:
                kw = dict(guardian_url="http://127.0.0.1:1/acs",
                          session_id="cache-test", agent_id="a",
                          platform="test",
                          methods_implemented=["steps/toolCallRequest"],
                          timeout=2.0)
                t0 = _time.time()
                self.assertIsNone(acs_common.ensure_session_handshake(**kw))
                first = _time.time() - t0
                t1 = _time.time()
                self.assertIsNone(acs_common.ensure_session_handshake(**kw))
                second = _time.time() - t1
                self.assertLess(second, 0.1,
                    f"second handshake attempt took {second:.3f}s — the "
                    f"failure was not negative-cached (first: {first:.3f}s)")
            finally:
                os.environ.pop("ACS_HANDSHAKE_CACHE", None)
                importlib.reload(acs_common)


# ----- 21. Degraded bootstrap: missing rfc8785 -----

CLAUDE_ADAPTER = HERE.parent.parent / "claude-code" / "acs_adapter.py"


class Item21_AdapterDegradedBootstrap(unittest.TestCase):
    """§10 makes rfc8785 mandatory, so its absence is not a degraded mode
    the adapter may take silently. Claude Code proceeds on any nonzero exit
    except 2, so a bare ImportError is an ungoverned step. §6.4:158 requires
    an audit event for it, and §6.4:156 puts it under the deployment's
    posture."""

    def test_adapter_that_cannot_load_audits_and_honors_the_posture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            shadow = Path(tmpdir) / "shadow"
            shadow.mkdir()
            (shadow / "rfc8785.py").write_text(
                "raise ImportError('simulating an environment without rfc8785')\n")
            event = json.dumps({"session_id": "s-1", "cwd": "/tmp",
                                "hook_event_name": "PreToolUse",
                                "tool_name": "Bash",
                                "tool_input": {"command": "rm -rf /home/u"}})

            for posture, expect_deny in (("1", True), ("0", False)):
                with self.subTest(ACS_DEFAULT_DENY=posture):
                    env = os.environ.copy()
                    env["PYTHONPATH"] = str(shadow)
                    env["ACS_DEFAULT_DENY"] = posture
                    env.pop("ACS_DISABLED", None)
                    p = subprocess.run([sys.executable, str(CLAUDE_ADAPTER)],
                                       input=event, capture_output=True,
                                       text=True, env=env, timeout=15)
                    self.assertIn("adapter_unavailable", p.stderr,
                        "§6.4:158 requires every step that proceeds without a "
                        "decision to be recorded; this path must not be silent")
                    if expect_deny:
                        self.assertIn('"permissionDecision": "deny"', p.stdout,
                            "the deployment set the posture to deny per §6.4:156, "
                            "so an unloadable adapter must not let the tool run")
                    else:
                        self.assertEqual(p.stdout.strip(), "",
                            "fail-open is the §6.4 default, so proceeding is "
                            "correct here as long as it is audited")

    def test_cursor_adapter_that_cannot_load_audits_and_honors_the_posture(self) -> None:
        """Same degraded-bootstrap contract for the Cursor adapter: gate
        events deny via {"permission": "deny"}; beforeSubmitPrompt blocks
        via exit code 2."""
        cursor_adapter = HERE.parent.parent / "cursor" / "acs_adapter.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            shadow = Path(tmpdir) / "shadow"
            shadow.mkdir()
            (shadow / "rfc8785.py").write_text(
                "raise ImportError('simulating an environment without rfc8785')\n")
            event = json.dumps({"conversation_id": "c-1",
                                "workspace_roots": ["/tmp"],
                                "tool_name": "Bash",
                                "tool_input": {"command": "rm -rf /home/u"}})
            env = os.environ.copy()
            env["PYTHONPATH"] = str(shadow)
            env["ACS_DEFAULT_DENY"] = "1"
            env.pop("ACS_DISABLED", None)

            p = subprocess.run([sys.executable, str(cursor_adapter), "preToolUse"],
                               input=event, capture_output=True,
                               text=True, env=env, timeout=15)
            self.assertIn("adapter_unavailable", p.stderr)
            self.assertIn('"permission": "deny"', p.stdout,
                "an unloadable Cursor adapter under deny posture must deny "
                "the gate event, not exit 1 with no JSON (which proceeds)")

            p = subprocess.run([sys.executable, str(cursor_adapter),
                                "beforeSubmitPrompt"],
                               input=event, capture_output=True,
                               text=True, env=env, timeout=15)
            self.assertIn("adapter_unavailable", p.stderr)
            self.assertEqual(p.returncode, 2,
                "beforeSubmitPrompt blocks via exit code 2; anything else "
                "lets the prompt through on adapter load failure")

    def test_nat_middleware_import_failure_is_loud_not_silent(self) -> None:
        """If acs_common (hence rfc8785) can't import, the NAT module
        must emit an 'UNGOVERNED' banner AND re-raise — never load
        cleanly while ungoverned."""
        nat_adapter_dir = HERE.parent.parent / "nat"
        with tempfile.TemporaryDirectory() as tmpdir:
            shadow = Path(tmpdir) / "shadow"
            shadow.mkdir()
            (shadow / "rfc8785.py").write_text(
                "raise ImportError('simulating an environment without rfc8785')\n")
            env = os.environ.copy()
            # Shadow first so the broken rfc8785 wins; run from the NAT dir
            # so `import acs_adapter` resolves to NAT's module.
            env["PYTHONPATH"] = str(shadow)
            p = subprocess.run([sys.executable, "-c", "import acs_adapter"],
                               cwd=str(nat_adapter_dir), capture_output=True,
                               text=True, env=env, timeout=30)
            self.assertNotEqual(p.returncode, 0,
                "a NAT middleware that can't load its signing dependency must "
                "NOT import cleanly — that would look governed while it isn't")
            self.assertIn("UNGOVERNED", p.stderr,
                f"the import-failure banner must be loud and name the "
                f"ungoverned state; stderr={p.stderr[:400]}")
            self.assertIn("rfc8785", p.stderr,
                "the banner must name the missing dependency and the fix")


# ----- 22. Cached ServerHello re-verification -----

class Item22_CachedServerHelloReverified(unittest.TestCase):
    """§4.1:75 says on_decision_failure is negotiated in the handshake.
    §10 says every response carries a signature and a verifier MUST reject
    one that does not cover the envelope. The cached ServerHello is a
    response, held at a predictable path the observed agent can write, and
    its only consumer is the fail posture."""

    SESSION = "55555555-5555-4555-8555-555555555555"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _hello(self, *, on_decision_failure: str):
        def handler(req: dict) -> dict:
            return {
                "type": "final", "acs_version": "0.1.0",
                "request_id": req["params"]["request_id"],
                "decision": "allow",
                "payload": {
                    "negotiated_version": "0.1.0",
                    "methods_evaluated":
                        req["params"]["payload"].get("methods_implemented", []),
                    "selected_transport": "http",
                    "signature_algorithms_supported": ["HMAC-SHA256"],
                    "timeout_config": {"default_ms": 5000},
                    "skew_window_ms": 300000,
                    "on_decision_failure": on_decision_failure,
                    "profiles_accepted": ["acs-core"],
                },
            }
        return handler

    def _cache_file(self, guardian_url: str) -> Path:
        import hashlib as _hashlib
        key = _hashlib.sha256(
            (self.SESSION + "|" + guardian_url).encode()).hexdigest()
        return self.cache_dir / f"{key}.json"

    def _run_claude_adapter(self, *, guardian_url: str,
                            secret: str) -> tuple[int, str, str]:
        env = os.environ.copy()
        env.update({
            "ACS_GUARDIAN_URL": guardian_url,
            "ACS_HMAC_SECRET": secret,
            "ACS_HANDSHAKE_CACHE": str(self.cache_dir),
            # Fresh-failure markers from earlier stanzas must not
            # short-circuit later ones except where the test says so.
            "ACS_HANDSHAKE_TIMEOUT_SECONDS": "2",
        })
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env.pop("ACS_DEFAULT_DENY", None)
        proc = subprocess.run(
            [sys.executable, str(CLAUDE_ADAPTER)],
            input=json.dumps({
                "session_id": self.SESSION, "cwd": "/tmp",
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": "echo hi"},
            }),
            capture_output=True, text=True, env=env, timeout=20)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cached_serverhello_is_reverified_before_governing_posture(self) -> None:
        from test_harness import ProgrammableGuardian
        g = ProgrammableGuardian()
        g.handlers["handshake/hello"] = self._hello(on_decision_failure="deny")
        with g:
            url = g.url()
            self._run_claude_adapter(guardian_url=url,
                                     secret=g.hmac_secret)  # populates cache
        cache = self._cache_file(url)
        self.assertTrue(cache.exists(), "handshake cache was not populated")

        # Guardian is down from here on, so the posture decides every event.
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn('"permissionDecision": "deny"', out,
            "an honest cached ServerHello declaring deny must fail closed")

        # Edit one word in the cached envelope: deny -> proceed.
        entry = json.loads(cache.read_text())
        # Keep the regression runnable against the reviewed implementation,
        # which cached the bare ServerHello payload.  A red-before result must
        # demonstrate the security behavior (the edit is trusted), not abort
        # while arranging the fixture because the cache format later changed.
        payload = (entry.get("result") or {}).get("payload", entry)
        self.assertEqual(payload["on_decision_failure"], "deny")
        payload["on_decision_failure"] = "proceed"
        cache.write_text(json.dumps(entry))
        # Refresh mtime so the TTL check passes and only the signature
        # can reject it.
        os.utime(cache)
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn("handshake_cache_signature_invalid", err,
            "§10 requires a verifier to reject a signature that does not "
            "cover the envelope. The edit must be detected, not accepted in "
            "silence. Note the edit still lands on the §4.1:75 startup "
            "posture, which defaults to proceed, so this makes the "
            "downgrade visible, not impossible.")

        # Replace the cache with a bare, fresh failure marker.
        cache.unlink()
        marker = cache.with_suffix(".failed")
        marker.touch()
        os.utime(marker)
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn("handshake_negative_cache_hit", err,
            "§4.1:77 requires a session that proceeds unguarded to be "
            "recorded. This branch must be audited, not silent.")


# ----- 23. ClientHello advertises only earned integrity capabilities -----

class Item23_ClientHelloCapabilityHonesty(unittest.TestCase):
    """An unsigned session must not advertise the signed ACS-Core floor.

    Capture the actual serialized ClientHello at the network boundary.  The
    fake transport deliberately refuses after capture because the behavior
    under test is the adapter's outbound capability claim, not a cooperative
    Guardian fixture repeating the same expectation.
    """

    def _capture_client_hello(self, secret: str | None) -> dict:
        saved = {name: os.environ.get(name) for name in
                 ("ACS_HMAC_SECRET", "ACS_HMAC_SECRET_FILE")}
        try:
            if secret is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = secret
            os.environ.pop("ACS_HMAC_SECRET_FILE", None)

            captured: list[dict] = []

            def refuse_after_capture(req, timeout):
                captured.append(json.loads(req.data.decode("utf-8")))
                raise urllib.error.URLError("capture complete")

            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(acs_common, "_HANDSHAKE_CACHE_DIR",
                                      Path(d)), \
                    mock.patch.object(acs_common.urllib.request, "urlopen",
                                      side_effect=refuse_after_capture):
                result = acs_common.ensure_session_handshake(
                    guardian_url="http://127.0.0.1:8787/acs",
                    session_id=str(uuid.uuid4()),
                    agent_id="capability-test",
                    platform="test",
                    methods_implemented=["steps/toolCallRequest"],
                )
            self.assertIsNone(result)
            self.assertEqual(len(captured), 1)
            return captured[0]
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_signed_and_unsigned_client_hello_claims_match_the_wire(self) -> None:
        signed = self._capture_client_hello("capability-secret")
        unsigned = self._capture_client_hello(None)

        signed_payload = signed["params"]["payload"]
        self.assertEqual(signed_payload["profiles_supported"], ["acs-core"])
        self.assertEqual(signed_payload["signature_algorithms_supported"],
                         ["HMAC-SHA256"])
        self.assertIn("signature", signed["params"],
            "a session advertising the Core integrity floor must actually "
            "sign its ClientHello")

        unsigned_payload = unsigned["params"]["payload"]
        self.assertEqual(unsigned_payload["profiles_supported"], [])
        self.assertEqual(unsigned_payload["signature_algorithms_supported"], [])
        self.assertNotIn("signature", unsigned["params"],
            "unsigned development mode must be explicit on the wire")


if __name__ == "__main__":
    unittest.main(verbosity=2)
