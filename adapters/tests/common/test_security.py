"""
Security tests for the shared `acs.core` and `acs.client` helpers and the Guardian
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

from acs import client  # noqa: E402
from acs import core  # noqa: E402
from acs.client import _exchange
from acs.client import _handshake as client_handshake  # noqa: E402
from acs.client import _store as client_store  # noqa: E402
from acs.examples import destructive_bash  # noqa: E402
from acs.testing.harness import launch_guardian, signing_env  # noqa: E402


HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "src" / "acs" / "guardian" / "example_guardian.py"


# ----- 1. SSRF via Guardian URL -----

class GuardianUrlSchemeAllowlist(unittest.TestCase):
    """ACS_GUARDIAN_URL must be http/https; file://, ftp://, data://,
    etc. must be refused before the adapter calls urlopen — otherwise
    an attacker who controls the env var can read arbitrary files."""

    def test_file_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError) as cm:
            client.validate_guardian_url("file:///etc/passwd")
        self.assertIn("scheme", str(cm.exception).lower())

    def test_ftp_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            client.validate_guardian_url("ftp://example.com/x")

    def test_data_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            client.validate_guardian_url("data:text/plain,evil")

    def test_javascript_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            client.validate_guardian_url("javascript:alert(1)")

    def test_http_accepted(self) -> None:
        client.validate_guardian_url("http://127.0.0.1:8787/acs")  # no raise

    def test_https_accepted(self) -> None:
        client.validate_guardian_url("https://guardian.internal/acs")


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
            "ACS_HMAC_SECRET_FILE": os.environ.get("ACS_HMAC_SECRET_FILE"), "ACS_HMAC_KEY_ID": "test-key",
            "ACS_HMAC_SECRET": os.environ.get("ACS_HMAC_SECRET"), "ACS_HMAC_KEY_ID": "test-key",
        }
        os.environ["ACS_HMAC_SECRET_FILE"] = str(self.secret_path)
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
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
        self.assertTrue(client.load_hmac_secret().startswith(b"super-secret"))

    def test_world_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o644)
        with self.assertRaises(client.SecretFilePermissionsError):
            client.load_hmac_secret()

    def test_group_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o640)
        with self.assertRaises(client.SecretFilePermissionsError):
            client.load_hmac_secret()

    def test_symlink_rejected(self) -> None:
        real = Path(self.tmpdir) / "real.key"
        real.write_bytes(b"x" * 32)
        os.chmod(real, 0o600)
        self.secret_path.unlink()
        os.symlink(real, self.secret_path)
        with self.assertRaises(client.SecretFilePermissionsError):
            client.load_hmac_secret()


# ----- 3. Guardian HTTP DoS via oversized body -----

class GuardianBodySizeCap(unittest.TestCase):
    """A POST with Content-Length > limit must be refused without reading
    the whole body. The Guardian's documented max_payload_size_bytes in
    the handshake is 1 MiB; the read path must enforce it."""

    @classmethod
    def setUpClass(cls) -> None:
        env = os.environ.copy()
        env.update(signing_env())
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
        import shutil
        self.tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        patcher = mock.patch.object(client_store, "_SESSION_STATE_DIR", self.tmpdir / "state")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_session_state_file_is_0600(self) -> None:
        client.save_session_state("test-session", {"x": 1})
        path = client_store._session_state_path("test-session")
        self.assertTrue(path.exists())
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600,
            f"session-state file mode is {oct(mode)}, want 0o600")

    def test_session_state_dir_is_0700(self) -> None:
        client.save_session_state("test-session", {"x": 1})
        d = client_store._SESSION_STATE_DIR
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
        result = destructive_bash.scan_destructive_bash_safely(large_cmd, max_len=8192)
        self.assertEqual(result, "input_too_large",
            "oversized command MUST be flagged, not scanned, not silently allowed")

    def test_small_destructive_command_still_caught(self) -> None:
        # Use the Guardian's actual pattern set
        for pat in destructive_bash.DESTRUCTIVE_BASH_PATTERNS:
            if pat.search("rm -rf /home/x"):
                return
        self.fail("destructive pattern matching broken")

    def test_small_safe_command_returns_none(self) -> None:
        self.assertIsNone(
            destructive_bash.scan_destructive_bash_safely("ls -la", max_len=8192))


class Item13_DestructiveRmFlagVariants(unittest.TestCase):
    """Regression: every `rm` variant that combines recursive + force,
    no matter what other harmless flags are present (verbose, interactive,
    etc.), MUST be caught.

    Original Guardian regex used `\\b` after a fixed `-rf` match, so
    `rm -rfv /tmp/...` slipped through — the trailing `v` defeated the
    word boundary. A trivial single-letter extension defeating the
    policy is the worst class of regex bug for a security control."""

    def _assert_caught(self, cmd: str) -> None:
        match = destructive_bash.matches_destructive_bash(cmd)
        self.assertTrue(match,
            f"REGRESSION: destructive command not caught: {cmd!r}. "
            f"The Guardian's regex must match rm with recursive+force "
            f"flags regardless of additional harmless flags.")

    def _assert_allowed(self, cmd: str) -> None:
        match = destructive_bash.matches_destructive_bash(cmd)
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

    def test_split_recursive_and_force_flags_caught(self) -> None:
        # Separate -r and -f tokens are the same command as -rf.
        self._assert_caught("rm -r -f /")
        self._assert_caught("rm -f -r /")
        self._assert_caught("rm -R -f ~")
        self._assert_caught("rm -r -f -v /home/x")
        self._assert_caught("rm -r --force $HOME")
        self._assert_allowed("rm -r -f ./build")

    def test_find_on_root_or_home_caught(self) -> None:
        # A word boundary after `/` or `~` never matches before a space, so the
        # find patterns once missed the bare root and home directory.
        self._assert_caught("find / -delete")
        self._assert_caught("find ~ -delete")
        self._assert_caught("find $HOME -delete")
        self._assert_caught("find / -exec rm {} +")
        self._assert_caught("find /home -delete")
        self._assert_allowed("find . -delete")
        self._assert_allowed("find / -name '*.log'")

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
        from acs.guardian import example_guardian
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
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        try:
            for bad in self.BAD_VALUES:
                with self.subTest(signature=bad[:30]):
                    env = self._make_envelope(bad)
                    try:
                        result = client.verify_signature(env)
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
        self.assertTrue(core.response_matches_request(self.REQ, resp))

    def test_wrong_jsonrpc_id_rejected(self) -> None:
        """A replayed response carries the OLD exchange's id."""
        resp = {"jsonrpc": "2.0", "id": "rpc-OTHER",
                "result": {"request_id": "11111111-1111-4111-8111-111111111111",
                           "decision": "allow"}}
        self.assertFalse(core.response_matches_request(self.REQ, resp))

    def test_wrong_request_id_rejected(self) -> None:
        resp = {"jsonrpc": "2.0", "id": "rpc-1",
                "result": {"request_id": "99999999-9999-4999-8999-999999999999",
                           "decision": "allow"}}
        self.assertFalse(core.response_matches_request(self.REQ, resp))

    def test_result_missing_request_id_rejected(self) -> None:
        """response-envelope.json requires request_id on every result;
        a result without one cannot be bound and must not be trusted."""
        resp = {"jsonrpc": "2.0", "id": "rpc-1",
                "result": {"decision": "allow"}}
        self.assertFalse(core.response_matches_request(self.REQ, resp))

    def test_error_response_binds_by_id_alone(self) -> None:
        """Error responses carry no result — the JSON-RPC id is the
        only binding, and it must still match."""
        ok = {"jsonrpc": "2.0", "id": "rpc-1",
              "error": {"code": -32005, "message": "replay"}}
        bad = {"jsonrpc": "2.0", "id": "rpc-2",
               "error": {"code": -32005, "message": "replay"}}
        self.assertTrue(core.response_matches_request(self.REQ, ok))
        self.assertFalse(core.response_matches_request(self.REQ, bad))


class Item17_GuardianRefusalClassification(unittest.TestCase):
    """Refusal codes = the Guardian is ALIVE and REFUSED this envelope.
    Every one is attacker-reachable (oversize the body, replay the
    deterministic request_id, strip the signature), so adapters fail
    closed on them regardless of posture (spec issue #32)."""

    def test_refusal_codes(self) -> None:
        for code in (-32000, -32004, -32005, -32006, -32600, -32700):
            with self.subTest(code=code):
                self.assertTrue(core.is_guardian_refusal(code))

    def test_non_refusal_codes_follow_posture(self) -> None:
        """Version/negotiation errors and unknowns are decision
        failures, not refusals — they follow the §6.4 posture."""
        for code in (None, -32001, -32002, -32003, -32099, 500):
            with self.subTest(code=code):
                self.assertFalse(core.is_guardian_refusal(code))


class Item18_AuditFileSink(unittest.TestCase):
    """ACS_AUDIT_FILE gives §6.4's audit half somewhere durable to
    land; hook-process stderr alone is not collected."""

    def test_audit_event_appends_to_file_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            audit_path = os.path.join(d, "audit.log")
            os.environ["ACS_AUDIT_FILE"] = audit_path
            try:
                client.audit_event("test_sink", foo="bar")
                client.audit_event("test_sink_2", baz=1)
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
            client.audit_event("still_works")  # must not raise
        finally:
            os.environ.pop("ACS_AUDIT_FILE", None)


class Item19_SecretFileUnreadableRaises(unittest.TestCase):
    """A configured-but-unreadable ACS_HMAC_SECRET_FILE must raise, not read as a missing secret."""

    def test_missing_secret_file_raises(self) -> None:
        os.environ["ACS_HMAC_SECRET_FILE"] = "/nonexistent-secret-file"
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        try:
            with self.assertRaises(client.SecretFileUnreadableError):
                client.load_hmac_secret()
        finally:
            os.environ.pop("ACS_HMAC_SECRET_FILE", None)

    def test_no_secret_at_all_reads_as_empty_and_is_refused(self) -> None:
        """No configuration reads as an empty secret, which load_signing_material refuses (secret_missing)."""
        os.environ.pop("ACS_HMAC_SECRET_FILE", None)
        old = os.environ.pop("ACS_HMAC_SECRET", None)
        try:
            self.assertEqual(client.load_hmac_secret(), b"")
            with self.assertRaises(client.SigningMaterialMissing) as refused:
                client.load_signing_material()
            self.assertEqual(refused.exception.cause, "secret_missing")
        finally:
            if old is not None:
                os.environ["ACS_HMAC_SECRET"] = old
                os.environ["ACS_HMAC_KEY_ID"] = "test-key"


class Item20_DeadGuardianCostsOneTimeoutPerSession(unittest.TestCase):
    """A session whose handshake got no answer stores that decision, so a
    dead Guardian costs one timeout per session, not one per hook event."""

    def test_second_event_of_the_session_is_fast(self) -> None:
        import time as _time
        signing = {**{k: v for k, v in os.environ.items() if k != "ACS_HMAC_SECRET_FILE"}, **signing_env()}
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, signing, clear=True), \
                mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(d)):
            kw = dict(config=client.Config.from_env({"ACS_GUARDIAN_URL": "http://127.0.0.1:1/acs"}),
                      session_id="cache-test", agent_id="a", platform="test",
                      methods_implemented=["steps/toolCallRequest"], timeout=2.0)
            t0 = _time.time()
            first = client.open_session(**kw)
            elapsed_first = _time.time() - t0
            t1 = _time.time()
            second = client.open_session(**kw)
            elapsed_second = _time.time() - t1
        self.assertIsInstance(first, client.NoAnswer)
        self.assertEqual(second, first)
        self.assertLess(elapsed_second, 0.1,
            f"second event took {elapsed_second:.3f}s; the session's no-answer "
            f"decision was not stored (first: {elapsed_first:.3f}s)")


BIN = Path(sys.executable).parent


def _audit_records(text: str) -> list[dict]:
    return [json.loads(line[len("ACS_AUDIT "):]) for line in text.splitlines()
            if line.startswith("ACS_AUDIT ")]


class Item21_AdapterDegradedBootstrap(unittest.TestCase):
    """§10 makes rfc8785 mandatory and the hosts proceed on a nonzero exit, so its absence is audited and follows the posture (§6.4)."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.shadow = self.tmp / "shadow"
        self.shadow.mkdir()
        (self.shadow / "rfc8785.py").write_text(
            "raise ImportError('simulating an environment without rfc8785')\n")

    def _commands(self, script: str, module: str) -> list[tuple[str, list[str]]]:
        installed = BIN / script
        self.assertTrue(installed.exists(),
            f"{installed} is missing; install the package (uv sync) so the "
            f"console script users run is the one under test")
        return [("installed", [str(installed)]), ("module", [sys.executable, "-m", module])]

    def _run(self, argv: list[str], stdin: str, **env_overrides: str):
        audit_file = self.tmp / f"audit-{uuid.uuid4().hex}.log"
        env = os.environ.copy()
        for name in ("ACS_DISABLED", "ACS_DEFAULT_DENY"):
            env.pop(name, None)
        # Shadow first so the broken rfc8785 wins over the installed one.
        env["PYTHONPATH"] = str(self.shadow)
        env["ACS_AUDIT_FILE"] = str(audit_file)
        env.update(env_overrides)
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                           env=env, timeout=15)
        records = _audit_records(p.stderr)
        file_records = _audit_records(audit_file.read_text()) if audit_file.exists() else []
        self.assertEqual(file_records, records,
            "every ACS_AUDIT record must also reach ACS_AUDIT_FILE, the durable "
            "sink §6.4 relies on")
        return p, records

    def _unavailable_record(self, records: list[dict], key: str, event: str,
                            posture: str) -> None:
        self.assertEqual([r["acs_audit_event"] for r in records], ["adapter_unavailable"],
            "§6.4 requires every step that proceeds without a decision to "
            "be recorded; this path must not be silent")
        record = records[0]
        self.assertEqual(record[key], event)
        self.assertEqual(record["posture"], posture)
        self.assertIn("rfc8785", record["error"])
        self.assertIn("timestamp", record)

    def test_claude_code_hook_that_cannot_load_audits_and_honors_the_posture(self) -> None:
        def event(name: str) -> str:
            return json.dumps({"session_id": "s-1", "cwd": "/tmp", "hook_event_name": name,
                               "tool_name": "Bash", "tool_input": {"command": "rm -rf /home/u"},
                               "prompt": "hello"})

        for form, argv in self._commands("acs-claude-code-hook",
                                         "acs.integrations.claude_code.hook"):
            with self.subTest(form=form, ACS_DEFAULT_DENY="1", hook="PreToolUse"):
                p, records = self._run(argv, event("PreToolUse"), ACS_DEFAULT_DENY="1")
                self.assertEqual(p.returncode, 0, p.stderr)
                decision = json.loads(p.stdout)["hookSpecificOutput"]
                self.assertEqual(decision["permissionDecision"], "deny",
                    "the deployment set the posture to deny per §6.4, so an "
                    "unloadable adapter must not let the tool run")
                self._unavailable_record(records, "hook", "PreToolUse", "deny")

            with self.subTest(form=form, ACS_DEFAULT_DENY="1", hook="UserPromptSubmit"):
                p, records = self._run(argv, event("UserPromptSubmit"), ACS_DEFAULT_DENY="1")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(json.loads(p.stdout)["decision"], "block")
                self._unavailable_record(records, "hook", "UserPromptSubmit", "deny")

            with self.subTest(form=form, ACS_DEFAULT_DENY="0", hook="PreToolUse"):
                p, records = self._run(argv, event("PreToolUse"), ACS_DEFAULT_DENY="0")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), "",
                    "fail-open is the §6.4 default, so proceeding is correct "
                    "here as long as it is audited")
                self._unavailable_record(records, "hook", "PreToolUse", "proceed")

            with self.subTest(form=form, ACS_DISABLED="1"):
                p, records = self._run(argv, event("PreToolUse"),
                                       ACS_DEFAULT_DENY="1", ACS_DISABLED="1")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), "",
                    "the kill switch bypasses the hook even when the adapter cannot load")
                self.assertEqual([r["acs_audit_event"] for r in records], ["acs_disabled_bypass"])
                self.assertEqual(records[0]["hook"], "PreToolUse")

    def test_cursor_hook_that_cannot_load_audits_and_honors_the_posture(self) -> None:
        """Gate events deny via {"permission": "deny"}; beforeSubmitPrompt
        blocks via {"continue": false} and exit code 0."""
        event = json.dumps({"conversation_id": "c-1", "workspace_roots": ["/tmp"],
                            "tool_name": "Bash", "tool_input": {"command": "rm -rf /home/u"}})

        for form, argv in self._commands("acs-cursor-hook", "acs.integrations.cursor.hook"):
            for gate in ("preToolUse", "subagentStart"):
                with self.subTest(form=form, ACS_DEFAULT_DENY="1", event=gate):
                    p, records = self._run(argv + [gate], event, ACS_DEFAULT_DENY="1")
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(json.loads(p.stdout)["permission"], "deny",
                        "an unloadable Cursor adapter under deny posture must deny "
                        "the gate event, not exit 1 with no JSON (which proceeds)")
                    self._unavailable_record(records, "event", gate, "deny")

            with self.subTest(form=form, ACS_DEFAULT_DENY="1", event="beforeSubmitPrompt"):
                p, records = self._run(argv + ["beforeSubmitPrompt"], event, ACS_DEFAULT_DENY="1")
                self.assertEqual(p.returncode, 0,
                    "beforeSubmitPrompt blocks with continue: false and exit code 0, which Cursor reads")
                self.assertIs(json.loads(p.stdout)["continue"], False)
                self._unavailable_record(records, "event", "beforeSubmitPrompt", "deny")

            with self.subTest(form=form, ACS_DEFAULT_DENY="0", event="preToolUse"):
                p, records = self._run(argv + ["preToolUse"], event, ACS_DEFAULT_DENY="0")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), "")
                self._unavailable_record(records, "event", "preToolUse", "proceed")

            with self.subTest(form=form, ACS_DISABLED="1"):
                p, records = self._run(argv + ["preToolUse"], event,
                                       ACS_DEFAULT_DENY="1", ACS_DISABLED="1")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(json.loads(p.stdout), {"permission": "allow"},
                                 "failClosed reads an empty reply as a failed hook, so the kill switch allows explicitly")
                self.assertEqual([r["acs_audit_event"] for r in records], ["acs_disabled_bypass"])
                self.assertEqual(records[0]["event"], "preToolUse")

    def test_an_adapter_that_raises_is_audited_and_fails_closed(self) -> None:
        """An uncaught exception would exit 1, which both hosts treat as proceed with no record; the
        session's posture is unknown here, so the step is denied under either local default."""
        (self.shadow / "crashing_adapter.py").write_text(
            "def main():\n    raise RecursionError('maximum recursion depth exceeded')\n")
        hooks = {
            "claude-code": ("acs.integrations.claude_code.hook", "hook",
                            json.dumps({"session_id": "s", "hook_event_name": "PreToolUse"}),
                            lambda out: json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"),
            "cursor": ("acs.integrations.cursor.hook", "event", "{}",
                       lambda out: json.loads(out)["permission"] == "deny"),
        }
        for name, (module, key, stdin, denied) in hooks.items():
            code = (f"import sys; sys.argv = ['hook', 'preToolUse']\n"
                    f"from acs.integrations._bootstrap import run_hook\n"
                    f"from {module} import _deny, _event_name\n"
                    f"sys.exit(run_hook('crashing_adapter', event_key='{key}', event_name=_event_name, deny=_deny))\n")
            for posture in ("1", "0"):
                with self.subTest(name, ACS_DEFAULT_DENY=posture):
                    p, records = self._run([sys.executable, "-c", code], stdin, ACS_DEFAULT_DENY=posture)
                    self.assertEqual(p.returncode, 0, p.stderr[-400:])
                    self.assertEqual([r["acs_audit_event"] for r in records], ["adapter_crashed"])
                    self.assertIn("RecursionError", records[0]["error"])
                    self.assertEqual(records[0]["posture"], "deny")
                    self.assertTrue(denied(p.stdout), p.stdout)

    def test_version_answers_with_stdin_open(self) -> None:
        for script, label in (("acs-claude-code-hook", "claude-code"), ("acs-cursor-hook", "cursor")):
            with self.subTest(script):
                proc = subprocess.Popen([str(BIN / script), "--version"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    returncode = proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    self.fail(f"{script} --version waited for stdin")
                finally:
                    proc.stdin.close()
                out = proc.stdout.read()
                proc.stdout.close()
                proc.stderr.close()
                self.assertEqual(returncode, 0)
                self.assertIn(f"({label})", out)

    def test_nat_middleware_import_failure_is_loud_not_silent(self) -> None:
        """Without acs.core the NAT module prints an UNGOVERNED banner and re-raises."""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.shadow)
        p = subprocess.run([sys.executable, "-c", "import acs.integrations.nat.adapter"],
                           capture_output=True, text=True, env=env, timeout=30)
        self.assertNotEqual(p.returncode, 0,
            "a NAT middleware that can't load its signing dependency must "
            "NOT import cleanly — that would look governed while it isn't")
        self.assertIn("UNGOVERNED", p.stderr,
            f"the import-failure banner must be loud and name the "
            f"ungoverned state; stderr={p.stderr[:400]}")
        self.assertIn("rfc8785", p.stderr,
            "the banner must name the missing dependency and the fix")


class Item22_StoredSessionDecisionIsAuthenticated(unittest.TestCase):
    """The stored decision sits where the agent can write, so it carries an HMAC under the session key; a record that fails it refuses the session (§4.1)."""

    SESSION = "55555555-5555-4555-8555-555555555555"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _hello(self, *, on_decision_failure: str):
        def handler(req: dict) -> dict:
            return {
                "negotiated_version": "0.1.0",
                "methods_evaluated":
                    req["params"]["payload"].get("methods_implemented", []),
                "selected_transport": "http",
                "signature_algorithms_supported": ["HMAC-SHA256"],
                "timeout_config": {"default_ms": 5000},
                "skew_window_ms": 300000,
                "on_decision_failure": on_decision_failure,
                "profiles_accepted": ["acs-core"],
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
            "ACS_HMAC_SECRET": secret, "ACS_HMAC_KEY_ID": "test-key",
            "ACS_HANDSHAKE_CACHE": str(self.cache_dir),
            "ACS_HANDSHAKE_TIMEOUT_SECONDS": "2",
        })
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env.pop("ACS_DEFAULT_DENY", None)
        proc = subprocess.run(
            [str(BIN / "acs-claude-code-hook")],
            input=json.dumps({
                "session_id": self.SESSION, "cwd": "/tmp",
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": "echo hi"},
            }),
            capture_output=True, text=True, env=env, timeout=20)
        return proc.returncode, proc.stdout, proc.stderr

    def test_a_stored_decision_the_agent_edits_refuses_the_session(self) -> None:
        from acs.testing.harness import ProgrammableGuardian
        g = ProgrammableGuardian()
        g.handlers["handshake/hello"] = self._hello(on_decision_failure="deny")
        with g:
            url = g.url()
            self._run_claude_adapter(guardian_url=url,
                                     secret=g.hmac_secret)  # stores the session decision
        record = self._cache_file(url)
        self.assertTrue(record.exists(), "the session decision was not stored")

        # Guardian is down from here on, so the posture decides every step.
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn('"permissionDecision": "deny"', out,
            "an honest stored ServerHello declaring deny must fail closed")
        self.assertIn("decision_failure_fail_closed", err)

        # Edit one word in the stored decision: deny -> proceed.
        entry = json.loads(record.read_text())
        self.assertEqual(entry["server_hello"]["on_decision_failure"], "deny")
        entry["server_hello"]["on_decision_failure"] = "proceed"
        record.write_text(json.dumps(entry))
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn('"permissionDecision": "deny"', out,
            "§10 requires a verifier to reject what its MAC does not cover; the "
            "edited record must refuse the session, not downgrade its posture")
        self.assertIn("session_record_invalid", err)

        # Replace it with a no-answer decision, which would run the session unguarded.
        record.write_text(json.dumps({"acs_session_record": 1, "decision": "no_answer",
                                      "cause": "transport_failure", "fields": {}, "mac": None}))
        rc, out, err = self._run_claude_adapter(guardian_url=url,
                                                secret=g.hmac_secret)
        self.assertIn('"permissionDecision": "deny"', out,
            "a forged 'unguarded' record must not let the session run without the Guardian")
        self.assertIn("session_record_invalid", err)


# ----- 23. ClientHello advertises only earned integrity capabilities -----

class Item23_ClientHelloCapabilityHonesty(unittest.TestCase):
    """The captured ClientHello claims the signed ACS-Core floor and is signed; a hook with no secret sends none."""

    def _capture_client_hello(self, secret: str | None) -> tuple[client.Handshake, list[dict]]:
        saved = {name: os.environ.get(name) for name in
                 ("ACS_HMAC_SECRET", "ACS_HMAC_SECRET_FILE")}
        try:
            if secret is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = secret
                os.environ["ACS_HMAC_KEY_ID"] = "test-key"
            os.environ.pop("ACS_HMAC_SECRET_FILE", None)

            captured: list[dict] = []

            def refuse_after_capture(req, timeout):
                captured.append(json.loads(req.data.decode("utf-8")))
                raise urllib.error.URLError("capture complete")

            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR",
                                      Path(d)), \
                    mock.patch.object(_exchange, "_open",
                                      side_effect=refuse_after_capture):
                result = client.open_session(
                    config=client.Config.from_env({"ACS_GUARDIAN_URL": "http://127.0.0.1:8787/acs"}),
                    session_id=str(uuid.uuid4()),
                    agent_id="capability-test",
                    platform="test",
                    methods_implemented=["steps/toolCallRequest"],
                )
            return result, captured
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_the_client_hello_claims_acs_core_and_is_signed(self) -> None:
        result, captured = self._capture_client_hello("capability-secret-0123456789abcdef")
        self.assertEqual(result, client.NoAnswer("transport_failure", {"error": "<urlopen error capture complete>"}))
        self.assertEqual(len(captured), 1)
        signed = captured[0]
        signed_payload = signed["params"]["payload"]
        self.assertEqual(signed_payload["profiles_supported"], ["acs-core"])
        self.assertEqual(signed_payload["signature_algorithms_supported"],
                         ["HMAC-SHA256"])
        self.assertIn("signature", signed["params"],
            "a session advertising the Core integrity floor must actually "
            "sign its ClientHello")

    def test_a_hook_with_no_secret_sends_no_client_hello(self) -> None:
        result, captured = self._capture_client_hello(None)
        self.assertEqual((result.cause, captured), ("secret_missing", []),
                         "ACS-Core signs every request (§10), so nothing goes out unsigned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
