"""
Integration tests for the ACS NAT middleware against the installed
nvidia-nat-core package (NAT 1.7.0+).

These tests construct a real NAT InvocationContext, run the adapter's
pre_invoke / post_invoke through the actual NAT middleware machinery,
and assert the round-trip behavior against a live example Guardian.

Requires:
  pip install nvidia-nat-core
"""
from __future__ import annotations

import asyncio
import os
import json
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

# Skip cleanly if NAT isn't installed in the environment running tests
try:
    from nat.middleware.middleware import (
        InvocationContext,
        FunctionMiddlewareContext,
    )
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

# Import adapter (it tolerates NAT missing)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from acs_adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402

if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402


HERE = Path(__file__).resolve().parent


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))
import acs_common  # noqa: E402
from test_harness import (  # noqa: E402
    ProgrammableGuardian,
    launch_guardian,
)


def _make_context(tool_name: str, args: dict) -> "InvocationContext":
    """Build a NAT InvocationContext that exercises the same path real NAT runtime would."""
    return InvocationContext(
        function_context=FunctionMiddlewareContext(
            name=tool_name,
            config=None,
            description=None,
            input_schema=None,
            single_output_schema=type(None),
            stream_output_schema=type(None),
        ),
        original_args=(),
        original_kwargs=args,
        modified_args=(),
        modified_kwargs=dict(args),
    )


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed in test environment")
class NATMiddlewareIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = os.environ.copy(); env["ACS_DEV_MODE"] = "1"; env.pop("ACS_HMAC_SECRET", None); env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc, cls.port = launch_guardian(env=env)
        cls.guardian_url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def _make_middleware(self, default_deny: bool = True) -> ACSMiddleware:
        cfg = ACSMiddlewareConfig(
            guardian_url=self.guardian_url,
            default_deny=default_deny,
            session_id="nat-test",
        )
        return ACSMiddleware(cfg)

    # ----- allow path -----

    def test_post_invoke_allow_passes_through(self) -> None:
        mw = self._make_middleware()
        ctx = _make_context("Read", {"file_path": "/tmp/x"})
        ctx.output = "file contents"
        result = asyncio.run(mw.post_invoke(ctx))
        self.assertIsNone(result)  # allow + no modification

    def test_negotiated_timeout_replaces_local_timeout(self) -> None:
        """A decision arriving after the ServerHello deadline is a timeout.

        The local config allows one second, while the signed ServerHello
        negotiates 100 ms.  A Guardian DENY at 300 ms therefore must not be
        applied; under the shipped fail-open posture the call proceeds with a
        `decision_timeout` audit.  Exercises the real HTTP boundary.
        """
        g = ProgrammableGuardian()

        def hello(req: dict) -> dict:
            result = g._default_handshake(req)
            result["payload"]["timeout_config"] = {"default_ms": 100}
            return result

        def delayed_deny(req: dict) -> dict:
            time.sleep(0.3)
            return {
                "type": "final", "acs_version": "0.1.0",
                "request_id": req["params"]["request_id"],
                "chain_hash": "0" * 64, "decision": "deny",
                "reasoning": "arrived after negotiated deadline",
            }

        g.handlers["handshake/hello"] = hello
        g.handlers["__default__"] = delayed_deny
        saved_secret = os.environ.get("ACS_HMAC_SECRET")
        saved_secret_file = os.environ.get("ACS_HMAC_SECRET_FILE")
        try:
            os.environ["ACS_HMAC_SECRET"] = g.hmac_secret
            os.environ.pop("ACS_HMAC_SECRET_FILE", None)
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(acs_common, "_HANDSHAKE_CACHE_DIR",
                                      Path(d)), g:
                mw = ACSMiddleware(ACSMiddlewareConfig(
                    guardian_url=g.url(), default_deny=False,
                    session_id=str(uuid.uuid4()), timeout_s=1.0,
                ))
                ctx = _make_context("Bash", {"command": "echo hi"})
                result = asyncio.run(mw.pre_invoke(ctx))
            self.assertIsNone(result,
                "the late DENY arrived after the negotiated deadline; the "
                "configured fail-open posture should control the timeout")
            self.assertAlmostEqual(mw._negotiated_timeout_s, 0.1)
        finally:
            if saved_secret is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = saved_secret
            if saved_secret_file is None:
                os.environ.pop("ACS_HMAC_SECRET_FILE", None)
            else:
                os.environ["ACS_HMAC_SECRET_FILE"] = saved_secret_file

    def test_acs_disabled_bypass_is_written_to_the_durable_sink(self) -> None:
        """Both NAT bypass boundaries must leave structured durable records."""
        saved_disabled = os.environ.get("ACS_DISABLED")
        saved_audit = os.environ.get("ACS_AUDIT_FILE")
        try:
            with tempfile.TemporaryDirectory() as d:
                audit_path = Path(d) / "nat-audit.log"
                os.environ["ACS_DISABLED"] = "1"
                os.environ["ACS_AUDIT_FILE"] = str(audit_path)
                mw = self._make_middleware(default_deny=False)
                ctx = _make_context("Read", {"file_path": "/tmp/x"})
                self.assertIsNone(asyncio.run(mw.pre_invoke(ctx)))
                ctx.output = "file contents"
                self.assertIsNone(asyncio.run(mw.post_invoke(ctx)))

                self.assertTrue(audit_path.exists(),
                    "ACS_DISABLED bypasses must not exist only on stderr")
                records = [
                    json.loads(line.removeprefix("ACS_AUDIT "))
                    for line in audit_path.read_text().splitlines()
                ]
            bypasses = [r for r in records
                        if r.get("acs_audit_event") == "acs_disabled_bypass"]
            self.assertEqual(len(bypasses), 2)
            self.assertEqual({r.get("method") for r in bypasses},
                             {"steps/toolCallRequest", "steps/toolCallResult"})
            self.assertEqual({r.get("session_id") for r in bypasses},
                             {mw._session_id})
        finally:
            if saved_disabled is None:
                os.environ.pop("ACS_DISABLED", None)
            else:
                os.environ["ACS_DISABLED"] = saved_disabled
            if saved_audit is None:
                os.environ.pop("ACS_AUDIT_FILE", None)
            else:
                os.environ["ACS_AUDIT_FILE"] = saved_audit

    # ----- fail posture -----

class ExtractArgumentsFromInvocationContext(unittest.TestCase):
    """NAT captures the function input as `modified_args[0]` (a Pydantic
    model from `_convert_input`), not only `modified_kwargs`, so
    `_extract_arguments` must flatten every shape NAT may use. The helper
    is duck-typed on the context — no NAT install needed.
    """

    def _ctx(self, *, modified_args=(), modified_kwargs=None,
              input_schema=None):
        """Build a duck-typed object matching what _extract_arguments reads."""
        from types import SimpleNamespace
        return SimpleNamespace(
            modified_args=tuple(modified_args),
            modified_kwargs=dict(modified_kwargs or {}),
            function_context=SimpleNamespace(input_schema=input_schema),
        )

    def test_pydantic_v2_model_in_modified_args_extracts_fields(self) -> None:
        """LangChain react_agent path: a Pydantic model in
        modified_args[0] must surface its field values."""
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("pydantic not installed")
        from acs_adapter import _extract_arguments

        class ShellInput(BaseModel):
            command: str

        ctx = self._ctx(modified_args=(ShellInput(command="rm -rf /tmp/x/"),))
        args = _extract_arguments(ctx)
        self.assertEqual(args.get("command"), "rm -rf /tmp/x/",
            "REGRESSION: LLM-driven rm -rf bypassed Guardian because adapter "
            "ignored Pydantic input in modified_args[0]; field 'command' "
            "must be extracted so policy can match destructive patterns")

    def test_plain_dict_in_modified_args_extracts_keys(self) -> None:
        """NAT may also pass a raw dict if the function takes one."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_args=({"command": "echo hi"},))
        self.assertEqual(_extract_arguments(ctx), {"command": "echo hi"})

    def test_modified_kwargs_still_works(self) -> None:
        """Existing path (named kwargs, e.g. from direct middleware tests)
        must still work — this is the path the integration tests above use."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_kwargs={"file_path": "/tmp/x"})
        self.assertEqual(_extract_arguments(ctx), {"file_path": "/tmp/x"})

    def test_kwargs_and_args_both_present_kwargs_first(self) -> None:
        """If both shapes are populated, both should appear in the result."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_args=({"command": "ls"},),
                          modified_kwargs={"timeout_s": 5})
        out = _extract_arguments(ctx)
        self.assertEqual(out.get("command"), "ls")
        self.assertEqual(out.get("timeout_s"), 5)

    def test_scalar_arg_with_schema_uses_field_name(self) -> None:
        """If the arg is a scalar (e.g. single string), name it after
        the input schema's first field — better than 'arg0' on the wire."""
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("pydantic not installed")
        from acs_adapter import _extract_arguments

        class Schema(BaseModel):
            command: str

        ctx = self._ctx(modified_args=("ls -la",), input_schema=Schema)
        self.assertEqual(_extract_arguments(ctx).get("command"), "ls -la")

    def test_empty_context_returns_empty(self) -> None:
        """No args, no kwargs, no schema → empty dict, not a crash."""
        from acs_adapter import _extract_arguments
        self.assertEqual(_extract_arguments(self._ctx()), {})

    def test_dataclass_in_modified_args(self) -> None:
        from acs_adapter import _extract_arguments
        from dataclasses import dataclass

        @dataclass
        class ShellInput:
            command: str

        ctx = self._ctx(modified_args=(ShellInput(command="ls"),))
        self.assertEqual(_extract_arguments(ctx).get("command"), "ls")


if __name__ == "__main__":
    unittest.main(verbosity=2)
