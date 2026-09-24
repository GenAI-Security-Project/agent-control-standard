"""End-to-end verification that EVERY ACS disposition (ALLOW, DENY,
MODIFY, ASK, DEFER, post_invoke DENY) is honored by the adapter when
NAT's middleware chain captures the input as `modified_args[0]` — the
shape every LangChain-based agent (react_agent, langgraph, etc.) uses
in production. The previous test suite drove `modified_kwargs` only,
masking a class of silent-bypass bugs (the `arguments: {}` envelope
we hit in the live Vertex run).

Each test:
  1. Spawns a `ProgrammableGuardian` configured to return a specific
     disposition for the toolCallRequest.
  2. Builds a real `ACSMiddleware` against it.
  3. Calls `pre_invoke` with input wrapped as a Pydantic model in
     `modified_args` (the LangChain shape).
  4. Asserts the disposition was honored — function input was rewritten
     for MODIFY, exception was raised for DENY/ASK/DEFER, output was
     redacted for post_invoke DENY.

Without these tests, MODIFY / output-redaction can silently drop on
the agent path and ship to production as theatre.
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    from nat.middleware.middleware import (  # type: ignore[import-not-found]
        InvocationContext, FunctionMiddlewareContext,
    )
    from pydantic import BaseModel
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))

from acs_adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402
if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402

from test_harness import ProgrammableGuardian  # noqa: E402


HMAC = "dispositions-live-shared-secret"


def _make_ctx_with_pydantic_input(tool_name: str, model_cls, model_instance):
    """Build an InvocationContext that mirrors what NAT's middleware
    chain produces when the LangChain wrapper calls
    `Function.acall_invoke(**kwargs)` — input lives in modified_args[0]
    as a Pydantic model, modified_kwargs is empty."""
    return InvocationContext(
        function_context=FunctionMiddlewareContext(
            name=tool_name,
            config=None,
            description=None,
            input_schema=model_cls,
            single_output_schema=type(None),
            stream_output_schema=type(None),
        ),
        original_args=(model_instance,),
        original_kwargs={},
        modified_args=[model_instance],
        modified_kwargs={},
    )


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class DispositionsLive(unittest.TestCase):
    """Run-once Guardian; per-test handler override."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.guardian = ProgrammableGuardian(hmac_secret=HMAC)
        cls.guardian.start()
        cls.url = f"http://127.0.0.1:{cls.guardian.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian.stop()

    def _mw(self, *, default_deny: bool = True) -> ACSMiddleware:
        import os
        # Restore env after the test — adapter reads ACS_HMAC_SECRET at
        # call time, and leaking this into adjacent tests (test_live's
        # ACS_DEV_MODE=1 no-signing setup) makes the next test pass
        # signed envelopes to an unsigned Guardian → response signature
        # invalid. addCleanup runs even on test failure.
        prior = os.environ.get("ACS_HMAC_SECRET")
        os.environ["ACS_HMAC_SECRET"] = HMAC
        def _restore():
            if prior is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = prior
        self.addCleanup(_restore)
        return ACSMiddleware(ACSMiddlewareConfig(
            guardian_url=self.url, default_deny=default_deny,
            session_id="dispositions-live"))

    def setUp(self) -> None:
        self.guardian.reset()

    def _set_response(self, method: str, response: dict) -> None:
        def handler(req):
            params = req.get("params", {}) or {}
            return {
                **response,
                "request_id": params.get("request_id", ""),
                "chain_hash": "0" * 64,
                "acs_version": "0.1.0",
                "type": "final",
            }
        self.guardian.handlers[method] = handler

    # ────────────────────────────────────────────────────────────────
    # MODIFY — Guardian rewrites the command; the function must run
    # with the OVERRIDE value, not the original
    # ────────────────────────────────────────────────────────────────

    def test_modify_overrides_pydantic_model_input(self) -> None:
        """REGRESSION: Adapter wrote overrides to context.modified_kwargs,
        but NAT's actual call uses context.modified_args[0] (the Pydantic
        model). MODIFY was silently dropped — Guardian saying 'rewrite
        rm -rf to echo safe' had ZERO effect. Agent ran the original
        dangerous command. The test below confirms the override
        actually reaches the function input."""

        class ShellInput(BaseModel):
            command: str

        original = ShellInput(command="rm -rf /tmp/secret-data/")
        ctx = _make_ctx_with_pydantic_input("Bash", ShellInput, original)

        self._set_response("steps/toolCallRequest", {
            "decision": "modify",
            "reasoning": "rewrite to safe command",
            "modifications": {"parameter_overrides": {"command": "echo SAFE"}},
        })

        mw = self._mw()
        result = asyncio.run(mw.pre_invoke(ctx))

        # The modification must reach the input that _ainvoke would actually
        # call the function with. NAT calls call_next(*modified_args, **modified_kwargs).
        # The adapter must EITHER mutate modified_args[0] in place or replace it.
        post_args = list(ctx.modified_args or [])
        post_kwargs = dict(ctx.modified_kwargs or {})

        # Flatten what _ainvoke would actually see
        if post_args and hasattr(post_args[0], "command"):
            effective = post_args[0].command
        elif "command" in post_kwargs:
            effective = post_kwargs["command"]
        else:
            self.fail("After MODIFY, no `command` reachable via modified_args[0] "
                       "or modified_kwargs — Guardian's parameter_overrides "
                       "silently dropped (this is the bug)")

        self.assertEqual(effective, "echo SAFE",
            "REGRESSION: Guardian's MODIFY override did not reach the function "
            "input. Adapter is writing to modified_kwargs, but NAT's call "
            "uses modified_args[0]. The agent would run the ORIGINAL "
            "(unsafe) command, defeating the purpose of MODIFY.")

    def test_modify_with_unapplied_redaction_blocks_instead_of_half_applying(self) -> None:
        """NAT must not apply overrides while dropping a sibling redaction."""
        class ShellInput(BaseModel):
            command: str
            secret: str

        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput,
            ShellInput(command="unsafe", secret="do-not-forward"))
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "apply both edits",
            "modifications": {
                "redactions": [
                    {"path": "/secret", "replacement": "[REDACTED]"}
                ],
                "parameter_overrides": {"command": "echo SAFE"},
            },
        })

        mw = self._mw(default_deny=False)
        try:
            asyncio.run(mw.pre_invoke(ctx))
            self.assertIsNotNone(getattr(ctx, "action", None),
                "combined MODIFY was neither raised nor converted to SKIP; "
                "the redaction was silently discarded")
        except ACSGuardianDenied:
            pass

    # ────────────────────────────────────────────────────────────────
    # ASK / DEFER substitution — per docs both substitute to DENY at
    # the middleware boundary. Verify the function does NOT execute.
    # ────────────────────────────────────────────────────────────────

    def test_ask_substituted_to_deny(self) -> None:
        class ShellInput(BaseModel):
            command: str
        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="ls"))
        self._set_response("steps/toolCallRequest", {
            "decision": "ask", "reasoning": "needs human approval",
        })
        mw = self._mw(default_deny=True)
        # Either raises ACSGuardianDenied or sets context.action = SKIP.
        # In both cases the function MUST NOT execute.
        try:
            result = asyncio.run(mw.pre_invoke(ctx))
            # If no exception, must have signaled SKIP via action
            action = getattr(ctx, "action", None)
            self.assertIsNotNone(action,
                "ASK was neither raised nor substituted to SKIP — function "
                "would execute despite Guardian asking for human approval")
        except ACSGuardianDenied:
            pass  # Expected on NAT 1.7.0

    def test_defer_substituted_to_deny(self) -> None:
        class ShellInput(BaseModel):
            command: str
        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="ls"))
        self._set_response("steps/toolCallRequest", {
            "decision": "defer", "reasoning": "policy postponed",
        })
        mw = self._mw(default_deny=True)
        try:
            asyncio.run(mw.pre_invoke(ctx))
            action = getattr(ctx, "action", None)
            self.assertIsNotNone(action,
                "DEFER was neither raised nor substituted to SKIP")
        except ACSGuardianDenied:
            pass

    # ────────────────────────────────────────────────────────────────
    # post_invoke DENY — Guardian observes the tool result and demands
    # redaction. The tool already ran; the OUTPUT must not flow.
    # ────────────────────────────────────────────────────────────────

    def test_post_invoke_deny_redacts_output(self) -> None:
        """Guardian sees the toolCallResult and decides the output is
        sensitive (e.g. an exfil leak). Adapter MUST clear context.output
        so the agent doesn't see the secret. If this fails, the agent
        gets the raw secret string anyway — silent leak."""
        class ShellInput(BaseModel):
            command: str
        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="cat /etc/secret"))

        # Simulate the tool already ran and produced sensitive output
        ctx.output = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        self._set_response("steps/toolCallResult", {
            "decision": "deny",
            "reasoning": "output contains a credential",
        })

        mw = self._mw()
        asyncio.run(mw.post_invoke(ctx))

        # The output must be cleared. If the secret still flows through
        # context.output, downstream readers (the LLM, callers, logs)
        # will see it. `output=None` is the canonical redaction signal;
        # downstream code that needs to distinguish "no output" from
        # "redacted" reads the ACS_AUDIT stderr log for the
        # post_invoke_redacted event (extra attributes on
        # InvocationContext are blocked by Pydantic validate_assignment).
        self.assertIsNone(ctx.output,
            "REGRESSION: post_invoke DENY did not clear context.output — "
            "the secret/sensitive value flows through despite Guardian "
            "demanding redaction")

    def test_post_invoke_structured_modify_never_leaks_unmodified_output(self) -> None:
        """A structured result redaction NAT cannot realize fails closed."""
        class ShellInput(BaseModel):
            command: str

        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="show-secret"))
        ctx.output = {"secret": "do-not-forward", "status": "ok"}
        self._set_response("steps/toolCallResult", {
            "decision": "modify", "reasoning": "remove credential",
            "modifications": {
                "redactions": [
                    {"path": "/secret", "replacement": "[REDACTED]"}
                ]
            },
        })

        mw = self._mw(default_deny=False)
        asyncio.run(mw.post_invoke(ctx))
        self.assertIsNone(ctx.output,
            "NAT cannot apply JSON-Pointer result redactions; passing the "
            "original output silently ignores the Guardian's MODIFY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
