"""Every disposition is honored when NAT passes the input as modified_args[0], the shape LangChain-based agents use."""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    from nat.middleware.middleware import (  # type: ignore[import-not-found]
        InvocationContext, FunctionMiddlewareContext,
    )
    from pydantic import BaseModel
    _NAT_OK = True
except ImportError:
    _NAT_OK = False


from acs.integrations.nat.adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402
if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig  # noqa: E402

from acs.client import _handshake as client_handshake  # noqa: E402
from acs.testing.harness import ProgrammableGuardian  # noqa: E402


HMAC = "dispositions-live-shared-secret-padded-to-32-bytes"


def _make_ctx_with_pydantic_input(tool_name: str, model_cls, model_instance):
    """The InvocationContext NAT's chain builds for Function.acall_invoke(**kwargs): the input in modified_args[0] as a Pydantic model."""
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
        # The adapter reads ACS_HMAC_SECRET at call time, so it is restored for the next test; addCleanup runs even on failure.
        prior = os.environ.get("ACS_HMAC_SECRET")
        os.environ["ACS_HMAC_SECRET"] = HMAC
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        def _restore():
            if prior is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = prior
                os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        self.addCleanup(_restore)
        return ACSMiddleware(ACSMiddlewareConfig(
            guardian_url=self.url, default_deny=default_deny))

    def setUp(self) -> None:
        self.guardian.reset()
        # Per-test handshake records, so no record left in the user's cache decides a session here.
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        patcher = mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name))
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def test_modify_overrides_pydantic_model_input(self) -> None:
        """The override reaches the input NAT calls the function with, modified_args[0]."""

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

        # NAT calls call_next(*modified_args, **modified_kwargs), so the override must be in modified_args[0].
        post_args = list(ctx.modified_args or [])
        post_kwargs = dict(ctx.modified_kwargs or {})

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

    def test_modify_reaches_the_function_once_through_nats_call_path(self) -> None:
        """NAT runs call_next(*modified_args, **modified_kwargs): the override must reach the function once, in the slot its input travels in."""
        from nat.middleware.middleware import FunctionMiddlewareContext

        class ShellInput(BaseModel):
            command: str
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "use the safe command",
            "modifications": {"parameter_overrides": {"command": "ls"}}})
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=ShellInput,
                                            single_output_schema=str, stream_output_schema=str)
        received: list[str] = []

        async def positional(value: ShellInput) -> str:
            received.append(value.command)
            return "ran"

        async def keywords(command: str) -> str:
            received.append(command)
            return "ran"
        mw = self._mw(default_deny=True)
        asyncio.run(mw.function_middleware_invoke(ShellInput(command="rm -rf /"), call_next=positional, context=context))
        asyncio.run(mw.function_middleware_invoke(command="rm -rf /", call_next=keywords, context=context))
        self.assertEqual(received, ["ls", "ls"])

        async def plain(command: str) -> str:
            received.append(command)
            return "ran"
        # A scalar input is the field the schema names at its position, as the Guardian saw it.
        asyncio.run(mw.function_middleware_invoke("rm -rf /", call_next=plain, context=context))
        self.assertEqual(received, ["ls", "ls", "ls"])

    def test_an_override_the_input_does_not_take_is_denied(self) -> None:
        """§6.5: a computed field reads its own value back, so the MODIFY cannot be applied and is a DENY."""
        from nat.middleware.middleware import FunctionMiddlewareContext
        from pydantic import computed_field

        class Derived(BaseModel):
            raw: str

            @computed_field
            @property
            def command(self) -> str:
                return self.raw
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "use the safe command",
            "modifications": {"parameter_overrides": {"command": "safe"}}})
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=Derived,
                                            single_output_schema=str, stream_output_schema=str)
        received: list[str] = []

        async def target(value: Derived) -> str:
            received.append(value.command)
            return "ran"
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(ACSGuardianDenied):
            asyncio.run(self._mw(default_deny=False).function_middleware_invoke(Derived(raw="unsafe"),
                                                                               call_next=target, context=context))
        self.assertEqual(received, [], "the function ran with the input the Guardian rewrote")
        audits = [json.loads(line.removeprefix("ACS_AUDIT ")) for line in err.getvalue().splitlines()
                  if line.startswith("ACS_AUDIT ")]
        self.assertEqual([a["reason_codes"] for a in audits if a["acs_audit_event"] == "modify_unsupported"],
                         [["modify_unsupported"]])

    def test_an_override_naming_no_field_of_the_input_is_denied(self) -> None:
        """§6.5: an override the function's input does not declare would leave the input unchanged, so it is a DENY."""
        from nat.middleware.middleware import FunctionMiddlewareContext

        class ShellInput(BaseModel):
            command: str
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "use the safe command",
            "modifications": {"parameter_overrides": {"cmd": "ls"}}})
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=ShellInput,
                                            single_output_schema=str, stream_output_schema=str)
        received: list = []

        async def model_input(value: ShellInput) -> str:
            received.append(value.command)
            return "ran"

        async def dict_input(value: dict) -> str:
            received.append(value["command"])
            return "ran"
        mw = self._mw(default_deny=False)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for target, value in ((model_input, ShellInput(command="rm -rf /")), (dict_input, {"command": "rm -rf /"})):
                with self.assertRaises(ACSGuardianDenied):
                    asyncio.run(mw.function_middleware_invoke(value, call_next=target, context=context))
        self.assertEqual(received, [], "the function ran its original input")
        audits = [json.loads(line.removeprefix("ACS_AUDIT ")) for line in err.getvalue().splitlines()
                  if line.startswith("ACS_AUDIT ")]
        self.assertEqual([a["acs_audit_event"] for a in audits].count("modify_unsupported"), 2)

    def test_an_override_the_input_rewrites_when_rebuilt_is_denied(self) -> None:
        from dataclasses import dataclass
        from nat.middleware.middleware import FunctionMiddlewareContext

        @dataclass
        class Normalized:
            command: str

            def __post_init__(self) -> None:
                self.command = self.command.replace("ls", "rm -rf /")
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "use the safe command",
            "modifications": {"parameter_overrides": {"command": "ls"}}})
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=None,
                                            single_output_schema=str, stream_output_schema=str)
        received: list = []

        async def target(value: Normalized) -> str:
            received.append(value.command)
            return "ran"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ACSGuardianDenied):
            asyncio.run(self._mw(default_deny=False).function_middleware_invoke(
                Normalized(command="echo"), call_next=target, context=context))
        self.assertEqual(received, [])

    def test_an_override_of_a_keyword_argument_is_applied_to_it_beside_a_model_input(self) -> None:
        from nat.middleware.middleware import FunctionMiddlewareContext

        class ShellInput(BaseModel):
            command: str
        self._set_response("steps/toolCallRequest", {
            "decision": "modify", "reasoning": "dry run only",
            "modifications": {"parameter_overrides": {"mode": "dry-run"}}})
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=ShellInput,
                                            single_output_schema=str, stream_output_schema=str)
        received: list = []

        async def mixed(value: ShellInput, *, mode: str) -> str:
            received.append((value.command, mode))
            return "ran"
        asyncio.run(self._mw(default_deny=True).function_middleware_invoke(
            ShellInput(command="rm -rf /"), call_next=mixed, context=context, mode="destructive"))
        self.assertEqual(received, [("rm -rf /", "dry-run")])

    def test_a_datetime_input_and_a_dict_output_reach_the_guardian_and_its_deny_applies(self) -> None:
        import datetime
        stamp = datetime.datetime(2026, 11, 1, 12, 0, tzinfo=datetime.timezone.utc)

        class Window(BaseModel):
            since: datetime.datetime
        deny = {"decision": "deny", "reasoning": "not in this window"}
        self._set_response("steps/toolCallRequest", deny)
        mw = self._mw(default_deny=False)
        self.guardian.reset()
        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(mw.pre_invoke(_make_ctx_with_pydantic_input("query", Window, Window(since=stamp))))
        sent = self.guardian.envelopes_for("steps/toolCallRequest")
        self.assertEqual(sent[0]["params"]["payload"]["arguments"]["since"]["value"], "2026-11-01T12:00:00Z")

        # The same value passed as a keyword argument, through NAT's call path.
        from nat.middleware.middleware import FunctionMiddlewareContext
        calls: list = []

        async def query(since):
            calls.append(since)
            return "rows"
        context = FunctionMiddlewareContext(name="query", config=None, description=None, input_schema=None,
                                            single_output_schema=str, stream_output_schema=str)
        self.guardian.reset()
        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(mw.function_middleware_invoke(since=stamp, call_next=query, context=context))
        self.assertEqual(calls, [])
        sent = self.guardian.envelopes_for("steps/toolCallRequest")
        self.assertEqual(sent[0]["params"]["payload"]["arguments"]["since"]["value"], "2026-11-01 12:00:00+00:00")

        self._set_response("steps/toolCallResult", deny)
        ctx = _make_ctx_with_pydantic_input("query", Window, Window(since=stamp))
        ctx.output = {"rows": 3, "fetched": stamp}
        asyncio.run(mw.post_invoke(ctx))
        self.assertIsNone(ctx.output, "the Guardian saw the output and denied it, so it never reaches the model")
        self.assertTrue(self.guardian.envelopes_for("steps/toolCallResult"))

    def test_ask_or_defer_on_a_result_withholds_the_output_and_audits_it(self) -> None:
        class ShellInput(BaseModel):
            command: str
        for disposition in ("ask", "defer"):
            with self.subTest(disposition):
                details = ({"ask_details": {"approver": {"type": "human", "id": "owner"}, "question": "Run it?", "timeout_seconds": 60}} if disposition == "ask" else {"defer_details": {"reason": "pending_dependency", "resolution_method": "timeout", "resolution_timeout_ms": 1000, "timeout_decision": "deny"}})
                self._set_response("steps/toolCallResult", {"decision": disposition, "reasoning": "needs a person", **details})
                mw = self._mw(default_deny=False)
                ctx = _make_ctx_with_pydantic_input("Bash", ShellInput, ShellInput(command="ls"))
                ctx.output = "secret listing"
                with mock.patch("acs.integrations.nat.adapter.audit_event") as audit:
                    asyncio.run(mw.post_invoke(ctx))
                self.assertIsNone(ctx.output)
                self.assertIn(("post_invoke_redacted", f"{disposition}_substituted_to_deny"),
                              [(c.args[0], c.kwargs.get("cause")) for c in audit.call_args_list])

    def test_an_output_the_signer_still_refuses_is_withheld_under_fail_open(self) -> None:
        from acs.client import _exchange

        class ShellInput(BaseModel):
            command: str
        sign = _exchange.sign_envelope

        def refuse_results(request, **kwargs):
            if request.get("method") == "steps/toolCallResult":
                raise ValueError("no RFC 8785 form")
            return sign(request, **kwargs)
        mw = self._mw(default_deny=False)
        ctx = _make_ctx_with_pydantic_input("Bash", ShellInput, ShellInput(command="ls"))
        ctx.output = "secret listing"
        with mock.patch.object(_exchange, "sign_envelope", refuse_results), \
                mock.patch("acs.integrations.nat.adapter.audit_event") as audit:
            asyncio.run(mw.post_invoke(ctx))
        self.assertIsNone(ctx.output)
        self.assertIn("envelope_not_signable", [c.kwargs.get("cause") for c in audit.call_args_list])
        self.assertNotIn("steps/toolCallResult", self.guardian.methods_seen())

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

    def test_a_modify_nat_cannot_apply_is_denied_and_recorded(self) -> None:
        """§6.5: a MODIFY the client cannot apply is a DENY, recorded with reason_codes ["modify_unsupported"]."""
        class ShellInput(BaseModel):
            command: str
            secret: str

        cases = {
            "tool call with redactions": ("steps/toolCallRequest",
                                          {"redactions": [{"path": "/secret", "replacement": "[REDACTED]"}]}),
            "tool call with replacement content": ("steps/toolCallRequest", {"modified_content": "echo SAFE"}),
            "tool result with structured edits": ("steps/toolCallResult", {"parameter_overrides": {"command": "x"}}),
        }
        for name, (method, mods) in cases.items():
            with self.subTest(name):
                ctx = _make_ctx_with_pydantic_input("Bash", ShellInput, ShellInput(command="unsafe", secret="s"))
                ctx.output = "SECRET-OUTPUT"
                self._set_response(method, {"decision": "modify", "reasoning": "rewrite", "modifications": mods})
                mw = self._mw(default_deny=False)
                err, raised = io.StringIO(), False
                with contextlib.redirect_stderr(err):
                    try:
                        asyncio.run(mw.pre_invoke(ctx) if method == "steps/toolCallRequest" else mw.post_invoke(ctx))
                    except ACSGuardianDenied:
                        raised = True
                if method == "steps/toolCallRequest":
                    self.assertTrue(raised or getattr(ctx, "action", None) is not None,
                                    "the call was neither raised nor skipped")
                else:
                    self.assertIsNone(ctx.output)
                audits = [json.loads(line.removeprefix("ACS_AUDIT ")) for line in err.getvalue().splitlines()
                          if line.startswith("ACS_AUDIT ")]
                self.assertEqual([a["reason_codes"] for a in audits if a["acs_audit_event"] == "modify_unsupported"],
                                 [["modify_unsupported"]])

    def test_ask_substituted_to_deny(self) -> None:
        class ShellInput(BaseModel):
            command: str
        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="ls"))
        self._set_response("steps/toolCallRequest", {
            "decision": "ask", "reasoning": "needs human approval",
        })
        mw = self._mw(default_deny=True)
        # Either ACSGuardianDenied or context.action = SKIP; the function must not run.
        try:
            result = asyncio.run(mw.pre_invoke(ctx))
            action = getattr(ctx, "action", None)
            self.assertIsNotNone(action,
                "ASK was neither raised nor substituted to SKIP — function "
                "would execute despite Guardian asking for human approval")
        except ACSGuardianDenied:
            pass  # Expected on NAT 1.7.0

    def test_an_integer_the_signer_cannot_encode_reaches_the_guardian_as_a_string(self) -> None:
        class IdInput(BaseModel):
            id: int
        ctx = _make_ctx_with_pydantic_input("lookup", IdInput, IdInput(id=2 ** 53 + 1))
        self._set_response("steps/toolCallRequest", {"decision": "allow", "reasoning": "fine"})
        mw = self._mw(default_deny=False)
        self.guardian.reset()
        asyncio.run(mw.pre_invoke(ctx))
        [request] = self.guardian.envelopes_for("steps/toolCallRequest")
        self.assertEqual(request["params"]["payload"]["arguments"]["id"]["value"], str(2 ** 53 + 1))

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

    def test_post_invoke_deny_redacts_output(self) -> None:
        class ShellInput(BaseModel):
            command: str
        ctx = _make_ctx_with_pydantic_input(
            "Bash", ShellInput, ShellInput(command="cat /etc/secret"))

        ctx.output = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        self._set_response("steps/toolCallResult", {
            "decision": "deny",
            "reasoning": "output contains a credential",
        })

        mw = self._mw()
        asyncio.run(mw.post_invoke(ctx))

        # output=None is the redaction signal; the post_invoke_redacted audit tells "redacted" from "no output".
        self.assertIsNone(ctx.output,
            "REGRESSION: post_invoke DENY did not clear context.output — "
            "the secret/sensitive value flows through despite Guardian "
            "demanding redaction")

    def test_post_invoke_unusable_disposition_redacts_output_under_fail_open(self) -> None:
        """An arrived decision outside the five dispositions fails closed, whatever the posture."""
        class ShellInput(BaseModel):
            command: str
        for decision in ("maybe", None):
            with self.subTest(decision=decision):
                ctx = _make_ctx_with_pydantic_input(
                    "Bash", ShellInput, ShellInput(command="cat /etc/secret"))
                ctx.output = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                self._set_response("steps/toolCallResult", {"decision": decision, "reasoning": "?"})
                asyncio.run(self._mw(default_deny=False).post_invoke(ctx))
                self.assertIsNone(ctx.output, "an unusable disposition let the output through")

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
