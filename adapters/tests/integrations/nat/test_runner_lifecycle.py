"""Every NAT run reports its whole lifecycle: the builder registers an exporter that NAT starts for each run before
WORKFLOW_START, so a run's first events and a later run's events all reach the Guardian."""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    from nat.builder.context import ContextState
    from nat.builder.workflow_builder import WorkflowBuilder
    from nat.data_models.intermediate_step import IntermediateStepPayload, IntermediateStepType, StreamEventData
    from nat.middleware.middleware import FunctionMiddlewareContext
    from nat.observability.exporter_manager import ExporterManager
    from nat.runtime.runner import Runner
    from nat.utils.reactive.subject import Subject
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.testing.harness import ProgrammableGuardian, validate_hook_payload

if _NAT_OK:
    from acs.integrations.nat.adapter import (ACSGuardianDenied, ACSLifecycleExporterConfig, ACSMiddleware,
                                              ACSMiddlewareConfig, build_acs_middleware)

SECRET = "nat-runner-lifecycle-secret-padded-to-32-bytes"
RUN = ["steps/sessionStart", "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
       "steps/agentResponse", "steps/sessionEnd"]


class _Entry:
    """A workflow entry function that makes one wrapped call through the middleware, as NAT's Runner invokes it."""
    has_single_output = True
    config = SimpleNamespace(name="lifecycle-workflow", type="local")
    instance_name = display_name = "lifecycle-workflow"

    def __init__(self, middleware: ACSMiddleware, executed: list[str]) -> None:
        self.middleware, self.executed = middleware, executed

    async def ainvoke(self, message: str, to_type=None) -> str:
        async def target(command: str) -> str:
            self.executed.append(command)
            return f"ran {command}"
        context = FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                            single_output_schema=str, stream_output_schema=str)
        return await self.middleware.function_middleware_invoke(command=message, call_next=target, context=context)


class _RunFailed(Exception):
    pass


class _Failing(_Entry):
    """A workflow entry function that fails after its wrapped call."""

    async def ainvoke(self, message: str, to_type=None) -> str:
        await super().ainvoke(message, to_type)
        raise _RunFailed(message)


class _Hangs(_Entry):
    """A workflow entry function that waits after its wrapped call until the run is cancelled."""

    async def ainvoke(self, message: str, to_type=None) -> str:
        await super().ainvoke(message, to_type)
        await asyncio.Event().wait()
        return message


class _TwoCalls(_Entry):
    """A workflow entry function that makes two wrapped calls, message-1 then message-2."""

    async def ainvoke(self, message: str, to_type=None) -> str:
        await super().ainvoke(f"{message}-1", to_type)
        return await super().ainvoke(f"{message}-2", to_type)


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class EveryRunReportsItsLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

    def _runs(self, *messages: str, with_builder: bool = True, entry: type[_Entry] = _Entry,
              default_deny: bool = False) -> list[str]:
        """Run each message through NAT's Runner with the exporters the middleware's builder registered."""
        executed: list[str] = []
        self.exporters: list[str] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=default_deny,
                                         session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, \
                    build_acs_middleware(config, builder if with_builder else None) as middleware:
                # Workflow.run hands each Runner the exporters its builder collected.
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}
                self.exporters = [name.split("_")[0] + "_" + name.split("_")[1] for name in exporters]
                manager = ExporterManager.from_exporters(exporters)
                for message in messages:
                    async with Runner(message, entry(middleware, executed), ContextState.get(), manager) as runner:
                        with contextlib.suppress(_RunFailed, ACSGuardianDenied):
                            await runner.result()
                    await middleware._lifecycle_sent()
        asyncio.run(run())
        return executed

    def test_two_consecutive_runs_each_report_every_hook_in_order(self) -> None:
        self.assertEqual(self._runs("first", "second"), ["first", "second"])
        self.assertEqual(self.exporters, ["acs_lifecycle"])
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + RUN + RUN)

    def test_session_end_counts_the_runs_decision_failures(self) -> None:
        # Threaded, so only the slow call times out and nothing queues behind it.
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        hello = self.guardian._default_handshake
        allow = self.guardian._default_allow
        self.guardian.handlers["handshake/hello"] = lambda req: {**hello(req), "timeout_config": {"default_ms": 300}}
        calls = iter([0.6, 0.0])
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: (time.sleep(next(calls)), allow(req))[1]
        self.assertEqual(self._runs("first", "second"), ["first", "second"],
                         "under proceed the call runs after its decision times out")
        first, second = (end["params"]["payload"] for end in self.guardian.envelopes_for("steps/sessionEnd"))
        self.assertEqual(first["summary"]["decision_failures"], {"timeout": 1})
        self.assertEqual(second["summary"]["decision_failures"], {}, "each run's sessionEnd reports its own run's failures")
        self.assertEqual(validate_hook_payload(first, "session-end.json"), [])

    def test_overlapping_runs_each_report_their_own_failures(self) -> None:
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        hello, allow = self.guardian._default_handshake, self.guardian._default_allow
        # slow-1 outlives the negotiated 400 ms; slow-2 answers inside it and keeps the slow run going past the fast one.
        delays = {"slow-1": 0.8, "slow-2": 0.3}

        def call(req):
            command = req["params"]["payload"]["arguments"]["command"]["value"]
            time.sleep(delays.get(command, 0.0))
            return allow(req)
        self.guardian.handlers.update({"handshake/hello": lambda req: {**hello(req), "timeout_config": {"default_ms": 400}},
                                       "steps/toolCallRequest": call})
        executed: list[str] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=False, session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}

                async def one(message: str, delay: float) -> None:
                    await asyncio.sleep(delay)
                    manager = ExporterManager.from_exporters(exporters)
                    async with Runner(message, _TwoCalls(middleware, executed), ContextState.get(), manager) as runner:
                        await runner.result()
                await asyncio.gather(one("slow", 0.0), one("fast", 0.5))
                await middleware._lifecycle_sent()
        asyncio.run(run())
        fast, slow = (end["params"]["payload"]["summary"]["decision_failures"]
                      for end in self.guardian.envelopes_for("steps/sessionEnd"))
        self.assertEqual((fast, slow), ({}, {"timeout": 1}), "the fast run ends first, after the slow run's failure")

    def test_a_failed_run_still_reports_its_end(self) -> None:
        """NAT pushes WORKFLOW_END only once the workflow returns; a failed run's sessionEnd goes out when NAT stops its exporter."""
        self.assertEqual(self._runs("first", "second", entry=_Failing), ["first", "second"])
        ended = RUN[:4] + ["steps/sessionEnd"]
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + ended + ended)
        for end in self.guardian.envelopes_for("steps/sessionEnd"):
            payload = end["params"]["payload"]
            self.assertEqual((payload["reason"], payload["summary"]), ("error", {"decision_failures": {}}))
            self.assertEqual(validate_hook_payload(payload, "session-end.json"), [])

    def test_a_cancelled_run_reports_its_end_as_cancelled(self) -> None:
        executed: list[str] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}

                async def one() -> None:
                    manager = ExporterManager.from_exporters(exporters)
                    async with Runner("first", _Hangs(middleware, executed), ContextState.get(), manager) as runner:
                        await runner.result()
                task = asyncio.create_task(one())
                while not executed:
                    await asyncio.sleep(0.01)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                await middleware._lifecycle_sent()
        asyncio.run(run())
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + RUN[:4] + ["steps/sessionEnd"])
        [end] = self.guardian.envelopes_for("steps/sessionEnd")
        self.assertEqual(end["params"]["payload"]["reason"], "cancelled")

    def test_a_denied_session_start_refuses_that_run(self) -> None:
        """hooks.md sessionStart: ALLOW / DENY. A denied run's calls are blocked and nothing more of it is sent."""
        allow = self.guardian._default_allow
        answers = iter(["deny", "allow"])
        # Answered late, so a call that did not wait for its run's sessionStart would reach the Guardian first.
        self.guardian.handlers["steps/sessionStart"] = lambda req: (time.sleep(0.3), {**allow(req), "decision": next(answers)})[1]
        self.assertEqual(self._runs("first", "second"), ["second"], "the denied run's call did not run")
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello", "steps/sessionStart"] + RUN)

    def test_a_refused_run_withholds_a_result_and_sends_nothing(self) -> None:
        from acs.client import SessionRefused
        from acs.integrations.nat.adapter import _Run
        middleware = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4())))
        self.addCleanup(middleware.close)
        middleware._runs["refused-run"] = _Run(outcome=SessionRefused("session_start_denied", {"decision": "deny"}))
        context = SimpleNamespace(function_context=SimpleNamespace(name="Read"), output="SECRET-OUTPUT",
                                  modified_args=("x",), modified_kwargs={})

        async def post() -> None:
            ContextState.get().workflow_run_id.set("refused-run")
            await middleware.post_invoke(context)
        asyncio.run(post())
        self.assertIsNone(context.output)
        self.assertNotIn("steps/toolCallResult", self.guardian.methods_seen())

    def test_a_session_start_without_a_decision_follows_the_posture(self) -> None:
        for default_deny, executed, sent in ((False, ["first"], RUN), (True, [], ["steps/sessionStart"])):
            with self.subTest(default_deny=default_deny):
                self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
                self.guardian.start()
                self.addCleanup(self.guardian.stop)
                hello, allow = self.guardian._default_handshake, self.guardian._default_allow
                self.guardian.handlers.update({
                    "handshake/hello": lambda req: {**hello(req), "timeout_config": {"default_ms": 300}},
                    "steps/sessionStart": lambda req: (time.sleep(0.6), allow(req))[1]})
                self.assertEqual(self._runs("first", default_deny=default_deny), executed)
                self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + sent)
                if not default_deny:
                    [end] = self.guardian.envelopes_for("steps/sessionEnd")
                    self.assertEqual(end["params"]["payload"]["summary"]["decision_failures"], {"timeout": 1})

    def test_without_the_builder_each_run_reports_from_its_first_call(self) -> None:
        self.assertEqual(self._runs("first", "second", with_builder=False), ["first", "second"])
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + RUN[2:] + RUN[2:],
                         "the late subscription follows each run's new stream")

    def test_without_the_builder_overlapping_runs_are_each_subscribed_once(self) -> None:
        for order in ("AA", "ABA", "ABAB"):
            with self.subTest(order):
                middleware = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(),
                                                               session_id=str(uuid.uuid4())))
                sent: list[str] = []
                middleware._emit_lifecycle_hook = lambda method, payload, run=None: sent.append(method)
                streams = {name: Subject() for name in "AB"}
                runs = {name: contextvars.copy_context() for name in "AB"}
                for name, run in runs.items():
                    run.run(ContextState.get().event_stream.set, streams[name])
                for name in order:
                    runs[name].run(middleware._ensure_lifecycle_subscribed)
                end = IntermediateStepPayload(event_type=IntermediateStepType.WORKFLOW_END, name="wf",
                                              data=StreamEventData(output="a"))
                for name in sorted(set(order)):
                    streams[name].on_next(SimpleNamespace(payload=end))
                middleware.close()
                self.assertEqual(sent, ["steps/agentResponse", "steps/sessionEnd"] * len(set(order)),
                                 "each run's end is reported once")

    def test_a_disabled_middleware_sends_nothing_across_runs(self) -> None:
        os.environ["ACS_DISABLED"] = "1"
        self.assertEqual(self._runs("only"), ["only"])
        self.assertEqual(self.exporters, [], "a disabled middleware registers no exporter")
        self.assertEqual(self.guardian.methods_seen(), [])


    def test_a_lifecycle_exporter_configured_on_its_own_is_refused(self) -> None:
        async def build() -> None:
            async with WorkflowBuilder() as builder:
                await builder.add_telemetry_exporter("acs", ACSLifecycleExporterConfig(middleware_key="unknown"))
        with self.assertRaisesRegex(ValueError, "added by the acs_guardian middleware"):
            asyncio.run(build())


if __name__ == "__main__":
    unittest.main()
