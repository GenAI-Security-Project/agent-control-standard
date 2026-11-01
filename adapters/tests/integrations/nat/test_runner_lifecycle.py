"""Every NAT run reports its whole lifecycle: the builder registers an exporter that NAT starts for each run before
WORKFLOW_START, so a run's first events and a later run's events all reach the Guardian."""
from __future__ import annotations

import asyncio
import contextvars
import os
import tempfile
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
from acs.testing.harness import ProgrammableGuardian

if _NAT_OK:
    from acs.integrations.nat.adapter import (ACSLifecycleExporterConfig, ACSMiddleware, ACSMiddlewareConfig,
                                              build_acs_middleware)

SECRET = "nat-runner-lifecycle-secret"
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


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class EveryRunReportsItsLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

    def _runs(self, *messages: str, with_builder: bool = True) -> list[str]:
        """Run each message through NAT's Runner with the exporters the middleware's builder registered."""
        executed: list[str] = []
        self.exporters: list[str] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=False,
                                         session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, \
                    build_acs_middleware(config, builder if with_builder else None) as middleware:
                # Workflow.run hands each Runner the exporters its builder collected.
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}
                self.exporters = [name.split("_")[0] + "_" + name.split("_")[1] for name in exporters]
                manager = ExporterManager.from_exporters(exporters)
                for message in messages:
                    async with Runner(message, _Entry(middleware, executed), ContextState.get(), manager) as runner:
                        await runner.result()
                    await middleware._lifecycle_sent()
        asyncio.run(run())
        return executed

    def test_two_consecutive_runs_each_report_every_hook_in_order(self) -> None:
        self.assertEqual(self._runs("first", "second"), ["first", "second"])
        self.assertEqual(self.exporters, ["acs_lifecycle"])
        self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"] + RUN + RUN)

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
