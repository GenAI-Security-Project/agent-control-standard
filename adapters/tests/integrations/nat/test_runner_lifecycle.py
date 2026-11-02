"""Each NAT run is its own ACS session, reported from before its WORKFLOW_START by the exporter its builder registers."""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import os
import tempfile
import threading
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

from acs.client import _exchange, _handshake
from acs.testing.harness import ProgrammableGuardian, validate_hook_payload

if _NAT_OK:
    from acs.integrations.nat.adapter import (ACSGuardianDenied, ACSLifecycleExporterConfig, ACSMiddleware,
                                              ACSMiddlewareConfig, build_acs_middleware)

SECRET = "nat-runner-lifecycle-secret-padded-to-32-bytes"
# The middleware opens its own session when NAT builds it; each run is a session of its own after that.
BUILD = ["handshake/hello"]
RUN = ["handshake/hello", "steps/sessionStart", "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
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
        # The call has returned, its result reported, before the run waits to be cancelled.
        self.executed.append("returned")
        await asyncio.Event().wait()
        return message


class _DeniedThenRetries(_Entry):
    """The "long" run makes a call, waits until released, and calls again; other runs make one call."""

    def __init__(self, middleware: ACSMiddleware, executed: list[str], started: asyncio.Event,
                 release: asyncio.Event) -> None:
        super().__init__(middleware, executed)
        self.started, self.release = started, release

    async def ainvoke(self, message: str, to_type=None) -> str:
        if message != "long":
            return await super().ainvoke(message, to_type)
        with contextlib.suppress(ACSGuardianDenied):
            await super().ainvoke("long-first", to_type)
        self.started.set()
        await self.release.wait()
        with contextlib.suppress(ACSGuardianDenied):
            await super().ainvoke("long-retry", to_type)
        return message


class _Waits(_Entry):
    """A workflow entry function that waits, before any call, until the run is cancelled."""

    async def ainvoke(self, message: str, to_type=None) -> str:
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

    def _sessions(self) -> list[list[str]]:
        """The methods the Guardian received for each session_id, sessions in the order they began."""
        sessions: dict[str, list[str]] = {}
        for request in self.guardian.received:
            session = ((request.get("params") or {}).get("metadata") or {}).get("session_id", "")
            sessions.setdefault(session, []).append(request.get("method", ""))
        return list(sessions.values())

    def _runs(self, *messages: str, with_builder: bool = True, entry: type[_Entry] = _Entry,
              default_deny: bool = False, prepare=None) -> list[str]:
        """Run each message through NAT's Runner with the exporters the middleware's builder registered."""
        executed: list[str] = []
        self.exporters: list[str] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=default_deny,
                                         session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, \
                    build_acs_middleware(config, builder if with_builder else None) as middleware:
                if prepare is not None:
                    prepare(middleware)
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
        # hooks.md sessionStart: once per session, before any other steps/* hook; sessionEnd seals it.
        self.assertEqual(self._sessions(), [BUILD, RUN, RUN])

    def test_a_runs_session_start_carries_its_workflow_name_however_late_it_goes_out(self) -> None:
        def slow_lifecycle(middleware) -> None:
            send = middleware._lifecycle._send

            def late(method, payload, run=None):
                time.sleep(0.3)
                send(method, payload, run)
            middleware._lifecycle._send = late
        self.assertEqual(self._runs("first", prepare=slow_lifecycle), ["first"])
        [start] = self.guardian.envelopes_for("steps/sessionStart")
        self.assertEqual(start["params"]["payload"]["platform_context"]["workflow_name"], "lifecycle-workflow")
        self.assertEqual(self._sessions(), [BUILD, RUN])

    def test_a_finished_runs_session_records_are_removed(self) -> None:
        self.assertEqual(self._runs("first", "second"), ["first", "second"])
        runs = [((r.get("params") or {}).get("metadata") or {}).get("session_id")
                for r in self.guardian.envelopes_for("steps/sessionStart")]
        self.assertEqual(len(set(runs)), 2)
        for session in runs:
            record = _handshake._handshake_cache_path(session, self.guardian.url())
            self.assertEqual([path.name for path in (record, Path(f"{record}.started"), Path(f"{record}.lock"))
                              if path.exists()], [])

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
        ended = RUN[:5] + ["steps/sessionEnd"]
        self.assertEqual(self._sessions(), [BUILD, ended, ended])
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
                while "returned" not in executed:
                    await asyncio.sleep(0.01)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                await middleware._lifecycle_sent()
        asyncio.run(run())
        self.assertEqual(self._sessions(), [BUILD, RUN[:5] + ["steps/sessionEnd"]])
        [end] = self.guardian.envelopes_for("steps/sessionEnd")
        self.assertEqual(end["params"]["payload"]["reason"], "cancelled")

    def test_a_run_cancelled_before_its_first_call_ends_as_cancelled(self) -> None:
        """The run's task is known from its WORKFLOW_START, so a run cancelled before any call is not reported as an error."""
        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}

                async def one() -> None:
                    manager = ExporterManager.from_exporters(exporters)
                    async with Runner("first", _Waits(middleware, []), ContextState.get(), manager) as runner:
                        await runner.result()
                task = asyncio.create_task(one())
                while "steps/userMessage" not in self.guardian.methods_seen():
                    await asyncio.sleep(0.01)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                await middleware._lifecycle_sent()
        asyncio.run(run())
        self.assertEqual(self._sessions(), [BUILD, RUN[:3] + ["steps/sessionEnd"]])
        [end] = self.guardian.envelopes_for("steps/sessionEnd")
        self.assertEqual(end["params"]["payload"]["reason"], "cancelled")

    def test_a_run_cancelled_during_an_exchange_ends_after_it(self) -> None:
        """A cancelled call leaves its round trip running in a worker thread; the run's sessionEnd goes out after it."""
        for held in ("steps/toolCallRequest", "steps/toolCallResult"):
            with self.subTest(held):
                self.guardian.reset()
                entered, release = threading.Event(), threading.Event()
                send = _exchange._open

                def hold(request, timeout, held=held):
                    if json.loads(request.data).get("method") == held:
                        entered.set()
                        release.wait(5)
                    return send(request, timeout=timeout)

                async def run() -> int:
                    config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
                    async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                        exporters = {name: c.instance for name, c in builder._telemetry_exporters.items()}

                        async def one() -> None:
                            manager = ExporterManager.from_exporters(exporters)
                            async with Runner("first", _Entry(middleware, []), ContextState.get(), manager) as runner:
                                await runner.result()
                        with mock.patch.object(_exchange, "_open", hold):
                            task = asyncio.create_task(one())
                            for _ in range(500):
                                if entered.is_set() or task.done():
                                    break
                                await asyncio.sleep(0.01)
                            self.assertTrue(entered.is_set(), self.guardian.methods_seen())
                            task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await task
                            # Held past the cancel, so a sessionEnd that did not wait would reach the Guardian first.
                            threading.Timer(0.3, release.set).start()
                            await asyncio.wait_for(middleware._lifecycle_sent(), 10)
                        return len(middleware._runs)
                self.assertEqual(asyncio.run(run()), 0)
                [session] = self._sessions()[1:]
                self.assertEqual(session[-1], "steps/sessionEnd", session)
                self.assertIn(held, session)

    def _outside_a_run(self, *commands: str, end_first: bool = False) -> tuple[list[str], list[bool]]:
        """Calls made straight through the middleware, outside any NAT run; whether each was blocked."""
        executed: list[str] = []
        blocked: list[bool] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
            async with build_acs_middleware(config, None) as middleware:
                context = FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                                    single_output_schema=str, stream_output_schema=str)

                async def target(command: str) -> str:
                    executed.append(command)
                    return f"ran {command}"
                for n, command in enumerate(commands):
                    if end_first and n == len(commands) - 1:
                        middleware._on_intermediate_step(SimpleNamespace(payload=IntermediateStepPayload(
                            event_type=IntermediateStepType.WORKFLOW_END, name="wf", data=StreamEventData(output="a"))))
                        await middleware._lifecycle_sent()
                    try:
                        await middleware.function_middleware_invoke(command=command, call_next=target, context=context)
                        blocked.append(False)
                    except ACSGuardianDenied:
                        blocked.append(True)
        asyncio.run(run())
        return executed, blocked

    def test_a_call_outside_any_run_opens_and_ends_the_middlewares_own_session(self) -> None:
        self.assertEqual(self._outside_a_run("first", "second"), (["first", "second"], [False, False]))
        own = ["handshake/hello", "steps/sessionStart"] + ["steps/toolCallRequest", "steps/toolCallResult"] * 2
        self.assertEqual(self._sessions(), [own + ["steps/sessionEnd"]], "sessionStart first, sessionEnd at shutdown")
        session = self.guardian.envelopes_for("steps/sessionEnd")[0]["params"]["metadata"]["session_id"]
        record = _handshake._handshake_cache_path(session, self.guardian.url())
        self.assertFalse(record.exists(), "the ended session's record is removed")

    def test_a_middleware_with_no_call_outside_a_run_sends_only_its_handshake(self) -> None:
        self.assertEqual(self._outside_a_run(), ([], []))
        self.assertEqual(self._sessions(), [BUILD])

    def test_a_call_after_the_middlewares_own_session_ended_is_refused(self) -> None:
        self.assertEqual(self._outside_a_run("first", "late", end_first=True), (["first"], [False, True]))
        [session] = self._sessions()
        self.assertEqual(session[-1], "steps/sessionEnd", "nothing goes out after the session's end")
        self.assertEqual(session.count("handshake/hello"), 1, "the ended session's id is not opened again")

    def test_a_worker_that_starts_after_the_runs_end_sends_nothing(self) -> None:
        """A cancelled call's worker may start only after the run's sessionEnd; it finds the run ended and sends nothing."""
        for held in ("steps/toolCallRequest", "steps/toolCallResult"):
            with self.subTest(held):
                self.guardian.reset()
                entered, release, done = threading.Event(), threading.Event(), threading.Event()

                async def run() -> None:
                    config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
                    async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                        exporters = {name: c.instance for name, c in builder._telemetry_exporters.items()}
                        exchange = middleware._exchange

                        def late(request, step, run, *rest, held=held):
                            try:
                                if request.get("method") == held:
                                    entered.set()
                                    release.wait(5)
                                return exchange(request, step, run, *rest)
                            finally:
                                done.set()
                        middleware._exchange = late

                        async def one() -> None:
                            manager = ExporterManager.from_exporters(exporters)
                            async with Runner("first", _Entry(middleware, []), ContextState.get(), manager) as runner:
                                await runner.result()
                        task = asyncio.create_task(one())
                        for _ in range(500):
                            if entered.is_set() or task.done():
                                break
                            await asyncio.sleep(0.01)
                        self.assertTrue(entered.is_set(), self.guardian.methods_seen())
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await task
                        await asyncio.wait_for(middleware._lifecycle_sent(), 10)
                        release.set()
                        for _ in range(500):
                            if done.is_set():
                                break
                            await asyncio.sleep(0.01)
                        await asyncio.wait_for(middleware._lifecycle_sent(), 10)
                asyncio.run(run())
                [session] = self._sessions()[1:]
                self.assertEqual(session[-1], "steps/sessionEnd", session)
                self.assertNotIn(held, session, "the late worker sent its step")

    def test_a_late_step_of_an_ended_run_does_not_open_it_again(self) -> None:
        from acs.client import SessionRefused
        middleware = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4())))
        self.addCleanup(middleware.close)
        middleware._run_state("ended")
        middleware._forget_run("ended")
        self.assertIsInstance(middleware._step("ended").decision, SessionRefused)
        self.assertNotIn("ended", middleware._runs)
        self.assertEqual(self.guardian.methods_seen(), [], "nothing was opened for the ended run")

    def test_shutdown_waits_for_the_middlewares_own_session_still_opening(self) -> None:
        entered, release = threading.Event(), threading.Event()
        send = _exchange._open

        def hold(request, timeout):
            if json.loads(request.data).get("method") == "steps/sessionStart":
                entered.set()
                release.wait(5)
            return send(request, timeout=timeout)
        session = str(uuid.uuid4())

        async def run() -> None:
            context = FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                                single_output_schema=str, stream_output_schema=str)

            async def target(command: str) -> str:
                return command
            with mock.patch.object(_exchange, "_open", hold):
                async with build_acs_middleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=session),
                                                None) as middleware:
                    task = asyncio.create_task(middleware.function_middleware_invoke(
                        command="hello", call_next=target, context=context))
                    for _ in range(500):
                        if entered.is_set() or task.done():
                            break
                        await asyncio.sleep(0.01)
                    self.assertTrue(entered.is_set(), self.guardian.methods_seen())
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
                    # Released while NAT shuts the middleware down, which waits for the session to open.
                    threading.Timer(0.3, release.set).start()
        asyncio.run(run())
        self.assertEqual(self._sessions(), [["handshake/hello", "steps/sessionStart", "steps/sessionEnd"]])
        record = _handshake._handshake_cache_path(session, self.guardian.url())
        self.assertEqual([path.name for path in (record, Path(f"{record}.started"), Path(f"{record}.lock"))
                          if path.exists()], [], "the ended session leaves no records")

    def test_a_denied_session_start_refuses_that_run(self) -> None:
        """hooks.md sessionStart: ALLOW / DENY. A denied run's calls are blocked and nothing more of it is sent."""
        allow = self.guardian._default_allow
        answers = iter(["deny", "allow"])
        # Answered late, so a call that did not wait for its run's sessionStart would reach the Guardian first.
        self.guardian.handlers["steps/sessionStart"] = lambda req: (time.sleep(0.3), {**allow(req), "decision": next(answers)})[1]
        self.assertEqual(self._runs("first", "second"), ["second"], "the denied run's call did not run")
        self.assertEqual(self._sessions(), [BUILD, RUN[:2], RUN], "a refused run's session sends nothing more")

    def test_a_refused_run_withholds_a_result_and_sends_nothing(self) -> None:
        from acs.client import SessionRefused
        from acs.integrations.nat.adapter import _Run
        middleware = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4())))
        self.addCleanup(middleware.close)
        middleware._runs["refused-run"] = _Run(session_id=str(uuid.uuid4()),
                                               decision=SessionRefused("session_start_denied", {"decision": "deny"}))
        context = SimpleNamespace(function_context=SimpleNamespace(name="Read"), output="SECRET-OUTPUT",
                                  modified_args=("x",), modified_kwargs={})

        async def post() -> None:
            ContextState.get().workflow_run_id.set("refused-run")
            await middleware.post_invoke(context)
        asyncio.run(post())
        self.assertIsNone(context.output)
        self.assertNotIn("steps/toolCallResult", self.guardian.methods_seen())

    def test_a_refused_run_stays_refused_while_other_runs_come_and_go(self) -> None:
        """A run's decision lasts until its sessionEnd, however many runs start and end meanwhile."""
        allow = self.guardian._default_allow
        answers = iter(["deny"] + ["allow"] * 10)
        self.guardian.handlers["steps/sessionStart"] = lambda req: {**allow(req), "decision": next(answers)}
        executed: list[str] = []
        tracked: list[int] = []

        async def run() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4()))
            async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                exporters = {name: configured.instance for name, configured in builder._telemetry_exporters.items()}
                started, release = asyncio.Event(), asyncio.Event()

                async def one(message: str) -> None:
                    entry = _DeniedThenRetries(middleware, executed, started, release)
                    async with Runner(message, entry, ContextState.get(), ExporterManager.from_exporters(exporters)) as runner:
                        await runner.result()
                long = asyncio.create_task(one("long"))
                await asyncio.wait_for(started.wait(), timeout=10)
                for i in range(3):
                    await one(f"short-{i}")
                await middleware._lifecycle_sent()
                tracked.append(len(middleware._runs))
                release.set()
                await asyncio.wait_for(long, timeout=10)
                await middleware._lifecycle_sent()
                tracked.append(len(middleware._runs))
        with mock.patch("acs.integrations.nat.adapter._MAX_COUNTED_RUNS", 2):
            asyncio.run(run())
        self.assertEqual(executed, ["short-0", "short-1", "short-2"], "neither call of the refused run ran")
        self.assertEqual(tracked, [1, 0], "a run is forgotten once its sessionEnd is handled")

    def test_a_running_runs_failure_counts_never_age_out(self) -> None:
        from acs.client import Resolution
        from acs.integrations.nat.adapter import _Run
        middleware = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id=str(uuid.uuid4())))
        self.addCleanup(middleware.close)
        middleware._runs["running"] = _Run(session_id=str(uuid.uuid4()))
        timeout = Resolution(True, "fail_open_bypass", "decision_timeout", {"failure_class": "timeout"},
                             decision_failure=True)
        with mock.patch("acs.integrations.nat.adapter._MAX_COUNTED_RUNS", 2):
            for run in ("running", "a", "b", "c"):
                middleware._count_failure(timeout, run)
        self.assertEqual(list(middleware._decision_failures), ["running", "b", "c"],
                         "only runs no sessionEnd will report age out")
        middleware._forget_run("running")
        self.assertEqual(list(middleware._decision_failures), ["b", "c"], "a forgotten run's counts go with it")
        middleware.close()
        middleware._runs["late"] = _Run(session_id=str(uuid.uuid4()))
        middleware._queue_lifecycle_hook("steps/sessionEnd", {"reason": "error"}, "late")
        self.assertEqual(middleware._runs, {}, "a sessionEnd the closed middleware cannot send is still handled")

    def test_a_session_start_without_a_decision_follows_the_posture(self) -> None:
        # The run's sessionEnd reports the start's timeout under either posture (§6.4): it is audit-only.
        for default_deny, executed, sent in ((False, ["first"], RUN), (True, [], RUN[:2] + ["steps/sessionEnd"])):
            with self.subTest(default_deny=default_deny):
                self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
                self.guardian.start()
                self.addCleanup(self.guardian.stop)
                hello, allow = self.guardian._default_handshake, self.guardian._default_allow
                self.guardian.handlers.update({
                    "handshake/hello": lambda req: {**hello(req), "timeout_config": {"default_ms": 300}},
                    "steps/sessionStart": lambda req: (time.sleep(0.6), allow(req))[1]})
                self.assertEqual(self._runs("first", default_deny=default_deny), executed)
                self.assertEqual(self._sessions(), [BUILD, sent])
                [end] = self.guardian.envelopes_for("steps/sessionEnd")
                self.assertEqual(end["params"]["payload"]["summary"]["decision_failures"], {"timeout": 1})

    def test_without_the_builder_each_run_reports_from_its_first_call(self) -> None:
        self.assertEqual(self._runs("first", "second", with_builder=False), ["first", "second"])
        # The first call opens the run's session, so its sessionStart still comes first.
        from_first_call = RUN[:2] + RUN[3:]
        self.assertEqual(self._sessions(), [BUILD, from_first_call, from_first_call],
                         "the late subscription follows each run's new stream")

    def test_without_the_builder_a_failed_run_still_ends(self) -> None:
        """NAT completes a run's stream whether or not the run returns, so the late subscription ends a failed run."""
        self.assertEqual(self._runs("first", with_builder=False, entry=_Failing), ["first"])
        self.assertEqual(self._sessions(), [BUILD, RUN[:2] + RUN[3:5] + ["steps/sessionEnd"]])
        [end] = self.guardian.envelopes_for("steps/sessionEnd")
        self.assertEqual(end["params"]["payload"]["reason"], "error")

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
