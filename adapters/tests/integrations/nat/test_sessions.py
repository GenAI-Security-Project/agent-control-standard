"""Each root NAT Runner is one ACS session, through NAT's own builder, session manager, request path and Runner."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

try:
    from nat.builder.builder import Builder
    from nat.builder.context import Context, ContextState
    from nat.builder.function_info import FunctionInfo
    from nat.builder.workflow_builder import WorkflowBuilder
    from nat.cli.register_workflow import register_function
    from nat.data_models.config import Config
    from nat.data_models.function import FunctionBaseConfig
    from nat.data_models.intermediate_step import (IntermediateStep, IntermediateStepPayload, IntermediateStepType,
                                                   StreamEventData)
    from nat.middleware.middleware import FunctionMiddlewareContext, InvocationContext
    from nat.observability.exporter_manager import ExporterManager
    from nat.runtime.runner import Runner
    from nat.runtime.session import SessionManager
    from starlette.requests import Request
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.testing.harness import ProgrammableGuardian

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSGuardianDenied, ACSMiddlewareConfig, build_acs_middleware
    from tests.integrations.nat._nat_runs import Fn, with_middleware

SECRET = "nat-sessions-test-secret-padded-to-32-bytes"
RUN = ["handshake/hello", "steps/sessionStart", "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
       "steps/agentResponse", "steps/sessionEnd"]
EXECUTED: list[str] = []

if _NAT_OK:
    class _ToolConfig(FunctionBaseConfig, name="acs_sessions_test_tool"):
        pass

    class _FlowConfig(FunctionBaseConfig, name="acs_sessions_test_flow"):
        pass

    @register_function(config_type=_ToolConfig)
    async def _tool(config: _ToolConfig, builder: Builder):
        async def run(command: str) -> str:
            if command.startswith("hang"):
                EXECUTED.append(command)
                await asyncio.Event().wait()
            if command.startswith("fail"):
                raise RuntimeError(command)
            EXECUTED.append(command)
            return f"ran {command}"
        yield FunctionInfo.from_fn(run, description="records the commands it runs")

    @register_function(config_type=_FlowConfig)
    async def _flow(config: _FlowConfig, builder: Builder):
        tool = await builder.get_function("tool")

        async def run(message: str) -> str:
            return await tool.ainvoke(message, to_type=str)
        yield FunctionInfo.from_fn(run, description="calls the tool once with its input")


def _config(url: str, **acs) -> "Config":
    return Config.model_validate({
        "middleware": {"acs": {"_type": "acs_guardian", "guardian_url": url, **acs}},
        "functions": {"tool": {"_type": "acs_sessions_test_tool", "middleware": ["acs"]}},
        "workflow": {"_type": "acs_sessions_test_flow"},
    })


def _request(**headers: str) -> "Request":
    raw = [(k.encode(), v.encode()) for k, v in headers.items()]
    scope = {"type": "http", "method": "POST", "path": "/generate", "headers": raw, "query_string": b"",
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8000), "scheme": "http", "path_params": {}}

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}
    return Request(scope, receive)


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class EachRootRunnerIsOneSession(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"},
                                        clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        EXECUTED.clear()
        self.executed: list[str] = []

    def _sessions(self) -> list[list[str]]:
        sessions: dict[str, list[str]] = {}
        for request in self.guardian.received:
            session = request["params"]["metadata"]["session_id"]
            method = request["method"]
            if method == "steps/sessionEnd":
                method += f":{request['params']['payload']['reason']}"
            sessions.setdefault(session, []).append(method)
        return list(sessions.values())

    def _ends(self) -> list[dict]:
        return [r["params"]["payload"] for r in self.guardian.envelopes_for("steps/sessionEnd")]

    def _serve(self, *requests, concurrent: bool = False, **acs) -> list:
        """Run each (input, headers) pair the way NAT's HTTP routes do: a session for the request, then a run."""
        outcomes: list = []

        async def main() -> None:
            config = _config(self.guardian.url(), **acs)
            async with WorkflowBuilder.from_config(config=config) as builder:
                manager = await SessionManager.create(config=config, shared_builder=builder)
                try:
                    async def one(message: str, headers: dict) -> None:
                        try:
                            request = _request(**headers) if headers is not None else None
                            async with manager.session(http_connection=request) as session:
                                async with session.run(message) as runner:
                                    outcomes.append(await runner.result(to_type=str))
                        except Exception as e:  # noqa: BLE001
                            outcomes.append(type(e).__name__)
                    if concurrent:
                        await asyncio.gather(*(one(m, h) for m, h in requests))
                    else:
                        for message, headers in requests:
                            await asyncio.create_task(one(message, headers))
                finally:
                    await manager.shutdown()
        asyncio.run(main())
        return outcomes

    def test_two_runs_are_two_sessions_and_building_sends_nothing(self) -> None:
        self.assertEqual(self._serve(("one", None), ("two", None)), ["ran one", "ran two"])
        self.assertEqual(self._sessions(), [RUN[:-1] + ["steps/sessionEnd:completed"]] * 2)

    def test_nats_function_middleware_chain_applies_a_deny(self) -> None:
        allow = self.guardian._default_allow
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: (
            {**allow(req), "decision": "deny", "reasoning": "blocked"}
            if req["params"]["payload"]["tool"]["name"] == "tool" else allow(req))
        self.assertEqual(self._serve(("rm", None)), ["ACSGuardianDenied"])
        self.assertEqual(EXECUTED, [], "a denied call never reaches the function")

    def test_nats_function_middleware_chain_applies_a_modify(self) -> None:
        allow = self.guardian._default_allow
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            **allow(req), "decision": "modify", "reasoning": "use the safe command",
            "modifications": {"parameter_overrides": {"command": "ls"}}}
        self.assertEqual(self._serve(("rm -rf /", None)), ["ran ls"])
        self.assertEqual(EXECUTED, ["ls"])
        [request] = self.guardian.envelopes_for("steps/toolCallRequest")
        self.assertEqual(request["params"]["payload"]["arguments"], {"command": {"value": "rm -rf /"}})

    def test_requests_sharing_a_run_id_header_are_separate_sessions(self) -> None:
        same = {"workflow-run-id": "client-chosen"}
        self.assertEqual(self._serve(("one", same), ("two", same)), ["ran one", "ran two"])
        self.assertEqual(len(self._sessions()), 2)
        self.assertEqual(EXECUTED, ["one", "two"])

    def test_concurrent_requests_sharing_a_run_id_header_are_separate_sessions(self) -> None:
        same = {"workflow-run-id": "client-chosen"}
        allow = self.guardian._default_allow
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: (time.sleep(0.2), allow(req))[1]
        self.assertEqual(sorted(self._serve(("one", same), ("two", same), concurrent=True)), ["ran one", "ran two"])
        self.assertEqual(len(self._sessions()), 2)
        for session in self._sessions():
            self.assertEqual(session.count("steps/sessionStart"), 1)
            self.assertTrue(session[-1].startswith("steps/sessionEnd"))

    def test_a_failed_run_ends_its_session_with_error(self) -> None:
        self.assertEqual(self._serve(("fail-now", None)), ["RuntimeError"])
        self.assertEqual([end["reason"] for end in self._ends()], ["error"])

    def _middleware_runs(self, body, *, with_builder: bool = True, **acs) -> None:
        asyncio.run(with_middleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), **acs), body,
                                    with_builder=with_builder))

    async def _call(self, middleware, command: str) -> str | None:
        async def target(command: str) -> str:
            self.executed.append(command)
            return f"ran {command}"
        context = FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                            single_output_schema=str, stream_output_schema=str)
        try:
            return await middleware.function_middleware_invoke(command=command, call_next=target, context=context)
        except ACSGuardianDenied:
            self.executed.append(f"denied {command}")
            return None

    def test_a_nested_runner_awaited_directly_stays_in_its_parents_session(self) -> None:
        async def body(middleware, run):
            async def inner(message):
                return await self._call(middleware, "inner")

            async def outer(message):
                await self._call(middleware, "outer-1")
                await run("inner", inner)
                return await self._call(middleware, "outer-2")
            await run("outer", outer)
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["outer-1", "inner", "outer-2"])
        [session] = self._sessions()
        self.assertEqual(session.count("steps/sessionStart"), 1)
        self.assertEqual(session.count("steps/toolCallRequest"), 3)
        # NAT 1.7.0 sends the parent's WORKFLOW_END to the nested Runner's closed stream, so no exporter sees it.
        self.assertEqual(session[-1], "steps/sessionEnd:error")

    def test_nested_runners_in_child_tasks_stay_in_the_parents_session(self) -> None:
        async def body(middleware, run):
            async def inner(message):
                return await self._call(middleware, message)

            async def outer(message):
                await asyncio.create_task(run("inner", inner, "child"))
                await asyncio.gather(run("inner", inner, "a"), run("inner", inner, "b"))
                return await self._call(middleware, "after")
            await run("outer", outer)
        self._middleware_runs(body)
        self.assertEqual(sorted(self.executed), ["a", "after", "b", "child"])
        [session] = self._sessions()
        self.assertEqual(session.count("steps/userMessage"), 1, "a nested Runner's input is not the user's message")
        self.assertEqual(session[-1], "steps/sessionEnd:completed")

    def test_replayed_remote_steps_leave_the_session_open(self) -> None:
        async def body(middleware, run):
            async def outer(message):
                await self._call(middleware, "before")
                uid = str(uuid.uuid4())
                Context.get().intermediate_step_manager.push_intermediate_steps([
                    IntermediateStep(parent_id="root", function_ancestry=Context.get().active_function,
                                     payload=IntermediateStepPayload(UUID=uid, event_type=kind, name="remote",
                                                                     data=StreamEventData(input="i", output="o")))
                    for kind in (IntermediateStepType.WORKFLOW_START, IntermediateStepType.WORKFLOW_END)])
                return await self._call(middleware, "after")
            await run("outer", outer)
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["before", "after"])
        [session] = self._sessions()
        self.assertEqual(session.count("steps/userMessage"), 1)
        self.assertEqual(session.count("steps/agentResponse"), 1)
        self.assertEqual(session[-1], "steps/sessionEnd:completed")

    def test_a_cancelled_run_ends_with_cancelled(self) -> None:
        async def body(middleware, run):
            async def hangs(message):
                await self._call(middleware, "first")
                self.executed.append("waiting")
                await asyncio.Event().wait()
            task = asyncio.create_task(run("hangs", hangs))
            while "waiting" not in self.executed:
                await asyncio.sleep(0.01)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._middleware_runs(body)
        self.assertEqual([session[-1] for session in self._sessions()], ["steps/sessionEnd:cancelled"])

    def test_without_the_builder_a_cancelled_run_ends_as_abandoned_at_close(self) -> None:
        async def body(middleware, run):
            async def hangs(message):
                await self._call(middleware, "first")
                self.executed.append("waiting")
                await asyncio.Event().wait()
            task = asyncio.create_task(run("hangs", hangs))
            while "waiting" not in self.executed:
                await asyncio.sleep(0.01)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._middleware_runs(body, with_builder=False)
        self.assertEqual([session[-1] for session in self._sessions()], ["steps/sessionEnd:abandoned"])

    def test_without_the_builder_runs_end_completed_or_error(self) -> None:
        async def body(middleware, run):
            async def ok(message):
                return await self._call(middleware, "ok")

            async def fails(message):
                await self._call(middleware, "fails")
                raise RuntimeError("run failed")
            await run("ok", ok)
            with contextlib.suppress(RuntimeError):
                await run("fails", fails)
        self._middleware_runs(body, with_builder=False)
        self.assertEqual([session[-1] for session in self._sessions()],
                         ["steps/sessionEnd:completed", "steps/sessionEnd:error"])

    def test_close_ends_an_open_run_as_abandoned_and_refuses_its_later_calls(self) -> None:
        async def body(middleware, run):
            closed = asyncio.Event()

            async def outlives_close(message):
                await self._call(middleware, "before")
                await closed.wait()
                return await self._call(middleware, "after")
            task = asyncio.create_task(run("long", outlives_close))
            while "before" not in self.executed:
                await asyncio.sleep(0.01)
            await asyncio.to_thread(middleware.close)
            closed.set()
            await task
            await run("late", outlives_close)
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["before", "denied after", "denied before", "denied after"])
        [session] = self._sessions()
        self.assertEqual(session[-1], "steps/sessionEnd:abandoned")

    def test_a_late_call_of_an_ended_run_is_refused_however_many_runs_pass(self) -> None:
        async def body(middleware, run):
            release = asyncio.Event()
            background: list[asyncio.Task] = []

            async def leaves_a_task(message):
                async def late():
                    await release.wait()
                    await self._call(middleware, "late")
                background.append(asyncio.create_task(late()))
                return await self._call(middleware, message)
            await run("first", leaves_a_task, "first")
            for n in range(5):
                await run("later", lambda message: self._call(middleware, message), f"later-{n}")
            release.set()
            await background[0]
        self._middleware_runs(body)
        self.assertEqual(self.executed[-1], "denied late")
        self.assertTrue(all(session.count("steps/sessionEnd:completed") == 1 and session[-1].startswith("steps/sessionEnd")
                            for session in self._sessions()))

    def test_two_middlewares_with_one_config_never_share_a_session_id(self) -> None:
        async def main() -> None:
            config = ACSMiddlewareConfig(guardian_url=self.guardian.url())
            for _ in range(2):
                async with WorkflowBuilder() as builder, build_acs_middleware(config, builder) as middleware:
                    exporters = {name: c.instance for name, c in builder._telemetry_exporters.items()}

                    async def one():
                        ContextState.get().workflow_run_id.set("client-chosen")
                        async with Runner("x", Fn("flow", lambda m: self._call(middleware, m)), ContextState.get(),
                                          ExporterManager.from_exporters(exporters)) as runner:
                            await runner.result()
                    await asyncio.create_task(one())
        asyncio.run(main())
        starts = [r["params"]["metadata"]["session_id"] for r in self.guardian.envelopes_for("steps/sessionStart")]
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(set(starts)), 2)

    def test_no_setting_makes_two_middlewares_share_the_session_of_calls_outside_a_run(self) -> None:
        os.environ["ACS_SESSION_ID"] = "fixed"
        for _ in range(2):
            async def body(middleware, run):
                await self._call(middleware, "outside")
            asyncio.run(with_middleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), session_id="fixed"),
                                        body))
        starts = {r["params"]["metadata"]["session_id"] for r in self.guardian.envelopes_for("steps/sessionStart")}
        self.assertEqual(len(starts), 2, "a session_id is never used twice (§10 derives the session key from it)")

    def test_a_slow_lifecycle_hook_of_one_run_does_not_hold_another_runs_calls(self) -> None:
        allow = self.guardian._default_allow
        self.guardian.handlers["steps/userMessage"] = lambda req: (
            time.sleep(1.5) if req["params"]["payload"]["content"][0]["value"] == "slow" else None, allow(req))[1]
        took: dict[str, float] = {}

        async def body(middleware, run):
            async def timed(message):
                started = time.monotonic()
                result = await self._call(middleware, message)
                took[message] = time.monotonic() - started
                return result
            slow = asyncio.create_task(run("slow", timed, "slow"))
            await asyncio.sleep(0.2)
            await run("fast", timed, "fast")
            await slow
        self._middleware_runs(body)
        self.assertLess(took["fast"], 1.0)

    def test_a_call_cancelled_mid_exchange_still_counts_its_decision_failure(self) -> None:
        hello, allow = self.guardian._default_handshake, self.guardian._default_allow
        self.guardian.handlers["handshake/hello"] = lambda req: {**hello(req), "timeout_config": {"default_ms": 300}}
        entered = threading.Event()

        def slow(req):
            entered.set()
            time.sleep(0.6)
            return allow(req)
        self.guardian.handlers["steps/toolCallRequest"] = slow

        async def body(middleware, run):
            task = asyncio.create_task(run("cancelled", lambda m: self._call(middleware, m)))
            await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._middleware_runs(body)
        [end] = self._ends()
        self.assertEqual(end["reason"], "cancelled")
        self.assertEqual(end["summary"]["decision_failures"], {"timeout": 1})

    def test_a_call_outside_any_run_uses_the_middlewares_own_session_until_close(self) -> None:
        async def body(middleware, run):
            await self._call(middleware, "outside")
            await run("inside", lambda m: self._call(middleware, "inside"))
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["outside", "inside"])
        own, inside = self._sessions()
        self.assertEqual(own, ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest",
                               "steps/toolCallResult", "steps/sessionEnd:completed"])
        self.assertEqual(inside[-1], "steps/sessionEnd:completed")

    def _bypassing(self, mode: str) -> None:
        hello = self.guardian._default_handshake
        if mode == "tool methods not evaluated":
            self.guardian.handlers["handshake/hello"] = lambda req: {
                **hello(req), "methods_evaluated": ["steps/sessionStart", "steps/userMessage", "steps/agentResponse",
                                                    "steps/sessionEnd"]}
        elif mode == "no answer, startup proceeds":
            os.environ["ACS_STARTUP_POSTURE"] = "proceed"
            self.guardian.handlers["handshake/hello"] = lambda req: {"code": -32603, "message": "unavailable"}

    @staticmethod
    def _late_result() -> "InvocationContext":
        return InvocationContext(
            function_context=FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                                       single_output_schema=str, stream_output_schema=str),
            original_args=(), original_kwargs={"command": "late"}, modified_args=(),
            modified_kwargs={"command": "late"}, output="SECRET")

    def test_no_call_runs_after_close_whatever_the_sessions_decision(self) -> None:
        for mode in ("tool methods not evaluated", "no answer, startup proceeds"):
            with self.subTest(mode):
                self.guardian.reset()
                self.executed = []
                self._bypassing(mode)
                outputs: list = []

                async def body(middleware, run):
                    await self._call(middleware, "before-close")
                    await asyncio.to_thread(middleware.close)
                    sent = list(self.guardian.methods_seen())
                    await self._call(middleware, "after-close")
                    context = self._late_result()
                    await middleware.post_invoke(context)
                    outputs.append(context.output)
                    self.assertEqual(self.guardian.methods_seen(), sent, "nothing goes out after close()")
                self._middleware_runs(body)
                self.assertEqual(self.executed, ["before-close", "denied after-close"])
                self.assertEqual(outputs, [None], "a result reported after close() is withheld")

    def test_a_detached_task_of_an_ended_run_runs_nothing_whatever_the_sessions_decision(self) -> None:
        for mode in ("tool methods not evaluated", "no answer, startup proceeds"):
            with self.subTest(mode):
                self.guardian.reset()
                self.executed = []
                self._bypassing(mode)
                outputs: list = []

                async def body(middleware, run):
                    release = asyncio.Event()
                    detached: list[asyncio.Task] = []

                    async def leaves_a_task(message):
                        async def late():
                            await release.wait()
                            await self._call(middleware, "late")
                            context = self._late_result()
                            await middleware.post_invoke(context)
                            outputs.append(context.output)
                        detached.append(asyncio.create_task(late()))
                        return await self._call(middleware, "inside")
                    await run("root", leaves_a_task)
                    release.set()
                    await detached[0]
                self._middleware_runs(body)
                self.assertEqual(self.executed, ["inside", "denied late"])
                self.assertEqual(outputs, [None], "a result the ended run's task reports is withheld")

    def test_no_call_runs_while_close_is_ending_the_sessions(self) -> None:
        self._bypassing("tool methods not evaluated")

        async def body(middleware, run):
            await self._call(middleware, "before-close")
            closing, release = threading.Event(), threading.Event()
            end = middleware._end_session

            def held(session, reason):
                closing.set()
                release.wait(5)
                end(session, reason)
            middleware._end_session = held
            closer = asyncio.create_task(asyncio.to_thread(middleware.close))
            await asyncio.to_thread(closing.wait, 5)
            await self._call(middleware, "while-closing")
            release.set()
            await closer
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["before-close", "denied while-closing"])

    def test_a_run_after_one_whose_end_nat_lost_is_a_session_of_its_own(self) -> None:
        async def body(middleware, run):
            async def outer(message):
                # Without the exporter, NAT completes the nested Runner's stream instead of this run's.
                async with Runner("nested", Fn("nested", lambda m: asyncio.sleep(0, "n")), ContextState.get(),
                                  ExporterManager.from_exporters({})) as nested:
                    await nested.result()
                return await self._call(middleware, "unexported")
            async with Runner("unexported", Fn("unexported", outer), ContextState.get(),
                              ExporterManager.from_exporters({})) as runner:
                await runner.result()
            await run("exported", lambda message: self._call(middleware, "exported"))
        self._middleware_runs(body)
        self.assertEqual(self.executed, ["unexported", "exported"])
        starts = [r["params"]["payload"]["platform_context"].get("workflow_name")
                  for r in self.guardian.envelopes_for("steps/sessionStart")]
        self.assertIn("exported", starts, "the later run opened a session of its own")

    def test_a_direct_call_after_a_run_in_the_same_task_uses_the_middlewares_own_session(self) -> None:
        for with_builder in (True, False):
            with self.subTest(with_builder=with_builder):
                self.guardian.reset()
                self.executed = []

                async def body(middleware, run):
                    await self._call(middleware, "outside-before")
                    await run("flow", lambda message: self._call(middleware, "inside"))
                    await self._call(middleware, "outside-after")
                self._middleware_runs(body, with_builder=with_builder)
                self.assertEqual(self.executed, ["outside-before", "inside", "outside-after"])
                own, inside = self._sessions()
                self.assertEqual(own.count("steps/toolCallRequest"), 2, "both outside calls are in the own session")
                self.assertEqual(own[-1], "steps/sessionEnd:completed")
                self.assertEqual(inside.count("steps/toolCallRequest"), 1)

    def _audits(self) -> list[dict]:
        path = Path(os.environ["ACS_AUDIT_FILE"])
        return [json.loads(line.removeprefix("ACS_AUDIT ")) for line in path.read_text().splitlines()] if path.exists() else []

    def _verdict_on(self, method: str, decision: dict, *, default_deny: bool = False) -> None:
        os.environ["ACS_AUDIT_FILE"] = str(self.records / "audit.log")
        allow = self.guardian._default_allow
        self.guardian.handlers[method] = lambda req: {**allow(req), **decision}

        async def body(middleware, run):
            async def entry(message):
                await self._call(middleware, "call")
                return "the answer"
            await run("flow", entry, "the question")
        self._middleware_runs(body, default_deny=default_deny)

    def test_a_denied_workflow_input_blocks_the_runs_calls(self) -> None:
        self._verdict_on("steps/userMessage", {"decision": "deny", "reasoning": "injected"})
        self.assertEqual(self.executed, ["denied call"])
        [session] = self._sessions()
        self.assertNotIn("steps/toolCallRequest", session)
        self.assertEqual(session[-1], "steps/sessionEnd:completed")
        [refused] = [a for a in self._audits() if a["acs_audit_event"] == "workflow_input_refused"]
        self.assertEqual((refused["decision"], refused["method"]), ("deny", "steps/userMessage"))

    def test_a_modify_on_the_workflow_input_is_a_deny_recorded_as_modify_unsupported(self) -> None:
        self._verdict_on("steps/userMessage", {"decision": "modify", "reasoning": "rewrite",
                                               "modifications": {"modified_content": "other"}})
        self.assertEqual(self.executed, ["denied call"])
        [unsupported] = [a for a in self._audits() if a["acs_audit_event"] == "modify_unsupported"]
        self.assertEqual((unsupported["reason_codes"], unsupported["method"]), (["modify_unsupported"], "steps/userMessage"))

    def test_an_undecided_workflow_input_follows_the_posture(self) -> None:
        hello, allow = self.guardian._default_handshake, self.guardian._default_allow
        self.guardian.handlers["handshake/hello"] = lambda req: {**hello(req), "timeout_config": {"default_ms": 200}}
        self.guardian.handlers["steps/userMessage"] = lambda req: (time.sleep(0.5), allow(req))[1]
        for default_deny, executed in ((False, ["call"]), (True, ["denied call"])):
            with self.subTest(default_deny=default_deny):
                self.executed = []

                async def body(middleware, run):
                    await run("flow", lambda m: self._call(middleware, "call"), "the question")
                self._middleware_runs(body, default_deny=default_deny)
                self.assertEqual(self.executed, executed)

    def test_a_workflow_input_the_signer_cannot_encode_reaches_the_guardian_replaced(self) -> None:
        os.environ["ACS_AUDIT_FILE"] = str(self.records / "audit.log")
        allow = self.guardian._default_allow
        self.guardian.handlers["steps/userMessage"] = lambda req: {**allow(req), "decision": "deny", "reasoning": "no"}

        async def body(middleware, run):
            await run("flow", lambda m: self._call(middleware, "call"), "lone surrogate \ud800")
        self._middleware_runs(body)
        [message] = [r for r in self.guardian.received if r["method"] == "steps/userMessage"]
        self.assertEqual(message["params"]["payload"]["content"], [{"type": "text", "value": "lone surrogate \ufffd"}])
        self.assertIn("envelope_normalized", [a["acs_audit_event"] for a in self._audits()])
        self.assertEqual(self.executed, ["denied call"])

    def test_a_verdict_on_the_workflow_output_is_recorded_as_unenforceable(self) -> None:
        self._verdict_on("steps/agentResponse", {"decision": "deny", "reasoning": "leaks a secret"})
        self.assertEqual(self.executed, ["call"])
        [unenforceable] = [a for a in self._audits() if a["acs_audit_event"] == "unenforceable_decision"]
        self.assertEqual((unenforceable["decision"], unenforceable["method"]), ("deny", "steps/agentResponse"))

    def test_a_modify_on_the_workflow_output_is_recorded_as_modify_unsupported(self) -> None:
        self._verdict_on("steps/agentResponse", {"decision": "modify", "reasoning": "rewrite",
                                                 "modifications": {"modified_content": "x"}})
        events = [a["acs_audit_event"] for a in self._audits()]
        self.assertIn("modify_unsupported", events)
        self.assertIn("unenforceable_decision", events)

    def test_a_finished_session_leaves_no_records(self) -> None:
        self.assertEqual(self._serve(("one", None)), ["ran one"])
        self.assertEqual(list(self.records.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
