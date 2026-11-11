"""Observe tool effects and caller results through the installed Relay runtime."""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nemo_relay as relay
from acs import core
from acs.client import _handshake
from acs.integrations.relay.adapter import ACSRelay, ACSGuardianDenied
from acs.integrations.relay.plugin import GuardianPlugin
from acs.testing.harness import ProgrammableGuardian

SECRET = "relay-test-secret-for-local-fixtures-only"


class LiveRelay(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        env = patch.dict(
            os.environ,
            ACS_HMAC_SECRET=SECRET,
            ACS_HMAC_KEY_ID="test-key",
            ACS_AUDIT_FILE=str(self.root / "audit.jsonl"),
        )
        env.start()
        self.addCleanup(env.stop)
        cache = patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", self.root / "sessions")
        cache.start()
        self.addCleanup(cache.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        self.adapter = ACSRelay(self.guardian.url())
        self.calls = []
        self.ledger = self.root / "effects.jsonl"
        self.ledger.write_text("")
        relay.intercepts.register_tool_execution(
            "acs-test", 1000, self.adapter.intercept
        )
        self.addCleanup(relay.intercepts.deregister_tool_execution, "acs-test")

    def answer(self, method, decision, modifications=None):
        result = {"decision": decision, "reasoning": "test policy"}
        if modifications is not None:
            result["modifications"] = modifications
        self.guardian.handlers[method] = lambda req: result

    async def tool(self, args):
        self.calls.append(args)
        with self.ledger.open("a") as file:
            file.write(json.dumps(args) + "\n")
        return relay.ToolExecutionResult("secret-output")

    async def execute(self, tool=None):
        return await relay.tools.execute("pay", {"amount": 1000}, tool or self.tool)

    def payloads(self, method):
        return [r["params"]["payload"] for r in self.guardian.envelopes_for(method)]

    def assert_no_effect(self):
        self.assertEqual(self.calls, [])
        self.assertEqual(self.ledger.read_text(), "")

    async def test_allow_and_lifecycle(self):
        result = await self.execute()
        self.assertEqual(result.result, "secret-output")
        self.assertEqual(
            self.guardian.envelopes_for("handshake/hello")[0]["params"]["payload"][
                "profiles_supported"
            ],
            [],
        )
        self.assertEqual(self.calls, [{"amount": 1000}])
        self.assertEqual(len(self.ledger.read_text().splitlines()), 1)
        self.assertEqual(
            self.guardian.methods_seen(),
            [
                "handshake/hello",
                "steps/sessionStart",
                "steps/toolCallRequest",
                "steps/toolCallResult",
                "steps/sessionEnd",
            ],
        )
        request = self.guardian.envelopes_for("steps/toolCallRequest")[0]
        self.assertEqual(
            self.payloads("steps/toolCallResult")[0]["request_id_ref"],
            request["params"]["request_id"],
        )

    async def test_deny_has_no_effect(self):
        self.answer("steps/toolCallRequest", "deny")
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()
        self.assertFalse(self.payloads("steps/toolCallResult"))

    async def test_rewrite_reaches_callback_and_ledger(self):
        self.answer(
            "steps/toolCallRequest", "modify", {"parameter_overrides": {"amount": 500}}
        )
        await self.execute()
        self.assertEqual(self.calls, [{"amount": 500}])
        self.assertEqual(json.loads(self.ledger.read_text()), {"amount": 500})
        self.assertEqual(
            self.payloads("steps/toolCallRequest")[0]["arguments"]["amount"]["value"],
            1000,
        )

    async def test_unsupported_request_modification_blocks(self):
        self.answer(
            "steps/toolCallRequest", "modify", {"modified_content": "replacement"}
        )
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()

    async def test_result_deny_withholds_output_after_effect(self):
        self.answer("steps/toolCallResult", "deny")
        with self.assertRaises(ACSGuardianDenied) as caught:
            await self.execute()
        self.assertNotIn("secret-output", str(caught.exception))
        self.assertEqual(len(self.calls), 1)

    async def test_result_replacement_reaches_caller(self):
        self.answer(
            "steps/toolCallResult", "modify", {"modified_content": "safe-output"}
        )
        self.assertEqual((await self.execute()).result, "safe-output")
        self.assertEqual(len(self.calls), 1)

    async def test_result_structured_edit_withholds_output(self):
        self.answer(
            "steps/toolCallResult", "modify", {"parameter_overrides": {"x": "safe"}}
        )
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assertEqual(len(self.calls), 1)

    async def test_ask_and_defer_block(self):
        for disposition in ("ask", "defer"):
            details = (
                {
                    "ask_details": {
                        "approver": {"type": "human", "id": "reviewer"},
                        "question": "Proceed?",
                        "timeout_seconds": 30,
                    }
                }
                if disposition == "ask"
                else {
                    "defer_details": {
                        "reason": "pending_dependency",
                        "resolution_method": "human_approval",
                        "resolution_timeout_ms": 1000,
                    }
                }
            )
            self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
                "decision": disposition,
                "reasoning": "pause",
                **details,
            }
            with self.assertRaises(ACSGuardianDenied) as caught:
                await self.execute()
            self.assertIn(disposition, str(caught.exception))
            self.assert_no_effect()

    async def test_session_start_denial_blocks_tool(self):
        self.answer("steps/sessionStart", "deny")
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()
        self.assertFalse(self.payloads("steps/toolCallRequest"))

    async def test_unsigned_result_blocks_delivery(self):
        def handler(req):
            self.guardian.sign_responses = False
            return {"decision": "allow"}

        self.guardian.handlers["steps/toolCallResult"] = handler
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assertEqual(len(self.calls), 1)

    async def test_malformed_allow_blocks_execution(self):
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "decision": "allow",
            "type": "invalid",
        }
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()

    async def test_failure_postures_and_audit_counts(self):
        from acs.client import Config, FailPosture

        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "code": -32603,
            "message": "internal error",
        }
        for fail_closed in (True, False):
            self.adapter.config = Config(
                self.guardian.url(), FailPosture(fail_closed, 0.1), True, False
            )
            if fail_closed:
                with self.assertRaises(ACSGuardianDenied):
                    await self.execute()
                self.assert_no_effect()
            else:
                await self.execute()
                self.assertEqual(len(self.calls), 1)
            end = self.payloads("steps/sessionEnd")[-1]
            self.assertEqual(sum(end["summary"]["decision_failures"].values()), 1)
        self.assertIn("fail_open_bypass", (self.root / "audit.jsonl").read_text())

    async def test_unreachable_guardian_blocks_execution(self):
        async with self.adapter.session():
            self.guardian.stop()
            with self.assertRaises(ACSGuardianDenied):
                await self.execute()
        self.assert_no_effect()
        self.assertIn("transport_failure", (self.root / "audit.jsonl").read_text())

    async def test_fail_open_session_start_failure_is_counted(self):
        from acs.client import Config, FailPosture

        self.adapter.config = Config(
            self.guardian.url(), FailPosture(False, 1), True, False
        )
        self.guardian.handlers["steps/sessionStart"] = lambda req: {
            "code": -32603,
            "message": "internal error",
        }
        await self.execute()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(
            self.payloads("steps/sessionEnd")[0]["summary"]["decision_failures"][
                "guardian_error"
            ],
            1,
        )

    async def test_late_allow_never_executes_tool(self):
        import time

        original = self.guardian._default_handshake
        self.guardian.handlers["handshake/hello"] = lambda req: {
            **original(req),
            "timeout_config": {
                "default_ms": 1000,
                "per_method_ms": {"steps/toolCallRequest": 50},
            },
        }

        def late(req):
            time.sleep(0.15)
            return {"decision": "allow"}

        self.guardian.handlers["steps/toolCallRequest"] = late
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        await asyncio.sleep(0.2)
        self.assert_no_effect()
        self.assertEqual(
            self.payloads("steps/sessionEnd")[0]["summary"]["decision_failures"][
                "timeout"
            ],
            1,
        )

    async def test_nested_calls_join_session(self):
        async def parent(args):
            return await self.execute()

        async with self.adapter.session():
            with relay.scope.scope("outer", relay.ScopeType.Agent):
                await relay.tools.execute("parent", {}, parent)
                await self.execute()
        self.assertEqual(len(self.payloads("steps/sessionStart")), 1)
        self.assertEqual(len(self.payloads("steps/toolCallRequest")), 3)
        self.assertEqual(
            len(
                {r["params"]["metadata"]["session_id"] for r in self.guardian.received}
            ),
            1,
        )
        self.assertEqual(
            self.payloads("steps/sessionEnd")[0]["summary"]["step_count"], 3
        )

    async def test_concurrent_calls_are_isolated(self):
        await asyncio.gather(self.execute(), self.execute())
        starts = self.guardian.envelopes_for("steps/sessionStart")
        self.assertEqual(
            len({r["params"]["metadata"]["session_id"] for r in starts}), 2
        )
        self.assertEqual(len(self.calls), 2)

    async def test_caller_cancellation_eventually_closes_session(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def wait(args):
            entered.set()
            await release.wait()
            return relay.ToolExecutionResult("finished")

        task = asyncio.create_task(self.execute(wait))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        for _ in range(100):
            if self.payloads("steps/sessionEnd"):
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.payloads("steps/sessionEnd")[0]["reason"], "cancelled")
        self.assertEqual(len(self.payloads("steps/toolCallResult")), 0)

    async def test_tool_exception_is_not_leaked(self):
        async def broken(args):
            raise ValueError("secret-exception")

        with self.assertRaises(ACSGuardianDenied) as caught:
            await self.execute(broken)
        self.assertNotIn("secret-exception", str(caught.exception))
        self.assertEqual(
            self.payloads("steps/toolCallResult")[0]["exit_status"], "failure"
        )

    async def test_configuration_plugin_installs_and_removes_gate(self):
        relay.intercepts.deregister_tool_execution("acs-test")
        relay.plugin.register("acs_guardian_test", GuardianPlugin())
        self.addCleanup(relay.plugin.deregister, "acs_guardian_test")
        toml = self.root / "plugins.toml"
        toml.write_text(
            'version = 1\n[[components]]\nkind = "acs_guardian_test"\n'
            "[components.config]\nguardian_url = "
            + json.dumps(self.guardian.url())
            + "\n"
        )
        async with relay.plugin.activate({"version": 1}, toml):
            self.answer("steps/toolCallRequest", "deny")
            with self.assertRaises(ACSGuardianDenied):
                await self.execute()
            self.assert_no_effect()
        await self.execute()
        self.assertEqual(len(self.calls), 1)

    async def test_unnegotiated_request_is_not_referenced_by_result(self):
        original = self.guardian._default_handshake
        self.guardian.handlers["handshake/hello"] = lambda req: {
            **original(req),
            "methods_evaluated": [
                "steps/sessionStart",
                "steps/toolCallResult",
                "steps/sessionEnd",
            ],
        }
        await self.execute()
        self.assertFalse(self.payloads("steps/toolCallRequest"))
        self.assertNotIn("request_id_ref", self.payloads("steps/toolCallResult")[0])
        self.assertIn("method_not_evaluated", (self.root / "audit.jsonl").read_text())

    async def test_guardian_refusal_never_fails_open(self):
        from acs.client import Config, FailPosture

        self.adapter.config = Config(
            self.guardian.url(), FailPosture(False, 1), True, False
        )
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "code": -32004,
            "message": "SIGNATURE_INVALID",
        }
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()

    async def test_unsigned_request_decision_never_executes(self):
        def handler(req):
            self.guardian.sign_responses = False
            return {"decision": "allow"}

        self.guardian.handlers["steps/toolCallRequest"] = handler
        with self.assertRaises(ACSGuardianDenied):
            await self.execute()
        self.assert_no_effect()

    async def test_wire_payloads_match_bundled_schemas(self):
        await self.execute()
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource

        resources = []
        for path in core.schemas_dir().rglob("*.json"):
            schema = json.loads(path.read_text())
            resources.append((schema["$id"], Resource.from_contents(schema)))
        registry = Registry().with_resources(resources)
        names = {
            "steps/sessionStart": "session-start",
            "steps/sessionEnd": "session-end",
            "steps/toolCallRequest": "tool-call-request",
            "steps/toolCallResult": "tool-call-result",
        }
        for request in self.guardian.received:
            schema = json.loads(
                (core.schemas_dir() / "request-envelope.json").read_text()
            )
            Draft202012Validator(
                schema,
                registry=registry,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(request)
            if request["method"] in names:
                schema = json.loads(
                    (
                        core.schemas_dir()
                        / "hooks"
                        / f"{names[request['method']]}.json"
                    ).read_text()
                )
                Draft202012Validator(schema, registry=registry).validate(
                    request["params"]["payload"]
                )


class Configuration(unittest.TestCase):
    def test_invalid_options_fail_native_plugin_validation(self):
        relay.plugin.register("acs_invalid_test", GuardianPlugin())
        self.addCleanup(relay.plugin.deregister, "acs_invalid_test")
        for options in ({"timeout_s": -1}, {"default_deny": "false"}, {"typo": True}):
            report = relay.plugin.validate_exact(
                {
                    "version": 1,
                    "components": [{"kind": "acs_invalid_test", "config": options}],
                }
            )
            self.assertTrue(
                any(d["level"] == "error" for d in report["config"]["diagnostics"]),
                report,
            )
