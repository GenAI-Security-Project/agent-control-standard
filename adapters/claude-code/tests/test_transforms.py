"""
Special-transform unit tests for the Claude Code adapter.

Per-event envelope + payload SCHEMA validation lives in the emission
suite (tests/test_emission.py), which validates the exact bytes the
production subprocess sends against the canonical schemas — a strictly
stronger check than validating build_request() output directly. This
file keeps ONLY the assertions emission does not make: adapter-specific
transforms whose correctness is not captured by "the envelope is
schema-valid".

Here: the PreToolUse(Agent) → steps/subagentStart remap and its subagent
lineage derivation. The spawn tool is `Agent` on current Claude Code
(legacy `Task` still matched); both names are exercised so the gate
cannot go dead on a rename. UUID coercion / argument extraction /
timestamp / metadata / argument-wrapping are asserted as emission
invariants on every captured envelope.
"""
from __future__ import annotations

import sys
import unittest
import uuid as _uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))
import acs_adapter  # noqa: E402


def _event(name: str, **extra) -> dict:
    base = {"session_id": "00000000-0000-0000-0000-000000000001",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/tmp/work", "hook_event_name": name}
    base.update(extra)
    return base


class SubagentSpawnMethodBinding(unittest.TestCase):
    """Envelope validation does not bind method to payload schema, so a
    method/payload mismatch on the spawn remap would pass schema checks.
    These pin the binding + lineage explicitly, for BOTH the current
    `Agent` tool name and the legacy `Task` name."""

    def test_agent_and_task_remap_to_subagent_start_method(self) -> None:
        # Agent = current Claude Code (docs 2026-08-22); Task = legacy.
        for tool in ("Agent", "Task"):
            with self.subTest(tool=tool):
                env = acs_adapter.build_request(_event(
                    "PreToolUse", tool_name=tool,
                    tool_input={"subagent_type": "researcher", "prompt": "x"},
                    tool_use_id=f"spawn-bind-{tool}", permission_mode="default"))
                self.assertEqual(env["method"], "steps/subagentStart",
                    f"PreToolUse({tool}) must emit the subagentStart method, "
                    f"not a generic toolCallRequest")
                # With tool_use_id: parent_step_id IS the envelope's
                # request_id (delegation step and spawn event are the same
                # wire step).
                self.assertEqual(env["params"]["payload"]["parent_step_id"],
                                 env["params"]["request_id"])

    def test_plain_tool_keeps_tool_call_request_method(self) -> None:
        env = acs_adapter.build_request(_event(
            "PreToolUse", tool_name="Bash",
            tool_input={"command": "echo hi"},
            tool_use_id="t-bind-2", permission_mode="default"))
        self.assertEqual(env["method"], "steps/toolCallRequest")

    def test_agent_without_tool_use_id_derives_from_request_id(self) -> None:
        """No tool_use_id: both ids derive from the envelope's own
        request_id — never a random uuid4 nor a uuid5 of the empty
        string (which would collide every id-less spawn on one id)."""
        ev = _event("PreToolUse", tool_name="Agent",
                    tool_input={"prompt": "x"}, permission_mode="default")
        ev.pop("tool_use_id", None)
        env = acs_adapter.build_request(ev)
        payload = env["params"]["payload"]
        rid = env["params"]["request_id"]
        self.assertEqual(payload["parent_step_id"], rid)
        self.assertEqual(
            payload["subagent_session_id"],
            str(_uuid.uuid5(_uuid.NAMESPACE_URL,
                            f"claude-code:subagent:{rid}")))
        # Two id-less spawns must NOT collide on subagent_session_id.
        env2 = acs_adapter.build_request(ev)
        self.assertNotEqual(payload["subagent_session_id"],
                            env2["params"]["payload"]["subagent_session_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
