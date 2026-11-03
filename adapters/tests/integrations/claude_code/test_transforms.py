from __future__ import annotations

import sys
import unittest
import uuid as _uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parents[2] / "src" / "acs" / "integrations" / "claude_code"
from acs.integrations.claude_code import adapter as acs_adapter  # noqa: E402


def _event(name: str, **extra) -> dict:
    base = {"session_id": "00000000-0000-0000-0000-000000000001",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/tmp/work", "hook_event_name": name}
    base.update(extra)
    return base


class SubagentSpawnMethodBinding(unittest.TestCase):
    """Envelope validation does not bind method to payload schema, so the spawn remap's binding and lineage are pinned here."""

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
                # With tool_use_id, parent_step_id is the envelope's request_id.
                self.assertEqual(env["params"]["payload"]["parent_step_id"],
                                 env["params"]["request_id"])

    def test_plain_tool_keeps_tool_call_request_method(self) -> None:
        env = acs_adapter.build_request(_event(
            "PreToolUse", tool_name="Bash",
            tool_input={"command": "echo hi"},
            tool_use_id="t-bind-2", permission_mode="default"))
        self.assertEqual(env["method"], "steps/toolCallRequest")

    def test_agent_without_tool_use_id_derives_from_request_id(self) -> None:
        """Without tool_use_id, both ids derive from the envelope's request_id, so id-less spawns do not collide."""
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
        env2 = acs_adapter.build_request(ev)
        self.assertNotEqual(payload["subagent_session_id"],
                            env2["params"]["payload"]["subagent_session_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
