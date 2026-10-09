"""
Emission conformance — Claude Code adapter.

Proves the PRODUCTION adapter (acs_adapter.py, run as the real
subprocess Claude Code spawns) emits ACS-Core traffic that passes the
CANONICAL schemas. Unlike test_envelope_schema.py — which calls
build_request() directly — this captures the exact bytes the subprocess
sends over HTTP to a validating CaptureGuardian whose oracle is the
schema files.

Every case asserts BOTH:
  - the expected ACS method was emitted exactly once, and
  - every captured envelope + payload passes its canonical schema and
    the protocol invariants (signature, UUIDs, RFC3339, metadata,
    argument wrapping).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "acs_adapter.py"
COMMON = HERE.parent.parent / "_common"
sys.path.insert(0, str(COMMON))

from capture_guardian import CaptureGuardian  # noqa: E402

SESSION = "11111111-1111-4111-8111-111111111111"


def _event(name: str, **extra) -> dict:
    base = {"session_id": SESSION, "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp/work", "hook_event_name": name}
    base.update(extra)
    return base


class ClaudeEmission(unittest.TestCase):
    def _emit(self, event: dict) -> CaptureGuardian:
        """Run the real adapter subprocess against a CaptureGuardian and
        return the guardian holding the captured, validated traffic."""
        g = CaptureGuardian()
        with g, tempfile.TemporaryDirectory() as cache:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": g.url(),
                "ACS_HMAC_SECRET": g.hmac_secret,
                "ACS_HANDSHAKE": "1",           # capture the handshake too
                "ACS_HANDSHAKE_CACHE": cache,   # fresh → handshake fires
                # Fresh, isolated turn/session state per one-shot emit so a
                # turn opened by one test can't leak into another (all
                # cases reuse one SESSION id).
                "ACS_SESSION_STATE_DIR": cache,
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            proc = subprocess.run(
                [sys.executable, str(ADAPTER)],
                input=json.dumps(event),
                capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(proc.returncode, 0,
            f"adapter exited {proc.returncode}; stderr:\n{proc.stderr}")
        return g

    def _assert_emits(self, event: dict, method: str) -> CaptureGuardian:
        g = self._emit(event)
        # handshake is always first, then the event method — exactly once.
        self.assertEqual(g.records_for(method) and len(g.records_for(method)), 1,
            f"expected exactly one {method}; captured {g.methods()}")
        self.assertIn("handshake/hello", g.methods(),
            "adapter must handshake before the first content event")
        g.assert_all_valid(self)  # schema + invariants oracle
        return g

    # ----- Core matrix -----
    def test_session_start(self):
        self._assert_emits(_event("SessionStart", source="startup",
                                  model="claude-opus-4-7"), "steps/sessionStart")

    def test_user_message(self):
        self._assert_emits(_event("UserPromptSubmit", prompt="hi"),
                           "steps/userMessage")

    def test_tool_call_request(self):
        self._assert_emits(_event("PreToolUse", tool_name="Bash",
                                  tool_input={"command": "echo hi"},
                                  tool_use_id="t1", permission_mode="default"),
                           "steps/toolCallRequest")

    def test_tool_call_result(self):
        self._assert_emits(_event("PostToolUse", tool_name="Bash",
                                  tool_input={"command": "echo hi"},
                                  tool_response={"stdout": "hi", "interrupted": False},
                                  tool_use_id="t1", duration_ms=12), "steps/toolCallResult")

    def test_agent_response(self):
        self._assert_emits(_event("Notification", message="done",
                                  notification_type="permission_prompt"),
                           "steps/agentResponse")

    def test_session_end(self):
        self._assert_emits(_event("SessionEnd", reason="clear"),
                           "steps/sessionEnd")

    def test_bare_stop_with_no_open_turn_emits_nothing(self):
        # steps/turnEnd needs an open turn; with none, the adapter audits
        # and emits nothing (full lifecycle: ClaudeSequentialSession).
        g = self._emit(_event("Stop", permission_mode="default"))
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"a Stop with no open turn must emit no step; got {content}")

    def test_subagent_start_via_agent_tool(self):
        # The spawn tool is `Agent` (docs 2026-08-22), legacy `Task`;
        # both must emit steps/subagentStart.
        for tool in ("Agent", "Task"):
            with self.subTest(tool=tool):
                self._assert_emits(_event("PreToolUse", tool_name=tool,
                                          tool_input={"subagent_type": "researcher",
                                                      "prompt": "look it up"},
                                          tool_use_id=f"spawn-{tool}",
                                          permission_mode="default"),
                                   "steps/subagentStart")

    def test_subagent_stop_not_forwarded(self):
        # steps/subagentStop requires final_chain_hash and Claude Code
        # has no chain to hash, so the event is KNOWN_UNMAPPED.
        g = self._emit(_event("SubagentStop",
                              transcript_path="/tmp/sub.jsonl",
                              stop_hook_active=False))
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"SubagentStop is unmapped and must emit no step; got {content}")

    # (Handshake advertised-vs-emitted containment is proved in
    #  ClaudeSequentialSession.)

    # ----- unmapped events must not masquerade as Core hooks -----
    def test_unknown_event_emits_nothing(self):
        g = self._emit(_event("SomeRenamedUpstreamHook"))
        # Only the (optional) handshake may appear; NO steps/* content hook.
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"an unmapped event produced Core hook traffic: {content}")


class ClaudeSequentialSession(unittest.TestCase):
    """Session-level invariants over ONE Guardian + ONE handshake cache:
    handshake fires exactly once, request_ids are unique,
    toolCallResult.request_id_ref links to its toolCallRequest, and the
    handshake advertises only methods demonstrably emitted in this run."""

    SEQUENCE = [
        _event("SessionStart", source="startup"),
        _event("UserPromptSubmit", prompt="do a thing"),
        _event("PreToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
               tool_use_id="tc-1", permission_mode="default"),
        _event("PostToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
               tool_response={"stdout": "hi", "interrupted": False},
               tool_use_id="tc-1", duration_ms=5),
        _event("Notification", message="fyi"),
        _event("PreToolUse", tool_name="Agent",
               tool_input={"subagent_type": "researcher", "prompt": "x"},
               tool_use_id="spawn-1", permission_mode="default"),
        # SubagentStop stays in the sequence as a realistic event but is
        # KNOWN_UNMAPPED (emits nothing) — see test_subagent_stop_not_forwarded.
        _event("SubagentStop", transcript_path="/tmp/sub.jsonl"),
        # Stop closes the turn opened by the UserPromptSubmit above →
        # steps/turnEnd (turn-tracking); SessionEnd then closes the session.
        _event("Stop", permission_mode="default"),
        _event("SessionEnd", reason="clear"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.g = CaptureGuardian()
        cls.g.start()
        cls._cache = tempfile.mkdtemp()
        cls._state = tempfile.mkdtemp()
        for event in cls.SEQUENCE:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": cls.g.url(),
                "ACS_HMAC_SECRET": cls.g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cls._cache,  # SHARED → handshake once
                "ACS_SESSION_STATE_DIR": cls._state,  # SHARED → turn_id persists
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            subprocess.run([sys.executable, str(ADAPTER)],
                           input=json.dumps(event), capture_output=True,
                           text=True, env=env, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.g.stop()

    def test_handshake_exactly_once(self):
        n = len(self.g.records_for("handshake/hello"))
        self.assertEqual(n, 1,
            f"handshake must fire once per session, not {n} times "
            f"(cache sharing broken?): {self.g.methods()}")

    def test_request_ids_unique(self):
        dupes = self.g.duplicate_request_ids()
        self.assertEqual(dupes, [],
            f"request_id MUST be unique per session; duplicates: {dupes}")

    def test_tool_result_references_its_request(self):
        req_id = self.g.request_id_for("steps/toolCallRequest")
        ref = self.g.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id,
            "toolCallResult.request_id_ref must link back to the "
            f"toolCallRequest's request_id ({ref!r} != {req_id!r})")

    def test_handshake_advertises_only_demonstrably_emitted_methods(self):
        """Advertised methods_implemented must EQUAL the set actually
        emitted in this session — equality catches both over-advertising
        (a declared method never demonstrated) and under-advertising
        (an emitted method never declared)."""
        advertised = set(self.g.handshake_methods_implemented())
        emitted = {m for m in self.g.methods() if m != "handshake/hello"}
        self.assertEqual(advertised, emitted,
            f"advertised != emitted; over-advertised={sorted(advertised - emitted)}, "
            f"under-advertised={sorted(emitted - advertised)}")

    def test_turn_lifecycle_is_consistent(self):
        """A turn opens with steps/turnStart (on the prompt) and closes with
        steps/turnEnd (on Stop), and every in-turn step carries the same
        metadata.turn_id (turn-start/turn-end.json, request-envelope.json:69)."""
        starts = self.g.records_for("steps/turnStart")
        ends = self.g.records_for("steps/turnEnd")
        self.assertEqual(len(starts), 1, f"one turnStart expected; {self.g.methods()}")
        self.assertEqual(len(ends), 1, f"one turnEnd expected; {self.g.methods()}")
        tid = self.g.payload_of("steps/turnStart").get("turn_id")
        self.assertTrue(tid, "turnStart must carry a turn_id")
        self.assertEqual(self.g.payload_of("steps/turnEnd").get("turn_id"), tid,
            "turnEnd.turn_id must equal the turnStart's")
        # userMessage and toolCallRequest (in-turn) must stamp metadata.turn_id.
        for method in ("steps/userMessage", "steps/toolCallRequest"):
            meta = (self.g.records_for(method)[0].parsed.get("params") or {}).get("metadata") or {}
            self.assertEqual(meta.get("turn_id"), tid,
                f"{method} must carry metadata.turn_id={tid!r}; got {meta.get('turn_id')!r}")
        # sessionStart / sessionEnd are session-level — NOT under the turn.
        for method in ("steps/sessionStart", "steps/sessionEnd"):
            meta = (self.g.records_for(method)[0].parsed.get("params") or {}).get("metadata") or {}
            self.assertIsNone(meta.get("turn_id"),
                f"{method} is session-level and must not carry a turn_id")


if __name__ == "__main__":
    unittest.main(verbosity=2)
