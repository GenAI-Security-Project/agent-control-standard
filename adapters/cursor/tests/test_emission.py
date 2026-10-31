"""
Emission conformance — Cursor adapter.

Same contract as the Claude Code emission suite: run the PRODUCTION
adapter as the real subprocess Cursor spawns (`acs_adapter.py <event>`),
capture the exact bytes against a validating CaptureGuardian whose
oracle is the canonical schemas, and assert method-emitted-once +
schema-valid + protocol invariants.
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

# Realistic Cursor conversation id — NOT a UUID, so the captured
# metadata.session_id proves coercion happens on the wire.
SESSION = "conv-cursor-emission-01"


class CursorEmission(unittest.TestCase):
    def _emit(self, event_name: str, event: dict) -> CaptureGuardian:
        g = CaptureGuardian()
        # workspace_roots is Cursor's real common-input field (docs 2026-08-22).
        event = {"session_id": SESSION, "workspace_roots": ["/tmp/work"], **event}
        with g, tempfile.TemporaryDirectory() as cache:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": g.url(),
                "ACS_HMAC_SECRET": g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cache,
                # subagentStart needs a recorded prior step OR falls back
                # to the spawn's own request_id — either way it's honest;
                # isolate session state so runs don't interfere.
                "ACS_SESSION_STATE_DIR": cache,
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            proc = subprocess.run(
                [sys.executable, str(ADAPTER), event_name],
                input=json.dumps(event),
                capture_output=True, text=True, env=env, timeout=20)
        self.assertIn(proc.returncode, (0, 2),
            f"adapter exited {proc.returncode}; stderr:\n{proc.stderr}")
        return g

    def _assert_emits(self, event_name: str, event: dict, method: str,
                      check=None):
        g = self._emit(event_name, event)
        self.assertEqual(len(g.records_for(method)), 1,
            f"expected exactly one {method}; captured {g.methods()}")
        self.assertIn("handshake/hello", g.methods())
        g.assert_all_valid(self)
        if check is not None:
            # CONTENT assertion — schema-valid-but-empty must not pass:
            # every input is Cursor's documented shape (docs.cursor.com,
            # 2026-08-22) and every check asserts the value landed in the
            # ACS payload.
            check(self, g.payload_of(method))
        return g

    def test_session_start(self):
        self._assert_emits(
            "sessionStart",
            {"is_background_agent": False, "composer_mode": "agent"},
            "steps/sessionStart",
            check=lambda t, p: t.assertEqual(
                p.get("platform_context", {}).get("workspace_root"),
                "/tmp/work",
                f"workspace_roots[0] must land in platform_context; got {p!r}"))

    def test_user_message(self):
        self._assert_emits(
            "beforeSubmitPrompt", {"prompt": "hi"}, "steps/userMessage",
            check=lambda t, p: t.assertEqual(
                p["content"][0]["value"], "hi", f"prompt must flow; got {p!r}"))

    def test_tool_call_request(self):
        self._assert_emits(
            "preToolUse",
            {"tool_name": "Bash", "tool_input": {"command": "echo hi"},
             "tool_use_id": "c1", "cwd": "/tmp/work"},
            "steps/toolCallRequest",
            check=lambda t, p: (
                t.assertEqual(p["tool"]["name"], "Bash"),
                t.assertEqual(p["arguments"]["command"]["value"], "echo hi")))

    def test_tool_call_result(self):
        # Real postToolUse: tool_output is a JSON-STRINGIFIED result
        # payload ("not raw terminal text"), duration in ms.
        self._assert_emits(
            "postToolUse",
            {"tool_name": "Shell",
             "tool_input": {"command": "npm test"},
             "tool_output": "{\"exitCode\":0,\"stdout\":\"All tests passed\"}",
             "tool_use_id": "c1", "cwd": "/tmp/work", "duration": 5432},
            "steps/toolCallResult",
            check=lambda t, p: (
                t.assertEqual(p["exit_status"], "success"),
                t.assertEqual(p["duration_ms"], 5432),
                t.assertEqual(p["outputs"][0]["value"].get("stdout"),
                              "All tests passed",
                              f"parsed tool_output must flow; got {p!r}")))

    def test_tool_call_result_nonzero_exitcode_is_failure(self):
        # tool_output's own exitCode is the real failure discriminator.
        self._assert_emits(
            "postToolUse",
            {"tool_name": "Shell", "tool_input": {"command": "false"},
             "tool_output": "{\"exitCode\":1,\"stdout\":\"\"}",
             "tool_use_id": "c2", "duration": 10},
            "steps/toolCallResult",
            check=lambda t, p: t.assertEqual(p["exit_status"], "failure",
                "nonzero exitCode in tool_output must map to failure"))

    def test_agent_response(self):
        # `text` is the real content field (docs 2026-08-22).
        self._assert_emits(
            "afterAgentResponse", {"text": "done"}, "steps/agentResponse",
            check=lambda t, p: t.assertEqual(
                p["content"][0]["value"], "done",
                f"afterAgentResponse.text must flow into content; got {p!r}"))

    def test_session_end(self):
        # Cursor reason `aborted` must map to the ACS enum member `cancelled`.
        self._assert_emits(
            "sessionEnd", {"reason": "aborted", "duration_ms": 45000},
            "steps/sessionEnd",
            check=lambda t, p: t.assertEqual(p["reason"], "cancelled"))

    def test_subagent_start(self):
        # tool_call_id (real per docs) links the spawn to the delegating
        # Task toolCallRequest, whose request_id is uuid5 of the same id.
        import uuid as _uuid
        expected_parent = str(_uuid.uuid5(
            _uuid.NAMESPACE_URL, "cursor:tool_use:tc-789"))
        self._assert_emits(
            "subagentStart",
            {"subagent_id": "sub-1", "subagent_type": "explore",
             "task": "explore auth", "tool_call_id": "tc-789",
             "subagent_model": "claude-sonnet-4-5"},
            "steps/subagentStart",
            check=lambda t, p: (
                t.assertEqual(p["parent_step_id"], expected_parent,
                    "tool_call_id must drive real spawn lineage"),
                t.assertEqual(p["subagent_descriptor"]["model_id"],
                              "claude-sonnet-4-5")))

    # Remaining mapped native events — documented input shapes
    # (docs.cursor.com, 2026-08-22) + content checks.
    EXTRA_NATIVE = [
        ("postToolUseFailure",
         {"tool_name": "Shell", "tool_input": {"command": "npm test"},
          "tool_use_id": "f1", "cwd": "/tmp/work",
          "error_message": "Command timed out after 30s",
          "failure_type": "timeout", "duration": 30000, "is_interrupt": False},
         "steps/toolCallResult",
         lambda t, p: (
             t.assertEqual(p["exit_status"], "timeout",
                 "failure_type=timeout must map to exit_status timeout"),
             t.assertIn("timed out", p["outputs"][0]["value"],
                 "error_message must flow into outputs"))),
        ("beforeShellExecution",
         {"command": "ls -la", "cwd": "/tmp/work", "sandbox": False},
         "steps/toolCallRequest",
         lambda t, p: t.assertEqual(
             p["arguments"]["command"]["value"], "ls -la")),
        ("afterShellExecution",
         {"command": "ls -la", "output": "total 0", "duration": 1234,
          "sandbox": False},
         "steps/toolCallResult",
         lambda t, p: (
             t.assertEqual(p["outputs"][0]["value"], "total 0",
                 "shell output must flow into outputs"),
             t.assertEqual(p["duration_ms"], 1234))),
        ("beforeMCPExecution",
         {"tool_name": "list_issues",
          "tool_input": "{\"team\": \"ACS\"}",   # JSON STRING per docs
          "url": "https://mcp.linear.app/sse"},
         "steps/toolCallRequest",
         lambda t, p: (
             t.assertEqual(p["tool"]["name"], "list_issues",
                 f"real tool_name must land (not ':'); got {p['tool']!r}"),
             t.assertEqual(p["arguments"]["team"]["value"], "ACS",
                 "stringified tool_input must be parsed into arguments"))),
        ("afterMCPExecution",
         {"tool_name": "list_issues",
          "tool_input": "{\"team\": \"ACS\"}",
          "result_json": "[{\"id\": \"ACS-1\"}]", "duration": 88},
         "steps/toolCallResult",
         lambda t, p: t.assertEqual(
             p["outputs"][0]["value"], {"id": "ACS-1"},
             f"result_json must be parsed into outputs; got {p!r}")),
        ("afterFileEdit",
         {"file_path": "/tmp/x.py",
          "edits": [{"old_string": "a", "new_string": "b"}]},
         "steps/toolCallResult",
         lambda t, p: t.assertEqual(
             p["outputs"][0]["value"]["edits"][0]["new_string"], "b",
             "edits must flow so the Guardian sees WHAT changed")),
        ("afterTabFileEdit",
         {"file_path": "/tmp/x.py",
          "edits": [{"old_string": "a", "new_string": "b"}]},
         "steps/toolCallResult", None),
        ("afterAgentThought",
         {"text": "thinking", "duration_ms": 5000},
         "steps/agentResponse",
         lambda t, p: t.assertEqual(p["content"][0]["value"], "thinking")),
    ]

    def test_extra_native_events_emit_valid(self):
        for event_name, body, method, check in self.EXTRA_NATIVE:
            with self.subTest(event=event_name):
                self._assert_emits(event_name, body, method, check=check)

    def test_bare_stop_with_no_open_turn_emits_nothing(self):
        # steps/turnEnd needs an open turn; with none, the adapter emits
        # nothing and audits it (full lifecycle: CursorSequentialSession).
        g = self._emit("stop", {"status": "completed"})
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"a stop with no open turn must emit no step; got {content}")

    def test_unknown_event_emits_no_core_hook(self):
        g = self._emit("someRenamedUpstreamHook", {})
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"an unmapped event produced Core hook traffic: {content}")

    def test_non_uuid_session_coerced_on_the_wire(self):
        """SESSION is a realistic non-UUID Cursor id; the captured
        envelope's metadata.session_id MUST be a coerced UUID (not the
        raw string) — proving coercion on the PRODUCTION path, not just
        in the direct transform unit tests."""
        import uuid
        g = self._emit("preToolUse", {"tool_name": "Read",
                                      "tool_input": {"file_path": "/tmp/x"}})
        wire_sid = (g.only("steps/toolCallRequest").parsed["params"]
                    ["metadata"]["session_id"])
        self.assertNotEqual(wire_sid, SESSION,
            "raw non-UUID session id leaked onto the wire uncoerced")
        uuid.UUID(wire_sid)  # raises if not a valid UUID
        g.assert_all_valid(self)


class CursorSequentialSession(unittest.TestCase):
    """One Guardian + one handshake cache + one session-state dir across
    an ordered sequence. Proves handshake-once, unique request_ids,
    request_id_ref linkage, and advertised ⊆ emitted. The shared session
    state also lets preCompact emit a valid entries_to_compact (it needs
    a prior recorded step)."""

    # (event_name, event_body) in order — documented Cursor shapes
    # (docs 2026-08-22): tool_use_id on pre/postToolUse, JSON-stringified
    # tool_output, `text` on afterAgentResponse.
    SEQUENCE = [
        ("sessionStart", {"is_background_agent": False}),
        ("beforeSubmitPrompt", {"prompt": "do a thing"}),
        ("preToolUse", {"tool_name": "Bash", "tool_input": {"command": "echo hi"},
                        "tool_use_id": "c1", "cwd": "/tmp/work"}),
        ("postToolUse", {"tool_name": "Bash",
                         "tool_input": {"command": "echo hi"},
                         "tool_output": "{\"exitCode\":0,\"stdout\":\"hi\"}",
                         "tool_use_id": "c1", "cwd": "/tmp/work",
                         "duration": 12}),
        ("afterAgentResponse", {"text": "done"}),
        ("preCompact", {"trigger": "auto"}),
        ("subagentStart", {"subagent_id": "sub-1", "subagent_type": "explore",
                           "task": "explore", "tool_call_id": "c1"}),
        # `stop` closes the turn opened by beforeSubmitPrompt;
        # sessionEnd then closes the session.
        ("stop", {"status": "completed", "loop_count": 0}),
        ("sessionEnd", {"reason": "completed", "duration_ms": 45000}),
    ]
    SESSION = "conv-cursor-sequential-01"  # non-UUID: exercises coercion across the stateful sequence too

    @classmethod
    def setUpClass(cls):
        cls.g = CaptureGuardian()
        cls.g.start()
        cls._cache = tempfile.mkdtemp()
        for name, body in cls.SEQUENCE:
            event = {"session_id": cls.SESSION,
                     "workspace_roots": ["/tmp/work"], **body}
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": cls.g.url(),
                "ACS_HMAC_SECRET": cls.g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cls._cache,      # SHARED → handshake once
                "ACS_SESSION_STATE_DIR": cls._cache,    # SHARED → preCompact entries populate
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            subprocess.run([sys.executable, str(ADAPTER), name],
                           input=json.dumps(event), capture_output=True,
                           text=True, env=env, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.g.stop()

    def test_all_captures_valid(self):
        self.g.assert_all_valid(self)

    def test_precompact_emitted_with_valid_entries(self):
        recs = self.g.records_for("steps/preCompact")
        self.assertEqual(len(recs), 1,
            f"preCompact should have emitted once; got {self.g.methods()}")
        entries = (recs[0].parsed.get("params") or {}).get("payload", {}).get("entries_to_compact")
        self.assertTrue(entries,
            "preCompact entries_to_compact must be non-empty (shared session "
            "state should carry the prior step_ids)")

    def test_handshake_exactly_once(self):
        self.assertEqual(len(self.g.records_for("handshake/hello")), 1,
            f"handshake must fire once per session: {self.g.methods()}")

    def test_request_ids_unique(self):
        self.assertEqual(self.g.duplicate_request_ids(), [],
            "request_id MUST be unique per session")

    def test_tool_result_references_its_request(self):
        req_id = self.g.request_id_for("steps/toolCallRequest")
        ref = self.g.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id,
            f"toolCallResult.request_id_ref must link to its request "
            f"({ref!r} != {req_id!r})")

    def test_handshake_advertises_only_demonstrably_emitted_methods(self):
        advertised = set(self.g.handshake_methods_implemented())
        emitted = {m for m in self.g.methods() if m != "handshake/hello"}
        # Both directions: subset alone would miss under-advertising.
        self.assertEqual(advertised, emitted,
            f"advertised != emitted; over-advertised={sorted(advertised - emitted)}, "
            f"under-advertised={sorted(emitted - advertised)}")

    def test_turn_lifecycle_is_consistent(self):
        """A turn opens with steps/turnStart (on beforeSubmitPrompt) and
        closes with steps/turnEnd (on stop); every in-turn step carries
        the same metadata.turn_id."""
        starts = self.g.records_for("steps/turnStart")
        ends = self.g.records_for("steps/turnEnd")
        self.assertEqual(len(starts), 1, f"one turnStart expected; {self.g.methods()}")
        self.assertEqual(len(ends), 1, f"one turnEnd expected; {self.g.methods()}")
        tid = self.g.payload_of("steps/turnStart").get("turn_id")
        self.assertTrue(tid, "turnStart must carry a turn_id")
        self.assertEqual(self.g.payload_of("steps/turnEnd").get("turn_id"), tid,
            "turnEnd.turn_id must equal the turnStart's")
        for method in ("steps/userMessage", "steps/toolCallRequest"):
            meta = (self.g.records_for(method)[0].parsed.get("params") or {}).get("metadata") or {}
            self.assertEqual(meta.get("turn_id"), tid,
                f"{method} must carry metadata.turn_id={tid!r}; got {meta.get('turn_id')!r}")
        for method in ("steps/sessionStart", "steps/sessionEnd"):
            meta = (self.g.records_for(method)[0].parsed.get("params") or {}).get("metadata") or {}
            self.assertIsNone(meta.get("turn_id"),
                f"{method} is session-level and must not carry a turn_id")


if __name__ == "__main__":
    unittest.main(verbosity=2)
