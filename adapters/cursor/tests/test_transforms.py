"""
Special-transform unit tests for the Cursor adapter.

Per-event envelope + payload SCHEMA validation now lives in the emission
suite (tests/test_emission.py), which validates the exact bytes the
production subprocess sends. This file keeps ONLY the adapter-specific
transforms emission does not assert — here, non-UUID conversation_id →
deterministic UUID coercion (Cursor session ids are not UUIDs; the
adapter must coerce so envelopes validate and cross-hook references stay
stable).
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ADAPTER_DIR))
import acs_adapter  # noqa: E402

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}$")


class UuidCoercion(unittest.TestCase):
    NON_UUID_INPUTS = ["conv-default", "test-cc-session", "workspace::42"]

    def test_non_uuid_conversation_id_coerced_to_uuid(self) -> None:
        """A non-UUID conversation_id must surface as a valid UUID in
        metadata.session_id (schema validity of the result is covered by
        emission; here we pin the coercion transform itself)."""
        for non_uuid in self.NON_UUID_INPUTS:
            with self.subTest(input=non_uuid):
                env = acs_adapter.build_request("preToolUse",
                    {"session_id": non_uuid, "tool_name": "Read",
                     "tool_input": {"file_path": "/tmp/x"}})
                sid = env["params"]["metadata"]["session_id"]
                self.assertRegex(sid, UUID_RE,
                    f"non-UUID input {non_uuid!r} produced non-UUID session_id {sid!r}")

    def test_empty_session_id_refused(self) -> None:
        """Empty session_id: the adapter refuses to build an envelope."""
        env = acs_adapter.build_request("preToolUse",
            {"session_id": "", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}})
        self.assertEqual(env, {},
            f"adapter must refuse to build an envelope for empty session_id; got {env}")

    def test_uuid_coercion_is_deterministic(self) -> None:
        """Same non-UUID input → same UUID, so subagentStart and a later
        subagentStop reference the same subagent across hooks."""
        a = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}})
        b = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/y"}})
        self.assertEqual(a["params"]["metadata"]["session_id"],
                         b["params"]["metadata"]["session_id"],
                         "uuid5 coercion must be deterministic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
