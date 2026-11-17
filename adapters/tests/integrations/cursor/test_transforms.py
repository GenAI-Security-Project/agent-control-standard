from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).resolve().parents[3] / "src" / "acs" / "integrations" / "cursor"
from acs.integrations.cursor import adapter as acs_adapter  # noqa: E402

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}$")


class UuidCoercion(unittest.TestCase):
    NON_UUID_INPUTS = ["conv-default", "test-cc-session", "workspace::42"]

    def test_non_uuid_conversation_id_coerced_to_uuid(self) -> None:
        for non_uuid in self.NON_UUID_INPUTS:
            with self.subTest(input=non_uuid):
                env = acs_adapter.build_request("preToolUse",
                    {"session_id": non_uuid, "tool_name": "Read",
                     "tool_input": {"file_path": "/tmp/x"}})
                sid = env["params"]["metadata"]["session_id"]
                self.assertRegex(sid, UUID_RE,
                    f"non-UUID input {non_uuid!r} produced non-UUID session_id {sid!r}")

    def test_empty_session_id_refused(self) -> None:
        env = acs_adapter.build_request("preToolUse",
            {"session_id": "", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}})
        self.assertEqual(env, {},
            f"adapter must refuse to build an envelope for empty session_id; got {env}")

    def test_uuid_coercion_is_deterministic(self) -> None:
        """The same input gives the same UUID, so the hooks of one conversation reference one session."""
        a = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}})
        b = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/y"}})
        self.assertEqual(a["params"]["metadata"]["session_id"],
                         b["params"]["metadata"]["session_id"],
                         "uuid5 coercion must be deterministic")


class JsonFieldParsing(unittest.TestCase):
    """Cursor's stringified MCP payloads come from the agent; an uncaught parse error exits 1, which Cursor proceeds on."""

    def test_unparseable_strings_pass_through(self) -> None:
        for name, raw in (("nested past the recursion limit", "[" * 20000 + "]" * 20000),
                          ("not JSON", "{"), ("plain text", "hello")):
            with self.subTest(name):
                self.assertEqual(acs_adapter._parse_json_field(raw), raw)
        self.assertEqual(acs_adapter._parse_json_field('{"a": 1}'), {"a": 1})


if __name__ == "__main__":
    unittest.main(verbosity=2)
