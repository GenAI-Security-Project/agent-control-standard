"""
The drop-in settings.json.example — the file people copy — must itself
cover the Core-minimum hook set, with gate hooks fail-closed.

Emission proves the adapter CAN emit each hook when invoked; this puts
the checked-in EXAMPLE config itself under test.

Assertions read the COMMAND STRING, not a per-hook `env` object:
Claude Code's command-hook fields carry no `env`, so anything placed
there is silently dropped and the hook runs with Claude Code's own
environment.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))
import wire  # noqa: E402


class ExampleConfigCoversCoreFloor(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = json.loads((ADAPTER_DIR / "settings.json.example").read_text())
        self.hooks = self.cfg.get("hooks", {})

    def test_example_wires_full_core_minimum(self) -> None:
        missing = set(wire.ACS_CORE_HOOKS) - set(self.hooks)
        self.assertEqual(missing, set(),
            f"settings.json.example (the copy-paste config) is missing "
            f"Core-minimum hooks {sorted(missing)}; wired: {sorted(self.hooks)}")

    def test_example_gate_hooks_are_fail_closed(self) -> None:
        """Gate hooks in the example must carry ACS_DEFAULT_DENY=1 in the
        command string — the only channel Claude Code passes through. A
        silent fail-open on a gate is a policy hole."""
        for hook in wire.GATE_HOOKS & set(wire.ACS_CORE_HOOKS):
            entries = self.hooks.get(hook, [])
            self.assertTrue(entries, f"gate hook {hook} missing from example")
            entry = entries[0]["hooks"][0]
            self.assertNotIn("env", entry,
                "Claude Code's command-hook fields are command, args, async, "
                "asyncRewake, shell plus the common ones. There is no `env`, so "
                "anything there is dropped and the hook runs with Claude Code's "
                "own environment. Use wire.py's inline VAR=value form.")
            cmd = entry["command"]
            self.assertIn("ACS_DEFAULT_DENY=1", cmd,
                f"gate hook {hook} must set ACS_DEFAULT_DENY=1 in the command "
                f"string, the only channel Claude Code passes through")

    def test_every_hook_carries_required_settings_inline(self) -> None:
        """Every wired hook must carry the deployment settings inline.
        Unset ACS_HMAC_SECRET_FILE means unsigned envelopes, which §10
        makes non-conformant; unset ACS_AUDIT_FILE means audit events
        that land nowhere, which §6.4:158 requires to land somewhere."""
        for hook, entries in self.hooks.items():
            entry = entries[0]["hooks"][0]
            self.assertNotIn("env", entry,
                f"{hook}: per-hook `env` is not a Claude Code field and is "
                f"silently dropped — use the inline VAR=value command form")
            cmd = entry.get("command", "")
            for required in ("ACS_GUARDIAN_URL=", "ACS_HMAC_SECRET_FILE=",
                             "ACS_AUDIT_FILE="):
                self.assertIn(required, cmd,
                    f"{hook} must carry {required} inline. Unset means unsigned "
                    f"envelopes, which §10 makes non-conformant, and audit "
                    f"events that land nowhere, which §6.4:158 requires")

    def test_example_equals_wire_py_output(self) -> None:
        """The checked-in example must BE wire.py's output for the same
        placeholder arguments, so the generator and the artifact cannot
        diverge."""
        expected = {}
        for hook in wire.ACS_CORE_HOOKS:
            cmd = wire.build_command(
                adapter_path=Path("/path/to/acs_adapter.py"),
                guardian_url="http://127.0.0.1:8787/acs",
                secret_file="/path/to/.acs/hmac.key",
                secret_env=None,
                default_deny=(hook in wire.GATE_HOOKS),
                host_allowlist=None,
                python_bin="python3",
                audit_file="/path/to/.acs/audit.log",
            )
            expected[hook] = [wire.build_hook_entry(cmd)]
        self.assertEqual(self.hooks, expected,
            "settings.json.example has drifted from wire.py's output for "
            "the documented placeholder arguments — regenerate it with "
            "wire.build_command/build_hook_entry rather than hand-editing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
