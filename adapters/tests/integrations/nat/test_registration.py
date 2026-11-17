"""NAT's own plugin discovery registers `_type: acs_guardian` from the installed package."""
from __future__ import annotations

import subprocess
import sys
import unittest

try:
    import nat.runtime.loader  # noqa: F401
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

# A fresh interpreter, because discovery fills NAT's process-wide registry.
DISCOVER = """
from nat.runtime.loader import PluginTypes, discover_and_register_plugins
from nat.cli.type_registry import GlobalTypeRegistry
discover_and_register_plugins(PluginTypes.COMPONENT)
print(sorted(r.local_name for r in GlobalTypeRegistry.get().get_registered_middleware()))
"""


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core is not installed")
class NatPluginDiscovery(unittest.TestCase):
    def test_discovery_registers_acs_guardian(self) -> None:
        p = subprocess.run([sys.executable, "-c", DISCOVER], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertIn("'acs_guardian'", p.stdout.strip().splitlines()[-1])

    def test_acs_nat_wire_loads_with_the_nat_extra(self) -> None:
        from importlib.metadata import entry_points
        self.assertTrue(callable(entry_points(group="console_scripts")["acs-nat-wire"].load()))


if __name__ == "__main__":
    unittest.main()
