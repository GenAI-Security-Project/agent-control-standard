from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acs.client import _store, load_session_state


class LoadSessionState(unittest.TestCase):
    def test_unusable_state_reads_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(_store, "_SESSION_STATE_DIR", Path(d)):
            path = _store._session_state_path("session", workspace=None)
            for name, content in (("nested past the recursion limit", b"[" * 20000 + b"]" * 20000),
                                  ("not JSON", b"{"), ("not an object", b"[1, 2]"), ("empty", b"")):
                with self.subTest(name):
                    Path(path).write_bytes(content)
                    self.assertEqual(load_session_state("session"), {})


if __name__ == "__main__":
    unittest.main()
