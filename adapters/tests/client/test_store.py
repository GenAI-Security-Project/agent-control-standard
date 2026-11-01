from __future__ import annotations

import os
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


class ConcurrentUpdates(unittest.TestCase):
    """Hook processes of one session run at once (parallel tool calls); no update may be lost or torn."""

    WORKERS = 8

    def _run(self, body: str) -> list[str]:
        import subprocess
        import sys
        import textwrap
        import time
        go = self.state / "go"
        script = textwrap.dedent(f"""
            import os, sys, time
            from acs.client import _store
            while not os.path.exists({str(go)!r}):
                time.sleep(0.001)
            worker = int(sys.argv[1])
        """) + textwrap.dedent(body)
        env = {**os.environ, "ACS_SESSION_STATE_DIR": str(self.state)}
        procs = [subprocess.Popen([sys.executable, "-c", script, str(i)], env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) for i in range(self.WORKERS)]
        time.sleep(0.5)
        go.write_text("")
        out = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 0, stderr)
            out += stdout.split()
        return out

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)

    def _final(self) -> dict:
        with mock.patch.object(_store, "_SESSION_STATE_DIR", self.state):
            return load_session_state("session")

    def test_every_parallel_step_and_the_open_turn_are_kept(self) -> None:
        self._run("""
            for i in range(25):
                _store.record_step("session", f"step-{worker}-{i}")
            if worker == 0:
                _store.open_turn("session", "turn-0")
        """)
        final = self._final()
        self.assertEqual(len(set(final["seen_step_ids"])), self.WORKERS * 25, "a parallel update was lost")
        self.assertEqual(final.get("turn_id"), "turn-0")
        self.assertEqual(sorted(p.name for p in self.state.glob("*.tmp")), [], "no temp file may be left behind")

    def test_mark_once_is_first_exactly_once(self) -> None:
        results = self._run("""
            print(_store.mark_once("session", "flag"))
        """)
        self.assertEqual(sorted(results), ["False"] * (self.WORKERS - 1) + ["True"])

    def test_writers_never_share_a_temp_file(self) -> None:
        with mock.patch.object(_store, "_SESSION_STATE_DIR", self.state):
            path = _store._session_state_path("session")
            shared = path.with_suffix(".json.tmp")
            shared.write_text("not the state")
            _store.record_step("session", "step")
        self.assertEqual(shared.read_text(), "not the state", "the old fixed temp path must not be reused")
        self.assertEqual(self._final()["seen_step_ids"], ["step"])


class McpUse(unittest.TestCase):
    def _record(self, env: dict, session: str = "session", tool: str = "mcp__srv__tool") -> list:
        from acs.client import _profiles
        with tempfile.TemporaryDirectory() as d, mock.patch.object(_store, "_SESSION_STATE_DIR", Path(d)), \
                mock.patch.dict(os.environ, env), mock.patch.object(_profiles, "audit_event") as audit:
            _profiles.record_mcp_use(session, tool=tool)
            _profiles.record_mcp_use(session, tool=tool)
        return audit.call_args_list

    def test_a_signed_session_records_its_degraded_claim_once(self) -> None:
        calls = self._record({"ACS_HMAC_SECRET": "s", "ACS_HMAC_KEY_ID": "test-key", "ACS_HMAC_SECRET_FILE": "", "ACS_HMAC_KEY_ID": "test-key"})
        self.assertEqual([c.args[0] for c in calls], ["profile_claim_degraded"])
        self.assertEqual((calls[0].kwargs["profile"], calls[0].kwargs["tool"]), ("acs-core", "mcp__srv__tool"))

    def test_an_unsigned_session_claims_nothing_to_degrade(self) -> None:
        self.assertEqual(self._record({"ACS_HMAC_SECRET": "", "ACS_HMAC_KEY_ID": "test-key", "ACS_HMAC_SECRET_FILE": "", "ACS_HMAC_KEY_ID": "test-key"}), [])
