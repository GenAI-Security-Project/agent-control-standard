from __future__ import annotations

import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from acs import client  # noqa: E402
from acs import core  # noqa: E402
from acs.client import _exchange
from acs.client import _handshake as client_handshake  # noqa: E402
from acs.client import _store as client_store  # noqa: E402

from acs.testing.harness import launch_guardian, sign_for_test, signing_env  # noqa: E402

HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "src" / "acs" / "guardian" / "example_guardian.py"


class Item01_JcsConsistency(unittest.TestCase):
    """RFC 8785 is a hard dependency; its output is pinned on the shapes where a sorted json.dumps diverges."""

    # duration_ms comes from the framework and is signed, so each shape reaches the wire.
    DIVERGENT = [
        ({"duration_ms": 1.0},   b'{"duration_ms":1}'),
        ({"duration_ms": -0.0},  b'{"duration_ms":0}'),
        ({"duration_ms": 1e16},  b'{"duration_ms":10000000000000000}'),
        ({"duration_ms": 0.5},   b'{"duration_ms":0.5}'),
    ]

    def test_rfc8785_canonical_output_on_divergent_shapes(self) -> None:
        from acs import core
        for sample, expected in self.DIVERGENT:
            with self.subTest(sample=sample):
                self.assertEqual(core.jcs_canonicalize(sample), expected)

    def test_non_bmp_key_ordering_matches_utf16_rule(self) -> None:
        """RFC 8785 §3.2.3 sorts keys by UTF-16 code units, so a non-BMP key sorts before U+FFFF; json.dumps gets this backwards."""
        from acs import core
        sample = {"￿": 1, "\U00010000": 2}
        out = core.jcs_canonicalize(sample).decode("utf-8")
        self.assertLess(out.index("\U00010000"), out.index("￿"),
            f"UTF-16 ordering violated in {out!r}")


class Item02_GuardianRegexInputCap(unittest.TestCase):
    """The Guardian's destructive-bash scan is capped like scan_destructive_bash_safely."""

    @classmethod
    def setUpClass(cls) -> None:
        env = os.environ.copy()
        env.update(signing_env())
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.statedir = tempfile.mkdtemp(prefix="acs-guardian-state-")
        env["ACS_GUARDIAN_STATE_DIR"] = cls.statedir
        cls.proc, cls.port = launch_guardian(env=env)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        try: cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired: cls.proc.kill()
        import shutil
        shutil.rmtree(cls.statedir, ignore_errors=True)

    def test_huge_bash_command_is_capped_not_scanned(self) -> None:
        # 500 KiB, which an uncapped scan would backtrack over.
        huge = "a " * (250 * 1024)
        body = json.dumps(sign_for_test({
            "jsonrpc": "2.0", "id": "ed1",
            "method": "steps/toolCallRequest",
            "params": {
                "acs_version": "0.1.0",
                "request_id": str(uuid.uuid4()),
                "timestamp": core.iso8601_now(),
                "metadata": {"agent_id": "t", "session_id": str(uuid.uuid4())},
                "payload": {"tool": {"name": "Bash"},
                            "arguments": {"command": {"value": huge}}},
            },
        })).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            elapsed = time.monotonic() - start
            data = json.loads(resp.read().decode())
        self.assertLess(elapsed, 1.0,
            f"Guardian took {elapsed:.2f}s to handle a 500 KiB command — "
            f"regex DoS gap not closed server-side")
        # An uncapped scan would allow it, since the input matches no destructive pattern.
        result = data.get("result", {})
        self.assertEqual(result.get("decision"), "deny",
            f"Guardian must deny oversized bash command (cannot safely scan); "
            f"got decision={result.get('decision')!r}, full={data}")


class Item04_ReplaySetTtlEviction(unittest.TestCase):
    def test_eviction_drops_entries_older_than_2x_skew_window(self) -> None:
        from acs.guardian import example_guardian
        sid = f"ttl-test-{uuid.uuid4()}"
        with tempfile.TemporaryDirectory() as tmp:
            example_guardian.STATE_DIR = Path(tmp)
            example_guardian.PERSIST_ENABLED = True
            st = example_guardian.SessionState(session_id=sid)
            old_ts = time.time() - (example_guardian.SKEW_WINDOW_MS / 1000) * 3
            recent_ts = time.time()
            with st.lock:
                st.seen_request_ids = {} if isinstance(st.seen_request_ids, dict) else st.seen_request_ids
                self.assertIsInstance(st.seen_request_ids, dict,
                    "FIX REQUIRED: seen_request_ids must become a dict "
                    "(request_id -> timestamp_seconds) so TTL eviction "
                    "can drop entries older than 2 × skew_window.")
                st.seen_request_ids["old-rid"] = old_ts
                st.seen_request_ids["new-rid"] = recent_ts
                example_guardian.evict_old_request_ids(st)
                self.assertNotIn("old-rid", st.seen_request_ids,
                    "old request_id not evicted")
                self.assertIn("new-rid", st.seen_request_ids,
                    "recent request_id wrongly evicted")


class Item05_SessionDecisionLifetime(unittest.TestCase):
    """§4.1 defers renegotiation to v0.2: a Guardian config change reaches
    the next session, and a running session keeps the decision its
    handshake made however old the stored record is."""

    def test_a_config_change_reaches_the_next_session_only(self) -> None:
        hello = {"negotiated_version": "0.1.0", "methods_evaluated": [], "selected_transport": "http",
                 "timeout_config": {"default_ms": 5000}}
        hellos = iter([{**hello, "on_decision_failure": "deny"}, {**hello, "on_decision_failure": "proceed"}])

        def respond(request, timeout=None):
            incoming = json.loads(request.data)
            answer = {"jsonrpc": "2.0", "id": incoming["id"], "result": next(hellos)}
            client.sign_envelope(answer, session_id=incoming["params"]["metadata"]["session_id"])
            return io.BytesIO(json.dumps(answer).encode())

        env = {**{k: v for k, v in os.environ.items() if not k.startswith("ACS_")}, **signing_env()}
        config = client.Config.from_env({"ACS_GUARDIAN_URL": "http://127.0.0.1:1/acs"})
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(tmp)), \
                mock.patch.object(_exchange, "_open", side_effect=respond):
            def open_(session_id: str):
                return client.open_session(config=config, session_id=session_id, agent_id="x",
                                           platform="t", methods_implemented=[])
            running = open_("running")
            for record in Path(tmp).glob("*.json"):
                os.utime(record, (0, 0))
            self.assertEqual(open_("running"), running)
            self.assertEqual(running.server_hello["on_decision_failure"], "deny")
            self.assertEqual(open_("next").server_hello["on_decision_failure"], "proceed")


class Item06_NatContextIdCollision(unittest.TestCase):
    """A frozen context's fallback must not key on id(), which Python reuses after GC."""

    def test_distinct_frozen_contexts_get_distinct_uuids(self) -> None:
        try:
            from acs.integrations.nat import adapter as nat_adapter
        except ImportError:
            self.skipTest("NAT adapter not importable in this env")

        class _StubConfig:
            guardian_url = "http://127.0.0.1:8787/acs"
            default_deny = False
            session_id = "frozen-test"
            timeout_s = 5.0
            target_function_or_group = "x"
            target_location = "input"

        class FrozenContext:
            __slots__ = ("function_context", "modified_kwargs")
            def __init__(self):
                class FC: name = "tool"
                self.function_context = FC()
                self.modified_kwargs = {}

        mw = nat_adapter.ACSMiddleware(_StubConfig())

        ctx1 = FrozenContext()
        rid1 = mw._correlation_request_id(ctx1)
        # Free ctx1, let Python recycle the id
        del ctx1
        import gc; gc.collect()
        ctx2 = FrozenContext()
        rid2 = mw._correlation_request_id(ctx2)
        self.assertNotEqual(rid1, rid2,
            f"FIX REQUIRED: two distinct (frozen) contexts produced the "
            f"same request_id ({rid1}). id(ctx) recycles after GC; the "
            f"frozen-context fallback must use a per-instance unique key "
            f"(WeakKeyDictionary).")


class Item07_UnicodeRoundTrip(unittest.TestCase):
    def _make_envelope(self, value):
        return {
            "jsonrpc": "2.0", "id": "u1", "method": "steps/toolCallRequest",
            "params": {
                "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "timestamp": "2026-06-17T12:00:00.000Z",
                "metadata": {"agent_id": "x", "session_id": "00000000-0000-4000-8000-000000000001"},
                "payload": {"tool": {"name": "Bash"},
                            "arguments": {"v": {"value": value}}},
            },
        }

    def test_emoji_round_trip(self) -> None:
        env = self._make_envelope("🚀 from agent — ✨")
        key = core.derive_session_key(b"test-secret", "sess")
        client.sign_envelope(env, key=key, session_id="sess", key_id="test-key")
        self.assertTrue(client.verify_signature(env, key=key, session_id="sess", key_id="test-key"))

    def test_null_byte_round_trip(self) -> None:
        env = self._make_envelope("before\x00after")
        key = core.derive_session_key(b"test-secret", "sess")
        client.sign_envelope(env, key=key, session_id="sess", key_id="test-key")
        self.assertTrue(client.verify_signature(env, key=key, session_id="sess", key_id="test-key"))

    def test_bmp_and_supplementary_planes_round_trip(self) -> None:
        env = self._make_envelope("שלום 🌍 こんにちは")
        key = core.derive_session_key(b"test-secret", "sess")
        client.sign_envelope(env, key=key, session_id="sess", key_id="test-key")
        self.assertTrue(client.verify_signature(env, key=key, session_id="sess", key_id="test-key"))


class Item08_Iso8601Parse(unittest.TestCase):
    """A brittle parser surfaces as TIMESTAMP_OUT_OF_WINDOW on legitimate requests."""

    GOOD = [
        "2026-06-17T12:00:00Z",
        "2026-06-17T12:00:00.000Z",
        "2026-06-17T12:00:00.123456Z",
        "2026-06-17T12:00:00+00:00",
        "2026-06-17T12:00:00.500+02:00",
        "2026-06-17T12:00:00-05:30",
    ]
    BAD = [
        "not a timestamp",
        "2026/06/17 12:00:00",
        "",
    ]

    def test_good_timestamps_parse(self) -> None:
        for ts in self.GOOD:
            try:
                core.parse_iso8601(ts)
            except Exception as e:
                self.fail(f"valid timestamp {ts!r} failed to parse: {e}")

    def test_bad_timestamps_raise_value_error(self) -> None:
        for ts in self.BAD:
            with self.assertRaises((ValueError, AttributeError),
                                   msg=f"{ts!r} should be rejected"):
                core.parse_iso8601(ts)


class Item09_HostAllowlist(unittest.TestCase):
    def setUp(self) -> None:
        self._old = os.environ.get("ACS_GUARDIAN_HOST_ALLOWLIST")

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("ACS_GUARDIAN_HOST_ALLOWLIST", None)
        else:
            os.environ["ACS_GUARDIAN_HOST_ALLOWLIST"] = self._old

    def test_allowlist_unset_accepts_any_http(self) -> None:
        os.environ.pop("ACS_GUARDIAN_HOST_ALLOWLIST", None)
        client.validate_guardian_url("http://127.0.0.1:8787/acs")
        client.validate_guardian_url("http://anything.example.com/acs")

    def test_allowlist_restricts_to_listed_hosts(self) -> None:
        os.environ["ACS_GUARDIAN_HOST_ALLOWLIST"] = "127.0.0.1,guardian.internal"
        client.validate_guardian_url("http://127.0.0.1:8787/acs")
        client.validate_guardian_url("https://guardian.internal/acs")
        with self.assertRaises(ValueError):
            client.validate_guardian_url("http://attacker.example.com/acs")


class Item10_CursorStateCollision(unittest.TestCase):
    """Two Cursor windows sharing a non-UUID session_id must not share state, or parent_step_id leaks across workspaces."""

    def test_same_session_id_different_workspace_distinct_paths(self) -> None:
        p1 = client_store._session_state_path("conv-default", workspace="/a/work1")
        p2 = client_store._session_state_path("conv-default", workspace="/b/work2")
        self.assertNotEqual(p1, p2,
            f"FIX REQUIRED: session-state path collides across workspaces: {p1}")


class Item12_StatePathHashLength(unittest.TestCase):
    def test_state_path_uses_full_sha256(self) -> None:
        p = client_store._session_state_path("any-session-id")
        self.assertRegex(p.stem, r"^[0-9a-f]{64}$",
            f"session-state filename {p.name!r} uses short hash; "
            f"expected 64-char SHA-256 hex digest")


class Item03_HaGuardianFileLock(unittest.TestCase):
    """Two Guardians sharing STATE_DIR: a request_id one accepted is a replay at the other."""

    def _start(self, statedir: str) -> tuple[subprocess.Popen, int]:
        env = os.environ.copy()
        env.update(signing_env())
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env["ACS_GUARDIAN_STATE_DIR"] = statedir
        return launch_guardian(env=env)

    def _post(self, port: int, body: dict) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/acs",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())

    def _envelope(self, sid, rid):
        return sign_for_test({"jsonrpc": "2.0", "id": str(uuid.uuid4()),
                "method": "steps/sessionStart",
                "params": {
                    "acs_version": "0.1.0", "request_id": rid,
                    "timestamp": core.iso8601_now(),
                    "metadata": {"agent_id": "ha", "session_id": sid, "platform": "t"},
                    "payload": {},
                }})

    def test_second_guardian_sees_first_guardians_replay_state(self) -> None:
        with tempfile.TemporaryDirectory() as statedir:
            proc_a, port_a = self._start(statedir)
            proc_b, port_b = self._start(statedir)
            try:
                sid = str(uuid.uuid4())
                rid = str(uuid.uuid4())
                r_a = self._post(port_a, self._envelope(sid, rid))
                self.assertIn("result", r_a,
                    f"Guardian A must accept first send; got {r_a}")
                r_b = self._post(port_b, self._envelope(sid, rid))
                self.assertIn("error", r_b,
                    "Guardian B accepted a replay of an envelope already "
                    "seen by Guardian A — HA file-locking + re-read on "
                    "check_replay broken; cross-instance replay window open")
                self.assertEqual(r_b["error"]["code"], -32005)
            finally:
                for p in (proc_a, proc_b):
                    p.terminate()
                    try: p.wait(timeout=2.0)
                    except subprocess.TimeoutExpired: p.kill()


class Item13_LaunchGuardianOwnsThePort(unittest.TestCase):
    """The returned port is bound by the returned process; a ping proves only that some Guardian answers."""

    @staticmethod
    def _dev_env() -> dict:
        env = os.environ.copy()
        env.update(signing_env())
        env.pop("ACS_HMAC_SECRET_FILE", None)
        return env

    @staticmethod
    def _stop(proc: subprocess.Popen) -> None:
        proc.terminate()
        try: proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired: proc.kill()

    def test_port_dies_with_the_returned_process(self) -> None:
        decoy, decoy_port = launch_guardian(env=self._dev_env())
        proc, port = launch_guardian(env=self._dev_env())
        try:
            self.assertNotEqual(port, decoy_port)
            self._stop(proc)
            time.sleep(0.2)
            self.assertIsNone(
                client.ping(f"http://127.0.0.1:{port}/acs", timeout=1.0),
                "port still answers after its owner was killed — the "
                "returned port was not bound by the returned process")
            self.assertIsNotNone(
                client.ping(f"http://127.0.0.1:{decoy_port}/acs", timeout=2.0))
        finally:
            self._stop(decoy)
            self._stop(proc)

    def test_child_that_exits_before_binding_raises(self) -> None:
        env = os.environ.copy()
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        with self.assertRaises(RuntimeError) as ctx:
            launch_guardian(env=env, timeout=3.0)
        self.assertIn("did not announce", str(ctx.exception))

    def test_returned_port_answers_acs_ping(self) -> None:
        proc, port = launch_guardian(env=self._dev_env())
        try:
            self.assertIsNone(proc.poll(), "returned process must be alive")
            result = client.ping(f"http://127.0.0.1:{port}/acs", timeout=2.0)
            self.assertIsNotNone(result, "returned port must answer system/ping")
        finally:
            self._stop(proc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
