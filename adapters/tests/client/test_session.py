"""open_session makes one §4.1 decision per session and refuses a modified record."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import _exchange
from acs.client import Config, Negotiated, NoAnswer, SessionRefused, open_session
from acs.client import _handshake
from acs.core import derive_session_key, sign_with_key

SECRET = "session-gate-test-secret"
URL = "http://127.0.0.1:8787/acs"
HELLO = {"negotiated_version": "0.1.0", "methods_evaluated": ["steps/toolCallRequest"],
         "selected_transport": "http", "timeout_config": {"default_ms": 5000},
         "on_decision_failure": "proceed", "profiles_accepted": ["acs-core"]}
FORGED = {"algorithm": "HMAC-SHA256", "value": "AAAA"}


def _signed(response: dict, session_id: str) -> dict:
    return sign_with_key(response, derive_session_key(SECRET.encode(), session_id))


def _answer(build, status: int = 200):
    def urlopen(req: Any, timeout: float):
        hello = json.loads(req.data)
        body = build(hello)
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status == 200:
            return io.BytesIO(raw)
        raise urllib.error.HTTPError(URL, status, "status", {}, io.BytesIO(raw))
    return urlopen


def _raises(exc: BaseException):
    def urlopen(*a: Any, **k: Any):
        raise exc
    return urlopen


def _result(hello: dict, result: dict, *, sign: bool = True) -> dict:
    response = {"jsonrpc": "2.0", "id": hello["id"], "result": dict(result)}
    return _signed(response, hello["params"]["metadata"]["session_id"]) if sign else response


def _error(hello: dict, code: Any, *, sign: bool = True, rpc_id: Any = "same") -> dict:
    response = {"jsonrpc": "2.0", "id": hello["id"] if rpc_id == "same" else rpc_id,
                "error": {"code": code, "message": "refused"}}
    return _signed(response, hello["params"]["metadata"]["session_id"]) if sign else response


def _forged_hello(hello: dict, **extra: Any) -> dict:
    response = _result(hello, {**HELLO, **extra}, sign=False)
    response["result"]["signature"] = FORGED
    return response


# (name, urlopen, expected decision type, expected cause)
CASES = [
    ("signed ServerHello", _answer(lambda h: _result(h, HELLO)), Negotiated, None),
    ("SESSION_REFUSED", _answer(lambda h: _error(h, -32000)), SessionRefused, "session_refused_response"),
    ("UNSUPPORTED_VERSION", _answer(lambda h: _error(h, -32001)), SessionRefused, "unsupported_version_response"),
    ("PROVENANCE_REQUIRED", _answer(lambda h: _error(h, -32002)), SessionRefused, "provenance_required_response"),
    ("SIGNATURE_INVALID", _answer(lambda h: _error(h, -32004)), SessionRefused, "signature_invalid_response"),
    ("SESSION_REFUSED under HTTP 403", _answer(lambda h: _error(h, -32000), 403),
     SessionRefused, "session_refused_response"),
    ("signed internal error", _answer(lambda h: _error(h, -32603)), NoAnswer, "internal_error_response"),
    ("signed method not found", _answer(lambda h: _error(h, -32601)), NoAnswer, "method_not_found_response"),
    ("unsigned SESSION_REFUSED", _answer(lambda h: _error(h, -32000, sign=False)),
     SessionRefused, "error_signature_invalid"),
    ("forged ServerHello", _answer(lambda h: _forged_hello(h)), SessionRefused, "server_hello_signature_invalid"),
    ("forged ServerHello with an integer RFC 8785 cannot encode", _answer(lambda h: _forged_hello(h, n=2**53)),
     SessionRefused, "server_hello_signature_invalid"),
    ("signed error for another request", _answer(lambda h: _error(h, -32603, rpc_id="other")),
     SessionRefused, "response_binding_mismatch"),
    ("signed result that is not a ServerHello", _answer(lambda h: _result(h, {"decision": "allow"})),
     NoAnswer, "invalid_server_hello"),
    ("connection refused", _raises(urllib.error.URLError(ConnectionRefusedError(61, "refused"))),
     NoAnswer, "transport_failure"),
    ("timeout", _raises(TimeoutError("timed out")), NoAnswer, "handshake_timeout"),
    ("bare HTTP 503", _answer(lambda h: b"", 503), NoAnswer, "http_503_error"),
    ("non-JSON-RPC HTTP 400", _answer(lambda h: {"error": "Bad Request"}, 400), NoAnswer, "http_400_error"),
    ("body that is not JSON", _answer(lambda h: b"<html>"), NoAnswer, "malformed_response"),
    ("unexpected exception", _raises(RuntimeError("boom")), NoAnswer, "adapter_exception"),
]


class _SessionTest(unittest.TestCase):
    ENV = {"ACS_HMAC_SECRET": SECRET}

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-session-")
        self.addCleanup(temporary.cleanup)
        self.cache = Path(temporary.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.dict(os.environ, {**env, **self.ENV}, clear=True),
                        mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", self.cache)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.audit = mock.patch.object(_handshake, "audit_event").start()
        self.addCleanup(mock.patch.stopall)

    def _open(self, urlopen=None, *, session_id: str = "session-1", **env: str):
        config = Config.from_env({"ACS_GUARDIAN_URL": URL, **env})
        with mock.patch.object(_exchange, "_open",
                               side_effect=urlopen or _answer(lambda h: _result(h, HELLO))) as network:
            decision = open_session(config=config, session_id=session_id, agent_id="test",
                                    platform="test", methods_implemented=["steps/toolCallRequest"])
        return decision, network.call_count

    def _record(self, session_id: str = "session-1") -> Path:
        return _handshake._handshake_cache_path(session_id, URL)


class Classification(_SessionTest):
    def test_every_handshake_answer(self) -> None:
        for i, (name, urlopen, kind, cause) in enumerate(CASES):
            with self.subTest(name):
                decision, calls = self._open(urlopen, session_id=f"classify-{i}")
                self.assertEqual(calls, 1)
                self.assertIsInstance(decision, kind)
                if cause is not None:
                    self.assertEqual(decision.cause, cause)

    def test_a_verifier_that_raises_refuses_the_session(self) -> None:
        with mock.patch.object(_handshake, "verify_signature", side_effect=RuntimeError("verifier bug")):
            decision, _ = self._open()
        self.assertEqual(decision, SessionRefused("response_unverifiable", {"error": "verifier bug"}))

    def test_handshake_disabled_is_no_answer_without_network(self) -> None:
        decision, calls = self._open(ACS_HANDSHAKE="0")
        self.assertEqual((decision, calls), (NoAnswer("handshake_disabled"), 0))
        self.assertTrue(self._record().exists())

    def test_a_missing_session_id_is_no_answer_and_is_not_stored(self) -> None:
        decision, calls = self._open(session_id="")
        self.assertEqual((decision, calls), (NoAnswer("missing_session_id"), 0))
        self.assertEqual(list(self.cache.glob("*")), [])

    def test_a_secret_that_cannot_be_loaded_refuses_the_session(self) -> None:
        secret_file = self.cache / "hmac.key"
        secret_file.write_text(SECRET)
        secret_file.chmod(0o644)
        with mock.patch.dict(os.environ, {"ACS_HMAC_SECRET_FILE": str(secret_file)}):
            decision, calls = self._open()
        self.assertIsInstance(decision, SessionRefused)
        self.assertEqual((decision.cause, calls), ("secret_unavailable", 0))


class Negotiation(_SessionTest):
    """A ServerHello must answer the ClientHello it was sent for; the client offers only what it implements."""

    def _hello(self, **change):
        hello = {**HELLO, **change}
        return _answer(lambda h: _result(h, {k: v for k, v in hello.items() if v is not None}))

    def test_a_server_hello_that_does_not_answer_the_client_hello_negotiates_nothing(self) -> None:
        cases = {"another major version": {"negotiated_version": "1.0.0"},
                 "transport not offered": {"selected_transport": "stdio"},
                 "profile not claimed": {"profiles_accepted": ["acs-core", "acs-trace"]},
                 "posture in another case": {"on_decision_failure": "Deny"},
                 "no default timeout": {"timeout_config": {"per_method_ms": {}}},
                 "no methods_evaluated": {"methods_evaluated": None}}
        for i, (name, change) in enumerate(cases.items()):
            with self.subTest(name):
                decision, calls = self._open(self._hello(**change), session_id=f"invalid-{i}")
                self.assertEqual(calls, 1)
                self.assertIsInstance(decision, NoAnswer)
                self.assertEqual(decision.cause, "invalid_server_hello")
                self.assertIn("problem", decision.fields)

    def test_the_client_offers_its_guardian_urls_transport(self) -> None:
        for scheme in ("http", "https"):
            with self.subTest(scheme):
                sent: list[dict] = []

                def urlopen(req, timeout):
                    sent.append(json.loads(req.data))
                    raise urllib.error.URLError("captured")

                config = Config.from_env({"ACS_GUARDIAN_URL": f"{scheme}://127.0.0.1:8787/acs"})
                with mock.patch.object(_exchange, "_open", side_effect=urlopen):
                    open_session(config=config, session_id=f"transport-{scheme}", agent_id="test",
                                 platform="test", methods_implemented=["steps/toolCallRequest"])
                self.assertEqual(sent[0]["params"]["payload"]["transports_supported"], [scheme])

    def test_a_required_profile_the_guardian_does_not_accept_refuses_the_session(self) -> None:
        required = {"ACS_REQUIRE_PROFILES": "acs-core"}
        refused, _ = self._open(self._hello(profiles_accepted=[]), session_id="required-declined", **required)
        self.assertEqual(refused, SessionRefused("required_profile_not_accepted", {"profiles": ["acs-core"]}))
        missing, _ = self._open(self._hello(profiles_accepted=None), session_id="required-missing", **required)
        self.assertEqual(missing.cause, "required_profile_not_accepted")
        accepted, _ = self._open(self._hello(), session_id="required-accepted", **required)
        self.assertIsInstance(accepted, Negotiated)

    def test_each_hook_applies_its_required_profiles_to_the_stored_negotiation(self) -> None:
        declining = self._hello(profiles_accepted=[])
        first, calls = self._open(declining, session_id="per-hook")
        self.assertEqual((type(first), calls), (Negotiated, 1))
        refused, calls = self._open(session_id="per-hook", ACS_REQUIRE_PROFILES="acs-core")
        self.assertEqual((refused, calls),
                         (SessionRefused("required_profile_not_accepted", {"profiles": ["acs-core"]}), 0),
                         "a stored negotiation must not skip this hook's requirement")
        again, calls = self._open(session_id="per-hook")
        self.assertEqual((again, calls), (first, 0), "the record keeps what the Guardian answered")

    def test_a_claimed_profile_the_guardian_declines_is_audited_once(self) -> None:
        self._open(self._hello(profiles_accepted=[]), session_id="declined")
        self._open(session_id="declined")
        declined = [c for c in self.audit.call_args_list if c.args[0] == "profile_not_accepted"]
        self.assertEqual([c.kwargs["profiles"] for c in declined], [["acs-core"]])
        self.audit.reset_mock()
        self._open(self._hello(profiles_accepted=None), session_id="unstated")
        self.assertNotIn("profile_not_accepted", [c.args[0] for c in self.audit.call_args_list])


class Lifetime(_SessionTest):
    """The first handshake decides the session; nothing expires it, and the next session asks again."""

    ANSWERS = {
        "negotiated": _answer(lambda h: _result(h, HELLO)),
        "refused": _answer(lambda h: _error(h, -32000)),
        "no answer": _raises(urllib.error.URLError(ConnectionRefusedError(61, "refused"))),
    }

    def test_each_decision_holds_for_the_session_after_its_record_ages(self) -> None:
        healthy = _answer(lambda h: _result(h, HELLO))
        for name, answer in self.ANSWERS.items():
            with self.subTest(name):
                session = f"lifetime-{name}"
                first, calls = self._open(answer, session_id=session)
                self.assertEqual(calls, 1)
                os.utime(self._record(session), (0, 0))
                again, calls = self._open(healthy, session_id=session)
                self.assertEqual((again, calls), (first, 0),
                    "the same session must not contact the Guardian again, however old its record")
                fresh, calls = self._open(healthy, session_id=f"{session}-next")
                self.assertEqual(calls, 1, "a new session handshakes")
                self.assertIsInstance(fresh, Negotiated)

    def test_the_first_stored_decision_wins(self) -> None:
        first = _handshake.store_session_decision(self.cache, "race", URL, NoAnswer("transport_failure"),
                                                  SECRET.encode())
        second = _handshake.store_session_decision(self.cache, "race", URL, Negotiated(HELLO),
                                                   SECRET.encode())
        self.assertEqual((first, second), (NoAnswer("transport_failure"), NoAnswer("transport_failure")))
        self.assertEqual(self._open(session_id="race"), (NoAnswer("transport_failure"), 0))

    def test_the_start_is_audited_once(self) -> None:
        event = "session_without_negotiated_guardian"
        cases = [({}, "fail_open"), ({"ACS_STARTUP_POSTURE": "refuse"}, "fail_closed")]
        for i, (env, posture) in enumerate(cases):
            with self.subTest(posture):
                self.audit.reset_mock()
                session = f"audit-{i}"
                self._open(self.ANSWERS["no answer"], session_id=session, **env)
                self._open(session_id=session, **env)
                calls = [c for c in self.audit.call_args_list if c.args[0] == event]
                self.assertEqual(len(calls), 1, self.audit.call_args_list)
                self.assertEqual(calls[0].kwargs["failure_class"], "handshake_failure")
                self.assertEqual(calls[0].kwargs["posture"], posture)
                self.assertEqual(calls[0].kwargs["cause"], "transport_failure")
        self.audit.reset_mock()
        self._open(self.ANSWERS["refused"], session_id="audit-refused")
        self.assertEqual([c.args[0] for c in self.audit.call_args_list], ["session_refused"])


class Records(_SessionTest):
    """The record sits where the observed agent can write; a modified one refuses the session."""

    def _rewrite(self, session_id: str, change) -> None:
        record = json.loads(self._record(session_id).read_text())
        change(record)
        self._record(session_id).write_text(json.dumps(record))

    def test_modified_records_refuse_the_session_without_network(self) -> None:
        def unguard(record: dict) -> None:
            record.update(decision="no_answer", cause="transport_failure", fields={})
            record.pop("server_hello")

        def strip_mac(record: dict) -> None:
            record["mac"] = None

        def other_session_mac(record: dict) -> None:
            body = {k: v for k, v in record.items() if k != "mac"}
            record["mac"] = _handshake._mac(body, SECRET.encode(), "another-session")

        for name, change in (("negotiated rewritten as unguarded", unguard),
                             ("MAC removed", strip_mac),
                             ("MAC from another session", other_session_mac)):
            with self.subTest(name):
                session = f"tamper-{name}"
                self._open(session_id=session)
                self._rewrite(session, change)
                decision, calls = self._open(session_id=session)
                self.assertEqual(calls, 0)
                self.assertIsInstance(decision, SessionRefused)
                self.assertEqual(decision.cause, "session_record_invalid")

    def test_a_corrupted_record_refuses_the_session_without_network(self) -> None:
        corruptions = {
            "truncated": lambda raw: raw[: len(raw) // 2],
            "empty": lambda raw: b"",
            "not JSON": lambda raw: b"\x00garbage",
            "not an object": lambda raw: b"[]",
            "another record version": lambda raw: raw.replace(b'"acs_session_record": 1', b'"acs_session_record": 2'),
            "nested past the recursion limit": lambda raw: b"[" * 20000 + b"]" * 20000,
        }
        for kind, answer in Lifetime.ANSWERS.items():
            for name, corrupt in corruptions.items():
                with self.subTest(decision=kind, corruption=name):
                    session = f"corrupt-{kind}-{name}"
                    self._open(answer, session_id=session)
                    record = self._record(session)
                    record.write_bytes(corrupt(record.read_bytes()))
                    decision, calls = self._open(session_id=session)
                    self.assertEqual(calls, 0, "a damaged record must not trigger another handshake")
                    self.assertEqual(decision, SessionRefused("session_record_invalid", {"record": str(record)}))

    def test_an_earlier_adapter_cache_refuses_the_session(self) -> None:
        legacy = {
            "bare ServerHello": dict(HELLO),
            "signed ServerHello envelope": _signed({"jsonrpc": "2.0", "id": "x", "result": dict(HELLO)},
                                                    "legacy-envelope"),
        }
        for name, content in legacy.items():
            with self.subTest(name):
                session = "legacy-envelope" if "envelope" in name else "legacy-bare"
                self.cache.mkdir(exist_ok=True)
                self._record(session).write_text(json.dumps(content))
                decision, calls = self._open(session_id=session)
                self.assertEqual(calls, 0)
                self.assertEqual(decision.cause, "session_record_legacy")

    def test_a_record_copied_from_another_endpoint_refuses_the_session(self) -> None:
        other = "http://127.0.0.1:9999/acs"
        _handshake.store_session_decision(self.cache, "copied", other, NoAnswer("transport_failure"),
                                          SECRET.encode())
        self._open(_answer(lambda h: _error(h, -32000)), session_id="copied")
        self._record("copied").write_bytes(_handshake._handshake_cache_path("copied", other).read_bytes())
        decision, calls = self._open(session_id="copied")
        self.assertEqual(calls, 0)
        self.assertEqual(decision.cause, "session_record_invalid")

    def test_a_decision_that_cannot_be_stored_refuses_the_session(self) -> None:
        failures = {"mkstemp": mock.patch.object(_handshake.tempfile, "mkstemp",
                                                 side_effect=OSError(28, "No space left on device")),
                    "link": mock.patch.object(_handshake.os, "link",
                                              side_effect=PermissionError(13, "Permission denied"))}
        for kind, answer in Lifetime.ANSWERS.items():
            for name, failure in failures.items():
                with self.subTest(decision=kind, failing=name):
                    self.audit.reset_mock()
                    with failure:
                        decision, _ = self._open(answer, session_id=f"unwritable-{kind}-{name}")
                    self.assertIsInstance(decision, SessionRefused)
                    self.assertEqual(decision.cause, "session_record_unwritable")
                    self.assertIn("session_record_unwritable",
                                  [c.args[0] for c in self.audit.call_args_list])
                    self.assertFalse(self._record(f"unwritable-{kind}-{name}").exists())

    def test_an_unreadable_record_refuses_the_session(self) -> None:
        self._open(session_id="unreadable")
        self._record("unreadable").chmod(0)
        self.addCleanup(self._record("unreadable").chmod, 0o600)
        decision, calls = self._open(session_id="unreadable")
        self.assertEqual((decision.cause, calls), ("session_record_unreadable", 0))

    def test_a_record_written_without_a_secret_is_refused_once_a_secret_is_configured(self) -> None:
        _handshake.store_session_decision(self.cache, "unsigned", URL, NoAnswer("transport_failure"), b"")
        decision, calls = self._open(session_id="unsigned")
        self.assertEqual((decision.cause, calls), ("session_record_invalid", 0))


class UnsignedMode(_SessionTest):
    ENV: dict = {}

    def test_an_unsigned_client_claims_no_profile_so_a_required_one_refuses(self) -> None:
        unsigned_hello = _answer(lambda h: _result(h, {**HELLO, "profiles_accepted": []}, sign=False))
        decision, _ = self._open(unsigned_hello, session_id="dev-required", ACS_REQUIRE_PROFILES="acs-core")
        self.assertEqual(decision.cause, "required_profile_not_accepted")

    def test_records_carry_no_mac_and_still_hold_the_session(self) -> None:
        first, _ = self._open(_raises(urllib.error.URLError("down")), session_id="dev")
        self.assertIsNone(json.loads(self._record("dev").read_text())["mac"])
        self.assertEqual(self._open(session_id="dev"), (first, 0))


if __name__ == "__main__":
    unittest.main()
