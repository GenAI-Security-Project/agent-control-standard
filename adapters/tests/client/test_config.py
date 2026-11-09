from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from acs.client import Config, FailPosture, Negotiated, NoAnswer, Refused, Resolution, SessionRefused, Undecided
from acs.client._config import DEFAULT_GUARDIAN_URL, DEFAULT_TIMEOUT_S, FAILURE_CLASSES, failure_class
from acs.core import schemas_dir

PROCEED = FailPosture(deny_on_failure=False, timeout_s=1.0)
DENY = FailPosture(deny_on_failure=True, timeout_s=1.0)


class Negotiation(unittest.TestCase):
    """§6.4: on_decision_failure and timeout_config come from the handshake."""

    def test_deny_wins_over_proceed(self) -> None:
        self.assertTrue(PROCEED.negotiated({"on_decision_failure": "deny"}).deny_on_failure)

    def test_a_server_hello_never_weakens_a_local_deny(self) -> None:
        for hello in ({"on_decision_failure": "proceed"}, {}, {"on_decision_failure": None}):
            with self.subTest(hello=hello):
                self.assertTrue(DENY.negotiated(hello).deny_on_failure)

    def test_only_the_local_config_opts_into_proceed(self) -> None:
        """A ServerHello can tighten the posture but never loosen it."""
        table = [({}, "proceed", True), ({}, None, True), ({"ACS_DEFAULT_DENY": "0"}, "proceed", False),
                 ({"ACS_DEFAULT_DENY": "0"}, None, False), ({"ACS_DEFAULT_DENY": "0"}, "deny", True)]
        for env, declared, denies in table:
            with self.subTest(env=env, on_decision_failure=declared):
                hello = {} if declared is None else {"on_decision_failure": declared}
                self.assertIs(Config.from_env(env).posture.negotiated(hello).deny_on_failure, denies)

    def test_proceed_stays_proceed_without_a_deny(self) -> None:
        for hello in ({"on_decision_failure": "proceed"}, {}, {"on_decision_failure": "DENY"}):
            with self.subTest(hello=hello):
                self.assertFalse(PROCEED.negotiated(hello).deny_on_failure)

    def test_the_negotiated_default_timeout_replaces_the_local_one(self) -> None:
        for default_ms, expected in ((250, 0.25), (8000, 8.0), (1500.0, 1.5)):
            with self.subTest(default_ms=default_ms):
                posture = PROCEED.negotiated({"timeout_config": {"default_ms": default_ms}})
                self.assertEqual(posture.timeout_s, expected,
                    "the ServerHello's timeout applies whether it is shorter or longer")

    def test_unusable_timeouts_keep_the_local_one(self) -> None:
        for timeout_config in ({"default_ms": 0}, {"default_ms": -5}, {"default_ms": "250"},
                               {"default_ms": True}, {"default_ms": None}, {}, [250], "250", None):
            with self.subTest(timeout_config=timeout_config):
                posture = PROCEED.negotiated({"timeout_config": timeout_config})
                self.assertEqual(posture.timeout_s, 1.0)

    def test_a_missing_or_malformed_server_hello_changes_nothing(self) -> None:
        for hello in (None, [], "deny", 0):
            with self.subTest(hello=hello):
                self.assertEqual(DENY.negotiated(hello), DENY)
                self.assertEqual(PROCEED.negotiated(hello), PROCEED)

    def test_per_method_timeouts_bound_their_own_methods(self) -> None:
        posture = PROCEED.negotiated({"timeout_config": {"default_ms": 2000, "per_method_ms": {
            "steps/toolCallRequest": 300, "steps/bad": 0, "steps/also_bad": "5"}}})
        self.assertEqual(posture.timeout_for("steps/toolCallRequest"), 0.3)
        self.assertEqual(posture.timeout_for("steps/userMessage"), 2.0)
        self.assertEqual(posture.timeout_for("steps/bad"), 2.0)
        self.assertEqual(posture.timeout_for("steps/also_bad"), 2.0)
        self.assertEqual(PROCEED.timeout_for("steps/toolCallRequest"), 1.0)

    def test_negotiation_returns_a_new_posture(self) -> None:
        negotiated = PROCEED.negotiated({"on_decision_failure": "deny",
                                         "timeout_config": {"default_ms": 100}})
        self.assertEqual(negotiated, FailPosture(deny_on_failure=True, timeout_s=0.1))
        self.assertEqual(PROCEED, FailPosture(deny_on_failure=False, timeout_s=1.0))


class Resolve(unittest.TestCase):
    """A refusal fails closed whatever the posture; anything else follows it, and every case is audited."""

    FIELDS = {"error_code": -32005}

    def test_resolution_table(self) -> None:
        refused = Refused("replay_detected_response", self.FIELDS)
        undecided = Undecided("transport_failure", self.FIELDS)
        closed = {"posture": "fail_closed"}
        refusal = {**self.FIELDS, "failure_class": "guardian_error", **closed}
        unreachable = {**self.FIELDS, "failure_class": "unreachable"}
        table = [
            (PROCEED, refused, Resolution(False, "guardian_refusal_fail_closed", refused.cause, refusal,
                                          decision_failure=True)),
            (DENY, refused, Resolution(False, "guardian_refusal_fail_closed", refused.cause, refusal,
                                       decision_failure=True)),
            (DENY, undecided, Resolution(False, "decision_failure_fail_closed", undecided.cause,
                                         {**unreachable, **closed}, decision_failure=True)),
            (PROCEED, undecided, Resolution(True, "fail_open_bypass", undecided.cause,
                                            {**unreachable, "posture": "fail_open"}, decision_failure=True)),
        ]
        for posture, outcome, expected in table:
            with self.subTest(deny=posture.deny_on_failure, outcome=type(outcome).__name__):
                self.assertEqual(posture.resolve(outcome), expected)


class FailureClasses(unittest.TestCase):
    """§6.4: every decision failure carries one of the failure classes sessionEnd counts."""

    def test_the_classes_are_the_ones_session_end_counts(self) -> None:
        schema = json.loads((schemas_dir() / "hooks" / "session-end.json").read_text())
        counted = schema["properties"]["summary"]["properties"]["decision_failures"]["propertyNames"]["enum"]
        self.assertEqual(sorted(FAILURE_CLASSES), sorted(counted))

    def test_each_cause_maps_to_its_class(self) -> None:
        table = {
            "decision_timeout": "timeout", "transport_failure": "unreachable",
            "malformed_response": "malformed_response", "response_binding_mismatch": "malformed_response",
            "response_signature_invalid": "signature_invalid", "error_signature_invalid": "signature_invalid",
            "response_unverifiable": "signature_invalid",
            "internal_error_response": "guardian_error", "replay_detected_response": "guardian_error",
            "http_503_error": "guardian_error", "http_403_refusal": "guardian_error", "key_id_rejected": "guardian_error",
            "adapter_exception": "observed_agent_error", "adapter_build_failed": "observed_agent_error",
            "adapter_translate_exception": "observed_agent_error", "request_exceeds_max_payload": "observed_agent_error",
            "guardian_url_rejected": "observed_agent_error", "invalid_stdin_json": "observed_agent_error",
            "something_new": "other",
        }
        for cause, expected in table.items():
            with self.subTest(cause):
                self.assertEqual(failure_class(cause), expected)
                self.assertIn(expected, FAILURE_CLASSES)

    def test_a_gate_restating_a_start_failure_is_not_counted_again(self) -> None:
        session = Negotiated({"on_decision_failure": "proceed"},
                             {"cause": "decision_timeout", "fields": {"failure_class": "timeout", "posture": "fail_open"}})
        gated = Config.from_env({"ACS_DEFAULT_DENY": "1"}).gate(session)
        self.assertEqual((gated.decision_failure, gated.fields["posture"]), (False, "fail_closed"))

    def test_a_session_end_goes_out_after_a_start_without_a_decision(self) -> None:
        """sessionEnd is audit-only and reports the session's decision failures (§6.4), so a fail-closed posture sends it."""
        failed = Negotiated({"on_decision_failure": "deny"}, {"cause": "decision_timeout", "fields": {}})
        deny = Config.from_env({"ACS_DEFAULT_DENY": "1"})
        self.assertIsNone(deny.gate(failed, "steps/sessionEnd"))
        self.assertFalse(deny.gate(failed, "steps/toolCallRequest").proceed)
        self.assertFalse(deny.gate(SessionRefused("session_start_denied", {}), "steps/sessionEnd").proceed,
                         "a refused session sends nothing, sessionEnd included (§4.1)")


class Gate(unittest.TestCase):
    """§4.1: only a negotiated session reaches the Guardian; the others settle each step locally."""

    def test_gate_table(self) -> None:
        fields = {"error_code": -32000}
        proceed, refuse = Config.from_env({"ACS_STARTUP_POSTURE": "proceed"}), Config.from_env({})
        table = [
            (proceed, Negotiated({"negotiated_version": "0.1.0"}), None),
            (proceed, SessionRefused("session_refused_response", fields),
             Resolution(False, "session_refused_fail_closed", "session_refused_response", fields)),
            (proceed, NoAnswer("transport_failure"),
             Resolution(True, "unguarded_session_bypass", "transport_failure", {})),
            (refuse, NoAnswer("transport_failure"),
             Resolution(False, "session_not_started_fail_closed", "transport_failure", {})),
        ]
        for config, session, expected in table:
            with self.subTest(session=session, startup=config.startup_posture):
                self.assertEqual(config.gate(session), expected)

    def test_deny_labels(self) -> None:
        for audit_type, label in (("session_refused_fail_closed", "session refused"),
                                  ("session_not_started_fail_closed", "session not started"),
                                  ("guardian_refusal_fail_closed", "refused"),
                                  ("decision_failure_fail_closed", "decision-failure")):
            with self.subTest(audit_type):
                self.assertEqual(Resolution(False, audit_type, "cause", {}).label, label)


class FromEnv(unittest.TestCase):
    def test_defaults(self) -> None:
        self.assertEqual(Config.from_env({}), Config(
            guardian_url=DEFAULT_GUARDIAN_URL,
            posture=FailPosture(deny_on_failure=True, timeout_s=DEFAULT_TIMEOUT_S),
            handshake_enabled=True, disabled=False, startup_posture=None))

    def test_startup_posture(self) -> None:
        """§4.1: a session with no negotiated Guardian refuses its steps unless the hook sets proceed."""
        table = [({}, False), ({"ACS_DEFAULT_DENY": "0"}, False), ({"ACS_DEFAULT_DENY": "1"}, False),
                 ({"ACS_STARTUP_POSTURE": "proceed", "ACS_DEFAULT_DENY": "1"}, True),
                 ({"ACS_STARTUP_POSTURE": " Proceed "}, True),
                 ({"ACS_STARTUP_POSTURE": "refuse"}, False),
                 ({"ACS_STARTUP_POSTURE": "procede"}, False),
                 ({"ACS_STARTUP_POSTURE": ""}, False)]
        for env, proceeds in table:
            with self.subTest(env=env):
                self.assertIs(Config.from_env(env).startup_proceeds, proceeds)

    def test_settings(self) -> None:
        config = Config.from_env({"ACS_GUARDIAN_URL": "https://guardian.example/acs",
                                  "ACS_DEFAULT_DENY": "1", "ACS_HANDSHAKE": "0",
                                  "ACS_DISABLED": "1"})
        self.assertEqual(config.guardian_url, "https://guardian.example/acs")
        self.assertTrue(config.posture.deny_on_failure)
        self.assertFalse(config.handshake_enabled)
        self.assertTrue(config.disabled)

    def test_required_profiles(self) -> None:
        self.assertEqual(Config.from_env({}).require_profiles, frozenset())
        self.assertEqual(Config.from_env({"ACS_REQUIRE_PROFILES": " ACS-Core, acs-trace ,,"}).require_profiles,
                         frozenset({"acs-core", "acs-trace"}))

    def test_switches_turn_on_only_with_1(self) -> None:
        for value in ("true", "yes", "0", ""):
            with self.subTest(value=value):
                self.assertFalse(Config.from_env({"ACS_DISABLED": value}).disabled)

    def test_only_0_opts_out_of_deny(self) -> None:
        for value in ("1", "", "false", "no", " 0", "00"):
            with self.subTest(value=value):
                self.assertTrue(Config.from_env({"ACS_DEFAULT_DENY": value}).posture.deny_on_failure)
        self.assertFalse(Config.from_env({"ACS_DEFAULT_DENY": "0"}).posture.deny_on_failure)

    @mock.patch.dict(os.environ, {"ACS_DEFAULT_DENY": "0", "ACS_DISABLED": "1"})
    def test_reads_only_the_mapping_it_is_given(self) -> None:
        config = Config.from_env({})
        self.assertTrue(config.posture.deny_on_failure)
        self.assertFalse(config.disabled)


if __name__ == "__main__":
    unittest.main()
