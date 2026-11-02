from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from acs.client._outcome import Handshake, Negotiated, Refused, SessionRefused, Undecided

DEFAULT_GUARDIAN_URL = "http://127.0.0.1:8787/acs"
DEFAULT_TIMEOUT_S = 5.0


# §6.4 failure classes, the acs.failure.class values in trace/otel-mapping.json.
FAILURE_CLASSES = ("timeout", "unreachable", "malformed_response", "guardian_error", "observed_agent_error",
                   "signature_invalid", "handshake_failure", "other")

_OBSERVED_AGENT_CAUSES = {"adapter_exception", "adapter_build_failed", "adapter_translate_exception",
                          "invalid_stdin_json", "guardian_url_rejected", "request_exceeds_max_payload"}
_SIGNATURE_CAUSES = {"response_signature_invalid", "error_signature_invalid", "response_unverifiable",
                     "server_hello_signature_invalid"}


def failure_class(cause: str) -> str:
    if cause in ("decision_timeout", "handshake_timeout"):
        return "timeout"
    if cause == "transport_failure":
        return "unreachable"
    if cause in ("malformed_response", "response_binding_mismatch"):
        return "malformed_response"
    if cause in _SIGNATURE_CAUSES:
        return "signature_invalid"
    if cause in _OBSERVED_AGENT_CAUSES:
        return "observed_agent_error"
    if cause.endswith("_response") or cause.startswith("http_") or cause == "key_id_rejected":
        return "guardian_error"
    return "other"


_DENY_LABELS = {
    "guardian_refusal_fail_closed": "refused",
    "session_refused_fail_closed": "session refused",
    "session_not_started_fail_closed": "session not started",
}


@dataclass(frozen=True)
class Resolution:
    """How a step without a usable decision ends: whether it proceeds, and the audit record that says why."""
    proceed: bool
    audit_type: str
    cause: str
    fields: Mapping[str, Any]
    message: str = ""
    # This step's own decision failure (§6.4), counted once; a session gate restating one is not.
    decision_failure: bool = False

    @property
    def label(self) -> str:
        return _DENY_LABELS.get(self.audit_type, "decision-failure")


def _positive(ms: object) -> bool:
    return isinstance(ms, (int, float)) and not isinstance(ms, bool) and ms > 0


@dataclass(frozen=True)
class FailPosture:
    """Whether a step proceeds when no usable decision arrives (§6.4), and how long it waits for one."""
    deny_on_failure: bool
    timeout_s: float
    # timeout_config.per_method_ms from the ServerHello, in seconds.
    per_method_timeout_s: Mapping[str, float] = field(default_factory=dict)

    def timeout_for(self, method: str) -> float:
        return self.per_method_timeout_s.get(method, self.timeout_s)

    def negotiated(self, server_hello: Mapping[str, Any] | None) -> FailPosture:
        """Apply a ServerHello: deny wins over proceed, and negotiated timeouts replace the local one."""
        if not isinstance(server_hello, Mapping):
            return self
        deny = self.deny_on_failure or server_hello.get("on_decision_failure") == "deny"
        timeout_s = self.timeout_s
        timeout_config = server_hello.get("timeout_config")
        timeout_config = timeout_config if isinstance(timeout_config, Mapping) else {}
        default_ms = timeout_config.get("default_ms")
        if _positive(default_ms):
            timeout_s = default_ms / 1000.0
        per_method = timeout_config.get("per_method_ms")
        per_method = per_method if isinstance(per_method, Mapping) else {}
        overrides = {method: ms / 1000.0 for method, ms in per_method.items() if _positive(ms)}
        return replace(self, deny_on_failure=deny, timeout_s=timeout_s, per_method_timeout_s=overrides)

    def resolve(self, outcome: Undecided | Refused) -> Resolution:
        """The one place a step without a usable decision is settled: a refusal blocks, anything else follows the posture."""
        proceed = not isinstance(outcome, Refused) and not self.deny_on_failure
        fields = {**outcome.fields, "failure_class": failure_class(outcome.cause),
                  "posture": "fail_open" if proceed else "fail_closed"}
        if isinstance(outcome, Refused):
            audit_type = "guardian_refusal_fail_closed"
        else:
            audit_type = "fail_open_bypass" if proceed else "decision_failure_fail_closed"
        return Resolution(proceed, audit_type, outcome.cause, fields, outcome.message, decision_failure=True)


@dataclass(frozen=True)
class Config:
    """ACS_GUARDIAN_URL, ACS_DEFAULT_DENY, ACS_STARTUP_POSTURE, ACS_REQUIRE_PROFILES, ACS_HANDSHAKE and ACS_DISABLED, read once at the entry point."""
    guardian_url: str
    posture: FailPosture
    handshake_enabled: bool
    disabled: bool
    startup_posture: str | None = None
    require_profiles: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        return cls(
            guardian_url=env.get("ACS_GUARDIAN_URL", DEFAULT_GUARDIAN_URL),
            posture=FailPosture(deny_on_failure=env.get("ACS_DEFAULT_DENY", "0") == "1",
                                timeout_s=DEFAULT_TIMEOUT_S),
            handshake_enabled=env.get("ACS_HANDSHAKE", "1") == "1",
            disabled=env.get("ACS_DISABLED") == "1",
            startup_posture=env.get("ACS_STARTUP_POSTURE", "").strip().lower() or None,
            require_profiles=frozenset(p.strip().lower() for p in env.get("ACS_REQUIRE_PROFILES", "").split(",")
                                       if p.strip()),
        )

    @property
    def startup_proceeds(self) -> bool:
        """Whether steps proceed with no negotiated Guardian (§4.1): unset follows the fail posture, "proceed" proceeds, anything else refuses."""
        if self.startup_posture is None:
            return not self.posture.deny_on_failure
        return self.startup_posture == "proceed"

    def gate(self, handshake: Handshake, method: str | None = None) -> Resolution | None:
        """None when this step goes to the Guardian; otherwise how it ends without one (§4.1), a session whose sessionStart got no decision included."""
        if isinstance(handshake, Negotiated):
            failure = handshake.start_failure
            # sessionEnd is audit-only and reports the session's decision failures (§6.4), the start's among them.
            if failure is None or method == "steps/sessionEnd" or not self.posture.negotiated(handshake.server_hello).deny_on_failure:
                return None
            return Resolution(False, "decision_failure_fail_closed", failure["cause"],
                              {**failure["fields"], "method": "steps/sessionStart", "posture": "fail_closed"})
        if isinstance(handshake, SessionRefused):
            return Resolution(False, "session_refused_fail_closed", handshake.cause, handshake.fields)
        if self.startup_proceeds:
            return Resolution(True, "unguarded_session_bypass", handshake.cause, handshake.fields)
        return Resolution(False, "session_not_started_fail_closed", handshake.cause, handshake.fields)
