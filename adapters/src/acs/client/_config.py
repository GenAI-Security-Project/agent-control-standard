from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from acs.client._outcome import Handshake, Negotiated, Refused, SessionRefused, Undecided

DEFAULT_GUARDIAN_URL = "http://127.0.0.1:8787/acs"
DEFAULT_TIMEOUT_S = 5.0


# The deny message's label for each audit type that blocks.
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

    @property
    def label(self) -> str:
        return _DENY_LABELS.get(self.audit_type, "decision-failure")


@dataclass(frozen=True)
class FailPosture:
    """Whether a step proceeds when no usable decision arrives (§6.4), and how long it waits for one."""
    deny_on_failure: bool
    timeout_s: float

    def negotiated(self, server_hello: Mapping[str, Any] | None) -> FailPosture:
        """Apply a ServerHello: deny wins over proceed, and a negotiated default timeout replaces the local one."""
        if not isinstance(server_hello, Mapping):
            return self
        deny = self.deny_on_failure or server_hello.get("on_decision_failure") == "deny"
        timeout_s = self.timeout_s
        timeout_config = server_hello.get("timeout_config")
        default_ms = timeout_config.get("default_ms") if isinstance(timeout_config, Mapping) else None
        if isinstance(default_ms, (int, float)) and not isinstance(default_ms, bool) and default_ms > 0:
            timeout_s = default_ms / 1000.0
        return replace(self, deny_on_failure=deny, timeout_s=timeout_s)

    def resolve(self, outcome: Undecided | Refused) -> Resolution:
        """The one place a step without a usable decision is settled: a refusal blocks, anything else follows the posture."""
        if isinstance(outcome, Refused):
            return Resolution(False, "guardian_refusal_fail_closed", outcome.cause, outcome.fields)
        if self.deny_on_failure:
            return Resolution(False, "decision_failure_fail_closed", outcome.cause, outcome.fields)
        return Resolution(True, "fail_open_bypass", outcome.cause, outcome.fields)


@dataclass(frozen=True)
class Config:
    """ACS_GUARDIAN_URL, ACS_DEFAULT_DENY, ACS_STARTUP_POSTURE, ACS_HANDSHAKE and ACS_DISABLED, read once at the entry point."""
    guardian_url: str
    posture: FailPosture
    handshake_enabled: bool
    disabled: bool
    startup_posture: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        return cls(
            guardian_url=env.get("ACS_GUARDIAN_URL", DEFAULT_GUARDIAN_URL),
            posture=FailPosture(deny_on_failure=env.get("ACS_DEFAULT_DENY", "0") == "1",
                                timeout_s=DEFAULT_TIMEOUT_S),
            handshake_enabled=env.get("ACS_HANDSHAKE", "1") == "1",
            disabled=env.get("ACS_DISABLED") == "1",
            startup_posture=env.get("ACS_STARTUP_POSTURE", "").strip().lower() or None,
        )

    @property
    def startup_proceeds(self) -> bool:
        """Whether steps proceed with no negotiated Guardian (§4.1): unset follows the fail posture, "proceed" proceeds, anything else refuses."""
        if self.startup_posture is None:
            return not self.posture.deny_on_failure
        return self.startup_posture == "proceed"

    def gate(self, handshake: Handshake) -> Resolution | None:
        """None when the session's steps go to the Guardian; otherwise how this step ends without one (§4.1)."""
        if isinstance(handshake, Negotiated):
            return None
        if isinstance(handshake, SessionRefused):
            return Resolution(False, "session_refused_fail_closed", handshake.cause, handshake.fields)
        if self.startup_proceeds:
            return Resolution(True, "unguarded_session_bypass", handshake.cause, handshake.fields)
        return Resolution(False, "session_not_started_fail_closed", handshake.cause, handshake.fields)
