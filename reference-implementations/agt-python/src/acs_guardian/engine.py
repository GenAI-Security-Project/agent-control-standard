"""The policy engine interface (Specification §12.1).

ACS defines the interface to the deterministic-layer engine, not the engine:
input is the request plus session context, output is a decision envelope plus
an optional ``delegate_to: agent``. This module defines that interface and
ships one small built-in engine so the Guardian does something observable
without a deployment-supplied policy.

The built-in engine is deliberately narrow: allow by default, deny a short
list of destructive shell patterns in ``steps/toolCallRequest``. It exists to
demonstrate the interface, not to be anyone's production policy -- policy
content is explicitly out of scope for the standard (CONTRIBUTING.md), and a
deployment replaces this engine with its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

ALLOW = "allow"
DENY = "deny"
MODIFY = "modify"
ASK = "ask"
DEFER = "defer"

DISPOSITIONS = (ALLOW, DENY, MODIFY, ASK, DEFER)


@dataclass
class EvaluationRequest:
    """What the Guardian hands the engine: the method, payload, and session facts."""

    method: str
    payload: dict[str, Any]
    session_id: str
    agent_id: str
    request_id: str


@dataclass
class Evaluation:
    """A decision envelope's policy-authored fields (response-envelope.json AcsResult)."""

    decision: str
    reasoning: str | None = None
    reason_codes: list[str] = field(default_factory=list)
    policy_references: list[dict[str, Any]] = field(default_factory=list)
    modifications: dict[str, Any] | None = None
    ask_details: dict[str, Any] | None = None
    defer_details: dict[str, Any] | None = None


class PolicyEngine(Protocol):
    """The §12.1 seam. Implementations must be side-effect free per evaluation."""

    def evaluate(self, request: EvaluationRequest) -> Evaluation: ...


# The AGT stock destructive-pattern rule's shape, kept small on purpose: these
# are the patterns a reference demo can defend as unambiguous, not a policy.
_DESTRUCTIVE_PATTERNS = (
    "rm -rf /",
    "rm -fr /",
    "mkfs",
    "dd if=",
    ":(){:|:&};:",
    "shutdown",
    "reboot",
)


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for item in value.values():
            found.extend(_flatten_strings(item))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(_flatten_strings(item))
        return found
    return []


class BuiltinEngine:
    """Allow by default; deny destructive shell commands on tool calls."""

    def evaluate(self, request: EvaluationRequest) -> Evaluation:
        if request.method != "steps/toolCallRequest":
            return Evaluation(decision=ALLOW)
        candidates = [request.payload.get("raw_command", "")]
        candidates.extend(_flatten_strings(request.payload.get("arguments", {})))
        for text in candidates:
            if not isinstance(text, str):
                continue
            lowered = text.lower()
            for pattern in _DESTRUCTIVE_PATTERNS:
                if pattern in lowered:
                    return Evaluation(
                        decision=DENY,
                        reasoning=(
                            f"tool call matches the destructive-command pattern {pattern!r}; "
                            "denied by the built-in engine"
                        ),
                        reason_codes=["destructive_shell_command_blocked"],
                        policy_references=[{"policy_id": "builtin", "rule_id": "destructive_command"}],
                    )
        return Evaluation(decision=ALLOW)
