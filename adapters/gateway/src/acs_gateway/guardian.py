"""The Guardian side of the gateway: readiness, sessions and one signed, transcribed step at a time.

acs.client is synchronous and blocks on sockets, so every method here runs in a worker thread (PREMORTEM P19).
"""
from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from acs.client import (
    Config,
    Decided,
    FailPosture,
    Negotiated,
    Resolution,
    Undecided,
    audit_event,
    open_session,
    ping,
    round_trip,
    sign_envelope,
)
from acs.core import Decision, method_evaluated, normalize_decision, request_envelope

from acs_gateway.config import GatewayConfig
from acs_gateway.sessions import Session
from acs_gateway.transcript import Transcript

SESSION_START = "steps/sessionStart"
TOOL_CALL_REQUEST = "steps/toolCallRequest"
TOOL_CALL_RESULT = "steps/toolCallResult"
METHODS = [SESSION_START, TOOL_CALL_REQUEST, TOOL_CALL_RESULT]
PLATFORM = "openai-responses-gateway"

@dataclass(frozen=True)
class StepResult:
    """What one step came to: a usable decision, or the cause that settles it as a deny."""
    method: str
    request_id: str | None
    decision: Decision | None = None
    reason_codes: list[str] = field(default_factory=list)
    # Set when no usable decision arrived. Every such step denies, whatever any ServerHello says.
    cause: str | None = None
    failure_class: str | None = None


_MAX_SAFE_INTEGER = 2**53 - 1
_SURROGATE = re.compile("[\ud800-\udfff]")


def jcs_problem(value: Any, depth: int = 0) -> str | None:
    """Why RFC 8785 can't encode value, or None.

    acs.client would rewrite such a value before signing, and then the transcript line written before the send would
    differ from the envelope sent. So the gateway refuses the step instead, and refusing a gated step denies it.
    """
    if depth > 100:
        return "nesting deeper than 100"
    if isinstance(value, str):
        return "lone surrogate in a string" if _SURROGATE.search(value) else None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return "integer beyond 2**53 - 1" if abs(value) > _MAX_SAFE_INTEGER else None
    if isinstance(value, float):
        return None if math.isfinite(value) else "non-finite number"
    if isinstance(value, dict):
        for key, item in value.items():
            problem = jcs_problem(key, depth + 1) or jcs_problem(item, depth + 1)
            if problem:
                return problem
        return None
    if isinstance(value, list):
        for item in value:
            problem = jcs_problem(item, depth + 1)
            if problem:
                return problem
        return None
    return f"unsupported type {type(value).__name__}"


class StepToken:
    """Settles the race between a step's worker and the deadline the event loop enforces (PREMORTEM P20).

    The worker claims the token before it writes the transcript line and sends. The loop cancels it at the deadline.
    Exactly one wins: a cancelled step writes and sends nothing, and a claimed one runs to the end, bounded by the
    decision timeout, while the loop waits for it before releasing the session lock.
    """

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self._lock = threading.Lock()
        self._state = "pending"
        # The claimed step's request_id, so a late answer's audit line still names its transcript lines.
        self.request_id: str | None = None
        # Set when the loop stopped waiting for a claimed step. The worker then starts no write and no send.
        self._retired = False
        self._writing = 0

    def retire(self) -> bool:
        """Retire the step. True when a write had already started, which can still land but nothing new will."""
        with self._lock:
            self._retired = True
            return self._writing > 0

    @property
    def retired(self) -> bool:
        with self._lock:
            return self._retired

    def begin_write(self) -> bool:
        """Start a write unless the step is retired, decided under the lock as one step with retirement. The lock is
        never held during the write itself, so a stalled disk can't block the loop that retires the step."""
        with self._lock:
            if self._retired:
                return False
            self._writing += 1
            return True

    def end_write(self) -> None:
        with self._lock:
            self._writing -= 1

    def claim(self, request_id: str) -> bool:
        with self._lock:
            if self._state == "cancelled" or time.monotonic() >= self.deadline:
                self._state = "cancelled"
                return False
            self._state = "claimed"
            self.request_id = request_id
            return True

    def cancel(self) -> bool:
        """True when the worker will write and send nothing, False when it already claimed the step."""
        with self._lock:
            if self._state == "claimed":
                return False
            self._state = "cancelled"
            return True


def write_line(token: StepToken | None, write: Callable[[], None]) -> bool:
    """Run one transcript write unless the token was retired first. False when it was."""
    if token is None:
        write()
        return True
    if not token.begin_write():
        return False
    try:
        write()
    finally:
        token.end_write()
    return True


class GuardianClient:
    def __init__(self, config: GatewayConfig, transcript: Transcript) -> None:
        self.config = config
        self.transcript = transcript
        # The gateway's own configuration always denies on a decision failure, and no startup posture lets an
        # unnegotiated session proceed. A ServerHello can't loosen either (D-045, PREMORTEM P23).
        self.base_posture = FailPosture(deny_on_failure=True, timeout_s=config.decision_timeout_s)
        self.acs_config = Config(guardian_url=config.guardian_url, posture=self.base_posture,
                                 handshake_enabled=True, disabled=False, startup_posture=None)

    def wait_ready(self) -> None:
        """Block until the Guardian answers system/ping, so no session stores a NoAnswer from a cold start."""
        deadline = time.monotonic() + self.config.ready_timeout_s
        while True:
            result = ping(self.config.guardian_url, timeout=2.0)
            if isinstance(result, dict) and (result.get("payload") or {}).get("status") == "ok":
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"the Guardian at {self.config.guardian_url} did not answer system/ping "
                                   f"within {self.config.ready_timeout_s:g}s")
            time.sleep(0.2)

    def posture(self, server_hello: Any) -> FailPosture:
        """The ServerHello's timeouts, never longer than ACS_DECISION_TIMEOUT_MS, and always fail closed."""
        negotiated = self.base_posture.negotiated(server_hello).closed()
        local = self.config.decision_timeout_s
        return replace(negotiated, timeout_s=min(negotiated.timeout_s, local),
                       per_method_timeout_s={m: min(s, local) for m, s in negotiated.per_method_timeout_s.items()})

    def open(self, session: Session) -> None:
        """Handshake, then sessionStart, so the session's chain roots there (A.4)."""
        def start(negotiated: Negotiated) -> Decided | Resolution | None:
            if not method_evaluated(dict(negotiated.server_hello), SESSION_START):
                return None
            outcome, _ = self._send(session.session_id, SESSION_START, {}, self.posture(negotiated.server_hello))
            return outcome

        handshake = open_session(config=self.acs_config, session_id=session.session_id, agent_id=self.config.agent_id,
                                 platform=PLATFORM, methods_implemented=METHODS, start=start)
        session.handshake = handshake
        hello = dict(handshake.server_hello) if isinstance(handshake, Negotiated) else None
        session.posture = self.posture(hello)
        audit_event("session_opened", session_id=session.session_id, epoch=session.epoch,
                    handshake=type(handshake).__name__, cause=getattr(handshake, "cause", None),
                    guardian_url=self.config.guardian_url)

    def step(self, session: Session, method: str, payload: dict[str, Any],
             token: StepToken | None = None) -> StepResult:
        """Never raises: anything that goes wrong on the gateway's side settles the step as a deny.

        token carries a deadline set when the step was queued, so time spent waiting for a worker counts against the
        decision timeout, and a step the loop already gave up on writes and sends nothing.
        """
        try:
            return self._step(session, method, payload, token)
        except Exception as e:  # noqa: BLE001
            audit_event("gateway_step_error", session_id=session.session_id, method=method, error=str(e))
            return StepResult(method, None, cause="adapter_exception", failure_class="observed_agent_error")

    def _step(self, session: Session, method: str, payload: dict[str, Any], token: StepToken | None) -> StepResult:
        gated = self.acs_config.gate(session.handshake, method)
        if gated is not None:
            return StepResult(method, None, cause=gated.cause, failure_class=gated.fields.get("failure_class"))
        hello = session.handshake.server_hello
        if not method_evaluated(dict(hello), method):
            # handshake.json makes a method left out of methods_evaluated allow by default. The gateway gates tool
            # calls and results on its own authority (D-045), so a Guardian can't switch gating off this way.
            audit_event("method_not_evaluated", session_id=session.session_id, method=method)
            return StepResult(method, None, cause="method_not_evaluated", failure_class="guardian_error")
        posture = session.posture
        if token is not None:
            remaining = token.deadline - time.monotonic()
            if remaining <= 0:
                return StepResult(method, None, cause="decision_timeout", failure_class="timeout")
            posture = replace(posture, timeout_s=min(posture.timeout_for(method), remaining), per_method_timeout_s={})
        outcome, request_id = self._send(session.session_id, method, payload, posture, token)
        if outcome is None:
            return StepResult(method, request_id, cause="decision_timeout", failure_class="timeout")
        if isinstance(outcome, Resolution):
            return StepResult(method, request_id, cause=outcome.cause, failure_class=outcome.fields.get("failure_class"))
        result = outcome.response.get("result") or {}
        codes = result.get("reason_codes")
        return StepResult(method, request_id, decision=normalize_decision(result),
                          reason_codes=[c for c in codes if isinstance(c, str)] if isinstance(codes, list) else [])

    def _send(self, session_id: str, method: str, payload: dict[str, Any], posture: FailPosture,
              token: StepToken | None = None) -> tuple[Decided | Resolution | None, str]:
        """None as the outcome means the token was cancelled first, so nothing was written or sent."""
        request_id = str(uuid.uuid4())
        request = request_envelope(method, request_id=request_id,
                                   metadata={"agent_id": self.config.agent_id, "session_id": session_id,
                                             "platform": PLATFORM},
                                   payload=payload)
        problem = jcs_problem(request["params"])
        if problem is not None:
            return posture.closed().resolve(Undecided("envelope_not_signable", {"error": problem},
                                                      f"envelope not signable: {problem}")), request_id
        try:
            sign_envelope(request, session_id=session_id)
        except Exception as e:  # noqa: BLE001
            return posture.closed().resolve(Undecided("envelope_not_signable", {"error": str(e)},
                                                      f"envelope not signable: {e}")), request_id
        signature = dict(request["params"]["signature"])
        if token is not None and not token.claim(request_id):
            return None, request_id
        # Written before the send, so the transcript holds every envelope in the order the Guardian chained it (P20).
        if not write_line(token, lambda: self.transcript.append(session_id, "req", request)):
            return None, request_id
        if token is not None and token.retired:
            # The loop gave up on this step and retired its session while the line was being written.
            return None, request_id
        outcome = round_trip(request, guardian_url=self.config.guardian_url, posture=posture,
                             session_id=session_id, gate=True)
        if request["params"].get("signature") != signature:
            audit_event("transcript_mismatch", session_id=session_id, method=method, request_id=request_id)
        if isinstance(outcome, Resolution):
            written = write_line(token, lambda: self.transcript.append(session_id, "resp", None, cause=outcome.cause))
        else:
            # round_trip has already verified the response's signature. acs.client accepts HMAC-SHA256 only, and
            # LAB-03 (issue #576) changes its algorithm dispatch to verify by key_id from the key document.
            written = write_line(token, lambda: self.transcript.append(session_id, "resp", outcome.response))
        if not written:
            return None, request_id
        return outcome, request_id
