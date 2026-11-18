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
    SessionRefused,
    Undecided,
    audit_event,
    open_session,
    ping,
    round_trip,
    sign_envelope,
)
from acs.core import Decision, method_evaluated, normalize_decision, request_envelope, response_shape_problem

from acs_gateway.config import GatewayConfig
from acs_gateway.sessions import Session
from acs_gateway.transcript import Transcript

SESSION_START = "steps/sessionStart"
SESSION_END = "steps/sessionEnd"
TOOL_CALL_REQUEST = "steps/toolCallRequest"
TOOL_CALL_RESULT = "steps/toolCallResult"
METHODS = [SESSION_START, TOOL_CALL_REQUEST, TOOL_CALL_RESULT, SESSION_END]
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
    # The Guardian's ask_details when it answered ask, as sent, for the approver page (LAB-08).
    ask_details: dict[str, Any] | None = None
    # Set when the session must take no further line, with the cause session_retired is audited with.
    retire: str | None = None
    # True once the request went to the Guardian. request_id can be set without a send: an envelope that couldn't be
    # signed, or a step cancelled after its id was minted. A step span claims acs.request_id only when sent (LAB-09).
    sent: bool = False


_MAX_SAFE_INTEGER = 2**53 - 1
_SURROGATE = re.compile("[\ud800-\udfff]")


def jcs_problem(value: Any, depth: int = 0) -> str | None:
    """Why RFC 8785 can't encode value, or None.

    acs.client would rewrite such a value before signing, so the Guardian would judge an envelope other than the one the
    gateway gated. The gateway refuses the step instead, and refusing a gated step denies it.
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
        self._sending = False
        # Whether a send ever started, so a step settled without its answer still says the Guardian got it.
        self.sent = False

    def retire(self) -> bool:
        """Retire the step. True when a write or the send had already started, which can still land but nothing new
        will."""
        with self._lock:
            self._retired = True
            return self._writing > 0 or self._sending

    def begin_send(self) -> bool:
        """Start the send unless the step is retired, decided under the lock as one step with retirement."""
        with self._lock:
            if self._retired:
                return False
            self._sending = True
            self.sent = True
            return True

    def end_send(self) -> None:
        with self._lock:
            self._sending = False

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


class _DiscardUnwritten(Exception):
    """The discards line for a withheld late answer could not be written, so its allow stands unmarked."""


class _StepRetired(Exception):
    """The loop retired the step. Raised inside on_wire, so acs.client refuses the step and sends nothing more."""


class Wire:
    """The on_wire callback for one exchange (PREMORTEM P6). It writes each envelope acs.client sends or receives to
    the transcript exactly once, through the step token, so the request line lands before the send (P20) and a
    retired step writes and sends nothing more.

    After round_trip or open_session returns, its fields say what was written, so the caller adds a gap line only
    for a request that was written and got no envelope back.
    """

    def __init__(self, transcript: Transcript, session_id: str, token: StepToken | None = None) -> None:
        self.transcript = transcript
        self.session_id = session_id
        self.token = token
        self.request_written = False
        # An answer envelope arrived. answer_written says its line landed, answer_cause what that line says.
        self.answer_seen = False
        self.answer_written = False
        self.answer_cause: str | None = None
        # A decoded JSON object that is no JSON-RPC answer. The caller writes it verbatim with the outcome's cause.
        self.body: dict[str, Any] | None = None
        self.sending = False
        self.stopped = False
        # A transcript write that raised. The caller re-raises it, so the step settles as the gateway's own error.
        self.error: BaseException | None = None

    def __call__(self, direction: str, envelope: Any) -> None:
        try:
            if direction == "req":
                self._request(envelope)
            else:
                self._answer(envelope)
        except _StepRetired:
            self.stopped = True
            raise
        except Exception as e:  # noqa: BLE001
            self.error = e
            raise

    def _request(self, envelope: Any) -> None:
        if not write_line(self.token, lambda: self.transcript.append(self.session_id, "req", envelope)):
            raise _StepRetired("the step was retired before its request line")
        self.request_written = True
        if self.token is not None:
            # Checked under the token's lock as one step with retirement, after the line and right before post().
            if not self.token.begin_send():
                raise _StepRetired("the step was retired before the send")
            self.sending = True

    def _answer(self, envelope: Any) -> None:
        if response_shape_problem(envelope) is not None:
            # A body that isn't a JSON-RPC answer, such as a 429's detail, gets its cause only once acs.client has
            # classified it, so the caller writes it then. A JSON object goes in verbatim, so a verifier sees what
            # the Guardian sent. Anything else leaves a gap line.
            if isinstance(envelope, dict):
                self.body = envelope
            return
        self.answer_seen = True
        if self.token is not None and time.monotonic() >= self.token.deadline:
            # An answer that arrives after its deadline keeps its envelope, since the Guardian chained it.
            self.answer_cause = "decision_timeout"
        cause = self.answer_cause
        if not write_line(self.token, lambda: self.transcript.append(self.session_id, "resp", envelope,
                                                                     cause=cause)):
            self.stopped = True
            return
        self.answer_written = True


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

    def open(self, session: Session) -> str | None:
        """Handshake, then sessionStart, so the session's chain roots there (A.4).

        Returns the sessionStart request_id, or None when none was sent, for the session's span (LAB-09).
        """
        sent: list[str] = []

        def start(negotiated: Negotiated) -> Decided | Resolution | None:
            if not method_evaluated(dict(negotiated.server_hello), SESSION_START):
                return None
            outcome, request_id = self._send(session.session_id, SESSION_START, {},
                                             self.posture(negotiated.server_hello))
            # An envelope the gateway couldn't sign never left it, so the session span has no request_id to claim.
            if not (isinstance(outcome, Resolution) and outcome.cause == "envelope_not_signable"):
                sent.append(request_id)
            return outcome

        wire = Wire(self.transcript, session.session_id)
        handshake = open_session(config=self.acs_config, session_id=session.session_id, agent_id=self.config.agent_id,
                                 platform=PLATFORM, methods_implemented=METHODS, start=start, on_wire=wire,
                                 response_keys=self.config.response_keys)
        session.handshake = handshake
        if wire.request_written and not wire.answer_seen and wire.error is None:
            # The ClientHello went out and no envelope came back, so its gap is explicit, as for a step. Nothing
            # else was written in between, since sessionStart follows only a ServerHello.
            try:
                self.transcript.append(session.session_id, "resp", wire.body,
                                       cause=getattr(handshake, "cause", None) or "no_answer")
            except Exception as e:  # noqa: BLE001
                # The same refusal acs.client gives when the ClientHello line fails: the record is incomplete, so
                # the session must not open.
                fields = {"dir": "resp", "method": "handshake/hello", "error": str(e)}
                audit_event("on_wire_failed", **fields)
                handshake = session.handshake = SessionRefused("on_wire_failed", fields)
        hello = dict(handshake.server_hello) if isinstance(handshake, Negotiated) else None
        session.posture = self.posture(hello)
        audit_event("session_opened", session_id=session.session_id, epoch=session.epoch,
                    handshake=type(handshake).__name__, cause=getattr(handshake, "cause", None),
                    guardian_url=self.config.guardian_url)
        return sent[0] if sent else None

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
        try:
            outcome, request_id = self._send(session.session_id, method, payload, posture, token)
        except _DiscardUnwritten as e:
            # repr, since an OSError raised with no arguments has no text at all.
            audit_event("gateway_step_error", session_id=session.session_id, method=method, phase="discard_late",
                        request_id=e.args[0], error=repr(e.__cause__))
            return StepResult(method, e.args[0], cause="decision_timeout", failure_class="timeout",
                              retire="discard_unwritten", sent=True)
        # The token saw whether the send started. Without one (sessionStart inside the handshake), only an envelope
        # the gateway couldn't sign stays unsent.
        if token is not None:
            sent = token.sent
        else:
            sent = not (isinstance(outcome, Resolution) and outcome.cause == "envelope_not_signable")
        if outcome is None:
            return StepResult(method, request_id, cause="decision_timeout", failure_class="timeout", sent=sent)
        if isinstance(outcome, Resolution):
            return StepResult(method, request_id, cause=outcome.cause, failure_class=outcome.fields.get("failure_class"),
                              sent=sent)
        result = outcome.response.get("result") or {}
        codes = result.get("reason_codes")
        details = result.get("ask_details")
        return StepResult(method, request_id, decision=normalize_decision(result),
                          reason_codes=[c for c in codes if isinstance(c, str)] if isinstance(codes, list) else [],
                          ask_details=details if isinstance(details, dict) else None, sent=sent)

    def _send(self, session_id: str, method: str, payload: dict[str, Any], posture: FailPosture,
              token: StepToken | None = None) -> tuple[Decided | Resolution | None, str]:
        """None as the outcome means no answer the gateway may use came in time: the token was cancelled or retired
        first, or the answer arrived after the token's deadline."""
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
        wire = Wire(self.transcript, session_id, token)
        try:
            outcome = round_trip(request, guardian_url=self.config.guardian_url, posture=posture,
                                 session_id=session_id, gate=True, on_wire=wire,
                                 response_keys=self.config.response_keys)
        finally:
            if wire.sending:
                token.end_send()
        if wire.error is not None:
            raise wire.error
        if request["params"].get("signature") != signature:
            audit_event("transcript_mismatch", session_id=session_id, method=method, request_id=request_id)
        if wire.stopped:
            # The loop retired the step, so no line may follow and no answer counts.
            return None, request_id
        # round_trip's own timeout was set before the request line was written, so a slow write lets an answer
        # through after the deadline. Whatever a late answer says, the step times out.
        late = token is not None and time.monotonic() >= token.deadline
        if not wire.answer_seen:
            if wire.request_written:
                # The request went out and no envelope came back, so the gap is explicit.
                cause = "decision_timeout" if late else outcome.cause
                if not write_line(token, lambda: self.transcript.append(session_id, "resp", wire.body, cause=cause)):
                    return None, request_id
            return (None if late else outcome), request_id
        if late:
            if wire.answer_written and wire.answer_cause is None:
                # On time when it arrived, late once its line landed: withheld, and the transcript says so.
                try:
                    self.discard_late(session_id, request_id, token)
                except Exception as e:  # noqa: BLE001
                    raise _DiscardUnwritten(request_id) from e
            return None, request_id
        return outcome, request_id

    def end(self, session: Session, reason: str, token: StepToken) -> StepResult:
        """steps/sessionEnd for a session the gateway is dropping, as one more step of it (rehearsal finding R9).

        reason is session-end.json's: abandoned for an eviction, error or cancelled for a retirement, cancelled for an
        epoch bump or a shutdown. Never raises, like step.
        """
        return self.step(session, SESSION_END, {"reason": reason}, token)

    def discard_late(self, session_id: str, request_id: str, token: StepToken | None) -> None:
        """Mark the answer on the line before as withheld for lateness (lab convention, issue #577)."""
        write_line(token, lambda: self.transcript.append(session_id, "resp", None, cause="decision_timeout",
                                                         discards=request_id))
