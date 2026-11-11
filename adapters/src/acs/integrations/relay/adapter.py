"""Enforce ACS decisions around Relay's managed tool callback."""

from __future__ import annotations

import asyncio
import contextvars
import json
import math
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from acs import __version__
from acs.client import (
    Config,
    FailPosture,
    Negotiated,
    Resolution,
    audit_event,
    audit_modify_unsupported,
    discard_session,
    open_session,
    round_trip,
    validate_guardian_url,
)
from acs.core import (
    method_evaluated,
    modify_composition_violation,
    normalize_decision,
    request_envelope,
)

ADAPTER_VERSION = __version__
METHODS = [
    "steps/sessionStart",
    "steps/toolCallRequest",
    "steps/toolCallResult",
    "steps/sessionEnd",
]


class ACSGuardianDenied(RuntimeError):
    """Execution or delivery of a result was refused; prior tool effects remain."""


@dataclass
class _Session:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    handshake: Any = None
    failures: Counter = field(default_factory=Counter)
    closed: bool = False
    calls: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _json(value):
    # Reject values whose wire representation would differ from execution.
    encoded = json.dumps(value, allow_nan=False)
    decoded = json.loads(encoded)
    if decoded != value:
        raise ValueError("tool value does not round-trip as JSON")
    return decoded


async def _io(function, *args, **kwargs):
    # Let a bounded exchange finish before releasing its session lock or cache.
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await asyncio.shield(task)
        finally:
            raise


class ACSRelay:
    """One execution interceptor, with optional explicit sessions across tool calls.

    Without an explicit session, each managed invocation owns its session. Nested
    managed calls inherit that session. Keep child tasks inside the session scope.
    """

    def __init__(
        self,
        guardian_url="http://127.0.0.1:8787/acs",
        *,
        timeout_s=5.0,
        default_deny=True,
        agent_id="nemo-relay",
    ):
        validate_guardian_url(guardian_url)
        if not isinstance(default_deny, bool):
            raise ValueError("default_deny must be boolean")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or timeout_s <= 0
        ):
            raise ValueError("timeout_s must be positive and finite")
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("agent_id must be non-empty")
        self.config = Config(
            guardian_url, FailPosture(default_deny, timeout_s), True, False
        )
        self.agent_id = agent_id
        self._current = contextvars.ContextVar(f"acs-relay-{id(self)}", default=None)

    def _metadata(self, session):
        return {
            "agent_id": self.agent_id,
            "platform": "nemo-relay",
            "session_id": session.id,
        }

    def _request(self, session, method, payload, request_id=None):
        return request_envelope(
            method,
            request_id=request_id or str(uuid.uuid4()),
            metadata=self._metadata(session),
            payload=payload,
        )

    def _resolution(self, session, method, result):
        if result.decision_failure:
            session.failures[result.fields.get("failure_class", "other")] += 1
        audit_event(
            result.audit_type,
            **{
                **result.fields,
                "cause": result.cause,
                "session_id": session.id,
                "method": method,
            },
        )
        if not result.proceed:
            raise ACSGuardianDenied(result.cause)

    async def _decide(self, session, method, payload, request_id=None):
        if session.closed:
            raise ACSGuardianDenied("session already ended")
        gated = self.config.gate(session.handshake, method)
        if gated is not None:
            self._resolution(session, method, gated)
            return None
        if not method_evaluated(session.handshake.server_hello, method):
            audit_event("method_not_evaluated", method=method, session_id=session.id)
            return None
        request = self._request(session, method, payload, request_id)
        # Serialize exchanges for a session, including concurrent child tasks.
        async with session.lock:
            posture = self.config.posture.negotiated(session.handshake.server_hello)
            result = await _io(
                round_trip,
                request,
                guardian_url=self.config.guardian_url,
                posture=posture,
                session_id=session.id,
                gate=True,
            )
        if isinstance(result, Resolution):
            self._resolution(session, method, result)
            return None
        return normalize_decision(result.response["result"])

    @asynccontextmanager
    async def session(self):
        """Group nested managed calls into one ACS session; nested contexts join it."""
        inherited = self._current.get()
        if inherited is not None:
            if inherited.closed:
                raise ACSGuardianDenied("session already ended")
            yield inherited.id
            return
        session = _Session()
        token = self._current.set(session)
        reason = "completed"
        try:

            def start(hello):
                session.handshake = hello
                if not method_evaluated(hello.server_hello, "steps/sessionStart"):
                    return None
                return round_trip(
                    self._request(session, "steps/sessionStart", {}),
                    guardian_url=self.config.guardian_url,
                    posture=self.config.posture.negotiated(hello.server_hello),
                    session_id=session.id,
                    gate=True,
                )

            session.handshake = await _io(
                open_session,
                config=self.config,
                session_id=session.id,
                agent_id=self.agent_id,
                platform="nemo-relay",
                methods_implemented=METHODS,
                profiles_supported=[],
                start=start,
            )
            gated = self.config.gate(session.handshake)
            if gated is not None:
                self._resolution(session, "steps/sessionStart", gated)
            if (
                isinstance(session.handshake, Negotiated)
                and session.handshake.start_failure
            ):
                failure = session.handshake.start_failure
                session.failures[failure["fields"].get("failure_class", "other")] += 1
            yield session.id
        except asyncio.CancelledError:
            reason = "cancelled"
            raise
        except BaseException:
            reason = "error"
            raise
        finally:
            # Mark before teardown: inherited tasks must never start another call.
            session.closed = True
            try:
                if isinstance(session.handshake, Negotiated) and method_evaluated(
                    session.handshake.server_hello, "steps/sessionEnd"
                ):
                    payload = {
                        "reason": reason,
                        "summary": {
                            "step_count": session.calls,
                            "decision_failures": dict(session.failures),
                        },
                    }
                    request = self._request(session, "steps/sessionEnd", payload)
                    result = await _io(
                        round_trip,
                        request,
                        guardian_url=self.config.guardian_url,
                        posture=self.config.posture.negotiated(
                            session.handshake.server_hello
                        ),
                        session_id=session.id,
                    )
                    if isinstance(result, Resolution):
                        audit_event(
                            result.audit_type,
                            **{
                                **result.fields,
                                "cause": result.cause,
                                "session_id": session.id,
                                "method": "steps/sessionEnd",
                            },
                        )
            finally:
                discard_session(session.id, self.config.guardian_url)
                self._current.reset(token)

    def _apply(self, session, method, decision, value, *, result=False):
        if decision is None or decision.disposition == "allow":
            return value
        if decision.disposition == "modify":
            changes = decision.modifications
            violation = modify_composition_violation(changes)
            if not violation:
                if (
                    not result
                    and set(changes) == {"parameter_overrides"}
                    and isinstance(value, dict)
                ):
                    return _json({**value, **changes["parameter_overrides"]})
                if result and set(changes) == {"modified_content"}:
                    return changes["modified_content"]
            audit_modify_unsupported(
                violation or "unsupported Relay modification shape",
                session_id=session.id,
                method=method,
            )
        audit_event(
            "relay_step_blocked",
            session_id=session.id,
            method=method,
            decision=decision.disposition,
            reasoning=decision.reasoning,
        )
        raise ACSGuardianDenied(f"{method}: {decision.disposition or 'unusable'}")

    async def intercept(self, context, next_call):
        """Evaluate the final Relay request and the caller-visible tool result."""
        import nemo_relay as relay

        async with self.session():
            session = self._current.get()
            session.calls += 1
            args = _json(context.args)
            if not isinstance(args, dict):
                raise ACSGuardianDenied("ACS tool arguments must be a JSON object")
            request_id = str(uuid.uuid4())
            decision = await self._decide(
                session,
                "steps/toolCallRequest",
                {
                    "tool": {"name": context.tool_name},
                    "arguments": {k: {"value": v} for k, v in args.items()},
                },
                request_id,
            )
            args = self._apply(session, "steps/toolCallRequest", decision, args)
            started = time.monotonic()
            try:
                output = await next_call(args)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Do not transmit exception text, which can itself carry secrets.
                failure = {
                    "tool": {"name": context.tool_name},
                    "exit_status": "failure",
                    "outputs": [],
                }
                if method_evaluated(
                    session.handshake.server_hello, "steps/toolCallRequest"
                ):
                    failure["request_id_ref"] = request_id
                await self._decide(session, "steps/toolCallResult", failure)
                raise ACSGuardianDenied(
                    "tool failed; exception details withheld"
                ) from None
            value = _json(output.result)
            payload = {
                "tool": {"name": context.tool_name},
                "exit_status": "success",
                "outputs": [{"value": value}],
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            if method_evaluated(
                session.handshake.server_hello, "steps/toolCallRequest"
            ):
                payload["request_id_ref"] = request_id
            decision = await self._decide(session, "steps/toolCallResult", payload)
            value = self._apply(
                session, "steps/toolCallResult", decision, value, result=True
            )
            # Return only the governed result. Downstream annotations and pending
            # marks could contain the original output and are deliberately omitted.
            return relay.ToolExecutionInterceptOutcome(value)
