# SPDX-License-Identifier: Apache-2.0
"""FastMCP server middleware and client wrapper speaking the signed ACS v0.1.0 wire contract.

Both surfaces share one session engine backed by ``acs.core`` and ``acs.client``:
each session runs one ``handshake/hello`` and ``steps/sessionStart``, gates every
tool call with ``steps/toolCallRequest`` before execution, reports outcomes with
``steps/toolCallResult`` (linked via ``request_id_ref``), and seals the session
with ``steps/sessionEnd``.

All Guardian HTTP exchanges execute off the asyncio event loop via
``asyncio.to_thread`` so a slow Guardian never stalls FastMCP's event loop.
"""
from __future__ import annotations

import asyncio
import enum
import json
import os
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import asdict, is_dataclass, replace
from typing import Any

from acs import __version__
from acs.client import (
    Config,
    Decided,
    FailPosture,
    Handshake,
    Negotiated,
    Resolution,
    ResponseKeys,
    audit_event,
    audit_modify_unsupported,
    discard_session,
    open_session,
    record_mcp_use,
    response_keys_from_env,
    round_trip,
)
from acs.core import (
    method_evaluated,
    modify_composition_violation,
    normalize_decision,
    request_envelope,
)

ADAPTER_VERSION = __version__
PLATFORM = "fastmcp"

# Advertised methods match emitted methods in both directions.
METHODS_IMPLEMENTED: tuple[str, ...] = (
    "steps/sessionStart",
    "steps/toolCallRequest",
    "steps/toolCallResult",
    "steps/sessionEnd",
)

try:
    from fastmcp.exceptions import ToolError as _FastMCPToolError
    from fastmcp.server.middleware import Middleware as _FastMCPMiddleware
    from fastmcp.tools import ToolResult as _FastMCPToolResult
    from mcp.types import TextContent as _MCPTextContent

    _FASTMCP_AVAILABLE = True
except ImportError:  # pragma: no cover - tested in base env without fastmcp extra
    _FastMCPToolError = Exception  # type: ignore[assignment, misc]
    _FastMCPMiddleware = object  # type: ignore[assignment, misc]
    _FastMCPToolResult = None  # type: ignore[assignment]
    _MCPTextContent = None  # type: ignore[assignment]
    _FASTMCP_AVAILABLE = False


class ACSGuardianDenied(_FastMCPToolError):  # type: ignore[misc]
    """Raised before tool execution when the Guardian denies, refuses, or fails closed."""

    def __init__(self, tool: str, reason: str, *, cause: str = "denied") -> None:
        super().__init__(f"ACS Guardian blocked {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason
        self.cause = cause


class _LossyValue(ValueError):
    """Raised when converting a Python mapping to JSON would collapse colliding keys."""


def _json_key(key: Any) -> str:
    if isinstance(key, str):
        return key
    if key is None or isinstance(key, (bool, int, float)):
        return json.dumps(key)
    return str(key)


def _put_unique(out: dict[str, Any], key: Any, value: Any) -> None:
    name = _json_key(key)
    if name in out:
        raise _LossyValue(
            f"{key!r} and another key both serialize to JSON key {name!r}, "
            "which would drop a value from the Guardian's view"
        )
    out[name] = value


def _keeps_entries(python_val: Any, sent_val: Any) -> bool:
    if isinstance(python_val, Mapping):
        return (
            isinstance(sent_val, dict)
            and len(sent_val) == len(python_val)
            and all(
                _keeps_entries(a, b)
                for a, b in zip(python_val.values(), sent_val.values(), strict=False)
            )
        )
    if isinstance(python_val, (str, bytes, bytearray)):
        return not isinstance(sent_val, (dict, list))
    if isinstance(python_val, Sequence):
        return (
            isinstance(sent_val, list)
            and len(sent_val) == len(python_val)
            and all(
                _keeps_entries(a, b)
                for a, b in zip(python_val, sent_val, strict=False)
            )
        )
    if isinstance(python_val, AbstractSet):
        return isinstance(sent_val, list) and len(sent_val) == len(python_val)
    return not isinstance(sent_val, (dict, list))


def _json_safe(value: Any) -> Any:
    """Convert value to a canonicalizable JSON structure; raise _LossyValue on key collisions."""
    if hasattr(value, "model_dump"):
        try:
            sent = value.model_dump(mode="json")
            raw = value.model_dump(mode="python")
            if not _keeps_entries(raw, sent):
                raise _LossyValue("model keys collide in JSON form")
            return sent
        except _LossyValue:
            raise
        except Exception:  # noqa: BLE001
            return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _json_safe(asdict(value))
    if isinstance(value, enum.Enum):
        return _json_safe(value.value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            _put_unique(out, key, _json_safe(item))
        return out
    if isinstance(value, (Sequence, AbstractSet)) and not isinstance(value, (bytes, bytearray)):
        return [_json_safe(item) for item in value]
    return str(value)


def _wrap_arguments(raw: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Wrap each tool argument in ACS v0.1.0 `{value: ...}` form (tool-call-request.json)."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _build_config(
    *,
    guardian_url: str | None = None,
    default_deny: bool | None = None,
    timeout_s: float | None = None,
    config: Config | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Build Config from environment once, overlaying explicit overrides via dataclasses.replace.

    Never bypasses Config.from_env, so ACS_DISABLED, ACS_STARTUP_POSTURE,
    ACS_HANDSHAKE, ACS_REQUIRE_PROFILES, and ACS_DEFAULT_DENY remain honored.
    """
    base = config if config is not None else Config.from_env(os.environ if env is None else env)
    posture = base.posture
    if default_deny is not None:
        posture = replace(posture, deny_on_failure=bool(default_deny))
    if timeout_s is not None:
        posture = replace(posture, timeout_s=float(timeout_s))
    return replace(
        base,
        guardian_url=guardian_url if guardian_url is not None else base.guardian_url,
        posture=posture,
    )


def _extract_result_value(result: Any) -> Any:
    """Extract a JSON-safe representation of a FastMCP ToolResult or client CallToolResult."""
    if result is None:
        return None
    if hasattr(result, "structured_content") and result.structured_content is not None:
        return _json_safe(result.structured_content)
    if hasattr(result, "data") and result.data is not None:
        return _json_safe(result.data)
    content = getattr(result, "content", None)
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        texts = [
            getattr(item, "text", None)
            for item in content
            if getattr(item, "text", None) is not None
        ]
        if len(texts) == 1:
            return texts[0]
        if texts:
            return "\n".join(texts)
        return _json_safe(content)
    return _json_safe(result)


def _rewrite_tool_result(original: Any, modified_text: str) -> Any:
    """Apply a Guardian MODIFY (`modified_content`) to a FastMCP ToolResult or plain value."""
    if _FASTMCP_AVAILABLE and _FastMCPToolResult is not None and isinstance(original, _FastMCPToolResult):
        sc = original.structured_content
        new_sc: Any = None
        if isinstance(sc, dict) and set(sc) == {"result"}:
            new_sc = {"result": modified_text}
        return _FastMCPToolResult(
            content=[_MCPTextContent(type="text", text=modified_text)],
            structured_content=new_sc,
        )
    if hasattr(original, "content") and _MCPTextContent is not None and hasattr(original, "model_copy"):
        updates: dict[str, Any] = {"content": [_MCPTextContent(type="text", text=modified_text)]}
        if hasattr(original, "data"):
            updates["data"] = modified_text
        if hasattr(original, "structured_content") and isinstance(original.structured_content, dict):
            if set(original.structured_content) == {"result"}:
                updates["structured_content"] = {"result": modified_text}
        return original.model_copy(update=updates)
    return modified_text


def _withhold_tool_result(original: Any, reason: str) -> Any:
    """Withhold a tool output after a post-execution deny/ask/defer/refusal."""
    message = f"[output withheld by ACS Guardian: {reason}]"
    if _FASTMCP_AVAILABLE and _FastMCPToolResult is not None and isinstance(original, _FastMCPToolResult):
        return _FastMCPToolResult(
            content=[_MCPTextContent(type="text", text=message)],
            is_error=True,
        )
    return None


def _extract_call_params(context: Any) -> tuple[str, dict[str, Any]]:
    """Read tool name and arguments from FastMCP MiddlewareContext (4.x and 2.x/3.x shapes)."""
    message = getattr(context, "message", context)
    if hasattr(message, "params") and message.params is not None and not hasattr(message, "name"):
        message = message.params
    name = getattr(message, "name", None)
    if not isinstance(name, str) or not name:
        raise ValueError("FastMCP call_tool context carries no tool name")
    raw_args = getattr(message, "arguments", None)
    if raw_args is None:
        return name, {}
    if isinstance(raw_args, Mapping):
        return name, dict(raw_args)
    raise ValueError(f"FastMCP tool arguments must be a mapping, got {type(raw_args).__name__}")


def _replace_call_arguments(context: Any, updated_args: dict[str, Any]) -> Any:
    """Return a copy of MiddlewareContext with updated tool arguments."""
    message = getattr(context, "message", None)
    if message is None:
        return context
    if hasattr(message, "model_copy"):
        new_msg = message.model_copy(update={"arguments": updated_args})
        if hasattr(context, "copy"):
            return context.copy(message=new_msg)
        if hasattr(context, "model_copy"):
            return context.model_copy(update={"message": new_msg})
    # Fallback for duck-typed contexts in unit tests.
    if hasattr(message, "arguments"):
        message.arguments = updated_args
    return context


class _FastMCPSession:
    """One ACS session shared across all calls of a FastMCP middleware or client scope."""

    def __init__(
        self,
        *,
        config: Config,
        agent_id: str,
        session_id: str | None = None,
        platform_context: Mapping[str, Any] | None = None,
        response_keys: ResponseKeys | None = None,
        on_wire: Callable[[str, Any], None] | None = None,
    ) -> None:
        self.config = config
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.platform_context = dict(platform_context) if platform_context else {}
        self.response_keys = response_keys
        self.on_wire = on_wire

        self._lock = threading.Lock()
        self._handshake: Handshake | None = None
        self._closed = False
        self._step_count = 0
        self._decision_failures: dict[str, int] = {}

    def _metadata(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "platform": PLATFORM,
        }

    def _count_failure(self, failure_class_name: str) -> None:
        with self._lock:
            self._decision_failures[failure_class_name] = (
                self._decision_failures.get(failure_class_name, 0) + 1
            )

    def _record_resolution(self, resolution: Resolution, *, method: str, tool: str | None = None) -> None:
        fields: dict[str, Any] = {
            **resolution.fields,
            "cause": resolution.cause,
            "method": method,
            "session_id": self.session_id,
            "guardian_url": self.config.guardian_url,
        }
        if tool is not None:
            fields["tool"] = tool
        audit_event(resolution.audit_type, **fields)
        if resolution.decision_failure:
            fclass = str(resolution.fields.get("failure_class") or "other")
            self._count_failure(fclass)

    def _send_session_start(self, negotiated: Negotiated) -> Decided | Resolution | None:
        if not method_evaluated(negotiated.server_hello, "steps/sessionStart"):
            audit_event(
                "method_not_evaluated",
                method="steps/sessionStart",
                session_id=self.session_id,
            )
            return None
        payload: dict[str, Any] = {}
        if self.platform_context:
            payload["platform_context"] = _json_safe(self.platform_context)
        req = request_envelope(
            "steps/sessionStart",
            request_id=str(uuid.uuid4()),
            metadata=self._metadata(),
            payload=payload,
        )
        posture = self.config.posture.negotiated(negotiated.server_hello)
        result = round_trip(
            req,
            guardian_url=self.config.guardian_url,
            posture=posture,
            session_id=self.session_id,
            gate=True,
            response_keys=self.response_keys,
            on_wire=self.on_wire,
        )
        if isinstance(result, Resolution) and result.decision_failure:
            fclass = str(result.fields.get("failure_class") or "other")
            self._count_failure(fclass)
        return result

    def _ensure_open_sync(self) -> Handshake:
        with self._lock:
            if self._handshake is not None:
                return self._handshake
            handshake = open_session(
                config=self.config,
                session_id=self.session_id,
                agent_id=self.agent_id,
                platform=PLATFORM,
                methods_implemented=list(METHODS_IMPLEMENTED),
                start=self._send_session_start,
                count_start_failure=self._count_failure,
                response_keys=self.response_keys,
                on_wire=self.on_wire,
            )
            self._handshake = handshake
            return handshake

    async def ensure_open(self) -> Handshake:
        return await asyncio.to_thread(self._ensure_open_sync)

    def _posture_for(self, handshake: Negotiated) -> FailPosture:
        return self.config.posture.negotiated(handshake.server_hello)

    def _gate_request_sync(
        self,
        tool_name: str,
        raw_args: Mapping[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        """Pre-execution gate. Returns (request_id, final_args) or raises ACSGuardianDenied."""
        if self._closed:
            audit_event(
                "call_after_session_end",
                method="steps/toolCallRequest",
                tool=tool_name,
                session_id=self.session_id,
            )
            raise ACSGuardianDenied(tool_name, "ACS session has already ended", cause="session_closed")

        if self.config.disabled:
            return None, dict(raw_args)

        handshake = self._ensure_open_sync()
        gated = self.config.gate(handshake, method="steps/toolCallRequest")
        if gated is not None:
            self._record_resolution(gated, method="steps/toolCallRequest", tool=tool_name)
            if gated.proceed:
                return None, dict(raw_args)
            raise ACSGuardianDenied(
                tool_name,
                gated.message or f"{gated.label} ({gated.cause})",
                cause=gated.cause,
            )

        assert isinstance(handshake, Negotiated)
        if not method_evaluated(handshake.server_hello, "steps/toolCallRequest"):
            audit_event(
                "method_not_evaluated",
                method="steps/toolCallRequest",
                tool=tool_name,
                session_id=self.session_id,
            )
            return None, dict(raw_args)

        try:
            safe_args = _json_safe(raw_args)
        except _LossyValue as exc:
            audit_event(
                "envelope_not_signable",
                method="steps/toolCallRequest",
                tool=tool_name,
                session_id=self.session_id,
                error=str(exc),
                failure_class="observed_agent_error",
                posture="fail_closed",
            )
            self._count_failure("observed_agent_error")
            raise ACSGuardianDenied(tool_name, str(exc), cause="envelope_not_signable") from exc

        req_id = str(uuid.uuid4())
        env = request_envelope(
            "steps/toolCallRequest",
            request_id=req_id,
            metadata=self._metadata(),
            payload={
                "tool": {"name": tool_name, "provider": "mcp"},
                "arguments": _wrap_arguments(safe_args),
            },
        )
        record_mcp_use(self.session_id, tool=tool_name)
        with self._lock:
            self._step_count += 1

        outcome = round_trip(
            env,
            guardian_url=self.config.guardian_url,
            posture=self._posture_for(handshake),
            session_id=self.session_id,
            gate=True,
            response_keys=self.response_keys,
            on_wire=self.on_wire,
        )
        if isinstance(outcome, Resolution):
            self._record_resolution(outcome, method="steps/toolCallRequest", tool=tool_name)
            if outcome.proceed:
                return req_id, dict(safe_args)
            raise ACSGuardianDenied(
                tool_name,
                outcome.message or f"{outcome.label} ({outcome.cause})",
                cause=outcome.cause,
            )

        decision = normalize_decision((outcome.response or {}).get("result"))
        if decision.disposition == "allow":
            return req_id, dict(safe_args)
        if decision.disposition == "modify":
            violation = modify_composition_violation(decision.modifications)
            if violation is not None:
                audit_modify_unsupported(
                    violation,
                    method="steps/toolCallRequest",
                    tool=tool_name,
                    session_id=self.session_id,
                )
                raise ACSGuardianDenied(tool_name, violation, cause="modify_unsupported")
            mods = decision.modifications
            overrides = mods.get("parameter_overrides")
            if (
                not isinstance(overrides, dict)
                or "redactions" in mods
                or "modified_content" in mods
            ):
                detail = "pre-execution MODIFY requires parameter_overrides without redactions or modified_content"
                audit_modify_unsupported(
                    detail,
                    method="steps/toolCallRequest",
                    tool=tool_name,
                    session_id=self.session_id,
                )
                raise ACSGuardianDenied(tool_name, detail, cause="modify_unsupported")
            merged = {**safe_args, **overrides}
            return req_id, merged
        if decision.disposition in ("ask", "defer"):
            audit_event(
                "disposition_substituted_deny",
                method="steps/toolCallRequest",
                tool=tool_name,
                session_id=self.session_id,
                original_decision=decision.disposition,
                reasoning=decision.reasoning,
            )
            raise ACSGuardianDenied(
                tool_name,
                decision.reasoning or f"{decision.disposition} substituted to deny at FastMCP boundary",
                cause=decision.disposition,
            )
        if decision.disposition == "deny":
            raise ACSGuardianDenied(tool_name, decision.reasoning or "denied by Guardian", cause="deny")
        # Unknown disposition -> fail closed regardless of posture (§6.4).
        audit_event(
            "malformed_response",
            method="steps/toolCallRequest",
            tool=tool_name,
            session_id=self.session_id,
            decision=decision.disposition,
            failure_class="malformed_response",
            posture="fail_closed",
        )
        self._count_failure("malformed_response")
        raise ACSGuardianDenied(
            tool_name,
            f"unknown Guardian disposition {decision.disposition!r}",
            cause="malformed_response",
        )

    async def gate_request(
        self,
        tool_name: str,
        raw_args: Mapping[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        return await asyncio.to_thread(self._gate_request_sync, tool_name, raw_args)

    def _gate_result_sync(
        self,
        tool_name: str,
        request_id_ref: str | None,
        output_value: Any,
        *,
        exit_status: str,
        duration_ms: int,
    ) -> tuple[str, str | None]:
        """Post-execution gate. Returns ('allow', None), ('modify', text), or ('withhold', reason)."""
        if self.config.disabled or self._closed:
            return "allow", None

        handshake = self._handshake
        if handshake is None:
            return "allow", None
        gated = self.config.gate(handshake, method="steps/toolCallResult")
        if gated is not None:
            self._record_resolution(gated, method="steps/toolCallResult", tool=tool_name)
            return ("allow", None) if gated.proceed else ("withhold", gated.message or gated.cause)

        assert isinstance(handshake, Negotiated)
        if not method_evaluated(handshake.server_hello, "steps/toolCallResult"):
            audit_event(
                "method_not_evaluated",
                method="steps/toolCallResult",
                tool=tool_name,
                session_id=self.session_id,
            )
            return "allow", None

        try:
            safe_out = _json_safe(output_value)
        except _LossyValue as exc:
            audit_event(
                "envelope_not_signable",
                method="steps/toolCallResult",
                tool=tool_name,
                session_id=self.session_id,
                error=str(exc),
                failure_class="observed_agent_error",
                posture="fail_closed",
            )
            self._count_failure("observed_agent_error")
            return "withhold", str(exc)

        payload: dict[str, Any] = {
            "tool": {"name": tool_name, "provider": "mcp"},
            "exit_status": exit_status,
            "outputs": [{"value": safe_out}],
            "duration_ms": max(0, int(duration_ms)),
        }
        if request_id_ref is not None:
            payload["request_id_ref"] = request_id_ref

        env = request_envelope(
            "steps/toolCallResult",
            request_id=str(uuid.uuid4()),
            metadata=self._metadata(),
            payload=payload,
        )
        with self._lock:
            self._step_count += 1

        outcome = round_trip(
            env,
            guardian_url=self.config.guardian_url,
            posture=self._posture_for(handshake),
            session_id=self.session_id,
            gate=True,
            response_keys=self.response_keys,
            on_wire=self.on_wire,
        )
        if isinstance(outcome, Resolution):
            self._record_resolution(outcome, method="steps/toolCallResult", tool=tool_name)
            if outcome.proceed:
                return "allow", None
            return "withhold", outcome.message or outcome.cause

        decision = normalize_decision((outcome.response or {}).get("result"))
        if decision.disposition == "allow":
            return "allow", None
        if decision.disposition == "modify":
            violation = modify_composition_violation(decision.modifications)
            if violation is not None:
                audit_modify_unsupported(
                    violation,
                    method="steps/toolCallResult",
                    tool=tool_name,
                    session_id=self.session_id,
                )
                return "withhold", violation
            modified = decision.modifications.get("modified_content")
            if isinstance(modified, str):
                return "modify", modified
            detail = "post-execution MODIFY requires modified_content string"
            audit_modify_unsupported(
                detail,
                method="steps/toolCallResult",
                tool=tool_name,
                session_id=self.session_id,
            )
            return "withhold", detail
        if decision.disposition in ("deny", "ask", "defer"):
            audit_event(
                "tool_result_withheld",
                method="steps/toolCallResult",
                tool=tool_name,
                session_id=self.session_id,
                decision=decision.disposition,
                reasoning=decision.reasoning,
            )
            return "withhold", decision.reasoning or f"output withheld ({decision.disposition})"
        audit_event(
            "malformed_response",
            method="steps/toolCallResult",
            tool=tool_name,
            session_id=self.session_id,
            decision=decision.disposition,
            failure_class="malformed_response",
            posture="fail_closed",
        )
        self._count_failure("malformed_response")
        return "withhold", f"unknown disposition {decision.disposition!r}"

    async def gate_result(
        self,
        tool_name: str,
        request_id_ref: str | None,
        output_value: Any,
        *,
        exit_status: str,
        duration_ms: int,
    ) -> tuple[str, str | None]:
        return await asyncio.to_thread(
            self._gate_result_sync,
            tool_name,
            request_id_ref,
            output_value,
            exit_status=exit_status,
            duration_ms=duration_ms,
        )

    def close_sync(self, reason: str = "completed") -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            handshake = self._handshake
            step_count = self._step_count
            failures = dict(self._decision_failures)

        try:
            if self.config.disabled or not isinstance(handshake, Negotiated):
                return
            gated = self.config.gate(handshake, method="steps/sessionEnd")
            if gated is not None:
                return
            if not method_evaluated(handshake.server_hello, "steps/sessionEnd"):
                return
            env = request_envelope(
                "steps/sessionEnd",
                request_id=str(uuid.uuid4()),
                metadata=self._metadata(),
                payload={
                    "reason": reason,
                    "summary": {
                        "step_count": step_count,
                        "decision_failures": failures,
                    },
                },
            )
            round_trip(
                env,
                guardian_url=self.config.guardian_url,
                posture=self._posture_for(handshake),
                session_id=self.session_id,
                gate=False,
                response_keys=self.response_keys,
                on_wire=self.on_wire,
            )
        finally:
            discard_session(self.session_id, self.config.guardian_url)

    async def aclose(self, reason: str = "completed") -> None:
        await asyncio.to_thread(self.close_sync, reason)


class ACSFastMCPMiddleware(_FastMCPMiddleware):  # type: ignore[misc]
    """FastMCP server middleware enforcing ACS verdicts around every ``tools/call``.

    Attach to any ``FastMCP`` server via ``mcp.add_middleware(ACSFastMCPMiddleware(...))``
    or pass in ``FastMCP("my-server", middleware=[ACSFastMCPMiddleware(...)])``.
    """

    def __init__(
        self,
        *,
        guardian_url: str | None = None,
        agent_id: str | None = None,
        default_deny: bool | None = None,
        timeout_s: float | None = None,
        session_id: str | None = None,
        platform_context: Mapping[str, Any] | None = None,
        config: Config | None = None,
        response_keys: ResponseKeys | None = None,
        on_wire: Callable[[str, Any], None] | None = None,
    ) -> None:
        self._config = _build_config(
            guardian_url=guardian_url,
            default_deny=default_deny,
            timeout_s=timeout_s,
            config=config,
        )
        resolved_agent_id = agent_id or os.environ.get("ACS_AGENT_ID") or "fastmcp-server"
        resolved_keys = response_keys if response_keys is not None else response_keys_from_env(os.environ)
        self._session = _FastMCPSession(
            config=self._config,
            agent_id=resolved_agent_id,
            session_id=session_id,
            platform_context=platform_context,
            response_keys=resolved_keys,
            on_wire=on_wire,
        )

    @property
    def session_id(self) -> str:
        return self._session.session_id

    async def __aenter__(self) -> ACSFastMCPMiddleware:
        if not self._config.disabled:
            await self._session.ensure_open()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        reason = "error" if exc_type is not None else "completed"
        await self._session.aclose(reason=reason)

    async def aclose(self, reason: str = "completed") -> None:
        await self._session.aclose(reason=reason)

    def close(self, reason: str = "completed") -> None:
        self._session.close_sync(reason=reason)

    async def on_call_tool(
        self,
        context: Any,
        call_next: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        tool_name, raw_args = _extract_call_params(context)
        req_id, final_args = await self._session.gate_request(tool_name, raw_args)
        call_context = (
            _replace_call_arguments(context, final_args)
            if final_args != raw_args
            else context
        )
        started = time.monotonic()
        try:
            result = await call_next(call_context)
        except Exception as tool_exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            await self._session.gate_result(
                tool_name,
                req_id,
                {"error": str(tool_exc), "error_type": type(tool_exc).__name__},
                exit_status="failure",
                duration_ms=duration_ms,
            )
            # Propagate tool exceptions unchanged; never disguise a tool failure as a Guardian deny.
            raise

        duration_ms = int((time.monotonic() - started) * 1000)
        action, detail = await self._session.gate_result(
            tool_name,
            req_id,
            _extract_result_value(result),
            exit_status="success",
            duration_ms=duration_ms,
        )
        if action == "modify" and detail is not None:
            return _rewrite_tool_result(result, detail)
        if action == "withhold":
            return _withhold_tool_result(result, detail or "denied by Guardian")
        return result


class GovernedFastMCPClient:
    """FastMCP client wrapper enforcing signed ACS verdicts around ``call_tool``.

    Use as an async context manager so all calls share one ACS session and one
    handshake, ending with ``steps/sessionEnd`` on exit::

        async with GovernedFastMCPClient(Client(mcp)) as client:
            result = await client.call_tool("greet", {"name": "acs"})
    """

    def __init__(
        self,
        inner: Any,
        *,
        guardian_url: str | None = None,
        agent_id: str | None = None,
        default_deny: bool | None = None,
        timeout_s: float | None = None,
        session_id: str | None = None,
        platform_context: Mapping[str, Any] | None = None,
        config: Config | None = None,
        response_keys: ResponseKeys | None = None,
        on_wire: Callable[[str, Any], None] | None = None,
    ) -> None:
        self._inner = inner
        self._entered_inner = False
        self._config = _build_config(
            guardian_url=guardian_url,
            default_deny=default_deny,
            timeout_s=timeout_s,
            config=config,
        )
        resolved_agent_id = agent_id or os.environ.get("ACS_AGENT_ID") or "fastmcp-client"
        resolved_keys = response_keys if response_keys is not None else response_keys_from_env(os.environ)
        self._session = _FastMCPSession(
            config=self._config,
            agent_id=resolved_agent_id,
            session_id=session_id,
            platform_context=platform_context,
            response_keys=resolved_keys,
            on_wire=on_wire,
        )

    @property
    def session_id(self) -> str:
        return self._session.session_id

    async def __aenter__(self) -> GovernedFastMCPClient:
        if hasattr(self._inner, "__aenter__"):
            await self._inner.__aenter__()
            self._entered_inner = True
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        reason = "error" if exc_type is not None else "completed"
        try:
            await self._session.aclose(reason=reason)
        finally:
            if self._entered_inner and hasattr(self._inner, "__aexit__"):
                self._entered_inner = False
                await self._inner.__aexit__(exc_type, exc, tb)

    async def aclose(self, reason: str = "completed") -> None:
        await self._session.aclose(reason=reason)

    def close(self, reason: str = "completed") -> None:
        self._session.close_sync(reason=reason)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Govern a tool call pre- and post-execution before returning the result."""
        raw_args = dict(arguments) if arguments is not None else {}
        req_id, final_args = await self._session.gate_request(name, raw_args)
        started = time.monotonic()
        try:
            result = await self._inner.call_tool(name, final_args, **kwargs)
        except Exception as tool_exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            await self._session.gate_result(
                name,
                req_id,
                {"error": str(tool_exc), "error_type": type(tool_exc).__name__},
                exit_status="failure",
                duration_ms=duration_ms,
            )
            raise

        duration_ms = int((time.monotonic() - started) * 1000)
        action, detail = await self._session.gate_result(
            name,
            req_id,
            _extract_result_value(result),
            exit_status="success",
            duration_ms=duration_ms,
        )
        if action == "modify" and detail is not None:
            return _rewrite_tool_result(result, detail)
        if action == "withhold":
            raise ACSGuardianDenied(name, detail or "output withheld by Guardian", cause="output_withheld")
        return result
