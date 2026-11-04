#!/usr/bin/env python3
"""Codex hook adapter: a PreToolUse event on stdin becomes a signed steps/toolCallRequest, and the Guardian's answer becomes the hook's output."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from typing import Any

from acs import __version__

from acs.client import (
    Config,
    Resolution,
    Undecided,
    audit_event,
    audit_modify_unsupported,
    open_session,
    round_trip,
)
from acs.core import (
    Decision,
    coerce_uuid,
    method_evaluated,
    modify_composition_violation,
    normalize_decision,
    request_envelope,
)

ADAPTER_VERSION = __version__

METHOD = "steps/toolCallRequest"
MAX_EVENT_BYTES = 1_000_000
# hooks.json.example gives the hook 30 s, which has to cover the handshake and the decision.
MAX_DECISION_S = 10.0
# Codex's shell and patch tools take their input as one command string, and updatedInput can rewrite only that.
COMMAND_TOOLS = frozenset({"Bash", "apply_patch"})
# The adapter denies an event without these rather than invent the identity the Guardian decides on.
REQUIRED_FIELDS = ("session_id", "turn_id", "tool_use_id", "tool_name")


class InvalidEvent(ValueError):
    """A hook event the adapter cannot represent without inventing identity or arguments."""


def _strict_json(raw: str) -> Any:
    """Parse with duplicate keys, NaN and infinities refused, since each lets the Guardian and Codex read different input."""
    def constant(value: str) -> Any:
        raise InvalidEvent("nonfinite_json")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InvalidEvent("duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(raw, parse_constant=constant, object_pairs_hook=unique)
    except InvalidEvent:
        raise
    except ValueError as e:
        raise InvalidEvent("invalid_json") from e


def _check_input(tool_name: str, tool_input: Any) -> None:
    if not isinstance(tool_input, dict):
        raise InvalidEvent("tool_input_not_object")
    if tool_name in COMMAND_TOOLS and not isinstance(tool_input.get("command"), str):
        raise InvalidEvent("command_not_string")


def _check_event(event: dict[str, Any]) -> None:
    for name in REQUIRED_FIELDS:
        value = event.get(name)
        if not isinstance(value, str) or not value.strip():
            raise InvalidEvent(f"missing_{name}")
    _check_input(event["tool_name"], event.get("tool_input"))


def _response(decision: str, reason: str = "", updated_input: dict | None = None) -> dict[str, Any]:
    hso: dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": decision}
    if reason:
        hso["permissionDecisionReason"] = reason
    if updated_input is not None:
        hso["updatedInput"] = updated_input
    return {"hookSpecificOutput": hso}


def _emit(payload: dict[str, Any]) -> None:
    if payload:
        print(json.dumps(payload, allow_nan=False))


def _session_id(event: dict[str, Any]) -> str:
    # Codex session ids need not be UUIDs, and an ACS session_id must be one.
    return coerce_uuid(event["session_id"], namespace_prefix="codex:session")


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return "codex:unknown"
    return f"codex:{hashlib.sha256(cwd.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"


def _metadata(event: dict[str, Any], session_id: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        # Codex's own turn id; the adapter sends no turnStart or turnEnd for it.
        "turn_id": event["turn_id"],
        "platform": "codex",
        "adapter_version": ADAPTER_VERSION,
        "codex_session_id": event["session_id"],
        "codex_tool_use_id": event["tool_use_id"],
    }
    for name in ("cwd", "permission_mode", "model"):
        if isinstance(event.get(name), str) and event[name]:
            metadata[name] = event[name]
    return metadata


def build_request(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)
    # Scoped to the session, since tool_use_id values can repeat across sessions.
    request_id = str(uuid.uuid5(uuid.UUID(session_id), f"codex:tool_use:{event['tool_use_id']}"))
    payload = {
        "tool": {"name": event["tool_name"]},
        "arguments": {k: {"value": v} for k, v in event["tool_input"].items()},
    }
    return request_envelope(METHOD, request_id=request_id, metadata=_metadata(event, session_id), payload=payload)


def translate(decision: Decision, event: dict[str, Any]) -> dict[str, Any]:
    tool_name = event["tool_name"]
    if not decision.known:
        # A decision outside the five dispositions denies under either posture (issue #32).
        audit_event("unusable_disposition", disposition=decision.disposition or "(missing)", hook="PreToolUse")
        return _response("deny", f"unusable Guardian disposition '{decision.disposition}'; failing closed")
    if decision.disposition == "allow":
        # Nothing: Codex then runs the call under its own approval policy and sandbox.
        return {}
    if decision.disposition == "deny":
        return _response("deny", decision.reasoning)
    if decision.disposition in ("ask", "defer"):
        # Codex marks a PreToolUse ask as a failed hook and runs the call, so neither can be passed on.
        audit_event("unenforceable_decision", decision=decision.disposition, hook="PreToolUse", tool=tool_name,
                    reason=decision.reasoning or "(none)", substituted="deny")
        return _response("deny", f"{decision.disposition.upper()} substituted to DENY, since Codex cannot hold "
                                 f"a tool call for approval: {decision.reasoning or '(no reasoning)'}")
    return _translate_modify(decision, event)


def _translate_modify(decision: Decision, event: dict[str, Any]) -> dict[str, Any]:
    tool_name = event["tool_name"]
    modifications = decision.modifications
    # §6.3: a modifications object that breaks the composition rules is a DENY, never half-applied.
    violation = modify_composition_violation(modifications)
    if violation:
        audit_event("modify_composition_invalid", hook="PreToolUse", detail=violation)
        return _response("deny", f"MODIFY refused ({violation}); failing closed per §6.3")
    overrides = modifications.get("parameter_overrides")
    # updatedInput replaces the arguments and nothing else, so any other operation would be dropped (§6.5).
    if set(modifications) != {"parameter_overrides"} or not isinstance(overrides, dict):
        audit_modify_unsupported("Codex applies only parameter_overrides", hook="PreToolUse", tool=tool_name)
        return _response("deny", f"MODIFY substituted to DENY, since Codex applies only parameter_overrides: "
                                 f"{decision.reasoning or '(no reasoning)'}")
    if tool_name in COMMAND_TOOLS and set(overrides) - {"command"}:
        # Codex rewrites only the command of a shell or patch call, so another override would be ignored.
        audit_modify_unsupported(f"{tool_name} takes only a command override", hook="PreToolUse", tool=tool_name)
        return _response("deny", f"MODIFY substituted to DENY, since Codex rewrites only the command of "
                                 f"{tool_name}: {decision.reasoning or '(no reasoning)'}")
    updated = {**event["tool_input"], **overrides}
    try:
        _check_input(tool_name, updated)
    except InvalidEvent as e:
        audit_modify_unsupported(f"the rewritten input fails its check ({e})", hook="PreToolUse", tool=tool_name)
        return _response("deny", f"MODIFY substituted to DENY, since the rewritten input is unusable ({e})")
    # Codex applies updatedInput only with allow (hooks reference, PreToolUse).
    return _response("allow", decision.reasoning, updated_input=updated)


def main() -> int:
    config = Config.from_env(os.environ)
    if sys.argv[1:2] == ["--version"]:
        print(f"acs-adapter (codex) {ADAPTER_VERSION}")
        return 0
    if config.disabled:
        # Every step proceeds ungoverned, so the bypass goes to the durable audit sink (§6.4).
        audit_event("acs_disabled_bypass",
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
        return 0

    raw = sys.stdin.read()
    try:
        if len(raw.encode("utf-8", "surrogatepass")) > MAX_EVENT_BYTES:
            raise InvalidEvent("event_too_large")
        event = _strict_json(raw)
        if not isinstance(event, dict):
            raise InvalidEvent("event_not_object")
        hook_name = event.get("hook_event_name")
        if hook_name != "PreToolUse":
            if not isinstance(hook_name, str) or not hook_name:
                raise InvalidEvent("missing_hook_event_name")
            # Only PreToolUse is mapped; another event is audited, so an ungoverned one is not a quiet one.
            audit_event("unmapped_hook_event", hook=hook_name, session_id=event.get("session_id"))
            return 0
        _check_event(event)
    except InvalidEvent as e:
        return _refuse(str(e))

    session_id = _session_id(event)
    try:
        return _govern(event, session_id, config)
    except Exception as e:  # noqa: BLE001
        # An exit 1 would let Codex run the call, so an adapter error denies it under either posture.
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(config.posture.closed().resolve(Undecided("adapter_exception", {"error": str(e)})),
                       session_id)


def _govern(event: dict[str, Any], session_id: str, config: Config) -> int:
    # §4.1: a refused or unanswered session sends the Guardian nothing; the step is settled here.
    session = open_session(config=config, session_id=session_id, agent_id=_agent_id(event), platform="codex",
                           methods_implemented=[METHOD], profiles_supported=[])
    gated = config.gate(session, METHOD)
    if gated is not None:
        return _settle(gated, session_id)
    server_hello = session.server_hello
    posture = config.posture.negotiated(server_hello)
    if not method_evaluated(server_hello, METHOD):
        # ALLOW-by-default (handshake.json): Codex's own approval policy decides, under either posture.
        audit_event("method_not_evaluated", method=METHOD, hook="PreToolUse", session_id=session_id)
        return 0
    timeout_s = posture.timeout_for(METHOD)
    if timeout_s > MAX_DECISION_S:
        return _refuse("unsupported_decision_timeout", session_id=session_id, timeout_ms=int(timeout_s * 1000))

    result = round_trip(build_request(event), guardian_url=config.guardian_url, posture=posture,
                        session_id=session_id, gate=True)
    if isinstance(result, Resolution):
        return _settle(result, session_id)
    _emit(translate(normalize_decision(result.response.get("result")), event))
    return 0


def _refuse(cause: str, **fields: Any) -> int:
    """Deny a call the adapter cannot put to the Guardian faithfully, under either posture: nothing decided it."""
    audit_event("codex_call_refused", cause=cause, hook="PreToolUse", **fields)
    _emit(_response("deny", f"ACS adapter: {cause}"))
    return 0


def _settle(resolution: Resolution, session_id: str | None) -> int:
    """Carry out a resolution: deny unless it proceeds, and audit which rule decided (§6.4)."""
    if resolution.message:
        sys.stderr.write(f"acs-adapter: {resolution.message}\n")
    if not resolution.proceed:
        _emit(_response("deny", f"ACS adapter: {resolution.label} ({resolution.cause})"))
    audit_event(resolution.audit_type, cause=resolution.cause, hook="PreToolUse",
                session_id=session_id, **resolution.fields)
    return 0


if __name__ == "__main__":
    sys.exit(main())
