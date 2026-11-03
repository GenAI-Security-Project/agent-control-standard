#!/usr/bin/env python3
"""Claude Code hook adapter: a hook event on stdin becomes an ACS step, and the Guardian's answer becomes the hook's output."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from typing import Any, Callable


from acs import __version__

from acs.client import (
    Config,
    count_decision_failure,
    current_session_id,
    decision_failure_counts,
    discard_session_state,
    end_session,
    Decided,
    FailPosture,
    Handshake,
    Negotiated,
    Refused,
    Resolution,
    Undecided,
    audit_event,
    audit_modify_unsupported,
    close_turn,
    current_turn,
    open_session,
    open_turn,
    record_mcp_use,
    round_trip,
    update_session_state,
)
from acs.core import (
    Decision,
    method_evaluated,
    modify_composition_violation,
    normalize_decision,
    request_envelope,
    turn_start_envelope,
)
from acs.integrations.claude_code.hook import _event_name

ADAPTER_VERSION = __version__


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

HOOK_MAP: dict[str, str] = {
    "SessionStart":     "steps/sessionStart",
    "SessionEnd":       "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse":       "steps/toolCallRequest",
    "PostToolUse":      "steps/toolCallResult",
    "PostToolUseFailure": "steps/toolCallResult",
    # Stop ends a turn, not the session.
    "Stop":             "steps/turnEnd",
    # An API error ends the turn with StopFailure instead of Stop.
    "StopFailure":      "steps/turnEnd",
}

# request-envelope.json requires metadata.turn_id on every step between a turnStart and its turnEnd.
_IN_TURN_METHODS = frozenset({
    "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
    "steps/agentResponse", "steps/subagentStart", "steps/turnEnd",
})

# Events deliberately not mapped, with the reason; anything outside
# HOOK_MAP and this set gets an `unmapped_hook_event` audit line.
KNOWN_UNMAPPED: dict[str, str] = {
    # steps/preCompact requires entries_to_compact (minItems 1) and the
    # PreCompact event carries no entry list, so no honest payload exists.
    "PreCompact": "platform exposes no entry list for steps/preCompact",
    "SubagentStop": "its event carries the subagent's agent_id, not the tool_use_id its subagentStart's subagent_session_id comes from",
    "Notification": "fires on permission and idle prompts, not on the model's reply",
}

# Hooks that decide whether an action runs: the tool call and the prompt.
_GATE_HOOKS = frozenset({"PreToolUse", "UserPromptSubmit"})
# Hooks whose step fails closed when its envelope cannot be signed: the gates, and the result the adapter can withhold.
_ENFORCED_HOOKS = _GATE_HOOKS | {"PostToolUse"}

# Hooks whose deny shape is {"decision": "block", "reason": "..."}; on PostToolUse it only adds the reason, so _withhold also replaces the output.
ENFORCEABLE_BLOCK_HOOKS = frozenset({
    "PostToolUse", "UserPromptSubmit",
})

# Claude Code reads a block on Stop as "keep going", so a DENY there is recorded and nothing is emitted.
AUDIT_ONLY_HOOKS = frozenset({
    "Stop", "StopFailure",
})

SESSION_END_REASON_MAP: dict[str, str] = {
    "clear":             "completed",
    # `resume` = the session ended by being resumed into a new one.
    "resume":            "completed",
    "logout":            "abandoned",
    "prompt_input_exit": "abandoned",
    "other":             "completed",
}

# Claude Code's "defer" works only in -p runs, so DEFER substitutes to deny, audited; §9.2 puts substitution on the Guardian.
PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "deny": "deny", "ask": "ask",
}


# ─── Response writers — one definition each, used everywhere ──────────────

def _emit(payload: dict[str, Any]) -> None:
    """Single point where the adapter writes to stdout. Idempotent if
    called with empty dict."""
    if not payload:
        return
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _pretool_response(decision: str, reason: str = "",
                       updated_input: dict | None = None) -> dict[str, Any]:
    """Build Claude Code's PreToolUse response shape."""
    hso: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
    }
    if reason:
        hso["permissionDecisionReason"] = reason
    if updated_input is not None:
        hso["updatedInput"] = updated_input
    return {"hookSpecificOutput": hso}


def _block_response(reason: str, hook_event: str | None = None) -> dict[str, Any]:
    """Claude Code's block shape; Stop must never get one, since Claude Code reads it there as "do not stop"."""
    out: dict[str, Any] = {"decision": "block", "reason": reason}
    if hook_event:
        out["hookSpecificOutput"] = {"hookEventName": hook_event}
    return out


_AGENT_IDS: dict[str, str] = {}


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    session_id = event.get("session_id") or ""
    if session_id not in _AGENT_IDS:
        project = _project_dir(event)
        _AGENT_IDS[session_id] = (f"claude-code:{hashlib.sha256(project.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"
                                  if project else "claude-code:unknown")
    return _AGENT_IDS[session_id]


# Claude Code's cwd follows Claude's cd, so the session's identity comes from where it started.
def _project_dir(event: dict[str, Any]) -> str:
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        return project
    cwd = event.get("cwd") or os.environ.get("PWD") or ""
    session_id = event.get("session_id")
    if not (session_id and cwd):
        return cwd
    opened = update_session_state(session_id, lambda state: state.setdefault("opening_dir", cwd))
    return opened if isinstance(opened, str) and opened else cwd


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _tool_use_request_id(tool_use_id: str | None) -> str | None:
    """Deterministic UUID5 from Claude Code's tool_use_id so PostToolUse
    can populate `request_id_ref` (per tool-call-result.json:19-23)
    linking back to its originating PreToolUse request."""
    if not tool_use_id:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"claude-code:tool_use:{tool_use_id}"))


# ─── Payload builders — dispatch table, one function per hook ──────────────
#
# Each function takes the Claude Code event dict and returns the
# hook-payload portion of the ACS envelope (the part that goes under
# `params.payload`). The dispatch table at the bottom maps hook names
# to these functions; build_payload is then a one-line dispatch.

def _payload_pretool_use(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": event.get("tool_name", "")},
        "arguments": _wrap_arguments(event.get("tool_input") or {}),
    }


def _tool_response(event: dict[str, Any]) -> Any:
    return event.get("tool_response", event.get("tool_output"))


def _payload_post_tool_use(event: dict[str, Any]) -> dict[str, Any]:
    tool_response = _tool_response(event)
    interrupted = isinstance(tool_response, dict) and tool_response.get("interrupted")
    payload: dict[str, Any] = {
        "tool": {"name": event.get("tool_name", "")},
        "exit_status": "failure" if interrupted else "success",
        "outputs": [{"value": tool_response}] if tool_response is not None else [],
    }
    ref = _tool_use_request_id(event.get("tool_use_id"))
    if ref:
        payload["request_id_ref"] = ref
    dur = event.get("duration_ms")
    # tool-call-result.json requires an INTEGER; Claude Code documents
    # duration_ms as a number, so coerce.
    if isinstance(dur, (int, float)) and not isinstance(dur, bool):
        payload["duration_ms"] = int(dur)
    return payload


def _payload_post_tool_use_failure(event: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": {"name": event.get("tool_name", "")},
        "exit_status": "failure",
        "outputs": [{"value": event.get("error") or "(no error message)"}],
    }
    ref = _tool_use_request_id(event.get("tool_use_id"))
    if ref:
        payload["request_id_ref"] = ref
    dur = event.get("duration_ms")
    if isinstance(dur, (int, float)) and not isinstance(dur, bool):
        payload["duration_ms"] = int(dur)
    return payload


def _payload_user_prompt(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "value": event.get("prompt", "")}]}


def build_agent_response_request(event: dict[str, Any]) -> dict[str, Any]:
    """steps/agentResponse for the reply a Stop carries in last_assistant_message, under the open turn."""
    metadata = _metadata(event)
    turn_id = current_turn(event.get("session_id"))
    if turn_id:
        metadata["turn_id"] = turn_id
    return request_envelope("steps/agentResponse", request_id=str(uuid.uuid4()), metadata=metadata,
                            payload={"content": [{"type": "text", "value": event["last_assistant_message"]}]})


def _payload_session_start(event: dict[str, Any]) -> dict[str, Any]:
    ctx = {k: v for k, v in (
        ("source", event.get("source")),
        ("model", event.get("model")),
        ("transcript_path", event.get("transcript_path")),
        ("host_session_id", event.get("host_session_id")),
    ) if v}
    return {"platform_context": ctx} if ctx else {}


def _payload_session_end(event: dict[str, Any]) -> dict[str, Any]:
    name = event.get("hook_event_name", "")
    raw_reason = event.get("reason") or ("completed" if name == "Stop" else "other")
    # §6.4: the session's decision failures per failure class; an empty count says none were recorded.
    counts = decision_failure_counts(event.get("session_id"))
    return {"reason": SESSION_END_REASON_MAP.get(raw_reason, "completed"), "summary": {"decision_failures": counts}}


# ─── Turn tracking ────────────────────────────────────────────────────────
# A turn opens on UserPromptSubmit (an explicit steps/turnStart) and closes
# on Stop (steps/turnEnd). The turn_id lives in the same disk-backed
# per-session state the Cursor adapter uses, so every in-turn step stamps
# metadata.turn_id and the turnEnd carries the matching id.

def _payload_turn_end(event: dict[str, Any]) -> dict[str, Any]:
    turn_id = current_turn(event.get("session_id"))
    outcome = "error" if event.get("hook_event_name") == "StopFailure" else "completed"
    return {"turn_id": turn_id or "", "outcome": outcome}


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "PreToolUse":       _payload_pretool_use,
    "PostToolUse":      _payload_post_tool_use,
    "PostToolUseFailure": _payload_post_tool_use_failure,
    "UserPromptSubmit": _payload_user_prompt,
    "SessionStart":     _payload_session_start,
    "SessionEnd":       _payload_session_end,
    "Stop":             _payload_turn_end,
    "StopFailure":      _payload_turn_end,
}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event.get("hook_event_name", ""))
    return builder(event) if builder else {}


# ─── Envelope construction ──────────────────────────────────────────────────

def _is_subagent_spawn(event: dict[str, Any]) -> bool:
    """True when this PreToolUse IS a subagent spawn.

    Claude Code spawns subagents via the `Agent` tool (hooks reference,
    fetched 2026-08-22); older builds named it `Task`, so match both.
    The separate `TaskCreate` / task-list feature is not a spawn."""
    return (event.get("hook_event_name") == "PreToolUse"
            and _is_subagent_tool(event.get("tool_name")))


def _is_subagent_tool(tool_name: str | None) -> bool:
    return (tool_name or "").lower() in ("agent", "task")


def _payload_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    """steps/subagentStart from PreToolUse on the Agent tool (or legacy Task).

    subagentStart is the confused-deputy spawn gate, which ACS-Core
    requires of a subagent-capable client. Field sources:
      - parent_step_id: this PreToolUse's own deterministic request_id
        (uuid5 of tool_use_id) — the spawn event is the delegation step.
      - subagent_session_id: uuid5 of the tool_use_id under a distinct
        namespace (the child's real session id exists only after spawn).
      - parent_session_id: the actual session_id.
      - intent_derivation: "derived_from_parent" — the prompt is parent-
        authored; "fresh" would claim underived authority.
    """
    tool_use_id = event.get("tool_use_id") or ""
    tool_input = event.get("tool_input") or {}
    if tool_use_id:
        subagent_session_id = str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"claude-code:subagent:{tool_use_id}"))
        parent_step_id = _tool_use_request_id(tool_use_id)
    else:
        # No tool_use_id: both ids are patched in build_request from the
        # envelope's own request_id and the degraded identity is audited.
        audit_event("subagent_spawn_id_unavailable",
                    session_id=event.get("session_id"),
                    detail="PreToolUse(Agent/Task) carried no tool_use_id; "
                           "subagent_session_id and parent_step_id "
                           "derive from the spawn envelope's request_id")
        subagent_session_id = None
        parent_step_id = None
    payload: dict[str, Any] = {
        "subagent_session_id": subagent_session_id,
        "parent_session_id": event.get("session_id", ""),
        "parent_step_id": parent_step_id,
        "intent_derivation": "derived_from_parent",
    }
    descriptor: dict[str, Any] = {}
    if tool_input.get("subagent_type"):
        descriptor["agent_name"] = str(tool_input["subagent_type"])
    if descriptor:
        payload["subagent_descriptor"] = descriptor
    return payload


def build_request(event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event.get("hook_event_name", ""))
    if method is None:
        return {}

    session_id = event.get("session_id")
    if not session_id:
        return {}

    # The Agent tool (legacy: Task) is Claude Code's subagent spawn — route it to the
    # dedicated confused-deputy gate instead of the generic tool hook.
    subagent_spawn = _is_subagent_spawn(event)
    if subagent_spawn:
        method = "steps/subagentStart"

    metadata = _metadata(event)

    # Stamp the open turn's id on in-turn steps (request-envelope.json:69).
    if method in _IN_TURN_METHODS:
        tid = current_turn(session_id)
        if tid:
            metadata["turn_id"] = tid

    # turnEnd needs an open turn; with none the emission is skipped, and main audits it.
    if method == "steps/turnEnd" and not current_turn(session_id):
        return {}

    # For PreToolUse (including the Task→subagentStart remap), pin
    # request_id to a deterministic UUID derived from tool_use_id so the
    # matching PostToolUse can reference it.
    request_id = (_tool_use_request_id(event.get("tool_use_id"))
                  if event.get("hook_event_name") == "PreToolUse"
                  else None) or str(uuid.uuid4())

    payload = (_payload_subagent_start(event) if subagent_spawn
               else build_payload(event))
    if subagent_spawn:
        # No tool_use_id case: the spawn event's own request_id is the
        # honest identity source — it IS the delegation step, and the
        # derived subagent id is unique per spawn instead of a stable
        # uuid5 of the empty string (see _payload_subagent_start).
        if payload.get("parent_step_id") is None:
            payload["parent_step_id"] = request_id
        if payload.get("subagent_session_id") is None:
            payload["subagent_session_id"] = str(uuid.uuid5(
                uuid.NAMESPACE_URL, f"claude-code:subagent:{request_id}"))

    return request_envelope(method, request_id=request_id, metadata=metadata, payload=payload)


def _metadata(event: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": event.get("session_id") or "",
        "platform": "claude-code",
        "adapter_version": ADAPTER_VERSION,
    }
    for k in ("cwd", "transcript_path", "permission_mode"):
        if event.get(k):
            metadata[k] = event[k]
    return metadata


def build_turn_start_request(event: dict[str, Any], turn_id: str) -> dict[str, Any]:
    return turn_start_envelope(_metadata(event), turn_id)


def _open_session(event: dict[str, Any], config: Config) -> Handshake:
    return open_session(
        config=config,
        session_id=event.get("session_id"),
        agent_id=_agent_id(event),
        platform="claude-code",
        # subagentStart and turnStart are emitted but not HOOK_MAP
        # values, so advertise them explicitly.
        methods_implemented=(list(HOOK_MAP.values())
                             + ["steps/subagentStart", "steps/turnStart", "steps/agentResponse"]),
        start=lambda session: _send_session_start(event, session, config),
        count_start_failure=lambda failure: count_decision_failure(event.get("session_id"), failure),
    )


def _send_session_start(event: dict[str, Any], session: Negotiated, config: Config) -> Decided | Resolution | None:
    """The session's one sessionStart, built from whichever hook opened the session."""
    session_id = event.get("session_id")
    if not method_evaluated(session.server_hello, "steps/sessionStart"):
        audit_event("method_not_evaluated", method="steps/sessionStart",
                    hook=event.get("hook_event_name"), session_id=session_id)
        return None
    opening = {k: event[k] for k in ("session_id", "host_session_id", "cwd", "transcript_path", "model", "source")
               if k in event}
    result = round_trip(build_request({**opening, "hook_event_name": "SessionStart"}),
                        guardian_url=config.guardian_url, posture=config.posture.negotiated(session.server_hello),
                        session_id=session_id)
    if isinstance(result, Resolution):
        count_decision_failure(session_id, result.fields.get("failure_class", "other"))
    return result


# Auto mode's SubagentHandback runs without a prompt, so an ask lets it through (hooks reference, PreToolUse ask decisions in auto mode).
_NO_PROMPT_TOOLS = frozenset({"SubagentHandback"})


def _translate_pretool(decision: Decision, original_input: dict, tool_name: str = "") -> dict[str, Any]:
    if decision.disposition == "allow":
        # Nothing: "allow" would skip Claude Code's own permission prompt, so the user's rules still decide.
        return {}
    if decision.disposition == "ask" and tool_name in _NO_PROMPT_TOOLS:
        audit_event("unenforceable_decision", decision="ask", hook="PreToolUse", tool=tool_name,
                    reason=decision.reasoning or "(none)", substituted="deny")
        return _pretool_response("deny", f"ACS Guardian asked for approval {tool_name} cannot hold: "
                                         f"{decision.reasoning or '(no reasoning)'}")
    if decision.disposition in PRETOOL_PERMISSION_MAP:
        return _pretool_response(PRETOOL_PERMISSION_MAP[decision.disposition], decision.reasoning)
    if decision.disposition == "defer":
        audit_event("defer_substituted_deny", hook="PreToolUse")
        return _pretool_response("deny", f"DEFER substituted to DENY: {decision.reasoning}")
    if decision.disposition == "modify":
        # §6.3: a modifications object that breaks the composition rules is a DENY, never half-applied.
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PreToolUse",
                        detail=violation)
            return _pretool_response(
                "deny", f"MODIFY refused ({violation}); failing closed per §6.3")
        if decision.modifications.get("redactions"):
            # updatedInput has no redaction operation, and dropping the redactions would change the decision, so the MODIFY is a DENY.
            audit_modify_unsupported("redactions", hook="PreToolUse")
            return _pretool_response(
                "deny", "MODIFY refused: Claude Code cannot apply the "
                "requested redactions without dropping part of the decision")
        overrides = decision.modifications.get("parameter_overrides")
        # A non-dict override cannot be applied as updatedInput, so §6.5 makes the MODIFY a DENY.
        if isinstance(overrides, dict):
            # updatedInput REPLACES the whole input, so merge the per-
            # argument overrides (modifications.json) onto the original.
            merged = {**original_input, **overrides}
            # "ask" shows the rewritten call to the user; "allow" would also skip their permission prompt.
            return _pretool_response("allow" if tool_name in _NO_PROMPT_TOOLS else "ask", decision.reasoning,
                                     updated_input=merged)
        audit_modify_unsupported("no parameter_overrides object", hook="PreToolUse")
        return _pretool_response(
            "deny",
            f"MODIFY substituted to DENY (no usable parameter_overrides): {decision.reasoning}",
        )
    return {}


def _replacement_output(tool_name: str, text: str) -> Any:
    """Bash's documented output shape holding text, or text for an MCP tool, whose output Claude Code does not validate."""
    if tool_name == "Bash":
        return {"stdout": text, "stderr": "", "interrupted": False, "isImage": False}
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        return text
    return None


# Fields of a built-in tool's output that name a kind rather than carry content.
_SHAPE_FIELDS = frozenset({"type", "mode"})


def _shaped_like(value: Any, text: str) -> Any:
    """value's structure with content strings replaced by text and lists emptied; a built-in tool ignores a replacement that breaks its output schema."""
    if isinstance(value, str):
        return text
    if isinstance(value, list):
        return []
    if isinstance(value, dict):
        return {k: v if k in _SHAPE_FIELDS and isinstance(v, str) else _shaped_like(v, text) for k, v in value.items()}
    return value


def _withhold(tool_name: str, reason: str, tool_response: Any = None) -> dict[str, Any]:
    """Keep a tool's output from Claude: replace it in the tool's own output shape, and record it when no shape is known."""
    out = _block_response(reason, "PostToolUse")
    text = f"[output withheld by the ACS Guardian: {reason}]"
    replacement = _replacement_output(tool_name, text)
    if replacement is None and isinstance(tool_response, (dict, str)):
        replacement = _shaped_like(tool_response, text)
    if replacement is None:
        # A block only adds the reason next to the result; Claude still sees the original output.
        audit_event("unenforceable_decision", hook="PostToolUse", tool=tool_name, reason=reason)
        return out
    out["hookSpecificOutput"]["updatedToolOutput"] = replacement
    return out


def _translate_posttool(decision: Decision, original_input: dict, tool_name: str = "",
                        tool_response: Any = None) -> dict[str, Any]:
    if decision.disposition == "deny":
        return _withhold(tool_name, decision.reasoning or "blocked by Guardian", tool_response)
    if decision.disposition == "modify":
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PostToolUse",
                        detail=violation)
            return _withhold(tool_name, f"MODIFY refused ({violation}); failing closed per §6.3", tool_response)
        updated = decision.modifications.get("modified_content")
        replacement = _replacement_output(tool_name, updated) if isinstance(updated, str) else None
        if replacement is not None:
            hso = {"hookEventName": "PostToolUse", "updatedToolOutput": replacement}
            if decision.reasoning:
                hso["additionalContext"] = decision.reasoning
            return {"hookSpecificOutput": hso}
        audit_modify_unsupported("structured edits on a tool result" if updated is None
                                 else "replacement content for this tool's output shape", hook="PostToolUse", tool=tool_name)
        return _withhold(tool_name, f"MODIFY substituted to DENY: {decision.reasoning}", tool_response)
    if decision.disposition in ("ask", "defer"):
        # The tool already ran and nothing can pause its output for a person.
        return _withhold(tool_name, f"{decision.disposition} on a delivered result: {decision.reasoning}", tool_response)
    return {}


def _translate_posttool_failure(decision: Decision, original_input: dict, tool_name: str = "") -> dict[str, Any]:
    if decision.disposition == "allow":
        return {}
    return _context_only(tool_name, decision.disposition, decision.reasoning)


def _context_only(tool_name: str, disposition: str, reason: str) -> dict[str, Any]:
    """PostToolUseFailure takes only additionalContext, so Claude has already seen the error: say so and record it."""
    if disposition == "modify":
        audit_modify_unsupported("PostToolUseFailure takes no replacement output", hook="PostToolUseFailure",
                                 tool=tool_name)
    audit_event("unenforceable_decision", decision=disposition, hook="PostToolUseFailure", tool=tool_name,
                reason=reason or "(none)")
    return {"hookSpecificOutput": {"hookEventName": "PostToolUseFailure",
                                   "additionalContext": f"ACS Guardian decision on this failed tool result ({disposition}): "
                                                        f"{reason or '(no reasoning)'}"}}


def _translate_user_prompt(decision: Decision, original_input: dict, tool_name: str = "") -> dict[str, Any]:
    if decision.disposition == "allow":
        return {}
    if decision.disposition == "deny":
        return _block_response(decision.reasoning or "blocked by Guardian")
    # The prompt hook can only allow or block, so ask, defer and modify block, audited (§6.4).
    audit_event("prompt_decision_substituted_block",
                disposition=decision.disposition, hook="UserPromptSubmit")
    if decision.disposition == "modify":
        audit_modify_unsupported("the prompt cannot be rewritten", hook="UserPromptSubmit")
    return _block_response(
        f"{decision.disposition} on user prompt not applicable at this hook — blocking: {decision.reasoning}")


def _translate_session_stop(decision: Decision, original_input: dict, tool_name: str = "") -> dict[str, Any]:
    if decision.disposition in ("deny", "ask", "defer"):
        audit_event("unenforceable_decision", decision=decision.disposition,
                    reason=decision.reasoning or "(none)")
    return {}


_TRANSLATORS: dict[str, Callable[[Decision, dict, str], dict[str, Any]]] = {
    "PreToolUse":       _translate_pretool,
    "PostToolUseFailure": _translate_posttool_failure,
    "UserPromptSubmit": _translate_user_prompt,
    "Stop":             _translate_session_stop,
    "StopFailure":      _translate_session_stop,
}


def translate_response(acs_response: dict[str, Any], hook_event: str,
                       original_input: dict | None = None, tool_name: str = "",
                       tool_response: Any = None) -> dict[str, Any]:
    decision = normalize_decision(acs_response.get("result"))

    # A decision outside the five dispositions denies under either posture (issue #32).
    if not decision.known:
        audit_event("unusable_disposition",
                    disposition=decision.disposition or "(missing)", hook=hook_event)
        reason = (f"unusable Guardian disposition '{decision.disposition}' — cannot be "
                  f"interpreted; failing closed (see issue #32)")
        if hook_event == "PreToolUse":
            return _pretool_response("deny", reason)
        if hook_event == "PostToolUse":
            return _withhold(tool_name, reason, tool_response)
        if hook_event == "PostToolUseFailure":
            return _context_only(tool_name, "deny", reason)
        if hook_event in ENFORCEABLE_BLOCK_HOOKS:
            return _block_response(reason)
        return {}

    if hook_event == "PostToolUse":
        return _translate_posttool(decision, original_input or {}, tool_name, tool_response)
    translator = _TRANSLATORS.get(hook_event)
    if translator:
        return translator(decision, original_input or {}, tool_name)

    if decision.reasoning:
        return {"hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": decision.reasoning,
        }}
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

def main() -> int:
    config = Config.from_env(os.environ)
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (claude-code) {ADAPTER_VERSION}")
        return 0
    if config.disabled:
        # Every step proceeds ungoverned, so the bypass goes to the durable audit sink (§6.4).
        audit_event("acs_disabled_bypass",
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
        return 0

    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("the event is not a JSON object")
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        # The hook's own deny shape needs its name, read from the raw text.
        return _settle(config.posture.resolve(Undecided("invalid_stdin_json")), _event_name(raw), None)

    hook_name = event.get("hook_event_name", "")
    if hook_name not in HOOK_MAP:
        if hook_name not in KNOWN_UNMAPPED:
            # Unrecognized hook (upstream rename or newly wired event):
            # audit it so an ungoverned session is not a quiet one.
            audit_event("unmapped_hook_event", hook=hook_name,
                        session_id=event.get("session_id"))
        return 0

    host_session_id = event.get("session_id")
    if host_session_id:
        session_id = current_session_id(host_session_id, config.guardian_url)
        if session_id != host_session_id:
            event = {**event, "session_id": session_id, "host_session_id": host_session_id}
    if hook_name != "SessionEnd" or not host_session_id:
        return _hook(event, hook_name, config)
    try:
        return _hook(event, hook_name, config)
    finally:
        end_session(event["session_id"], config.guardian_url)
        discard_session_state(event["session_id"])


def _hook(event: dict[str, Any], hook_name: str, config: Config) -> int:
    session_id = event.get("session_id")

    # §4.1: a refused or unanswered session sends the Guardian nothing; each step is settled here.
    session = _open_session(event, config)
    gated = config.gate(session, HOOK_MAP.get(hook_name))
    if gated is not None:
        return _settle(gated, hook_name, session_id, tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))
    if hook_name == "SessionStart":
        # The reasoning the Guardian allowed sessionStart with reaches Claude on every SessionStart, resume and compact included.
        if session.start_context:
            _emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": session.start_context}})
        return 0
    server_hello = session.server_hello
    posture = config.posture.negotiated(server_hello)

    try:
        return _govern(event, hook_name, session_id, server_hello, posture, config)
    except Exception as e:  # noqa: BLE001
        # Settled with the session's effective posture; an exit 1 would let the host proceed.
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       hook_name, session_id, tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))


def _govern(event: dict[str, Any], hook_name: str, session_id: str | None,
            server_hello: dict[str, Any], posture: FailPosture, config: Config) -> int:
    tool_name = event.get("tool_name")
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        record_mcp_use(session_id, tool=tool_name)
    # A prompt opens its turn with a decision-eligible turnStart before the userMessage, and a deny blocks the prompt (turn-start.json).
    if hook_name == "UserPromptSubmit":
        _close_interrupted_turn(event, config, posture, server_hello, session_id)
        turn_id = str(uuid.uuid4())
        if method_evaluated(server_hello, "steps/turnStart"):
            result = round_trip(build_turn_start_request(event, turn_id), guardian_url=config.guardian_url, gate=True,
                                posture=posture, session_id=session_id)
            if isinstance(result, Resolution):
                return _settle(result, "UserPromptSubmit", session_id)
            turn_start = normalize_decision(result.response.get("result"))
            if turn_start.disposition != "allow":
                # Only allow applies to a turn start, so any other disposition blocks the prompt.
                audit_event("turn_start_blocked", turn_id=turn_id,
                            disposition=turn_start.disposition or "(unusable)")
                _send_turn_end(event, config, posture, server_hello, session_id, turn_id, "denied_at_start")
                _emit(_block_response(
                    f"turn blocked at start ({turn_start.disposition or 'unusable'}): {turn_start.reasoning}"))
                return 0
        else:
            audit_event("method_not_evaluated", method="steps/turnStart",
                        hook=hook_name, session_id=session_id)
        open_turn(session_id, turn_id)

    if hook_name == "Stop" and isinstance(event.get("last_assistant_message"), str) and event["last_assistant_message"]:
        _send_agent_response(event, config, posture, server_hello, session_id)

    try:
        request = build_request(event)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       hook_name, session_id, tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))
    if not request:
        if hook_name in AUDIT_ONLY_HOOKS:
            audit_event("turn_end_no_open_turn", session_id=session_id)
            return 0
        sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
        return _settle(posture.resolve(Undecided("adapter_build_failed")), hook_name, session_id,
                       tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))

    method = request.get("method", "")
    if not method_evaluated(server_hello, method):
        # ALLOW-by-default (handshake.json): recorded and skipped, never sent
        # or counted as a decision failure.
        audit_event("method_not_evaluated", method=method, hook=hook_name,
                    session_id=session_id)
        if hook_name in AUDIT_ONLY_HOOKS:
            close_turn(session_id)
        return 0
    if method == "steps/toolCallResult":
        origin = ("steps/subagentStart" if _is_subagent_tool(event.get("tool_name"))
                  else "steps/toolCallRequest")
        if not method_evaluated(server_hello, origin):
            # The originating request was never sent, so citing it would dangle.
            request["params"]["payload"].pop("request_id_ref", None)

    result = round_trip(request, guardian_url=config.guardian_url, posture=posture, session_id=session_id,
                        gate=hook_name in _ENFORCED_HOOKS)
    if isinstance(result, Resolution):
        return _settle(result, hook_name, session_id, tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))
    response = result.response

    # A translation bug would exit 1, which the host reads as proceed, so it fails closed here.
    try:
        _emit(translate_response(response, hook_name, original_input=event.get("tool_input") or {},
                                 tool_name=event.get("tool_name") or "", tool_response=_tool_response(event)))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: translate error: {e}\n")
        return _settle(posture.resolve(Refused("adapter_translate_exception", {"error": str(e)})),
                       hook_name, session_id, tool_name=event.get("tool_name") or "",
                       tool_response=_tool_response(event))

    if hook_name in AUDIT_ONLY_HOOKS:
        close_turn(session_id)
    return 0


def _send_agent_response(event: dict[str, Any], config: Config, posture: FailPosture,
                         server_hello: dict, session_id: str | None) -> None:
    """Send the reply Stop carries as steps/agentResponse; it is already delivered, so any decision is recorded, not applied."""
    if not method_evaluated(server_hello, "steps/agentResponse"):
        audit_event("method_not_evaluated", method="steps/agentResponse", hook="Stop", session_id=session_id)
        return
    try:
        request = build_agent_response_request(event)
    except Exception as e:  # noqa: BLE001
        _record(posture.resolve(Undecided("adapter_build_failed", {"error": str(e)})), "Stop",
                "steps/agentResponse", session_id)
        return
    _record(round_trip(request, guardian_url=config.guardian_url, posture=posture, session_id=session_id), "Stop",
            "steps/agentResponse", session_id)


def _close_interrupted_turn(event: dict[str, Any], config: Config, posture: FailPosture,
                            server_hello: dict, session_id: str | None) -> None:
    """Close a turn still open when the next prompt arrives as interrupted: Stop does not run after a user interrupt."""
    turn_id = current_turn(session_id)
    if not turn_id:
        return
    close_turn(session_id)
    _send_turn_end(event, config, posture, server_hello, session_id, turn_id, "interrupted")


def _send_turn_end(event: dict[str, Any], config: Config, posture: FailPosture, server_hello: dict,
                   session_id: str | None, turn_id: str, outcome: str) -> None:
    if not method_evaluated(server_hello, "steps/turnEnd"):
        audit_event("method_not_evaluated", method="steps/turnEnd", hook="UserPromptSubmit", session_id=session_id)
        return
    request = request_envelope("steps/turnEnd", request_id=str(uuid.uuid4()),
                               metadata={**_metadata(event), "turn_id": turn_id},
                               payload={"turn_id": turn_id, "outcome": outcome})
    _record(round_trip(request, guardian_url=config.guardian_url, posture=posture, session_id=session_id),
            "UserPromptSubmit", "steps/turnEnd", session_id)


def _record(result: Decided | Resolution, hook: str, method: str, session_id: str | None) -> None:
    """Record the outcome of a step that already happened: a failure is audited and counted, a decision is not applied."""
    if isinstance(result, Resolution):
        audit_event(result.audit_type, **{**result.fields, "cause": result.cause, "hook": hook,
                                          "method": method, "session_id": session_id})
        if result.decision_failure:
            count_decision_failure(session_id, result.fields.get("failure_class", "other"))
        return
    decision = normalize_decision(result.response.get("result"))
    if decision.disposition == "modify":
        audit_modify_unsupported("the step already happened", hook=hook, method=method, session_id=session_id)
    elif decision.disposition != "allow":
        audit_event("unenforceable_decision", decision=decision.disposition or "(unusable)", hook=hook,
                    method=method, reason=decision.reasoning or "(none)", session_id=session_id)


def _settle(resolution: Resolution, hook_name: str, session_id: str | None, *, tool_name: str = "",
            tool_response: Any = None) -> int:
    """Carry out a resolution: block in the hook's shape unless it proceeds, and audit which rule decided (§6.4)."""
    if resolution.message:
        sys.stderr.write(f"acs-adapter: {resolution.message}\n")
    if not resolution.proceed:
        _emit_deny(hook_name, f"ACS adapter: {resolution.label} ({resolution.cause})", tool_name, tool_response)
    audit_event(resolution.audit_type, cause=resolution.cause, hook=hook_name,
                session_id=session_id, **resolution.fields)
    if resolution.decision_failure:
        count_decision_failure(session_id, resolution.fields.get("failure_class", "other"))
    return 0


def _emit_deny(hook_name: str, msg: str, tool_name: str = "", tool_response: Any = None) -> None:
    if hook_name in AUDIT_ONLY_HOOKS:
        audit_event("unenforceable_decision", hook=hook_name, reason=msg)
        return
    if hook_name == "PreToolUse":
        _emit(_pretool_response("deny", msg))
    elif hook_name == "PostToolUse":
        _emit(_withhold(tool_name, msg, tool_response))
    elif hook_name == "PostToolUseFailure":
        _emit(_context_only(tool_name, "deny", msg))
    elif hook_name in ENFORCEABLE_BLOCK_HOOKS:
        _emit(_block_response(msg))


if __name__ == "__main__":
    sys.exit(main())
