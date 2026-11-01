#!/usr/bin/env python3
"""
ACS adapter for Claude Code hooks.

Translates a Claude Code hook event (read from stdin as JSON) into an
ACS JSON-RPC request, signs it (HMAC-SHA256 baseline per Specification
§10 when ACS_HMAC_SECRET is set), sends it to a Guardian, and
translates the ACS response back to Claude Code's expected output.

Wire-format ground truth: GenAI-Security-Project/agent-control-standard specification/v0.1.0/

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    "1" = fail-closed on adapter error or unknown
                      Guardian disposition. Default: "0" (spec default
                      per §6.4 is fail-open with audit event). Switch
                      to "1" for production deployments that prefer
                      fail-closed availability tradeoff. The negotiated
                      ServerHello's `on_decision_failure` also applies:
                      the adapter fails closed when EITHER this env var
                      or the Guardian's declared posture says deny
                      (most-restrictive-wins).
                      Guardian REFUSALS (SIGNATURE_INVALID, REPLAY_DETECTED,
                      oversized/malformed envelope, …) always fail closed
                      regardless of posture — a refusal is an alive
                      Guardian rejecting the envelope, and every refusal
                      is attacker-reachable (see GUARDIAN_REFUSAL_CODES).
  ACS_HMAC_SECRET     Shared secret for baseline HMAC-SHA256 envelope
                      signing per §10 (or ACS_HMAC_SECRET_FILE, preferred
                      for production). If unset, requests are unsigned
                      (local-dev mode, loud audit event). ACS-Core
                      conformance requires one of these to be set.
  ACS_AGENT_ID        Explicit agent_id for metadata. If unset, derived
                      from cwd as `claude-code:<sha8(cwd)>`.
  ACS_STARTUP_POSTURE "proceed" or "refuse": what this hook does in a
                      session with no negotiated Guardian, because its
                      handshake got no answer (§4.1). "proceed" lets the
                      step run with nothing sent to the Guardian, "refuse"
                      denies it; the session keeps no negotiated Guardian
                      for its lifetime. Unset follows ACS_DEFAULT_DENY.
  ACS_HANDSHAKE       "0" skips the handshake, so the session gets no
                      answer and ACS_STARTUP_POSTURE settles every step.
                      Default "1". Each session's decision is stored in
                      ~/.cache/acs-adapter-handshake/ for its lifetime.
  ACS_AUDIT_FILE      Append every ACS_AUDIT event to this file (0600)
                      in addition to stderr, so the §6.4 audit half of
                      the fail-open trade lands somewhere durable.
  ACS_DISABLED        "1" = incident kill switch: the adapter exits
                      immediately with no Guardian traffic and no output
                      (one stderr line). Use when a degraded Guardian is
                      stalling every hook and you need the agent usable
                      NOW; re-enable by unsetting. Documented incident
                      procedure — faster and more reversible than
                      hand-editing settings.json per machine.
"""
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
    Decided,
    FailPosture,
    Handshake,
    Negotiated,
    Refused,
    Resolution,
    Undecided,
    audit_event,
    close_turn,
    current_turn,
    open_session,
    open_turn,
    record_mcp_use,
    round_trip,
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
    "Notification":     "steps/agentResponse",
    # Stop fires at the end of a TURN (every reply), not the session;
    # the turn is opened by steps/turnStart on UserPromptSubmit.
    "Stop":             "steps/turnEnd",
}

# In-turn steps carry metadata.turn_id (request-envelope.json:69); session-
# level steps (sessionStart/sessionEnd) and the spawn gate do not open under
# the parent's turn. turnStart sets it; turnEnd echoes it.
_IN_TURN_METHODS = frozenset({
    "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
    "steps/agentResponse", "steps/turnEnd",
})

# Events deliberately not mapped, with the reason; anything outside
# HOOK_MAP and this set gets an `unmapped_hook_event` audit line.
KNOWN_UNMAPPED: dict[str, str] = {
    # steps/preCompact requires entries_to_compact (minItems 1) and the
    # PreCompact event carries no entry list, so no honest payload exists.
    "PreCompact": "platform exposes no entry list for steps/preCompact",
    # steps/subagentStop requires final_chain_hash and Claude Code keeps
    # no chain; wired once the schema PR making it optional lands (mapping.md).
    "SubagentStop": "final_chain_hash required by current schema and unknowable (no chain)",
}

# Hooks whose deny shape is {"decision": "block", "reason": "..."} AND whose
# block actually prevents the action.
ENFORCEABLE_BLOCK_HOOKS = frozenset({
    "PostToolUse", "UserPromptSubmit",
})

# Claude Code reads {"decision":"block"} on Stop as "do not stop, keep
# going" (hooks.md:290 — the turn already happened), so a DENY here is
# recorded and nothing is emitted.
AUDIT_ONLY_HOOKS = frozenset({
    "Stop",
})

SESSION_END_REASON_MAP: dict[str, str] = {
    "clear":             "completed",
    # `resume` = the session ended by being resumed into a new one.
    "resume":            "completed",
    "logout":            "abandoned",
    "prompt_input_exit": "abandoned",
    "other":             "completed",
}

# permissionDecision accepts allow | deny | ask (no native "defer"), so
# DEFER substitutes to deny, audited. Deployment behavior, not spec-
# mandated: §9.2 puts disposition substitution on the Guardian.
PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask",
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
    """Build Claude Code's generic block shape, used only by the hooks
    where a block actually prevents the action: PostToolUse and
    UserPromptSubmit (ENFORCEABLE_BLOCK_HOOKS). Stop must never receive
    one — Claude Code reads a block there as "do not stop"."""
    out: dict[str, Any] = {"decision": "block", "reason": reason}
    if hook_event:
        out["hookSpecificOutput"] = {"hookEventName": hook_event}
    return out


# ─── Helpers ────────────────────────────────────────────────────────────────

def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd") or os.environ.get("PWD") or ""
    if cwd:
        return f"claude-code:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "claude-code:unknown"


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


def _payload_post_tool_use(event: dict[str, Any]) -> dict[str, Any]:
    tool_response = event.get("tool_response", event.get("tool_output"))
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


def _payload_user_prompt(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "value": event.get("prompt", "")}]}


def _payload_notification(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "value": event.get("message", "")}]}


def _payload_session_start(event: dict[str, Any]) -> dict[str, Any]:
    ctx = {k: v for k, v in (
        ("source", event.get("source")),
        ("model", event.get("model")),
        ("transcript_path", event.get("transcript_path"))
    ) if v}
    return {"platform_context": ctx} if ctx else {}


def _payload_session_end(event: dict[str, Any]) -> dict[str, Any]:
    name = event.get("hook_event_name", "")
    raw_reason = event.get("reason") or ("completed" if name == "Stop" else "other")
    return {"reason": SESSION_END_REASON_MAP.get(raw_reason, "completed")}


# ─── Turn tracking ────────────────────────────────────────────────────────
# A turn opens on UserPromptSubmit (an explicit steps/turnStart) and closes
# on Stop (steps/turnEnd). The turn_id lives in the same disk-backed
# per-session state the Cursor adapter uses, so every in-turn step stamps
# metadata.turn_id and the turnEnd carries the matching id.

def _turn_ws(event: dict[str, Any]) -> str | None:
    return event.get("cwd") or None


def _payload_turn_end(event: dict[str, Any]) -> dict[str, Any]:
    """steps/turnEnd — closes the turn opened at the last UserPromptSubmit.
    turn_id comes from session state (empty if no turn is open, in which
    case build_request skips the emission). Claude's Stop fires on normal
    turn completion and carries no error discriminator, so outcome is
    'completed'."""
    turn_id = current_turn(event.get("session_id"), workspace=_turn_ws(event))
    return {"turn_id": turn_id or "", "outcome": "completed"}


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "PreToolUse":       _payload_pretool_use,
    "PostToolUse":      _payload_post_tool_use,
    "UserPromptSubmit": _payload_user_prompt,
    "Notification":     _payload_notification,
    "SessionStart":     _payload_session_start,
    "SessionEnd":       _payload_session_end,
    "Stop":             _payload_turn_end,
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
        tid = current_turn(session_id, workspace=_turn_ws(event))
        if tid:
            metadata["turn_id"] = tid

    # steps/turnEnd needs a turn_id (>=1); if no turn is open there is
    # nothing to close honestly, so skip the emission (main audits it).
    if method == "steps/turnEnd" and not current_turn(session_id, workspace=_turn_ws(event)):
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


def _open_session(event: dict[str, Any], config: Config, started: list | None = None) -> Handshake:
    """The session's §4.1 decision. The first event of a session_id handshakes, stores
    the decision and sends sessionStart; every later hook process of that session reads
    the decision without a network call."""
    return open_session(
        config=config,
        session_id=event.get("session_id"),
        agent_id=_agent_id(event),
        platform="claude-code",
        # subagentStart and turnStart are emitted but not HOOK_MAP
        # values, so advertise them explicitly.
        methods_implemented=(list(HOOK_MAP.values())
                             + ["steps/subagentStart", "steps/turnStart"]),
        start=lambda session: _send_session_start(event, session, config, started),
    )


def _send_session_start(event: dict[str, Any], session: Negotiated, config: Config,
                        started: list | None) -> Decided | Resolution | None:
    """The session's one sessionStart, built from whichever hook opened the session; the session chain roots there (§8)."""
    session_id = event.get("session_id")
    if not method_evaluated(session.server_hello, "steps/sessionStart"):
        audit_event("method_not_evaluated", method="steps/sessionStart",
                    hook=event.get("hook_event_name"), session_id=session_id)
        return None
    opening = {k: event[k] for k in ("session_id", "cwd", "transcript_path", "model", "source") if k in event}
    result = round_trip(build_request({**opening, "hook_event_name": "SessionStart"}),
                        guardian_url=config.guardian_url, posture=config.posture.negotiated(session.server_hello),
                        session_id=session_id)
    if isinstance(result, Decided) and started is not None:
        started.append(result)
    return result


# ─── Response translation — dispatch table, one function per hook ─────────

def _translate_pretool(decision: Decision, original_input: dict) -> dict[str, Any]:
    if decision.disposition in PRETOOL_PERMISSION_MAP:
        return _pretool_response(PRETOOL_PERMISSION_MAP[decision.disposition], decision.reasoning)
    if decision.disposition == "defer":
        # No native defer in permissionDecision; spec default
        # timeout_decision is deny (§6). Audited so substitution rate
        # is machine-visible.
        audit_event("defer_substituted_deny", hook="PreToolUse")
        return _pretool_response(
            "deny", f"DEFER substituted to DENY (no native defer): {decision.reasoning}")
    if decision.disposition == "modify":
        # §6.3:146 — a modifications object that breaks the composition
        # rules (both shapes, or overlapping structured targets) is
        # un-interpretable; fail closed to DENY rather than half-apply it.
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PreToolUse",
                        detail=violation)
            return _pretool_response(
                "deny", f"MODIFY refused ({violation}); failing closed per §6.3:146")
        if decision.modifications.get("redactions"):
            # Claude's updatedInput can replace arguments, but it exposes no
            # native JSON-Pointer redaction operation.  Applying sibling
            # parameter_overrides while dropping redactions would change the
            # Guardian's decision. Treat the valid-but-unrealizable compound
            # edit as DENY until the whole modification can be applied.
            audit_event("modify_unapplied_redactions", hook="PreToolUse")
            return _pretool_response(
                "deny", "MODIFY refused: Claude Code cannot apply the "
                "requested redactions without dropping part of the decision")
        overrides = decision.modifications.get("parameter_overrides")
        # A non-dict override cannot be applied as updatedInput; §6.3:146
        # fails an unrealizable modification closed to DENY.
        if isinstance(overrides, dict):
            # updatedInput REPLACES the whole input, so merge the per-
            # argument overrides (modifications.json) onto the original.
            merged = {**original_input, **overrides}
            return _pretool_response("allow", decision.reasoning, updated_input=merged)
        return _pretool_response(
            "deny",
            f"MODIFY substituted to DENY (no usable parameter_overrides): {decision.reasoning}",
        )
    return {}


def _translate_posttool(decision: Decision, original_input: dict) -> dict[str, Any]:
    if decision.disposition == "deny":
        return _block_response(decision.reasoning or "blocked by Guardian", "PostToolUse")
    if decision.disposition == "modify":
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PostToolUse",
                        detail=violation)
            return _block_response(
                f"MODIFY refused ({violation}); failing closed per §6.3:146")
        updated = decision.modifications.get("modified_content")
        if updated is not None:
            hso = {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": str(updated),
            }
            if decision.reasoning:
                hso["additionalContext"] = decision.reasoning
            return {"hookSpecificOutput": hso}
        return _block_response(
            f"MODIFY substituted to DENY (no modified_content): {decision.reasoning}")
    if decision.disposition in ("ask", "defer"):
        return _block_response(
            f"{decision.disposition} on post-tool not supported by Claude Code: {decision.reasoning}")
    return {}


def _translate_user_prompt(decision: Decision, original_input: dict) -> dict[str, Any]:
    if decision.disposition == "allow":
        return {}
    if decision.disposition == "deny":
        return _block_response(decision.reasoning or "blocked by Guardian")
    # The prompt hook can only allow or block, so ask, defer and modify block, audited (§6.4).
    audit_event("prompt_decision_substituted_block",
                disposition=decision.disposition, hook="UserPromptSubmit")
    return _block_response(
        f"{decision.disposition} on user prompt not applicable at this hook — blocking: {decision.reasoning}")


def _translate_session_stop(decision: Decision, original_input: dict) -> dict[str, Any]:
    """Stop (steps/turnEnd) is not decision-eligible — the turn has
    already happened (hooks.md:290). A DENY cannot be enforced here, and
    Claude Code reads {"decision":"block"} on Stop as "do not stop,
    continue the conversation", so emitting one would turn a denial into
    an instruction to keep working. Record it and emit nothing."""
    if decision.disposition in ("deny", "ask", "defer"):
        audit_event("unenforceable_decision", decision=decision.disposition,
                    reason=decision.reasoning or "(none)")
    return {}


_TRANSLATORS: dict[str, Callable[[Decision, dict], dict[str, Any]]] = {
    "PreToolUse":       _translate_pretool,
    "PostToolUse":      _translate_posttool,
    "UserPromptSubmit": _translate_user_prompt,
    "Stop":             _translate_session_stop,
}


def translate_response(acs_response: dict[str, Any], hook_event: str,
                       original_input: dict | None = None) -> dict[str, Any]:
    # normalize_decision never raises: this runs outside main()'s
    # try/except and an uncaught error is exit 1, which Claude Code
    # proceeds on.
    decision = normalize_decision(acs_response.get("result"))

    # An arrived decision outside the five dispositions fails closed;
    # whether §6.4:156 (posture) or §6.3:146 (fail closed) governs is
    # unsettled and tracked in issue #32 — deny is the safe reading.
    if not decision.known:
        audit_event("unusable_disposition",
                    disposition=decision.disposition or "(missing)", hook=hook_event)
        reason = (f"unusable Guardian disposition '{decision.disposition}' — cannot be "
                  f"interpreted; failing closed (see issue #32)")
        if hook_event == "PreToolUse":
            return _pretool_response("deny", reason)
        # Stop is deliberately absent. Claude Code reads
        # {"decision":"block"} there as "do not stop", so a block would
        # increase activity instead of preventing it.
        if hook_event in ENFORCEABLE_BLOCK_HOOKS:
            return _block_response(reason)
        return {}

    translator = _TRANSLATORS.get(hook_event)
    if translator:
        return translator(decision, original_input or {})

    # Informational hooks (SessionStart, SessionEnd, Notification):
    # surface the Guardian's `reasoning` as additionalContext when present.
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
        # Incident kill switch: every step proceeds ungoverned, so the
        # bypass must land in the durable audit sink (§6.4:158).
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

    session_id = event.get("session_id")

    # §4.1: a refused or unanswered session sends the Guardian nothing; each step is settled here.
    started: list = []
    session = _open_session(event, config, started)
    gated = config.gate(session)
    if gated is not None:
        return _settle(gated, hook_name, session_id)
    if hook_name == "SessionStart":
        # The session's sessionStart went out when the session opened, from this hook or an earlier one.
        if started:
            _emit(translate_response(started[0].response, hook_name))
        return 0
    server_hello = session.server_hello
    # §6.4:154: the negotiated posture and default timeout govern every round trip below.
    posture = config.posture.negotiated(server_hello)

    try:
        return _govern(event, hook_name, session_id, server_hello, posture, config)
    except Exception as e:  # noqa: BLE001
        # Settled with the session's effective posture; an exit 1 would let the host proceed.
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       hook_name, session_id)


def _govern(event: dict[str, Any], hook_name: str, session_id: str | None,
            server_hello: dict[str, Any], posture: FailPosture, config: Config) -> int:
    tool_name = event.get("tool_name")
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        record_mcp_use(session_id, tool=tool_name, workspace=_turn_ws(event))
    # Turn tracking: a UserPromptSubmit OPENS a turn with an explicit,
    # decision-eligible steps/turnStart BEFORE the userMessage. A Guardian
    # MAY deny to block the whole turn (turn-start.json); the deny lands in
    # the prompt's own block shape so the prompt is blocked.
    if hook_name == "UserPromptSubmit":
        turn_id = str(uuid.uuid4())
        if method_evaluated(server_hello, "steps/turnStart"):
            result = round_trip(build_turn_start_request(event, turn_id), guardian_url=config.guardian_url,
                                posture=posture, session_id=session_id)
            if isinstance(result, Resolution):
                return _settle(result, "UserPromptSubmit", session_id)
            turn_start = normalize_decision(result.response.get("result"))
            if turn_start.disposition != "allow":
                # Only allow applies to a turn start, so any other disposition blocks the prompt.
                audit_event("turn_start_blocked", turn_id=turn_id,
                            disposition=turn_start.disposition or "(unusable)")
                _emit(_block_response(
                    f"turn blocked at start ({turn_start.disposition or 'unusable'}): {turn_start.reasoning}"))
                return 0
        else:
            audit_event("method_not_evaluated", method="steps/turnStart",
                        hook=hook_name, session_id=session_id)
        open_turn(session_id, turn_id, workspace=_turn_ws(event))

    try:
        request = build_request(event)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       hook_name, session_id)
    if not request:
        if hook_name == "Stop":
            # turnEnd with no open turn: audit it rather than fabricate
            # a turn_id.
            audit_event("turn_end_no_open_turn", session_id=session_id)
            return 0
        sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
        return _settle(posture.resolve(Undecided("adapter_build_failed")), hook_name, session_id)

    method = request.get("method", "")
    if not method_evaluated(server_hello, method):
        # ALLOW-by-default (handshake.json): recorded and skipped, never sent
        # or counted as a decision failure.
        audit_event("method_not_evaluated", method=method, hook=hook_name,
                    session_id=session_id)
        if hook_name == "Stop":
            close_turn(session_id, workspace=_turn_ws(event))
        return 0
    if method == "steps/toolCallResult":
        origin = ("steps/subagentStart" if _is_subagent_tool(event.get("tool_name"))
                  else "steps/toolCallRequest")
        if not method_evaluated(server_hello, origin):
            # The originating request was never sent, so citing it would dangle.
            request["params"]["payload"].pop("request_id_ref", None)

    result = round_trip(request, guardian_url=config.guardian_url, posture=posture, session_id=session_id)
    if isinstance(result, Resolution):
        return _settle(result, hook_name, session_id)
    response = result.response

    # A translation bug would exit 1, which the host reads as proceed, so it fails closed here.
    try:
        _emit(translate_response(response, hook_name,
                                 original_input=event.get("tool_input") or {}))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: translate error: {e}\n")
        return _settle(posture.resolve(Refused("adapter_translate_exception", {"error": str(e)})),
                       hook_name, session_id)

    # Close the turn after the turnEnd has been emitted/recorded.
    if hook_name == "Stop":
        close_turn(session_id, workspace=_turn_ws(event))
    return 0


def _settle(resolution: Resolution, hook_name: str, session_id: str | None) -> int:
    """Carry out a resolution: block in the hook's native shape unless it proceeds, and record why per §6.4.

    The audit type says which rule decided (fail_open_bypass,
    decision_failure_fail_closed, guardian_refusal_fail_closed, or a session
    gate: unguarded_session_bypass, session_not_started_fail_closed,
    session_refused_fail_closed); `cause` says
    what went wrong, so an unreachable Guardian (an ops issue) reads apart from
    a malformed envelope (a client bug).
    """
    if resolution.message:
        sys.stderr.write(f"acs-adapter: {resolution.message}\n")
    if not resolution.proceed:
        _emit_deny(hook_name, f"ACS adapter: {resolution.label} ({resolution.cause})")
    audit_event(resolution.audit_type, cause=resolution.cause, hook=hook_name,
                session_id=session_id, **resolution.fields)
    return 0


def _emit_deny(hook_name: str, msg: str) -> None:
    """Emit a deny in the hook's native response shape — except on the
    audit-only hooks, where no enforceable shape exists and a block
    would instruct Claude Code to keep going."""
    if hook_name in AUDIT_ONLY_HOOKS:
        audit_event("unenforceable_decision", hook=hook_name, reason=msg)
        return
    if hook_name == "PreToolUse":
        _emit(_pretool_response("deny", msg))
    elif hook_name in ENFORCEABLE_BLOCK_HOOKS:
        _emit(_block_response(msg))


if __name__ == "__main__":
    sys.exit(main())
