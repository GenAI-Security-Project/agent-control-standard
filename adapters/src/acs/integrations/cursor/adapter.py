#!/usr/bin/env python3
"""
ACS adapter for Cursor hooks.

Translates a Cursor hook event into a signed ACS JSON-RPC request,
sends it to a Guardian, and translates the ACS response back to
Cursor's expected output format.

Wire-format ground truth: GenAI-Security-Project/agent-control-standard specification/v0.1.0/

Note on payload completeness: Cursor does not expose every field ACS
v0.1.0 hook schemas require.

  - `subagentStart` — three of four required fields (subagent_session_id,
    parent_session_id, parent_step_id) are populated from real session
    data via deterministic UUID5 and the adapter's session-state tracking
    of the last step_id. When NO prior step is recorded, parent_step_id
    is the spawn event's own request_id (the spawn is the first observed
    parent step) with a `subagent_start_parent_step_unknown` audit event
    — never the session id masquerading as a step id. The fourth field,
    `intent_derivation`, is hardcoded to `derived_from_parent` (the
    defensible default for IDE-spawned subagents).
  - `preCompact` — both required fields are real: `entries_to_compact` is
    the list of step_ids the adapter has observed in this session;
    `triggered_by` comes from Cursor's `trigger` field.
  - `subagentStop` — NOT forwarded. Its event carries no identifier of
    the subagentStart it ends, so it cannot name the subagent_session_id
    steps/subagentStop requires (mapping.md).

See the README per-hook honesty table for the full mapping.

Usage in hooks.json:
  { "command": "/path/to/acs-cursor-hook preToolUse" }

Environment variables (same defaults / semantics as the Claude Code adapter):
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    "1" = fail-closed. Default "0" (spec default per §6.4).
                      Cursor also honors per-hook `failClosed: true` in hooks.json.
                      The ServerHello's `on_decision_failure` also applies
                      (most-restrictive-wins). Guardian REFUSALS
                      (SIGNATURE_INVALID, REPLAY_DETECTED, malformed /
                      oversized envelope) always fail closed regardless of
                      posture — every refusal is attacker-reachable.
  ACS_HMAC_SECRET     Shared secret for HMAC-SHA256 signing per §10 (or
                      ACS_HMAC_SECRET_FILE, preferred). Unset = no signing
                      (local dev, loud audit event).
  ACS_AGENT_ID        Explicit agent_id; defaults to cursor:<sha8(workspace)>.
  ACS_STARTUP_POSTURE "proceed" or "refuse": what this hook does in a
                      session with no negotiated Guardian (§4.1); the
                      session keeps none for its lifetime. Unset follows
                      ACS_DEFAULT_DENY.
  ACS_HANDSHAKE       "0" skips the handshake; ACS_STARTUP_POSTURE then
                      settles every step. Default "1".
  ACS_AUDIT_FILE      Append every ACS_AUDIT event to this file (0600) in
                      addition to stderr.
  ACS_DISABLED        "1" = incident kill switch: exit immediately, no
                      Guardian traffic, no output (one stderr line).
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
    load_session_state,
    open_session,
    open_turn,
    record_mcp_use,
    record_step,
    round_trip,
)
from acs.core import (
    Decision,
    coerce_uuid,
    method_evaluated,
    modify_composition_violation,
    normalize_decision,
    request_envelope,
    turn_start_envelope,
)
from acs.integrations.cursor.hook import PERMISSION_EVENTS

_GATE_EVENTS = PERMISSION_EVENTS | {"beforeSubmitPrompt"}
# Events whose step fails closed when its envelope cannot be signed: the gates, and the result the adapter can withhold.
_ENFORCED_EVENTS = _GATE_EVENTS | {"postToolUse"}

ADAPTER_VERSION = __version__


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

# Cursor hook event -> ACS step method.
HOOK_MAP: dict[str, str] = {
    "sessionStart":         "steps/sessionStart",
    "sessionEnd":           "steps/sessionEnd",
    # `stop` ends a TURN (each reply), not the session: steps/turnEnd
    # closes the turn opened by steps/turnStart on beforeSubmitPrompt,
    # while steps/sessionEnd seals the chain once per session.
    "stop":                 "steps/turnEnd",
    "preToolUse":           "steps/toolCallRequest",
    "postToolUse":          "steps/toolCallResult",
    "postToolUseFailure":   "steps/toolCallResult",
    "subagentStart":        "steps/subagentStart",
    "beforeShellExecution": "steps/toolCallRequest",
    "afterShellExecution":  "steps/toolCallResult",
    "beforeMCPExecution":   "steps/toolCallRequest",
    "afterMCPExecution":    "steps/toolCallResult",
    "afterFileEdit":        "steps/toolCallResult",
    "beforeSubmitPrompt":   "steps/userMessage",
    "preCompact":           "steps/preCompact",
    "afterAgentResponse":   "steps/agentResponse",
    "afterAgentThought":    "steps/agentResponse",
    "afterTabFileEdit":     "steps/toolCallResult",
}

# Cursor events deliberately NOT mapped, with the reason; an event outside
# HOOK_MAP and this set gets an `unmapped_hook_event` audit line so a
# renamed upstream hook surfaces as ungoverned rather than quiet.
KNOWN_UNMAPPED: dict[str, str] = {
    "subagentStop": "its event carries no identifier of the subagentStart it ends",
    "beforeReadFile": "read gate not wired in this adapter (candidate steps/knowledgeRetrieval)",
    "beforeTabFileRead": "Tab read gate not wired in this adapter (candidate steps/knowledgeRetrieval)",
    # Fires outside any agent session (no conversation_id), so there is
    # no ACS session to attach it to.
    "workspaceOpen": "app-lifecycle event outside any agent session",
}

POST_TOOL_EVENTS = frozenset({
    "postToolUse", "postToolUseFailure", "afterMCPExecution",
    "afterShellExecution", "afterFileEdit", "afterTabFileEdit",
})

# Cursor has no defer, so defer asks; preToolUse does not enforce ask, so _translate_permission denies ask and defer there.
PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask", "defer": "ask",  # no native defer
}

SESSION_END_REASONS = frozenset({"completed", "cancelled", "error", "timeout", "abandoned"})


# ─── Response writers — one definition each, used everywhere ──────────────

def _emit(payload: dict[str, Any]) -> None:
    """Single point where the adapter writes to stdout. Idempotent on
    empty dict. beforeSubmitPrompt uses internal __exit_code/_reasoning
    keys (handled in main) and never reaches this writer with them."""
    if not payload:
        return
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _permission_response(decision: str, message: str = "",
                          updated_input: dict | None = None) -> dict[str, Any]:
    """Cursor's permission-event response shape: top-level `permission`
    plus optional user/agent messages and updated_input (preToolUse only)."""
    out: dict[str, Any] = {"permission": decision}
    if message:
        out["user_message"] = message
        out["agent_message"] = message
    if updated_input is not None:
        out["updated_input"] = updated_input
    return out


def _post_tool_response(additional_context: str | None = None,
                         updated_mcp_tool_output: Any | None = None) -> dict[str, Any]:
    """postToolUse response — the ONLY post-tool event with documented
    output fields: `additional_context` and (for MCP tools)
    `updated_mcp_tool_output` (docs show an object value)."""
    out: dict[str, Any] = {}
    if additional_context:
        out["additional_context"] = additional_context
    if updated_mcp_tool_output is not None:
        out["updated_mcp_tool_output"] = updated_mcp_tool_output
    return out


# ─── Helpers ────────────────────────────────────────────────────────────────

def _first_workspace_root(event: dict[str, Any]) -> str | None:
    """`workspace_roots` is Cursor's real common-input field — an array
    (multiroot workspaces carry several); take the first."""
    roots = event.get("workspace_roots")
    if isinstance(roots, list) and roots and isinstance(roots[0], str):
        return roots[0]
    return None


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = (event.get("cwd") or _first_workspace_root(event)
           or os.environ.get("PWD") or "")
    if cwd:
        return f"cursor:{hashlib.sha256(cwd.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"
    return "cursor:unknown"


def _session_id(event: dict[str, Any]) -> str:
    raw = event.get("session_id") or event.get("conversation_id") or ""
    return coerce_uuid(raw, namespace_prefix="cursor") if raw else ""


def _workspace(event: dict[str, Any]) -> str | None:
    """Folded into the state key, so two windows sharing a non-UUID conversation_id stay apart."""
    return _first_workspace_root(event) or event.get("cwd") or None


def _parse_json_field(raw: Any) -> Any:
    """Cursor's MCP hooks carry `tool_input`/`result_json`/`tool_output`
    as JSON-STRINGIFIED payloads (hooks docs): parse strings, pass objects
    through, return the raw string on invalid JSON — never raise, since an
    uncaught throw here exits 1 and Cursor proceeds."""
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            # Any parse failure counts, including RecursionError from deep nesting.
            return raw
    return raw


def _int_ms(raw: Any) -> int | None:
    """duration_ms must be an integer per tool-call-result.json; Cursor
    sends `duration` as a number. Coerce or omit — never emit a float."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    return None


# ─── Turn tracking ────────────────────────────────────────────────────────
# A turn opens on beforeSubmitPrompt (an explicit steps/turnStart) and
# closes on `stop` (steps/turnEnd). turn_id is held in per-session state so
# every in-turn step stamps metadata.turn_id and the turnEnd matches.
_IN_TURN_METHODS = frozenset({
    "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
    "steps/agentResponse", "steps/turnEnd",
})


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json:26-37 — each arg is {value, provenance?}."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _outputs_list(raw: Any) -> list[dict[str, Any]]:
    """tool-call-result.json wants outputs as array of {value, provenance?}."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item if isinstance(item, dict) and "value" in item else {"value": item} for item in raw]
    return [{"value": raw}]


def _tool_use_request_id(tool_call_id: str | None) -> str | None:
    """Deterministic UUID5 so postToolUse can carry request_id_ref linking
    back to the originating preToolUse (per tool-call-result.json:19-23)."""
    if not tool_call_id:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor:tool_use:{tool_call_id}"))


# ─── Payload builders — dispatch table, one function per Cursor event ─────

def _payload_pretool(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": event.get("tool_name") or event.get("tool", "")},
        "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
    }


def _payload_before_shell(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": "Shell"},
        "arguments": _wrap_arguments({"command": event.get("command", "")}),
    }


def _payload_before_mcp(event: dict[str, Any]) -> dict[str, Any]:
    """beforeMCPExecution real input (docs 2026-08-22): `tool_name`,
    `tool_input` (JSON-STRINGIFIED params), plus `url` (remote server) or
    `command` (stdio server) as the provider."""
    args = _parse_json_field(event.get("tool_input"))
    if not isinstance(args, dict):
        # Unparseable/non-object params: carry them as one opaque argument
        # rather than dropping them (the Guardian still sees the content).
        args = {"raw_params": args} if args is not None else {}
    tool: dict[str, Any] = {"name": event.get("tool_name", "")}
    provider = event.get("url") or event.get("command")
    if provider:
        tool["provider"] = str(provider)
    return {"tool": tool, "arguments": _wrap_arguments(args)}


# postToolUseFailure.failure_type → ACS exit_status enum
# (tool-call-result.json: success | failure | timeout | blocked).
_FAILURE_TYPE_TO_EXIT_STATUS = {
    "error": "failure",
    "timeout": "timeout",
    "permission_denied": "blocked",
}


def _payload_posttool(event: dict[str, Any]) -> dict[str, Any]:
    """postToolUse real input (docs 2026-08-22): `tool_output` is a
    JSON-STRINGIFIED result (for Shell it carries exitCode/stdout) plus
    `duration` (ms); postToolUseFailure instead carries `error_message` +
    `failure_type` ("error"|"timeout"|"permission_denied") + `duration`."""
    is_failure = (event.get("hook_event_name") == "postToolUseFailure"
                  or event.get("_event_name") == "postToolUseFailure")
    if is_failure:
        exit_status = _FAILURE_TYPE_TO_EXIT_STATUS.get(
            (event.get("failure_type") or "").lower(), "failure")
        outputs = _outputs_list(event.get("error_message") or "(no error message)")
    else:
        parsed = _parse_json_field(event.get("tool_output"))
        # Honest failure detection where the payload carries it: Shell
        # tool_output is a JSON object with exitCode.
        exit_status = "success"
        if isinstance(parsed, dict):
            code = parsed.get("exitCode")
            if isinstance(code, int) and code != 0:
                exit_status = "failure"
        outputs = _outputs_list(parsed)
    payload = {
        "tool": {"name": event.get("tool_name") or event.get("tool", "")},
        "exit_status": exit_status,
        "outputs": outputs,
    }
    dur = _int_ms(event.get("duration"))
    if dur is not None:
        payload["duration_ms"] = dur
    ref = _tool_use_request_id(event.get("tool_use_id") or event.get("tool_call_id"))
    if ref:
        payload["request_id_ref"] = ref
    return payload


def _payload_after_shell(event: dict[str, Any]) -> dict[str, Any]:
    """afterShellExecution real input (docs 2026-08-22): `command`,
    `output`, `duration`, `sandbox` — no exit code and no correlation id
    on this hook, so exit_status is 'success' (the schema requires a value;
    postToolUse carries the discriminating exitCode) and request_id_ref is
    omitted (mapping.md)."""
    payload = {
        "tool": {"name": "Shell"},
        "exit_status": "success",
        "outputs": _outputs_list(event.get("output")),
    }
    dur = _int_ms(event.get("duration"))
    if dur is not None:
        payload["duration_ms"] = dur
    return payload


def _payload_after_mcp(event: dict[str, Any]) -> dict[str, Any]:
    """afterMCPExecution real input (docs 2026-08-22): `tool_name`,
    `tool_input` (string), `result_json` (JSON-STRINGIFIED response),
    `duration`; no correlation id exists on this hook, so request_id_ref
    is omitted (pre/postToolUse carry the tool_use_id correlation)."""
    payload = {
        "tool": {"name": event.get("tool_name", "")},
        "exit_status": "success",
        "outputs": _outputs_list(_parse_json_field(event.get("result_json"))),
    }
    dur = _int_ms(event.get("duration"))
    if dur is not None:
        payload["duration_ms"] = dur
    return payload


def _payload_file_edit(event: dict[str, Any]) -> dict[str, Any]:
    """afterFileEdit / afterTabFileEdit real input: `file_path` +
    `edits` [{old_string, new_string}]. Carry both so the Guardian sees
    WHAT changed, not just which file."""
    output: dict[str, Any] = {"file_path": event.get("file_path", "")}
    edits = event.get("edits")
    if isinstance(edits, list) and edits:
        output["edits"] = edits
    return {
        "tool": {"name": "Edit"},
        "exit_status": "success",
        "outputs": _outputs_list(output),
    }


def _payload_before_submit_prompt(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text",
                         "value": event.get("prompt") or event.get("user_message", "")}]}


def _payload_after_agent(event: dict[str, Any]) -> dict[str, Any]:
    """afterAgentResponse / afterAgentThought real content field is
    `text` (docs 2026-08-22)."""
    return {"content": [{"type": "text", "value": event.get("text", "")}]}


def _payload_session_start(event: dict[str, Any]) -> dict[str, Any]:
    """sessionStart real input: `session_id`, `is_background_agent`,
    `composer_mode`, plus the common `workspace_roots`. platform_context
    is schema-open (session-start.json), so carry the real facts."""
    ctx: dict[str, Any] = {}
    root = _first_workspace_root(event)
    if root:
        ctx["workspace_root"] = root
    if isinstance(event.get("workspace_roots"), list):
        ctx["workspace_roots"] = event["workspace_roots"]
    if event.get("composer_mode"):
        ctx["composer_mode"] = event["composer_mode"]
    if isinstance(event.get("is_background_agent"), bool):
        ctx["is_background_agent"] = event["is_background_agent"]
    if event.get("cursor_version"):
        ctx["cursor_version"] = event["cursor_version"]
    if event.get("host_session_id"):
        ctx["host_session_id"] = event["host_session_id"]
    return {"platform_context": ctx} if ctx else {}


# Cursor's real sessionEnd reason set is completed | aborted | error |
# window_close | user_close (docs 2026-08-22), mapped onto the ACS enum
# (completed | cancelled | error | timeout | abandoned).
_CURSOR_SESSION_END_REASON_MAP = {
    "completed": "completed",
    "aborted": "cancelled",
    "error": "error",
    "window_close": "abandoned",
    "user_close": "abandoned",
}


def _payload_session_end(event: dict[str, Any]) -> dict[str, Any]:
    raw = (event.get("reason") or "").lower()
    mapped = _CURSOR_SESSION_END_REASON_MAP.get(raw)
    if mapped is None:
        # Legacy/unknown value: accept it if it happens to be an ACS enum
        # member already, else default to completed.
        mapped = raw if raw in SESSION_END_REASONS else "completed"
    counts = decision_failure_counts(_session_id(event), workspace=_workspace(event))
    return {"reason": mapped, "summary": {"decision_failures": counts}}


# Cursor stop.status → ACS turn-end outcome enum
# (completed | deferred | error | interrupted | denied_at_start).
_CURSOR_STOP_STATUS_TO_OUTCOME = {
    "completed": "completed",
    "aborted": "interrupted",
    "error": "error",
}


def _payload_turn_end(event: dict[str, Any]) -> dict[str, Any]:
    """Closes the turn opened at the last beforeSubmitPrompt; turn_id
    comes from session state (empty → build_request skips the emission).
    Cursor's `stop` carries `status` ∈ completed|aborted|error (docs
    2026-08-22)."""
    outcome = _CURSOR_STOP_STATUS_TO_OUTCOME.get(
        (event.get("status") or "").lower(), "completed")
    return {"turn_id": current_turn(_session_id(event), workspace=_workspace(event)) or "", "outcome": outcome}


def _payload_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    """All four schema-required fields from real session data. Lineage,
    best first (docs 2026-08-22): uuid5 of the event's `tool_call_id`
    (the same id the delegating preToolUse pinned as its request_id),
    then the last recorded step, then (audited) the spawn envelope's own
    request_id."""
    sub_raw = event.get("subagent_id", "")
    sid = _session_id(event)
    parent_step_id = _tool_use_request_id(event.get("tool_call_id"))
    if not parent_step_id:
        st = load_session_state(sid, workspace=_workspace(event))
        parent_step_id = st.get("last_step_id")
    if not parent_step_id:
        # No tool_call_id and no prior step: build_request patches in
        # this envelope's own request_id (sentinel None here) and the
        # degraded lineage is audited.
        audit_event("subagent_start_parent_step_unknown",
                    session_id=sid,
                    detail="no tool_call_id and no prior step recorded; "
                           "parent_step_id set to the spawn event's own "
                           "request_id")
        parent_step_id = None
    payload = {
        "subagent_session_id": str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"cursor-subagent:{sid}:{sub_raw or 'unknown'}")),
        "parent_session_id": sid,
        "parent_step_id": parent_step_id,
        # IDE subagents inherit the parent's context, so derived_from_parent.
        "intent_derivation": "derived_from_parent",
    }
    descriptor: dict[str, Any] = {}
    if sub_raw:
        descriptor["agent_id"] = sub_raw
    if event.get("subagent_type"):
        descriptor["agent_name"] = str(event["subagent_type"])
    if event.get("subagent_model"):
        descriptor["model_id"] = str(event["subagent_model"])
    if descriptor:
        payload["subagent_descriptor"] = descriptor
    return payload


def _payload_precompact(event: dict[str, Any]) -> dict[str, Any]:
    """entries_to_compact: the step_ids observed this session — an honest
    superset of whatever Cursor compacts. `triggered_by` maps Cursor's
    {auto, manual} onto the closed pre-compact.json enum (a raw 'auto'
    would be schema-invalid); with no observed steps the schema's >=1
    cannot be met honestly, so entries stay empty and build_request skips
    the emission."""
    sid = _session_id(event)
    st = load_session_state(sid, workspace=_workspace(event))
    seen = list(st.get("seen_step_ids") or [])
    trigger = (event.get("trigger") or "").lower()
    triggered_by = {"manual": "manual",
                    "auto": "framework_initiated"}.get(trigger,
                                                       "framework_initiated")
    return {"entries_to_compact": seen, "triggered_by": triggered_by}


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "preToolUse":           _payload_pretool,
    "beforeShellExecution": _payload_before_shell,
    "beforeMCPExecution":   _payload_before_mcp,
    "postToolUse":          _payload_posttool,
    "postToolUseFailure":   _payload_posttool,
    "afterShellExecution":  _payload_after_shell,
    "afterMCPExecution":    _payload_after_mcp,
    "afterFileEdit":        _payload_file_edit,
    "afterTabFileEdit":     _payload_file_edit,
    "beforeSubmitPrompt":   _payload_before_submit_prompt,
    "afterAgentResponse":   _payload_after_agent,
    "afterAgentThought":    _payload_after_agent,
    "sessionStart":         _payload_session_start,
    "sessionEnd":           _payload_session_end,
    "stop":                 _payload_turn_end,
    "subagentStart":        _payload_subagent_start,
    "preCompact":           _payload_precompact,
}


def build_payload(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event_name)
    if not builder:
        return {}
    # _payload_posttool branches on event_name; thread it through
    if event_name in ("postToolUse", "postToolUseFailure"):
        event = {**event, "_event_name": event_name}
    return builder(event)


# ─── Envelope construction ──────────────────────────────────────────────────

def build_request(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event_name)
    if method is None:
        return {}

    session_id = _session_id(event)
    if not session_id:
        return {}

    metadata = _metadata(event_name, event)

    # Stamp the open turn's id on in-turn steps (request-envelope.json:69).
    if method in _IN_TURN_METHODS:
        tid = current_turn(_session_id(event), workspace=_workspace(event))
        if tid:
            metadata["turn_id"] = tid

    # turnEnd needs an open turn; with none the emission is skipped, and main audits it.
    if method == "steps/turnEnd" and not current_turn(_session_id(event), workspace=_workspace(event)):
        return {}

    # Pin *Request request_ids deterministically (uuid5 of `tool_use_id`
    # / `tool_call_id`) so a matching *Result can cite request_id_ref;
    # the shell/MCP-specific hooks carry no id, so their request_ids stay
    # random and their results uncorrelated (mapping.md).
    if method == "steps/toolCallRequest":
        ref = _tool_use_request_id(event.get("tool_use_id") or event.get("tool_call_id"))
        request_id = ref or str(uuid.uuid4())
    else:
        request_id = str(uuid.uuid4())

    payload = build_payload(event_name, event)
    # subagentStart with no prior step: the spawn envelope's own
    # request_id is the parent_step_id (see _payload_subagent_start).
    if method == "steps/subagentStart" and payload.get("parent_step_id") is None:
        payload["parent_step_id"] = request_id

    # preCompact requires >=1 entry; none observed this session → skip
    # the emission (audited) rather than fabricate one.
    if method == "steps/preCompact" and not payload.get("entries_to_compact"):
        audit_event("precompact_skipped_no_observed_entries",
                    session_id=session_id,
                    detail="no prior step_ids observed this session; cannot "
                           "honestly populate entries_to_compact (>=1 required)")
        return {}

    return request_envelope(method, request_id=request_id, metadata=metadata, payload=payload)


def _metadata(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": _session_id(event),
        "platform": "cursor",
        "adapter_version": ADAPTER_VERSION,
        "cursor_event": event_name,
    }
    ws = event.get("cwd") or _first_workspace_root(event)
    if ws:
        metadata["workspace_path"] = ws
    return metadata


def build_turn_start_request(event: dict[str, Any], turn_id: str) -> dict[str, Any]:
    return turn_start_envelope(_metadata("beforeSubmitPrompt", event), turn_id)


def _open_session(event: dict[str, Any], config: Config) -> Handshake:
    return open_session(
        config=config,
        session_id=_session_id(event),
        agent_id=_agent_id(event),
        platform="cursor",
        # steps/turnStart is emitted on beforeSubmitPrompt but is not a
        # HOOK_MAP value; advertise it so advertised == emitted.
        methods_implemented=list(HOOK_MAP.values()) + ["steps/turnStart"],
        start=lambda session: _send_session_start(event, session, config),
        count_start_failure=lambda failure: count_decision_failure(_session_id(event), failure,
                                                                   workspace=_workspace(event)),
    )


def _send_session_start(event: dict[str, Any], session: Negotiated, config: Config) -> Decided | Resolution | None:
    """The session's one sessionStart, from whichever hook opened it; Cursor runs sessionStart and beforeSubmitPrompt concurrently."""
    session_id = _session_id(event)
    if not method_evaluated(session.server_hello, "steps/sessionStart"):
        audit_event("method_not_evaluated", method="steps/sessionStart", session_id=session_id)
        return None
    result = round_trip(build_request("sessionStart", event), guardian_url=config.guardian_url,
                        posture=config.posture.negotiated(session.server_hello), session_id=session_id)
    if isinstance(result, Resolution):
        count_decision_failure(session_id, result.fields.get("failure_class", "other"), workspace=_workspace(event))
    return result


def _translate_permission(decision: Decision, event_name: str, original_input: dict,
                          tool_name: str = "") -> dict[str, Any]:
    if decision.disposition in ("ask", "defer") and event_name == "preToolUse":
        # Cursor accepts ask on preToolUse but does not enforce it, so the tool would run: deny instead.
        audit_event("unenforceable_decision", decision=decision.disposition, event=event_name,
                    reason=decision.reasoning or "(none)", substituted="deny")
        return _permission_response("deny", f"ACS Guardian asked for approval Cursor cannot hold here: "
                                            f"{decision.reasoning or '(no reasoning)'}")
    if decision.disposition in PERMISSION_MAP:
        return _permission_response(PERMISSION_MAP[decision.disposition], decision.reasoning)
    if decision.disposition == "modify":
        # §6.3: a modifications object that breaks the composition rules is a DENY, never half-applied.
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", event=event_name,
                        detail=violation)
            return _permission_response(
                "deny", f"MODIFY refused ({violation}); failing closed per §6.3")
        if decision.modifications.get("redactions"):
            # updated_input cannot express redactions, so the override half is never applied alone.
            audit_modify_unsupported("redactions", event=event_name)
            return _permission_response(
                "deny", "MODIFY refused: Cursor cannot apply the requested "
                "redactions without dropping part of the decision")
        overrides = decision.modifications.get("parameter_overrides")
        if event_name != "preToolUse":
            unsupported = "no updated_input on this event"
        elif _is_mcp_tool(tool_name):
            # Cursor ignores updated_input for an HTTP MCP server's tool, and the name does not say which kind it is.
            unsupported = "updated_input on an MCP tool"
        elif not isinstance(overrides, dict):
            unsupported = "no parameter_overrides object"
        else:
            # updated_input replaces the whole input.
            merged = {**original_input, **overrides}
            return _permission_response("allow", decision.reasoning, updated_input=merged)
        audit_modify_unsupported(unsupported, event=event_name, tool=tool_name)
        return _permission_response("deny",
                                     f"MODIFY substituted to DENY: {decision.reasoning}")
    return {}


def _is_mcp_tool(tool_name: Any) -> bool:
    return isinstance(tool_name, str) and tool_name.startswith("MCP:")


def _mcp_output_replaceable(tool_name: Any, tool_output: Any) -> bool:
    """updated_mcp_tool_output replaces an MCP tool's output, except an HTTP MCP server's, whose tool_output arrives as {"redacted": true} (hooks docs)."""
    parsed = _parse_json_field(tool_output)
    return _is_mcp_tool(tool_name) and not (isinstance(parsed, dict) and parsed.get("redacted") is True)


def _post_tool_deny(event_name: str, reason: str) -> dict[str, Any]:
    # postToolUse fires after execution — no block exists; the denial
    # reaches the conversation as additional_context and is audited.
    audit_event("unenforceable_decision", decision="deny", event=event_name, reason=reason or "(none)")
    return _post_tool_response(additional_context=f"ACS Guardian denied this result: {reason or '(no reasoning)'}")


def _translate_post_tool(decision: Decision, event_name: str, tool_name: str = "",
                         tool_output: Any = None) -> dict[str, Any]:
    """Only `postToolUse` documents output fields (`additional_context`,
    and `updated_mcp_tool_output` for MCP tools); every other post-tool
    event documents "No output fields currently supported" (docs
    2026-08-22), so an arrived restrictive decision there is recorded and
    nothing is emitted."""
    if event_name != "postToolUse":
        if decision.disposition == "modify":
            audit_modify_unsupported("no output field on this event", event=event_name, tool=tool_name)
        if decision.disposition in ("deny", "modify", "ask", "defer"):
            audit_event("unenforceable_decision", decision=decision.disposition,
                        event=event_name, reason=decision.reasoning or "(none)")
        return {}
    if decision.disposition == "deny":
        return _post_tool_deny(event_name, decision.reasoning)
    if decision.disposition == "modify":
        violation = modify_composition_violation(decision.modifications)
        if violation:
            audit_event("modify_composition_invalid", event=event_name,
                        detail=violation)
            return _post_tool_response(
                additional_context=f"MODIFY refused ({violation})")
        updated = decision.modifications.get("modified_content")
        if updated is not None and _mcp_output_replaceable(tool_name, tool_output):
            # Docs show an OBJECT value; ACS modified_content is a string.
            # Parse JSON content when it is JSON, else pass the string.
            return _post_tool_response(
                updated_mcp_tool_output=_parse_json_field(updated))
        audit_modify_unsupported("structured edits on a tool result" if updated is None
                                 else "updated_mcp_tool_output on this tool", event=event_name, tool=tool_name)
        return _post_tool_deny(event_name, f"MODIFY substituted to DENY: {decision.reasoning}")
    if decision.disposition in ("ask", "defer"):
        # The tool already ran and its result is delivered: nothing can hold it for a person.
        audit_event("unenforceable_decision", decision=decision.disposition, event=event_name,
                    reason=decision.reasoning or "(none)")
    if decision.reasoning:
        return _post_tool_response(additional_context=decision.reasoning)
    return {}


def _translate_before_submit_prompt(decision: Decision, event_name: str) -> dict[str, Any]:
    """The prompt hook can only allow or block, so every other decision blocks (§6.4)."""
    if decision.disposition == "allow":
        return {"__exit_code": 0, "_reasoning": None}
    if decision.disposition != "deny":
        audit_event("prompt_decision_substituted_block",
                    disposition=decision.disposition, event="beforeSubmitPrompt")
        if decision.disposition == "modify":
            audit_modify_unsupported("the prompt cannot be rewritten", event="beforeSubmitPrompt")
    return {"__exit_code": 2,
            "_reasoning": decision.reasoning or f"{decision.disposition} on prompt not applicable — blocking"}


def translate_response(acs_response: dict[str, Any], event_name: str,
                       original_input: dict | None = None, tool_name: str = "",
                       tool_output: Any = None) -> dict[str, Any]:
    decision = normalize_decision(acs_response.get("result"))
    original_input = original_input or {}

    # An arrived-but-uninterpretable decision fails closed; the exact
    # spec basis is unsettled (§6.4 vs. arrived-and-unusable),
    # tracked in issue #32.
    if not decision.known:
        audit_event("unusable_disposition",
                    disposition=decision.disposition or "(missing)", event=event_name)
        reason = (f"unusable Guardian disposition '{decision.disposition}' — cannot be "
                  f"interpreted; failing closed (see issue #32)")
        if event_name in PERMISSION_EVENTS:
            return _permission_response("deny", reason)
        if event_name == "beforeSubmitPrompt":
            return {"__exit_code": 2, "_reasoning": reason}
        # Post-tool / observational events have no enforceable shape;
        # the audit event above is the record.
        return {}

    if event_name in PERMISSION_EVENTS:
        return _translate_permission(decision, event_name, original_input, tool_name)
    if event_name in POST_TOOL_EVENTS:
        return _translate_post_tool(decision, event_name, tool_name, tool_output)
    if event_name == "beforeSubmitPrompt":
        return _translate_before_submit_prompt(decision, event_name)

    # Remaining events are observational with no response shape — empty
    # dict skips stdout emission.
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

def main() -> int:
    config = Config.from_env(os.environ)
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (cursor) {ADAPTER_VERSION}")
        return 0
    if config.disabled:
        # Every step proceeds ungoverned, so the bypass goes to the durable audit sink (§6.4).
        audit_event("acs_disabled_bypass",
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
        return 0

    if len(sys.argv) < 2:
        sys.stderr.write("acs-adapter: missing event name argument (usage: acs_adapter.py <event_name>)\n")
        return 1
    event_name = sys.argv[1]

    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("the event is not a JSON object")
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        return _settle(config.posture.resolve(Undecided("invalid_stdin_json")), event_name, None)

    if event_name not in HOOK_MAP:
        if event_name not in KNOWN_UNMAPPED:
            # Upstream rename or unknown wired event — audit it so the
            # ungoverned step is recorded, never silent.
            audit_event("unmapped_hook_event", event=event_name,
                        session_id=_session_id(event))
        return 0

    host_session_id = _session_id(event)
    if host_session_id:
        session_id = current_session_id(host_session_id, config.guardian_url)
        if session_id != host_session_id:
            event = {**event, "session_id": session_id, "host_session_id": host_session_id}
    if event_name != "sessionEnd" or not host_session_id:
        return _hook(event_name, event, config)
    try:
        return _hook(event_name, event, config)
    finally:
        end_session(_session_id(event), config.guardian_url)
        discard_session_state(_session_id(event), workspace=_workspace(event))


def _hook(event_name: str, event: dict[str, Any], config: Config) -> int:
    session_id = _session_id(event)

    # §4.1: a refused or unanswered session sends the Guardian nothing; each step is settled here.
    session = _open_session(event, config)
    gated = config.gate(session, HOOK_MAP.get(event_name))
    if gated is not None:
        return _settle(gated, event_name, session_id, workspace=_workspace(event))
    if event_name == "sessionStart":
        # The session's sessionStart went out when the session opened, from this hook or an earlier one.
        return 0
    server_hello = session.server_hello
    posture = config.posture.negotiated(server_hello)

    try:
        return _govern(event_name, event, session_id, server_hello, posture, config)
    except Exception as e:  # noqa: BLE001
        # Settled with the session's effective posture; an exit 1 would let the host proceed.
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       event_name, session_id, workspace=_workspace(event))


def _govern(event_name: str, event: dict[str, Any], session_id: str | None,
            server_hello: dict[str, Any], posture: FailPosture, config: Config) -> int:
    tool_name = event.get("tool_name")
    # MCP tools reach the generic tool hooks as MCP:<tool_name>.
    if event_name in ("beforeMCPExecution", "afterMCPExecution") or (
            isinstance(tool_name, str) and tool_name.startswith("MCP:")):
        record_mcp_use(session_id, tool=str(tool_name or ""), workspace=_workspace(event))
    # A prompt opens its turn with a decision-eligible turnStart before the userMessage, and a deny blocks the prompt.
    if event_name == "beforeSubmitPrompt":
        turn_id = str(uuid.uuid4())
        if method_evaluated(server_hello, "steps/turnStart"):
            result = round_trip(build_turn_start_request(event, turn_id), guardian_url=config.guardian_url, gate=True,
                                posture=posture, session_id=session_id)
            if isinstance(result, Resolution):
                return _settle(result, "beforeSubmitPrompt", session_id, workspace=_workspace(event))
            turn_start = normalize_decision(result.response.get("result"))
            if turn_start.disposition != "allow":
                # Only allow applies to a turn start, so any other disposition blocks the prompt.
                audit_event("turn_start_blocked", turn_id=turn_id,
                            disposition=turn_start.disposition or "(unusable)",
                            event="beforeSubmitPrompt")
                msg = (f"turn blocked at start ({turn_start.disposition or 'unusable'}): "
                       f"{turn_start.reasoning}")
                sys.stderr.write(f"acs-adapter: {msg}\n")
                sys.stdout.write(json.dumps({"continue": False,
                                             "user_message": msg}) + "\n")
                return 0
        else:
            audit_event("method_not_evaluated", method="steps/turnStart",
                        event=event_name, session_id=session_id)
        open_turn(session_id, turn_id, workspace=_workspace(event))

    try:
        request = build_request(event_name, event)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _settle(posture.resolve(Undecided("adapter_exception", {"error": str(e)})),
                       event_name, session_id, workspace=_workspace(event))
    if not request:
        if event_name == "stop":
            # turnEnd with no open turn: nothing to close honestly.
            audit_event("turn_end_no_open_turn", session_id=session_id)
            return 0
        sys.stderr.write(f"acs-adapter: could not build request for {event_name}\n")
        return _settle(posture.resolve(Undecided("adapter_build_failed")), event_name, session_id, workspace=_workspace(event))

    method = request.get("method", "")
    if not method_evaluated(server_hello, method):
        # ALLOW-by-default (handshake.json): audited and skipped, never sent,
        # tracked as a step, or counted as a decision failure.
        audit_event("method_not_evaluated", method=method, event=event_name,
                    session_id=session_id)
        if event_name == "stop":
            close_turn(session_id, workspace=_workspace(event))
        return _explicit_allow(event_name)
    if method == "steps/toolCallResult" and not method_evaluated(server_hello, "steps/toolCallRequest"):
        # The originating request was never sent, so citing it would dangle.
        request["params"]["payload"].pop("request_id_ref", None)

    # Track this step in session state so subsequent subagentStart /
    # preCompact events can cite a real parent_step_id / entries_to_compact.
    try:
        rid_for_state = request.get("params", {}).get("request_id")
        if session_id and rid_for_state:
            record_step(session_id, rid_for_state, workspace=_workspace(event))
    except Exception:  # noqa: BLE001
        pass

    result = round_trip(request, guardian_url=config.guardian_url, posture=posture, session_id=session_id,
                        gate=event_name in _ENFORCED_EVENTS)
    if isinstance(result, Resolution):
        return _settle(result, event_name, session_id, workspace=_workspace(event))
    response = result.response

    # A bug escaping translate_response would exit 1 = Cursor proceeds;
    # this guard makes any translation bug fail closed instead.
    try:
        out = translate_response(response, event_name, original_input=event.get("tool_input") or {},
                                 tool_name=event.get("tool_name") or "", tool_output=event.get("tool_output"))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: translate error: {e}\n")
        return _settle(posture.resolve(Refused("adapter_translate_exception", {"error": str(e)})),
                       event_name, session_id, workspace=_workspace(event))

    # Close the turn after the turnEnd has been emitted/recorded.
    if event_name == "stop":
        close_turn(session_id, workspace=_workspace(event))

    if event_name == "beforeSubmitPrompt":
        exit_code = out.pop("__exit_code", 0)
        reasoning = out.pop("_reasoning", None)
        # Exit 0 so Cursor shows user_message; an allow says continue true, so failClosed reads the hook as answered.
        if exit_code == 0:
            sys.stdout.write(json.dumps({"continue": True}) + "\n")
            return 0
        sys.stderr.write(f"acs-adapter: blocking prompt: {reasoning}\n")
        sys.stdout.write(json.dumps({
            "continue": False,
            "user_message": reasoning or "blocked by ACS Guardian",
        }) + "\n")
        return 0

    _emit(out)
    return 0


def _explicit_allow(event_name: str) -> int:
    """Cursor's allow shape: a failClosed gate reads an empty reply as a failed hook."""
    if event_name in PERMISSION_EVENTS:
        _emit(_permission_response("allow"))
    elif event_name == "beforeSubmitPrompt":
        sys.stdout.write(json.dumps({"continue": True}) + "\n")
    return 0


def _settle(resolution: Resolution, event_name: str, session_id: str | None, *, workspace: str | None = None) -> int:
    """Carry out a resolution in the event's native shape, allow or deny, and record why per §6.4.

    A proceed carries Cursor's explicit allow: failClosed covers hook crashes
    and timeouts, and the posture already decided this step.
    """
    if resolution.message:
        sys.stderr.write(f"acs-adapter: {resolution.message}\n")
    if resolution.decision_failure:
        count_decision_failure(session_id, resolution.fields.get("failure_class", "other"), workspace=workspace)
    if resolution.proceed:
        audit_event(resolution.audit_type, cause=resolution.cause, event=event_name,
                    session_id=session_id, **resolution.fields)
        return _explicit_allow(event_name)
    return _deny_with_audit(resolution.audit_type, event_name, session_id,
                            resolution.cause, dict(resolution.fields), label=resolution.label)


def _deny_with_audit(audit_type: str, event_name: str,
                     session_id: str | None, cause: str,
                     audit_extras: dict, *, label: str = "decision-failure") -> int:
    audit_event(audit_type,
                cause=cause, event=event_name, session_id=session_id,
                **audit_extras)
    if event_name in PERMISSION_EVENTS:
        _emit(_permission_response(
            "deny", f"ACS adapter: {label} ({cause})"))
        return 0
    if event_name == "beforeSubmitPrompt":
        sys.stderr.write(f"acs-adapter: prompt blocked ({cause})\n")
        sys.stdout.write(json.dumps({
            "continue": False,
            "user_message": f"ACS adapter: prompt blocked ({cause})",
        }) + "\n")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
