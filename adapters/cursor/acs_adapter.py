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
  - `subagentStop` — NOT forwarded. `final_chain_hash` is genuinely
    unknowable (Cursor maintains no chain); better to omit than
    fabricate. A separate schema PR proposes making the field optional
    for chain-less frameworks; honest wiring resumes when the spec
    owners approve it.

See the README per-hook honesty table for the full mapping.

Usage in hooks.json:
  { "command": "python3 /path/to/acs_adapter.py preToolUse" }

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
  ACS_HANDSHAKE       "0" disables handshake. Default "1".
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
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
try:
    from acs_common import (  # noqa: E402
        ACS_VERSION,
        MAX_REQUEST_BODY_BYTES,
        audit_event,
        coerce_uuid,
        ensure_session_handshake,
        guardian_error_cause,
        is_guardian_refusal,
        iso8601_now,
        load_session_state,
        modify_composition_violation,
        normalize_decision,
        record_step,
        response_matches_request,
        save_session_state,
        sign_envelope,
        validate_guardian_url,
        verify_signature,
    )
except ImportError as _bootstrap_error:
    # acs_common hard-requires rfc8785 (§10 permits no alternative
    # canonicalization), so the import can fail before main() runs; a bare
    # exit 1 would skip the §6.4:158 audit and ignore ACS_DEFAULT_DENY,
    # so both are handled here with the standard library only.
    def _degraded_exit() -> int:
        if os.environ.get("ACS_DISABLED") == "1":
            # The documented kill switch is read in main(), which never runs
            # on this path. An operator who set it must still get a bypass.
            sys.stderr.write("acs-adapter: ACS_DISABLED=1, hook bypassed\n")
            return 0
        _hook = sys.argv[1] if len(sys.argv) > 1 else ""
        _deny = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
        _line = "ACS_AUDIT " + json.dumps({
            "acs_audit_event": "adapter_unavailable",
            "event": _hook,
            "posture": "deny" if _deny else "proceed",
            "error": str(_bootstrap_error).split("\n")[0],
            "detail": "adapter could not load; no envelope was sent",
        })
        sys.stderr.write(_line + "\n")
        _sink = os.environ.get("ACS_AUDIT_FILE", "").strip()
        if _sink:
            try:
                _fd = os.open(_sink, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(_fd, "a") as _f:
                    _f.write(_line + "\n")
            except OSError:
                pass
        if not _deny:
            return 0
        _reason = ("ACS adapter unavailable (dependency missing); "
                   "failing closed per the deployment posture")
        # Gate events with a {"permission": ...} deny shape.
        if _hook in ("preToolUse", "subagentStart",
                     "beforeShellExecution", "beforeMCPExecution"):
            print(json.dumps({"permission": "deny",
                              "user_message": _reason,
                              "agent_message": _reason}))
            return 0
        if _hook == "beforeSubmitPrompt":
            # Documented native block + exit code 2 belt-and-braces.
            sys.stderr.write(f"acs-adapter: {_reason}\n")
            print(json.dumps({"continue": False, "user_message": _reason}))
            return 2
        return 0

    if __name__ == "__main__":
        raise SystemExit(_degraded_exit())
    raise


class RequestTooLargeError(Exception):
    """Serialized envelope exceeds the Guardian's body cap; checked before
    the POST so an attacker-sized envelope cannot ride the
    transport-failure fail-open path."""


class GuardianHTTPRefusalError(Exception):
    """Guardian answered non-2xx — alive and refusing at the HTTP layer,
    distinct from a transport failure; carries the parsed JSON-RPC error
    body when present."""

    def __init__(self, status: int, jsonrpc_error: dict | None):
        self.status = status
        self.jsonrpc_error = jsonrpc_error or {}
        super().__init__(f"HTTP {status}")


# Carried in request metadata and printed by --version; bump on every
# behavior change to this file.
ADAPTER_VERSION = "0.1.2"

GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"

# Effective fail posture = most-restrictive of ACS_DEFAULT_DENY and the
# ServerHello's `on_decision_failure` (§6.4); set once per invocation in main().
_SERVER_DENY = False

# §6.4:154: wait up to the NEGOTIATED timeout — seeded from the
# ServerHello's timeout_config.default_ms in main(); 5s floor with no handshake.
_DECISION_TIMEOUT_S = 5.0


def _effective_default_deny() -> bool:
    return DEFAULT_DENY or _SERVER_DENY


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
    # `final_chain_hash` is schema-required and unknowable (Cursor keeps
    # no chain); wiring resumes when the separate schema PR making the
    # field optional lands.
    "subagentStop": "final_chain_hash unknowable (no chain on Cursor side)",
    # Blockable read gates (permission allow|deny per Cursor docs) with no
    # v0.1 wiring; candidate steps/knowledgeRetrieval mapping (mapping.md).
    "beforeReadFile": "read gate not wired in this adapter (candidate steps/knowledgeRetrieval)",
    "beforeTabFileRead": "Tab read gate not wired in this adapter (candidate steps/knowledgeRetrieval)",
    # Fires outside any agent session (no conversation_id), so there is
    # no ACS session to attach it to.
    "workspaceOpen": "app-lifecycle event outside any agent session",
}

# Cursor events whose deny shape is `{"permission": "deny", ...}`
# (vs `beforeSubmitPrompt` which uses exit code 2, and post-tool events
# which only carry `additional_context`).
PERMISSION_EVENTS = frozenset({
    "preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution",
})

POST_TOOL_EVENTS = frozenset({
    "postToolUse", "postToolUseFailure", "afterMCPExecution",
    "afterShellExecution", "afterFileEdit", "afterTabFileEdit",
})

# Deployment substitution, not spec-mandated (§9.2 puts substitution on
# the Guardian): Cursor has no native "defer", so defer→ask. Cursor
# documents `ask` on preToolUse as accepted-but-not-yet-enforced — a soft
# signal, not a hard hold.
PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask", "defer": "ask",  # no native defer
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})

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
        return f"cursor:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "cursor:unknown"


def _session_id(event: dict[str, Any]) -> str:
    raw = event.get("session_id") or event.get("conversation_id") or ""
    return coerce_uuid(raw, namespace_prefix="cursor") if raw else ""


def _workspace(event: dict[str, Any]) -> str | None:
    """Workspace identifier folded into the session-state file key so
    two Cursor windows on different projects can't collide on a shared
    non-UUID conversation_id."""
    return _first_workspace_root(event) or event.get("cwd") or None


def _parse_json_field(raw: Any) -> Any:
    """Cursor's MCP hooks carry `tool_input`/`result_json`/`tool_output`
    as JSON-STRINGIFIED payloads (hooks docs): parse strings, pass objects
    through, return the raw string on invalid JSON — never raise, since an
    uncaught throw here exits 1 and Cursor proceeds."""
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
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


def _current_turn_id(event: dict[str, Any]) -> str | None:
    sid = _session_id(event)
    if not sid:
        return None
    return load_session_state(sid, workspace=_workspace(event)).get("turn_id")


def _open_turn(event: dict[str, Any], turn_id: str) -> None:
    sid = _session_id(event)
    st = load_session_state(sid, workspace=_workspace(event))
    st["turn_id"] = turn_id
    save_session_state(sid, st, workspace=_workspace(event))


def _close_turn(event: dict[str, Any]) -> None:
    sid = _session_id(event)
    st = load_session_state(sid, workspace=_workspace(event))
    st.pop("turn_id", None)
    save_session_state(sid, st, workspace=_workspace(event))


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
    return {"reason": mapped}


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
    return {"turn_id": _current_turn_id(event) or "", "outcome": outcome}


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

    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "cursor",
        "adapter_version": ADAPTER_VERSION,
        "cursor_event": event_name,
    }
    ws = event.get("cwd") or _first_workspace_root(event)
    if ws:
        metadata["workspace_path"] = ws

    # Stamp the open turn's id on in-turn steps (request-envelope.json:69).
    if method in _IN_TURN_METHODS:
        tid = _current_turn_id(event)
        if tid:
            metadata["turn_id"] = tid

    # steps/turnEnd needs a turn_id (>=1); with no open turn there is
    # nothing to close honestly, so skip the emission (main audits it).
    if method == "steps/turnEnd" and not _current_turn_id(event):
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

    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": request_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": payload,
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def build_turn_start_request(event: dict[str, Any], turn_id: str) -> dict[str, Any]:
    """steps/turnStart opening the turn for a beforeSubmitPrompt. turn_id
    SHOULD equal the envelope's request_id (turn-start.json), so we use it
    for both. Decision-eligible: a Guardian MAY deny to block the turn
    (blocks the prompt via exit code 2)."""
    session_id = _session_id(event)
    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "cursor",
        "adapter_version": ADAPTER_VERSION,
        "cursor_event": "beforeSubmitPrompt",
        "turn_id": turn_id,
    }
    ws = event.get("cwd") or _first_workspace_root(event)
    if ws:
        metadata["workspace_path"] = ws
    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "steps/turnStart",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": turn_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": {"turn_id": turn_id, "triggered_by": "user_message"},
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def _maybe_handshake(event: dict[str, Any]) -> dict | None:
    """Called on every hook event. Idempotent per session via disk
    cache — only the first event of a session actually POSTs
    handshake/hello. Returns the negotiated ServerHello (cached or
    fresh) or None. See ensure_session_handshake's docstring."""
    if not HANDSHAKE_ENABLED:
        # ACS_HANDSHAKE=0 skips the §4-REQUIRED handshake (dev/test
        # only); record the non-conformance rather than skip silently (§4.1:77).
        audit_event("handshake_disabled_nonconformant",
                    session_id=_session_id(event),
                    detail="ACS_HANDSHAKE=0 — §4 handshake skipped; "
                           "session is NON-CONFORMANT")
        return None
    sid = _session_id(event)
    if not sid:
        return None
    return ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=sid,
        agent_id=_agent_id(event),
        platform="cursor",
        # steps/turnStart is emitted on beforeSubmitPrompt but is not a
        # HOOK_MAP value; advertise it so advertised == emitted.
        methods_implemented=list(HOOK_MAP.values()) + ["steps/turnStart"],
    )


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    validate_guardian_url(GUARDIAN_URL)  # SSRF: refuse file://, ftp://, etc.
    body = json.dumps(request).encode("utf-8")
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise RequestTooLargeError(len(body))
    req = urllib.request.Request(
        GUARDIAN_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_DECISION_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        parsed = None
        try:
            parsed = json.loads(e.read().decode("utf-8")).get("error")
        except Exception:  # noqa: BLE001
            pass
        raise GuardianHTTPRefusalError(e.code, parsed) from e


# ─── Response translation — dispatch table by event category ──────────────
#
# Cursor's response shapes group naturally into 4 categories:
#   - permission events (preToolUse, subagentStart, beforeShellExecution,
#     beforeMCPExecution): {"permission": ..., "user_message": ..., "agent_message": ...,
#     "updated_input": ...}
#   - post-tool events (postToolUse, postToolUseFailure, afterShellExecution,
#     afterMCPExecution, afterFileEdit, afterTabFileEdit): {"additional_context": ...,
#     "updated_mcp_tool_output": ...}
#   - beforeSubmitPrompt: uses exit code 2 (not stdout) to block; carries
#     internal __exit_code/_reasoning keys consumed by main()
#   - everything else: no response shape (Stop, SessionStart, SessionEnd, etc.)

def _translate_permission(decision: str, reasoning: str,
                           modifications: dict, event_name: str,
                           original_input: dict) -> dict[str, Any]:
    if decision in PERMISSION_MAP:
        return _permission_response(PERMISSION_MAP[decision], reasoning)
    if decision == "modify":
        # §6.3:146 — refuse an un-interpretable modifications object
        # (both shapes, or overlapping structured targets) rather than
        # half-apply it.
        violation = modify_composition_violation(modifications)
        if violation:
            audit_event("modify_composition_invalid", event=event_name,
                        detail=violation)
            return _permission_response(
                "deny", f"MODIFY refused ({violation}); failing closed per §6.3:146")
        if modifications.get("redactions"):
            # updated_input cannot express JSON-Pointer redactions; never
            # apply only the override half of a compound decision.
            audit_event("modify_unapplied_redactions", event=event_name)
            return _permission_response(
                "deny", "MODIFY refused: Cursor cannot apply the requested "
                "redactions without dropping part of the decision")
        overrides = modifications.get("parameter_overrides")
        # A non-dict override cannot be applied — fail closed per §6.3:146.
        if isinstance(overrides, dict) and event_name == "preToolUse":
            # parameter_overrides are per-argument EDITS while Cursor's
            # updated_input REPLACES the whole input, so merge onto the
            # original.
            merged = {**original_input, **overrides}
            return _permission_response("allow", reasoning, updated_input=merged)
        return _permission_response("deny",
                                     f"MODIFY substituted to DENY: {reasoning}")
    return {}


def _translate_post_tool(decision: str, reasoning: str,
                          modifications: dict, event_name: str) -> dict[str, Any]:
    """Only `postToolUse` documents output fields (`additional_context`,
    and `updated_mcp_tool_output` for MCP tools); every other post-tool
    event documents "No output fields currently supported" (docs
    2026-08-22), so an arrived restrictive decision there is recorded and
    nothing is emitted."""
    if event_name != "postToolUse":
        if decision in ("deny", "modify", "ask", "defer"):
            audit_event("unenforceable_decision", decision=decision,
                        event=event_name, reason=reasoning or "(none)")
        return {}
    if decision == "deny":
        # postToolUse fires after execution — no block exists; the denial
        # reaches the conversation as additional_context and is audited.
        audit_event("unenforceable_decision", decision="deny",
                    event=event_name, reason=reasoning or "(none)")
        return _post_tool_response(
            additional_context=f"ACS Guardian denied this result: "
                               f"{reasoning or '(no reasoning)'}")
    if decision == "modify":
        violation = modify_composition_violation(modifications)
        if violation:
            audit_event("modify_composition_invalid", event=event_name,
                        detail=violation)
            return _post_tool_response(
                additional_context=f"MODIFY refused ({violation})")
        updated = modifications.get("modified_content")
        if updated is not None:
            # Docs show an OBJECT value; ACS modified_content is a string.
            # Parse JSON content when it is JSON, else pass the string.
            return _post_tool_response(
                updated_mcp_tool_output=_parse_json_field(updated))
        return _post_tool_response(
            additional_context=f"MODIFY received: {reasoning}")
    if reasoning:
        return _post_tool_response(additional_context=reasoning)
    return {}


def _translate_before_submit_prompt(decision: str, reasoning: str,
                                     modifications: dict,
                                     event_name: str) -> dict[str, Any]:
    """The prompt hook can only allow (exit 0) or block (exit 2), so every
    non-allow decision fails closed per §6.4; returns internal
    __exit_code/_reasoning keys for main()."""
    if decision == "allow":
        return {"__exit_code": 0, "_reasoning": None}
    if decision != "deny":
        # Audit the substitution for decisions the prompt hook can't apply.
        audit_event("prompt_decision_substituted_block",
                    disposition=decision, event="beforeSubmitPrompt")
    return {"__exit_code": 2,
            "_reasoning": reasoning or f"{decision} on prompt not applicable — blocking"}


def translate_response(acs_response: dict[str, Any], event_name: str,
                       original_input: dict | None = None) -> dict[str, Any]:
    # normalize_decision coerces every field to a safe type and never
    # raises — an uncaught throw here would exit 1 and Cursor would proceed.
    decision, reasoning, modifications = normalize_decision(
        acs_response.get("result"))
    original_input = original_input or {}

    # An arrived-but-uninterpretable decision fails closed; the exact
    # spec basis is unsettled (§6.4:156 vs. arrived-and-unusable),
    # tracked in issue #32.
    if decision not in KNOWN_DECISIONS:
        audit_event("unusable_disposition",
                    disposition=decision or "(missing)", event=event_name)
        reason = (f"unusable Guardian disposition '{decision}' — cannot be "
                  f"interpreted; failing closed (see issue #32)")
        if event_name in PERMISSION_EVENTS:
            return _permission_response("deny", reason)
        if event_name == "beforeSubmitPrompt":
            return {"__exit_code": 2, "_reasoning": reason}
        # Post-tool / observational events have no enforceable shape;
        # the audit event above is the record.
        return {}

    if event_name in PERMISSION_EVENTS:
        return _translate_permission(decision, reasoning, modifications,
                                     event_name, original_input)
    if event_name in POST_TOOL_EVENTS:
        return _translate_post_tool(decision, reasoning, modifications, event_name)
    if event_name == "beforeSubmitPrompt":
        return _translate_before_submit_prompt(decision, reasoning, modifications, event_name)

    # Remaining events are observational with no response shape — empty
    # dict skips stdout emission.
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

def _guardian_roundtrip(request: dict[str, Any], event_name: str,
                        event: dict[str, Any]) -> tuple[dict | None, int | None]:
    """POST one request and validate the response. Returns
    (result_dict, None) for a good, bound, signed result, or
    (None, exit_code) when a terminal fail/force_deny was already emitted
    in the event's shape; shared by the turnStart pre-step and the main step."""
    session_id = _session_id(event)
    try:
        response = call_guardian(request)
    except RequestTooLargeError as e:
        sys.stderr.write(f"acs-adapter: envelope exceeds body cap: {e}\n")
        return None, _force_deny(event_name, session_id,
                                 cause="request_exceeds_max_payload",
                                 body_bytes=e.args[0], method=request.get("method"))
    except GuardianHTTPRefusalError as e:
        code = e.jsonrpc_error.get("code")
        cause = (guardian_error_cause(code) if code is not None
                 else f"http_{e.status}_refusal")
        sys.stderr.write(
            f"acs-adapter: Guardian refused at HTTP layer ({e.status}, {cause})\n")
        return None, _force_deny(event_name, session_id, cause=cause,
                                 http_status=e.status, error_code=code,
                                 error_message=e.jsonrpc_error.get("message"),
                                 method=request.get("method"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", None)
        is_timeout = isinstance(e, TimeoutError) or isinstance(reason, TimeoutError)
        if is_timeout:
            cause = "decision_timeout"
            sys.stderr.write(
                f"acs-adapter: decision timed out after {_DECISION_TIMEOUT_S:g}s: {e}\n")
        else:
            cause = "transport_failure"
            sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return None, _fail(event_name, session_id, cause=cause,
                           request_id=request.get("params", {}).get("request_id"),
                           method=request.get("method"), error=str(e))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return None, _fail(event_name, session_id,
                           cause="adapter_exception", error=str(e))

    if not response_matches_request(request, response):
        sys.stderr.write("acs-adapter: response not bound to request\n")
        return None, _force_deny(event_name, session_id,
                                 cause="response_binding_mismatch")

    if "error" in response:
        if not verify_signature(response, session_id=session_id):
            sys.stderr.write("acs-adapter: error response signature invalid\n")
            claimed = response.get("error") or {}
            return None, _force_deny(
                event_name, session_id, cause="error_signature_invalid",
                claimed_error_code=claimed.get("code"),
                claimed_cause=guardian_error_cause(claimed.get("code")))
        err = response.get("error") or {}
        code = err.get("code")
        cause = guardian_error_cause(code)
        sys.stderr.write(
            f"acs-adapter: Guardian returned JSON-RPC error {code} ({cause}): "
            f"{err.get('message','')}\n")
        common = dict(cause=cause, error_code=code,
                      error_message=err.get("message"),
                      request_id=request.get("params", {}).get("request_id"),
                      method=request.get("method"))
        if is_guardian_refusal(code):
            return None, _force_deny(event_name, session_id, **common)
        return None, _fail(event_name, session_id, **common)

    if not verify_signature(response, session_id=session_id):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return None, _force_deny(event_name, session_id,
                                 cause="response_signature_invalid")
    return response, None


def main() -> int:
    global _SERVER_DENY, _DECISION_TIMEOUT_S
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (cursor) {ADAPTER_VERSION}")
        return 0
    if os.environ.get("ACS_DISABLED") == "1":
        # Incident kill switch — a structured audit event so the bypass
        # reaches the durable sink (§6.4:158).
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
    except json.JSONDecodeError as e:
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        return _fail(event_name, cause="invalid_stdin_json")

    if event_name not in HOOK_MAP:
        if event_name not in KNOWN_UNMAPPED:
            # Upstream rename or unknown wired event — audit it so the
            # ungoverned step is recorded, never silent.
            audit_event("unmapped_hook_event", event=event_name,
                        session_id=_session_id(event))
        return 0

    server_hello = _maybe_handshake(event)
    if server_hello and server_hello.get("on_decision_failure") == "deny":
        _SERVER_DENY = True
    # §6.4:154 — honor the negotiated round-trip timeout.
    if server_hello:
        default_ms = (server_hello.get("timeout_config") or {}).get("default_ms")
        if isinstance(default_ms, (int, float)) and default_ms > 0:
            _DECISION_TIMEOUT_S = default_ms / 1000.0

    session_id = _session_id(event)

    # Turn tracking: beforeSubmitPrompt OPENS a turn with an explicit,
    # decision-eligible steps/turnStart BEFORE the userMessage. A Guardian
    # MAY deny to block the whole turn — which blocks the prompt (exit 2).
    if event_name == "beforeSubmitPrompt":
        turn_id = str(uuid.uuid4())
        ts_response, terminal = _guardian_roundtrip(
            build_turn_start_request(event, turn_id), "beforeSubmitPrompt", event)
        if terminal is not None:
            return terminal
        ts_decision, ts_reason, _ = normalize_decision(ts_response.get("result"))
        if ts_decision != "allow":
            # A turn boundary can't be modify/ask'd — any non-allow
            # blocks the prompt (exit 2).
            audit_event("turn_start_blocked", turn_id=turn_id,
                        disposition=ts_decision or "(unusable)",
                        event="beforeSubmitPrompt")
            msg = (f"turn blocked at start ({ts_decision or 'unusable'}): "
                   f"{ts_reason}")
            sys.stderr.write(f"acs-adapter: {msg}\n")
            sys.stdout.write(json.dumps({"continue": False,
                                         "user_message": msg}) + "\n")
            return 2
        _open_turn(event, turn_id)

    try:
        request = build_request(event_name, event)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(event_name, session_id, cause="adapter_exception", error=str(e))
    if not request:
        if event_name == "stop":
            # turnEnd with no open turn: nothing to close honestly.
            audit_event("turn_end_no_open_turn", session_id=session_id)
            return 0
        sys.stderr.write(f"acs-adapter: could not build request for {event_name}\n")
        return _fail(event_name, session_id, cause="adapter_build_failed")

    # Track this step in session state so subsequent subagentStart /
    # preCompact events can cite a real parent_step_id / entries_to_compact.
    try:
        rid_for_state = request.get("params", {}).get("request_id")
        if session_id and rid_for_state:
            record_step(session_id, rid_for_state, workspace=_workspace(event))
    except Exception:  # noqa: BLE001
        pass

    response, terminal = _guardian_roundtrip(request, event_name, event)
    if terminal is not None:
        return terminal

    # A bug escaping translate_response would exit 1 = Cursor proceeds;
    # this guard makes any translation bug fail closed instead.
    try:
        out = translate_response(response, event_name,
                                 original_input=event.get("tool_input") or {})
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: translate error: {e}\n")
        return _force_deny(event_name, session_id,
                           cause="adapter_translate_exception", error=str(e))

    # Close the turn after the turnEnd has been emitted/recorded.
    if event_name == "stop":
        _close_turn(event)

    if event_name == "beforeSubmitPrompt":
        exit_code = out.pop("__exit_code", 0)
        reasoning = out.pop("_reasoning", None)
        # Documented output is {"continue": bool, "user_message": str}
        # (docs 2026-08-22): emit the native shape and keep exit 2 as
        # belt-and-braces; on allow, {"continue": true} keeps
        # failClosed:true from misreading the hook as failed.
        if exit_code == 0:
            sys.stdout.write(json.dumps({"continue": True}) + "\n")
            return 0
        sys.stderr.write(f"acs-adapter: blocking prompt: {reasoning}\n")
        sys.stdout.write(json.dumps({
            "continue": False,
            "user_message": reasoning or "blocked by ACS Guardian",
        }) + "\n")
        return exit_code

    _emit(out)
    return 0


def _fail(event_name: str = "", session_id: str | None = None, *,
          cause: str = "unknown", **audit_extras) -> int:
    """Apply the deployment's fail posture and record an audit event per
    §6.4; `cause` names what actually went wrong independently of the
    posture (which ACS_DEFAULT_DENY / the ServerHello determine)."""
    if _effective_default_deny():
        return _deny_with_audit("decision_failure_fail_closed",
                                event_name, session_id, cause, audit_extras)

    audit_event("fail_open_bypass",
                cause=cause, event=event_name, session_id=session_id, **audit_extras)
    return 0


def _force_deny(event_name: str = "", session_id: str | None = None, *,
                cause: str = "unknown", **audit_extras) -> int:
    """Fail closed REGARDLESS of posture — for conditions where 'proceed'
    is a bypass primitive: Guardian refusals, response↔request binding
    mismatches, and invalid response signatures."""
    return _deny_with_audit("guardian_refusal_fail_closed",
                            event_name, session_id, cause, audit_extras)


def _deny_with_audit(audit_type: str, event_name: str,
                     session_id: str | None, cause: str,
                     audit_extras: dict) -> int:
    """Emit a deny in the event's native shape + one audit event."""
    audit_event(audit_type,
                cause=cause, event=event_name, session_id=session_id,
                **audit_extras)
    if event_name in PERMISSION_EVENTS:
        _emit(_permission_response(
            "deny", f"ACS adapter: decision-failure ({cause})"))
        return 0
    if event_name == "beforeSubmitPrompt":
        sys.stderr.write(f"acs-adapter: prompt blocked ({cause})\n")
        sys.stdout.write(json.dumps({
            "continue": False,
            "user_message": f"ACS adapter: prompt blocked ({cause})",
        }) + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
