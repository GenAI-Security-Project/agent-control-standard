#!/usr/bin/env python3
"""Codex PreToolUse -> signed ACS toolCallRequest -> native decision.

First slice only: no session/turn lifecycle or ACS-Core profile claim.
Runtime: Python 3.10+ and sibling _common/ (rfc8785 required).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ADAPTER_VERSION = "0.1.0"
METHOD = "steps/toolCallRequest"
MAX_BYTES = 1_000_000
MAX_DECISION_SECONDS = 10.0  # leave room for handshake inside a 30s hook


def response(decision: str, reason: str = "", updated_input: dict | None = None) -> dict:
    output = {"hookEventName": "PreToolUse", "permissionDecision": decision}
    if reason:
        output["permissionDecisionReason"] = reason
    if updated_input is not None:
        output["updatedInput"] = updated_input
    return {"hookSpecificOutput": output}


def emit(output: dict) -> None:
    print(json.dumps(output, allow_nan=False))


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
try:
    from acs_common import (
        ACS_VERSION, audit_event, coerce_uuid, ensure_session_handshake,
        guardian_error_cause, is_guardian_refusal, iso8601_now,
        load_hmac_secret, modify_composition_violation, normalize_decision,
        response_matches_request, sign_envelope, validate_guardian_url,
        verify_signature,
    )
except Exception:
    # Nonblocking hook failures must not silently turn a missing dependency
    # (or invalid shared-library configuration) into permission to execute.
    if __name__ != "__main__":
        raise
    sys.stderr.write('ACS_AUDIT {"acs_audit_event":"adapter_unavailable"}\n')
    emit(response("deny", "ACS Codex adapter could not load; check dependencies/configuration"))
    raise SystemExit(0)


class Refusal(ValueError):
    """An arrived/constructed message cannot safely be honored."""


def strict_json(raw: str | bytes):
    def invalid_constant(value):
        raise Refusal("nonfinite_json")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refusal("duplicate_json_key")
            result[key] = value
        return result

    return json.loads(raw, parse_constant=invalid_constant, object_pairs_hook=unique_pairs)


def validate_event(event) -> None:
    if not isinstance(event, dict):
        raise Refusal("hook_input_not_object")
    for name in ("session_id", "turn_id", "tool_use_id", "tool_name"):
        if not isinstance(event.get(name), str) or not event[name].strip():
            raise Refusal(f"missing_or_invalid_{name}")
    validate_input(event["tool_name"], event.get("tool_input"))


def validate_input(tool: str, tool_input) -> None:
    if not isinstance(tool_input, dict):
        raise Refusal("tool_input_not_object")
    if tool in ("Bash", "apply_patch") and not isinstance(tool_input.get("command"), str):
        raise Refusal("command_must_be_string")


def agent_id(event: dict) -> str:
    cwd = event.get("cwd", "")
    return os.environ.get("ACS_AGENT_ID") or "codex:" + hashlib.sha256(
        str(cwd).encode()).hexdigest()[:8]


def session_id(event: dict) -> str:
    # Codex can supply opaque IDs (e.g. thr_*); ACS requires a UUID.
    return coerce_uuid(event["session_id"], namespace_prefix="codex:session")


def build_request(event: dict) -> dict:
    sid = session_id(event)
    metadata = {
        "agent_id": agent_id(event), "session_id": sid,
        "turn_id": event["turn_id"], "platform": "codex",
        "adapter_version": ADAPTER_VERSION,
        "codex_session_id": event["session_id"],
        "codex_tool_use_id": event["tool_use_id"],
    }
    for name in ("cwd", "permission_mode", "model"):
        if isinstance(event.get(name), str):
            metadata[name] = event[name]
    # Include the session in the key: tools in different sessions can reuse IDs.
    rid = str(uuid.uuid5(uuid.UUID(sid), "codex:tool_use:" + event["tool_use_id"]))
    envelope = {
        "jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": METHOD,
        "params": {
            "acs_version": ACS_VERSION, "request_id": rid,
            "timestamp": iso8601_now(), "metadata": metadata,
            "payload": {
                "tool": {"name": event["tool_name"]},
                "arguments": {key: {"value": value}
                              for key, value in event["tool_input"].items()},
            },
        },
    }
    sign_envelope(envelope, session_id=sid)
    return envelope


def denied(cause: str) -> dict:
    audit_event("codex_denied", cause=cause, hook="PreToolUse")
    return response("deny", f"ACS: {cause}")


def failure(cause: str, default_deny: bool) -> dict:
    audit_event("decision_failure_fail_closed" if default_deny else "fail_open_bypass",
                cause=cause, hook="PreToolUse")
    # No decision preserves Codex's own permission/approval checks.
    return response("deny", f"ACS: {cause}") if default_deny else {}


def translate(result: dict, event: dict) -> dict:
    if result.get("type") != "final" or result.get("acs_version") != ACS_VERSION:
        return denied("unsupported_result_type_or_version")
    decision, reason, modifications = normalize_decision(result)
    if decision in ("allow", "deny"):
        return response(decision, reason)
    if decision in ("ask", "defer"):
        # Codex does NOT implement PreToolUse ask. Returning it is a hook
        # error and execution continues. Never forward it to the host.
        return denied(f"{decision}_substituted_deny")
    if decision != "modify":
        return denied("unusable_disposition")
    violation = modify_composition_violation(modifications)
    if violation:
        return denied("invalid_modify_composition")
    # Only named parameter overrides are implemented. Do not half-apply a
    # compound edit or silently discard a future modification operation.
    if set(modifications) != {"parameter_overrides"} or not isinstance(
            modifications.get("parameter_overrides"), dict):
        return denied("unsupported_modifications")
    if event["tool_name"] in ("Bash", "apply_patch") and set(
            modifications["parameter_overrides"]) - {"command"}:
        # Codex's shell/patch hook contract only guarantees rewriting command.
        # Do not silently ignore a Guardian's change to another tool setting.
        return denied("unsupported_command_override")
    updated = {**event["tool_input"], **modifications["parameter_overrides"]}
    try:
        validate_input(event["tool_name"], updated)
    except Refusal:
        return denied("invalid_updated_input")
    return response("allow", reason, updated)


def call_guardian(url: str, request: dict, timeout: float) -> dict:
    body = json.dumps(request, allow_nan=False).encode()
    if len(body) > MAX_BYTES:
        raise Refusal("request_too_large")
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    # The signed request must not be redirected to a different endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as reply:
            raw = reply.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise Refusal(f"guardian_http_{exc.code}") from exc
    if len(raw) > MAX_BYTES:
        raise Refusal("response_too_large")
    try:
        result = strict_json(raw)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("malformed_guardian_response") from exc
    if not isinstance(result, dict) or result.get("jsonrpc") != "2.0":
        raise Refusal("invalid_response_envelope")
    if ("result" in result) == ("error" in result):
        raise Refusal("invalid_response_envelope")
    container = result.get("result", result.get("error"))
    if not isinstance(container, dict):
        raise Refusal("invalid_response_container")
    if not response_matches_request(request, result):
        raise Refusal("response_binding_mismatch")
    if not verify_signature(result, session_id=request["params"]["metadata"]["session_id"]):
        raise Refusal("response_signature_invalid")
    return result


def run(event: dict) -> dict:
    validate_event(event)
    url = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
    validate_guardian_url(url)
    # This slice is signed-only. A missing/unreadable secret is a setup error,
    # not the same thing as a temporary Guardian outage.
    if not load_hmac_secret():
        return denied("signing_secret_required")
    posture = os.environ.get("ACS_DEFAULT_DENY", "0")
    if posture not in ("0", "1"):
        return denied("invalid_failure_posture")
    default_deny = posture == "1"
    hello = ensure_session_handshake(
        guardian_url=url, session_id=session_id(event), agent_id=agent_id(event),
        platform="codex", methods_implemented=[METHOD], profiles_supported=[],
        transports_supported=["http"], timeout=5.0,
    )
    if hello is None:
        return failure("handshake_failed", default_deny)
    if not isinstance(hello, dict) or hello.get("negotiated_version") != ACS_VERSION:
        return denied("invalid_server_hello")
    if hello.get("selected_transport") != "http" or METHOD not in hello.get("methods_evaluated", []):
        return denied("unsupported_negotiation")
    if hello.get("on_decision_failure", "proceed") not in ("deny", "proceed"):
        return denied("invalid_negotiated_posture")
    default_deny |= hello.get("on_decision_failure") == "deny"
    milliseconds = (hello.get("timeout_config") or {}).get("default_ms", 5000)
    if (isinstance(milliseconds, bool) or not isinstance(milliseconds, (int, float))
            or not math.isfinite(milliseconds) or not 0 < milliseconds <= MAX_DECISION_SECONDS * 1000):
        return denied("unsupported_decision_timeout")
    request = build_request(event)
    try:
        result = call_guardian(url, request, milliseconds / 1000)
    except (urllib.error.URLError, TimeoutError, OSError):
        return failure("guardian_unreachable_or_timeout", default_deny)
    if "error" in result:
        code = result["error"].get("code")
        if not isinstance(code, int) or isinstance(code, bool):
            return denied("invalid_error_code")
        cause = guardian_error_cause(code)
        return denied(cause) if is_guardian_refusal(code) else failure(cause, default_deny)
    return translate(result["result"], event)


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print(f"acs-adapter (codex) {ADAPTER_VERSION}")
        return 0
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise Refusal("hook_input_too_large")
        event = strict_json(raw)
        if isinstance(event, dict) and event.get("hook_event_name") not in (None, "PreToolUse"):
            audit_event("unmapped_hook_event", hook=event.get("hook_event_name"))
            return 0
        if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
            raise Refusal("invalid_hook_event")
        output = run(event)
    except Refusal as exc:
        output = denied(str(exc))
    except Exception as exc:
        # Exit 1 is not a reliable denial. Emit a valid native deny even
        # when parsing, bootstrap configuration, or translation goes wrong.
        audit_event("adapter_exception", error_type=type(exc).__name__)
        output = response("deny", "ACS adapter failed; inspect the audit log")
    emit(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
