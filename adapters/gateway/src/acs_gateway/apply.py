"""Turn a step's result into the Responses API item the client or the model receives (A.4, applying a decision)."""
from __future__ import annotations

import copy
import json
import secrets
from dataclasses import dataclass
from typing import Any

from acs.core import modify_composition_violation

from acs_gateway.guardian import StepResult

# The one artifact of governance the client and the model may see.
NEUTRAL_LINE = "I couldn't complete that action."
DEFAULT_REDACTION = "[REDACTED]"


def neutral_message() -> dict[str, Any]:
    """An assistant message carrying the neutral line, with an id shaped like the upstream's own."""
    return {"type": "message", "id": f"msg_{secrets.token_hex(24)}", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": NEUTRAL_LINE, "annotations": []}]}


def unsupported_tool(body: dict[str, Any]) -> str | None:
    """The first declared tool that isn't a function tool, named by its type, or None.

    The gateway gates function tools only. Hosted tools (mcp, code_interpreter, web_search, file_search) run
    upstream where no hook can reach them, and client-run ones (custom, shell, computer use) have no gate yet.
    """
    tools = body.get("tools")
    if tools is None:
        return None
    if not isinstance(tools, list):
        return type(tools).__name__
    for tool in tools:
        kind = tool.get("type") if isinstance(tool, dict) else None
        if kind != "function":
            return kind if isinstance(kind, str) else type(tool).__name__
    return None


def is_foreign_call(item: dict[str, Any]) -> bool:
    """An output item asking for a tool run the gateway can't gate: any *_call but function_call, or an MCP approval."""
    kind = item.get("type")
    return isinstance(kind, str) and kind != "function_call" and (
        kind.endswith("_call") or kind == "mcp_approval_request")


def is_foreign_output(item: dict[str, Any]) -> bool:
    """An input item carrying a non-function tool's result, or an MCP approval, to the model."""
    kind = item.get("type")
    return isinstance(kind, str) and kind != "function_call_output" and (
        kind.endswith("_call_output") or kind == "mcp_approval_response")


def neutralize_foreign_output(item: dict[str, Any]) -> dict[str, Any]:
    """An MCP approval becomes a refusal, and any other foreign output carries only the neutral line."""
    if item.get("type") == "mcp_approval_response":
        return {**item, "approve": False}
    return {**item, "output": NEUTRAL_LINE}


@dataclass(frozen=True)
class Applied:
    # "allow", "deny" or "modify": what the gateway did, which a failure or an unusable MODIFY turns into deny.
    decision: str
    # The item to deliver, or None when a call is removed.
    item: dict[str, Any] | None
    # Why the step denied without the Guardian saying deny: a decision failure or a MODIFY the gateway can't apply.
    cause: str | None = None


def parse_arguments(raw: Any) -> dict[str, Any] | None:
    """A function_call's arguments as an object, or None when they aren't a JSON object."""
    try:
        value = json.loads(raw) if isinstance(raw, str) else None
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def call_payload(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # tool.version carries the tool digest once LAB-07 (issue #580) computes it.
    return {"tool": {"name": name}, "arguments": {k: {"value": v} for k, v in arguments.items()}}


def result_payload(name: str, output: Any, request_id_ref: str | None) -> tuple[dict[str, Any], bool]:
    """The toolCallResult payload, and whether outputs[0].value is parsed JSON a redaction can point into."""
    value, parsed = output, False
    if isinstance(output, str):
        try:
            value, parsed = json.loads(output), True
        except (ValueError, RecursionError):
            value = output
    payload: dict[str, Any] = {"tool": {"name": name}, "exit_status": "success", "outputs": [{"value": value}]}
    if request_id_ref:
        payload["request_id_ref"] = request_id_ref
    return payload, parsed


def _decided(result: StepResult) -> str | None:
    """The Guardian's disposition when the gateway may follow it, or None when the step must deny."""
    if result.cause is not None:
        return None
    if not result.evaluated:
        return "allow"
    return result.decision.disposition if result.decision is not None else None


def apply_call(item: dict[str, Any], arguments: dict[str, Any], result: StepResult) -> Applied:
    disposition = _decided(result)
    if disposition == "allow":
        return Applied("allow", item)
    if disposition != "modify":
        # deny, ask (LAB-08, issue #581), defer, an unknown decision and every failure remove the call.
        return Applied("deny", None, result.cause)
    modifications = result.decision.modifications
    if modify_composition_violation(modifications):
        return Applied("deny", None, "modify_composition_invalid")
    overrides = modifications.get("parameter_overrides")
    if set(modifications) - {"parameter_overrides"} or not isinstance(overrides, dict):
        return Applied("deny", None, "modify_unsupported")
    return Applied("modify", {**item, "arguments": json.dumps({**arguments, **overrides})})


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _redact(document: Any, path: str, replacement: str) -> bool:
    """Replace the value at an RFC 6901 pointer that already exists. False when the pointer doesn't resolve."""
    if not path.startswith("/"):
        return False
    tokens = [_unescape(t) for t in path[1:].split("/")]
    target = document
    for token in tokens[:-1]:
        if isinstance(target, dict) and token in target:
            target = target[token]
        elif isinstance(target, list) and token.isdigit() and int(token) < len(target):
            target = target[int(token)]
        else:
            return False
    last = tokens[-1]
    if isinstance(target, dict) and last in target:
        target[last] = replacement
        return True
    if isinstance(target, list) and last.isdigit() and int(last) < len(target):
        target[int(last)] = replacement
        return True
    return False


def apply_result(item: dict[str, Any], payload: dict[str, Any], parsed: bool, result: StepResult) -> Applied:
    """A denied output is replaced by the neutral line rather than removed, since the model refuses a call without one."""
    denied = {**item, "output": NEUTRAL_LINE}
    disposition = _decided(result)
    if disposition == "allow":
        return Applied("allow", item)
    if disposition != "modify":
        return Applied("deny", denied, result.cause)
    modifications = result.decision.modifications
    if modify_composition_violation(modifications):
        return Applied("deny", denied, "modify_composition_invalid")
    if set(modifications) == {"modified_content"}:
        return Applied("modify", {**item, "output": modifications["modified_content"]})
    redactions = modifications.get("redactions")
    if set(modifications) != {"redactions"} or not isinstance(redactions, list) or not redactions:
        return Applied("deny", denied, "modify_unsupported")
    edited = copy.deepcopy(payload)
    for redaction in redactions:
        replacement = redaction.get("replacement", DEFAULT_REDACTION)
        if not isinstance(replacement, str) or not _redact(edited, redaction.get("path", ""), replacement):
            # A redaction the gateway can't place would forward the raw value, so the whole output is withheld.
            return Applied("deny", denied, "modify_unsupported")
    value = edited["outputs"][0]["value"]
    output = json.dumps(value) if parsed else value if isinstance(value, str) else json.dumps(value)
    return Applied("modify", {**item, "output": output})
