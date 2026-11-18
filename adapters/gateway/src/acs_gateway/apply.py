"""Turn a step's result into the Responses API item the client or the model receives (A.4, applying a decision)."""
from __future__ import annotations

import copy
import json
import secrets
from dataclasses import dataclass
from typing import Any

from acs.core import modify_composition_violation

from acs_gateway.guardian import StepResult
from acs_gateway.strict import loads_recording

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


# Shadow and enforce accept only what an unmodified FinBot sends (openai_client.py and chat.py at 1450fc4), plus the
# ordinary Responses API fields that don't move history or tools out of the gateway's sight. Anything else, such as
# prompt, previous_response_id, conversation, background or include, could hide items or enable tools upstream.
ALLOWED_FIELDS = frozenset({"model", "input", "instructions", "tools", "tool_choice", "stream", "max_output_tokens",
                            "reasoning", "text", "metadata", "parallel_tool_calls", "store", "user", "temperature",
                            "top_p"})
# Input items the gateway can read and gate. An item with a role and no type is a message.
ALLOWED_INPUT_TYPES = frozenset({"message", "function_call", "function_call_output", "reasoning"})
# Output items the gateway lets through: text, gated function calls, and the reasoning that goes with them.
ALLOWED_OUTPUT_TYPES = frozenset({"message", "function_call", "reasoning"})


def item_type(item: Any) -> str:
    """An item's type, "message" for a role-only message, or the Python type name for a non-object."""
    if not isinstance(item, dict):
        return type(item).__name__
    kind = item.get("type")
    if kind is None and "role" in item:
        return "message"
    return kind if isinstance(kind, str) else type(kind).__name__


def unsupported_field(body: dict[str, Any]) -> str | None:
    """The first top-level field outside ALLOWED_FIELDS, or None."""
    return next((field for field in body if field not in ALLOWED_FIELDS), None)


def unsupported_tool_choice(body: dict[str, Any]) -> str | None:
    """The tool_choice, rendered for the audit line, when it isn't auto, none, required, or a function choice naming a
    declared function tool. A hosted tool named here would run upstream, out of the gateway's reach."""
    choice = body.get("tool_choice")
    if choice is None or choice in ("auto", "none", "required"):
        return None
    if isinstance(choice, dict) and set(choice) == {"type", "name"} and choice.get("type") == "function":
        tools = body.get("tools") if isinstance(body.get("tools"), list) else []
        declared = {t.get("name") for t in tools if isinstance(t, dict) and t.get("type") == "function"}
        if choice.get("name") in declared:
            return None
    return json.dumps(choice, sort_keys=True, default=str)[:200]


# Content parts FinBot's history can hold, by where they sit. FinBot sends string content only, and the model's own
# messages and reasoning carry the rest. input_file, input_image and input_audio can pull stored content in by
# file_id, out of the gate's sight, so they appear nowhere.
_MESSAGE_PARTS = frozenset({"input_text", "output_text", "refusal"})
_OUTPUT_PARTS = frozenset({"input_text", "output_text"})
ALLOWED_CONTENT_PARTS = {
    "message": {"content": _MESSAGE_PARTS},
    "reasoning": {"summary": frozenset({"summary_text"}), "content": frozenset({"reasoning_text"})},
    "function_call_output": {"output": _OUTPUT_PARTS},
}


def unsupported_content_part(body: dict[str, Any]) -> str | None:
    """The type of the first part of an input item outside the allowlist for where it sits, or None."""
    items = body.get("input")
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        for field, allowed in ALLOWED_CONTENT_PARTS.get(item_type(item), {}).items():
            parts = item.get(field)
            if parts is None or isinstance(parts, str):
                continue
            if not isinstance(parts, list):
                # Content is a string or a list of parts. Anything else is a shape the gateway can't read.
                return "non_list_value"
            for part in parts:
                kind = part.get("type") if isinstance(part, dict) else None
                if kind not in allowed:
                    return kind if isinstance(kind, str) else type(part).__name__
    return None


def unsupported_input_item(body: dict[str, Any]) -> str | None:
    """The type of the first input item outside ALLOWED_INPUT_TYPES, or None."""
    items = body.get("input")
    if not isinstance(items, list):
        return None
    return next((item_type(i) for i in items if item_type(i) not in ALLOWED_INPUT_TYPES), None)


@dataclass(frozen=True)
class Applied:
    # "allow", "deny" or "modify": what the gateway did, which a failure or an unusable MODIFY turns into deny.
    decision: str
    # The item to deliver, or None when a call is removed.
    item: dict[str, Any] | None
    # Why the step denied without the Guardian saying deny: a decision failure or a MODIFY the gateway can't apply.
    cause: str | None = None
    # A modified call's merged arguments, so the caller can take their canonical form without parsing them again.
    arguments: dict[str, Any] | None = None


def parse_arguments(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """A function_call's arguments as an object, and the first key they repeat, from one parse. The object is None
    when they aren't a JSON object or repeat a key, since the client and the Guardian could then read different
    values."""
    if not isinstance(raw, str):
        return None, None
    try:
        value, repeated = loads_recording(raw)
    except (ValueError, RecursionError):
        return None, None
    if repeated is not None or not isinstance(value, dict):
        return None, repeated
    return value, None


def call_payload(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # tool.version carries the tool digest once LAB-07 (issue #580) computes it.
    return {"tool": {"name": name}, "arguments": {k: {"value": v} for k, v in arguments.items()}}


def result_payload(name: str, output: Any, request_id_ref: str | None) -> tuple[dict[str, Any], bool, str | None]:
    """The toolCallResult payload, whether outputs[0].value is parsed JSON a redaction can point into, and the first
    key the output repeats, or None. Parsed once, strictly."""
    value, parsed, repeated = output, False, None
    if isinstance(output, str):
        try:
            value, repeated = loads_recording(output)
            parsed = True
        except (ValueError, RecursionError):
            value = output
    payload: dict[str, Any] = {"tool": {"name": name}, "exit_status": "success", "outputs": [{"value": value}]}
    if request_id_ref:
        payload["request_id_ref"] = request_id_ref
    return payload, parsed, repeated


def _decided(result: StepResult) -> str | None:
    """The Guardian's disposition when the gateway may follow it, or None when the step must deny."""
    if result.cause is not None:
        return None
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
    merged = {**arguments, **overrides}
    return Applied("modify", {**item, "arguments": json.dumps(merged)}, arguments=merged)


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _index(token: str, items: list[Any]) -> int | None:
    """The array index an RFC 6901 token names, or None. Only ASCII digits without a leading zero count, since
    str.isdigit also accepts digits from other scripts, which int() then reads or refuses."""
    if not (token.isascii() and token.isdigit()) or (len(token) > 1 and token[0] == "0"):
        return None
    index = int(token)
    return index if index < len(items) else None


def _redact(document: Any, path: str, replacement: str) -> bool:
    """Replace the value at an RFC 6901 pointer that already exists. False when the pointer doesn't resolve."""
    if not path.startswith("/"):
        return False
    tokens = [_unescape(t) for t in path[1:].split("/")]
    target = document
    for token in tokens[:-1]:
        if isinstance(target, dict) and token in target:
            target = target[token]
        elif isinstance(target, list) and (index := _index(token, target)) is not None:
            target = target[index]
        else:
            return False
    last = tokens[-1]
    if isinstance(target, dict) and last in target:
        target[last] = replacement
        return True
    if isinstance(target, list) and (index := _index(last, target)) is not None:
        target[index] = replacement
        return True
    return False


def _output_value(payload: dict[str, Any]) -> tuple[bool, Any]:
    """outputs[0].value after the redactions, and whether that shape survived them. A redaction may replace the
    output item or the outputs array itself, and then nothing is left to read back."""
    outputs = payload.get("outputs")
    if not isinstance(outputs, list) or not outputs or not isinstance(outputs[0], dict) or "value" not in outputs[0]:
        return False, None
    return True, outputs[0]["value"]


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
    survived, value = _output_value(edited)
    if not survived:
        # The Guardian's MODIFY was valid and is honored: it redacted the whole output, so none of it is forwarded.
        return Applied("modify", denied, "output_withheld")
    output = json.dumps(value) if parsed else value if isinstance(value, str) else json.dumps(value)
    return Applied("modify", {**item, "output": output})
