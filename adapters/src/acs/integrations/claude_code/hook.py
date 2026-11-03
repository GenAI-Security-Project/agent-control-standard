"""The acs-claude-code-hook command: run the adapter, or record why it could not load and apply the posture."""
from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable

from acs.integrations._bootstrap import run_hook


def _event_name(raw: str) -> str:
    """The event's top-level hook_event_name, scanned without parsing when the event does not parse."""
    try:
        event = json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return _top_level_string(raw, "hook_event_name")
    name = event.get("hook_event_name", "") if isinstance(event, dict) else ""
    return name if isinstance(name, str) else ""


def _top_level_string(raw: str, key: str, accept: Callable[[str], bool] = lambda s: s.isascii() and s.isalpha()) -> str:
    """The last string value of `key` in the top-level JSON object, skipping nested values iteratively; "" if none."""
    found, depth, last_key, awaiting, i = "", 0, None, False, 0
    while i < len(raw):
        c = raw[i]
        if c == '"':
            j = i + 1
            while j < len(raw) and raw[j] != '"':
                j += 2 if raw[j] == "\\" else 1
            text, i = raw[i + 1:j], j + 1
            if depth == 1:
                if awaiting:
                    try:
                        found = json.loads(f'"{text}"')
                    except ValueError:
                        found = ""
                    awaiting = False
                else:
                    last_key = text
            continue
        if c in "{[":
            depth += 1
            awaiting = False
        elif c in "}]":
            depth -= 1
        elif depth == 1 and c == ":":
            awaiting = last_key == key
        elif depth == 1 and c == ",":
            last_key, awaiting = None, False
        i += 1
    return found if accept(found) else ""


def _deny(event_name: str, reason: str) -> int:
    if event_name == "PreToolUse":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }, "systemMessage": f"ACS blocked this tool call: {reason}"}))
    elif event_name == "UserPromptSubmit":
        print(json.dumps({"decision": "block", "reason": reason, "systemMessage": f"ACS blocked this: {reason}"}))
    return 0


def _cursor_event(raw: str) -> str:
    try:
        event = json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return _top_level_string(raw, "hook_event_name") if _top_level_string(raw, "cursor_version", bool) else ""
    name = event.get("hook_event_name") if isinstance(event, dict) and "cursor_version" in event else None
    return name if isinstance(name, str) else ""


def main() -> int:
    if sys.argv[1:2] != ["--version"]:
        raw = sys.stdin.read()
        sys.stdin = io.StringIO(raw)
        cursor_event = _cursor_event(raw)
        if cursor_event:
            # Cursor runs the Claude Code hooks it imports from .claude/settings.json with its own events and answers.
            from acs.integrations.cursor import hook as cursor_hook
            sys.argv = [sys.argv[0], cursor_event]
            return cursor_hook.main()
    return run_hook("acs.integrations.claude_code.adapter", event_key="hook",
                    event_name=_event_name, deny=_deny)


if __name__ == "__main__":
    sys.exit(main())
