"""The acs-claude-code-hook command: run the adapter, or record why it could not load and apply the posture."""
from __future__ import annotations

import json
import sys

from acs.integrations._bootstrap import run_hook


def _event_name() -> str:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        event = {}
    return event.get("hook_event_name", "") if isinstance(event, dict) else ""


def _deny(event_name: str, reason: str) -> int:
    if event_name == "PreToolUse":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))
    elif event_name == "UserPromptSubmit":
        print(json.dumps({"decision": "block", "reason": reason}))
    return 0


def main() -> int:
    return run_hook("acs.integrations.claude_code.adapter", event_key="hook",
                    event_name=_event_name, deny=_deny)


if __name__ == "__main__":
    sys.exit(main())
