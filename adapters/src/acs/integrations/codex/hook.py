"""The acs-codex-hook command: run the adapter, or record why it could not load and apply the posture."""
from __future__ import annotations

import json
import sys

from acs.integrations._bootstrap import run_hook


def _event_name(raw: str) -> str:
    """The event's hook_event_name; an event that does not parse counts as PreToolUse, the one event this command is registered on."""
    try:
        event = json.loads(raw or "{}")
    except ValueError:
        return "PreToolUse"
    name = event.get("hook_event_name") if isinstance(event, dict) else None
    return name if isinstance(name, str) and name else "PreToolUse"


def _deny(event_name: str, reason: str) -> int:
    if event_name == "PreToolUse":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))
    return 0


def main() -> int:
    return run_hook("acs.integrations.codex.adapter", event_key="hook",
                    event_name=_event_name, deny=_deny)


if __name__ == "__main__":
    sys.exit(main())
