"""The acs-cursor-hook command: run the adapter, or record why it could not load and apply the posture."""
from __future__ import annotations

import json
import sys

from acs.integrations._bootstrap import run_hook

# Gate events, which take a {"permission": ...} deny.
PERMISSION_EVENTS = frozenset({"preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution"})
# Gate events where {} leaves the action to Cursor's sandbox and approval, which an explicit allow can bypass (Cursor 3.17.8, Allowlist with Sandbox, checked 2026-11-03).
CURSOR_DECIDES_EVENTS = frozenset({"preToolUse", "beforeShellExecution", "beforeMCPExecution"})


def _event_name(raw: str) -> str:
    return sys.argv[1] if len(sys.argv) > 1 else ""


def _deny(event_name: str, reason: str) -> int:
    if event_name in PERMISSION_EVENTS:
        message = f"ACS blocked this tool call: {reason}"
        print(json.dumps({"permission": "deny", "user_message": message, "agent_message": message}))
        return 0
    if event_name == "beforeSubmitPrompt":
        # The documented native block, read with exit code 0 so Cursor shows the message.
        sys.stderr.write(f"acs-adapter: {reason}\n")
        print(json.dumps({"continue": False, "user_message": reason}))
        return 0
    return 0


def _allow(event_name: str) -> int:
    if event_name in CURSOR_DECIDES_EVENTS:
        print("{}")
    elif event_name in PERMISSION_EVENTS:
        print(json.dumps({"permission": "allow"}))
    elif event_name == "beforeSubmitPrompt":
        print(json.dumps({"continue": True}))
    return 0


def main() -> int:
    return run_hook("acs.integrations.cursor.adapter", event_key="event",
                    event_name=_event_name, deny=_deny, allow=_allow)


if __name__ == "__main__":
    sys.exit(main())
