"""The acs-cursor-hook command: run the adapter, or record why it could not load and apply the posture."""
from __future__ import annotations

import json
import sys

from acs.integrations._bootstrap import run_hook

# Gate events, which take a {"permission": ...} deny.
PERMISSION_EVENTS = frozenset({"preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution"})


def _event_name() -> str:
    return sys.argv[1] if len(sys.argv) > 1 else ""


def _deny(event_name: str, reason: str) -> int:
    if event_name in PERMISSION_EVENTS:
        print(json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason}))
        return 0
    if event_name == "beforeSubmitPrompt":
        # The documented native block, plus exit code 2.
        sys.stderr.write(f"acs-adapter: {reason}\n")
        print(json.dumps({"continue": False, "user_message": reason}))
        return 2
    return 0


def main() -> int:
    return run_hook("acs.integrations.cursor.adapter", event_key="event",
                    event_name=_event_name, deny=_deny)


if __name__ == "__main__":
    sys.exit(main())
