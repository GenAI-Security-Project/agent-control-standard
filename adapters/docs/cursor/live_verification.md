# Cursor live verification

Cursor is a desktop application with no documented headless mode, so the live test cannot run in CI. It can be reproduced manually by a reviewer with Cursor installed.

## Status: ✅ Verified via manual reproduction

The procedure below has been run end-to-end and produced the expected outcomes (5+ events flowed from a real Cursor session through the adapter to the example Guardian, all hooks routed correctly, zero adapter errors). Real captured payloads are not committed to the repo because Cursor's hook events contain session-identifying fields (workspace path, conversation id, user email).

## Procedure

```bash
# 1. Start the example Guardian
python3 ../../example-guardian/example_guardian.py --port 8787

# 2. In a new shell, set up a test project with the adapter wired in
mkdir -p /tmp/acs-cursor-live/.cursor
cat > /tmp/acs-cursor-live/.cursor/hooks.json <<'EOF'
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      { "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py sessionStart" }
    ],
    "beforeSubmitPrompt": [
      { "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py beforeSubmitPrompt" }
    ],
    "preToolUse": [
      { "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py preToolUse" }
    ],
    "postToolUse": [
      { "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py postToolUse" }
    ],
    "beforeShellExecution": [
      { "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py beforeShellExecution" }
    ]
  }
}
EOF

# 3. Open the project in Cursor and prompt the agent to do something
#    that triggers tool calls (a benign Grep or a Shell command works).

# 4. Observe the Guardian's stderr for hook events:
#    [guardian] steps/sessionStart   session=<uuid> step=<uuid>
#    [guardian] steps/userMessage    session=<uuid> step=<uuid>
#    [guardian] steps/toolCallRequest session=<uuid> step=<uuid>
#    [guardian] steps/toolCallResult  session=<uuid> step=<uuid>
```

## Expected outcomes

A benign prompt that triggers tool use should produce, in order, on the Guardian's stderr:

1. `steps/sessionStart` (Cursor's `sessionStart` event)
2. `steps/userMessage` (Cursor's `beforeSubmitPrompt`)
3. `steps/toolCallRequest` (Cursor's `preToolUse` for the first tool)
4. `steps/toolCallResult` (Cursor's `postToolUse`)
5. Additional `toolCallRequest` / `toolCallResult` pairs for each subsequent tool the agent invokes

The Cursor UI should show the agent's tool calls proceeding normally; no policy block messages because the example Guardian's policy only denies destructive Bash patterns and writes to system paths.

## Deny-path verification

To exercise the deny path, prompt the Cursor agent to run a command matching the example Guardian's destructive regex against a clearly nonexistent target (something the agent has no real reason to run). The Guardian should respond with `deny`; the adapter should emit `{"permission": "deny", "user_message": "destructive Bash pattern..."}`; Cursor should surface the block in its UI and not execute the command.

## Cursor event schema notes

While running the reproduction, the Cursor events sent to the adapter include several fields beyond what the public `create-hook` skill documentation specifies. These are handled by the adapter's existing fallback logic without modification:

- Both `session_id` and `conversation_id` are present (the adapter prefers `session_id`)
- `generation_id`, `model`, `composer_mode`, `cursor_version`
- `workspace_roots`, `transcript_path`, `user_email` (deployment-specific, the adapter does not forward these to the Guardian by default)
- For tools: `tool_use_id`, `duration`
- For Shell: `command`, `cwd`, `sandbox`

If your Guardian wants to incorporate any of these into policy decisions, extend `acs_adapter.py`'s `build_payload` to include the relevant fields.
