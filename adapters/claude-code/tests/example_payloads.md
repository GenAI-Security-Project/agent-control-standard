# Real-world payload examples — Claude Code

These are the actual JSON shapes Claude Code emits on stdin for each hook, captured from a real `claude` session and **masked**. Identifying fields are replaced with placeholders. Use these to understand the schema the adapter parses.

All fields documented in [Claude Code's hook docs](https://code.claude.com/docs/en/hooks) plus several that appear in real payloads but aren't in the public docs (flagged below).

---

## SessionStart

```json
{
  "session_id": "00000000-0000-0000-0000-000000000001",
  "transcript_path": "/Users/<user>/.claude/projects/<project-slug>/<session-id>.jsonl",
  "cwd": "/path/to/project",
  "hook_event_name": "SessionStart",
  "source": "startup"
}
```

`source` enum: `startup`, `resume`, `clear`, `compact`.

---

## UserPromptSubmit

```json
{
  "session_id": "00000000-0000-0000-0000-000000000001",
  "transcript_path": "/Users/<user>/.claude/projects/<project-slug>/<session-id>.jsonl",
  "cwd": "/path/to/project",
  "permission_mode": "default",
  "hook_event_name": "UserPromptSubmit",
  "prompt": "<user prompt text>"
}
```

`permission_mode` enum: `default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`.

---

## PreToolUse (Bash tool)

```json
{
  "session_id": "00000000-0000-0000-0000-000000000001",
  "transcript_path": "/Users/<user>/.claude/projects/<project-slug>/<session-id>.jsonl",
  "cwd": "/path/to/project",
  "permission_mode": "acceptEdits",
  "effort": {"level": "high"},
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "echo hello",
    "description": "Echo a test string"
  },
  "tool_use_id": "toolu_00000000000000000000000000"
}
```

Fields not in the public docs but present in real payloads: `effort.level`, `tool_use_id`. The adapter forwards `tool_use_id` to the Guardian as part of the payload context.

---

## PostToolUse (Bash tool)

```json
{
  "session_id": "00000000-0000-0000-0000-000000000001",
  "transcript_path": "/Users/<user>/.claude/projects/<project-slug>/<session-id>.jsonl",
  "cwd": "/path/to/project",
  "permission_mode": "acceptEdits",
  "effort": {"level": "high"},
  "hook_event_name": "PostToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "echo hello",
    "description": "Echo a test string"
  },
  "tool_response": {
    "stdout": "hello",
    "stderr": "",
    "interrupted": false,
    "isImage": false,
    "noOutputExpected": false
  },
  "tool_use_id": "toolu_00000000000000000000000000",
  "duration_ms": 5616
}
```

**Important schema difference from docs:** the public docs describe a `tool_output` string field, but real Claude Code emits a `tool_response` **object** with `stdout`, `stderr`, `interrupted`, `isImage`, `noOutputExpected`. The adapter reads `tool_response` first, falls back to `tool_output` for forward-compat.

---

## Adapter response shapes

### Allow (any PreToolUse)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow"
  }
}
```

### Deny (PreToolUse)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "destructive Bash pattern in: rm -rf /home/u"
  }
}
```

### Modify (PreToolUse) — passes modified tool_input back to Claude Code

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": {"command": "echo hello # sanitized by Guardian"}
  }
}
```

### Block on lifecycle hooks (PostToolUse, UserPromptSubmit, Stop, etc.)

These use top-level `decision: "block"`:

```json
{
  "decision": "block",
  "reason": "ACS adapter: Guardian unreachable"
}
```

---

## Masking convention used here

| Field | Real value contains | Masked as |
|---|---|---|
| `session_id` | Real UUID from the session | `00000000-0000-0000-0000-000000000001` |
| `transcript_path` | Real absolute path on the user's machine | `/Users/<user>/.claude/projects/<project-slug>/<session-id>.jsonl` |
| `cwd` | Real working directory at runtime | `/path/to/project` |
| `prompt` | Actual user input | `<user prompt text>` |
| `tool_use_id` | Real Claude Code internal id | `toolu_00000000000000000000000000` |
| `command` | Real command (sometimes preserved when benign) | Either preserved or `<command>` |

No real session data is committed to this repo.
