# Real-world payload examples — Cursor

These are the actual JSON shapes Cursor emits on stdin for each hook, captured from a real Cursor agent session and **masked**. Identifying fields are replaced with placeholders. Use these to understand the schema the adapter parses.

The fields documented in Cursor's bundled `create-hook` skill (`~/.cursor/skills-cursor/create-hook/SKILL.md`) plus several that appear in real payloads but aren't in the public-facing docs (flagged below).

---

## sessionStart

```json
{
  "session_id": "00000000-0000-0000-0000-000000000001",
  "transcript_path": "/Users/<user>/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/<session-id>.jsonl",
  "cwd": "/path/to/workspace",
  "hook_event_name": "sessionStart",
  "cursor_version": "3.7.x",
  "workspace_roots": ["/path/to/workspace"],
  "user_email": "<user@example.com>"
}
```

Fields not in the public skill docs but present in real payloads: `cursor_version`, `workspace_roots`, `user_email`. The adapter does not forward `user_email` to the Guardian by default.

---

## beforeSubmitPrompt

```json
{
  "conversation_id": "00000000-0000-0000-0000-000000000001",
  "generation_id": "00000000-0000-0000-0000-000000000002",
  "model": "default",
  "composer_mode": "agent",
  "prompt": "<user prompt text>",
  "attachments": [],
  "session_id": "00000000-0000-0000-0000-000000000001",
  "hook_event_name": "beforeSubmitPrompt",
  "cursor_version": "3.7.x",
  "workspace_roots": ["/path/to/workspace"],
  "user_email": "<user@example.com>",
  "transcript_path": "/Users/<user>/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/<session-id>.jsonl"
}
```

`session_id` and `conversation_id` typically hold the same UUID in agent mode. The adapter prefers `session_id`.

---

## preToolUse (Grep)

```json
{
  "conversation_id": "00000000-0000-0000-0000-000000000001",
  "generation_id": "00000000-0000-0000-0000-000000000002",
  "model": "default",
  "tool_name": "Grep",
  "tool_input": {
    "pattern": "TODO",
    "file_path": "/path/to/workspace"
  },
  "tool_use_id": "tool_00000000-0000-0000-0000-000000000003",
  "session_id": "00000000-0000-0000-0000-000000000001",
  "hook_event_name": "preToolUse",
  "cursor_version": "3.7.x",
  "workspace_roots": ["/path/to/workspace"],
  "user_email": "<user@example.com>",
  "transcript_path": "/Users/<user>/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/<session-id>.jsonl"
}
```

---

## postToolUse (Grep)

```json
{
  "conversation_id": "00000000-0000-0000-0000-000000000001",
  "generation_id": "00000000-0000-0000-0000-000000000002",
  "model": "default",
  "tool_name": "Grep",
  "tool_input": {
    "pattern": "TODO",
    "file_path": "/path/to/workspace"
  },
  "tool_output": "{\"pattern\":\"TODO\",\"success\":true}",
  "duration": 19.175,
  "tool_use_id": "tool_00000000-0000-0000-0000-000000000003",
  "session_id": "00000000-0000-0000-0000-000000000001",
  "hook_event_name": "postToolUse",
  "cursor_version": "3.7.x",
  "workspace_roots": ["/path/to/workspace"],
  "user_email": "<user@example.com>",
  "transcript_path": "/Users/<user>/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/<session-id>.jsonl"
}
```

---

## beforeShellExecution

```json
{
  "conversation_id": "00000000-0000-0000-0000-000000000001",
  "generation_id": "00000000-0000-0000-0000-000000000002",
  "model": "default",
  "command": "ls -la",
  "cwd": "/path/to/workspace",
  "sandbox": true,
  "session_id": "00000000-0000-0000-0000-000000000001",
  "hook_event_name": "beforeShellExecution",
  "cursor_version": "3.7.x",
  "workspace_roots": ["/path/to/workspace"],
  "user_email": "<user@example.com>",
  "transcript_path": "/Users/<user>/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/<session-id>.jsonl"
}
```

`sandbox` indicates whether Cursor will run the command in its sandbox.

---

## Adapter response shapes

Per-event output keys differ. See the [mapping table](../mapping.md#disposition-mapping) for the full matrix.

### Allow (permission events)

```json
{"permission": "allow"}
```

### Deny (permission events)

```json
{
  "permission": "deny",
  "user_message": "destructive Bash pattern in: rm -rf /home/u",
  "agent_message": "destructive Bash pattern in: rm -rf /home/u"
}
```

### Modify (preToolUse with parameter_overrides)

```json
{
  "permission": "allow",
  "updated_input": {"command": "ls -la # sanitized"},
  "user_message": "command sanitized by Guardian"
}
```

### Post-tool events (additional_context)

```json
{"additional_context": "audit: tool ran in 19ms; output 142 bytes"}
```

### beforeSubmitPrompt (block via exit code, not stdout)

The adapter writes nothing to stdout and exits with code 2. Cursor treats exit-2 as a block.

---

## Masking convention used here

| Field | Real value contains | Masked as |
|---|---|---|
| `session_id`, `conversation_id` | Real UUIDs | `00000000-0000-0000-0000-000000000001` |
| `generation_id`, `tool_use_id` | Real UUIDs | `00000000-0000-0000-0000-00000000000X` / `tool_<uuid>` |
| `cursor_version` | Real version (e.g. `3.7.21`) | `3.7.x` |
| `workspace_roots`, `cwd` | Real workspace path | `/path/to/workspace` |
| `transcript_path` | Real absolute path | `/Users/<user>/.cursor/...` |
| `user_email` | Real user identity | `<user@example.com>` |
| `prompt`, `command` | Real content (sometimes preserved when benign) | `<user prompt text>` / preserved |

No real session data is committed to this repo.
