# Codex to ACS mapping: first slice

## Hook and identity mapping

| Input | ACS representation |
|---|---|
| `PreToolUse` | `steps/toolCallRequest`, synchronous decision before execution |
| `tool_name` | `payload.tool.name`; preserve Codex's canonical name (`Bash` for shell/exec) |
| `tool_input` object | Each argument becomes `{ "value": original_value }`; no invented provenance |
| `session_id` | Preserve a UUID; otherwise deterministic UUID5 in the `codex:session` namespace. Keep the original as `metadata.codex_session_id` |
| `turn_id` | Preserve as `metadata.turn_id`; no fabricated `turnStart` or `turnEnd` |
| `tool_use_id` | UUID5 scoped to the normalized session for `request_id`; keep original in metadata |
| `cwd`, `model`, `permission_mode` | Metadata when strings |
| Other hook events | No ACS event; `unmapped_hook_event` audit |

The session ID, turn ID, tool-call ID, tool name, and object input are required.
Missing or invalid fields deny rather than inventing identity. The adapter never
reads the transcript, whose format is not a stable hook interface.

Handshake occurs on the first tool call and uses the shared signed cache. It
advertises exactly one step method, HTTP, no Wrapped MCP, and no conformance
profiles. Signing alone is not ACS-Core conformance. No session or turn lifecycle
events, tool results, heartbeat, or subagent-specific gates are emitted.

## Decision mapping

| Guardian decision | Codex `hookSpecificOutput` for `PreToolUse` |
|---|---|
| ALLOW | `permissionDecision: "allow"`; ordinary Codex permissions still apply |
| DENY | `permissionDecision: "deny"` with the Guardian reasoning |
| MODIFY with only `parameter_overrides` | Merge overrides onto original arguments; return `permissionDecision: "allow"` plus complete `updatedInput` |
| Other MODIFY shapes | Audited DENY; never apply only part of a requested edit |
| ASK / DEFER | Audited DENY; this slice has no approval/resumption implementation |
| Unknown/missing decision | Audited DENY |

For `Bash` and `apply_patch`, the merged `updatedInput.command` must remain a
string, and only `command` overrides are accepted. Other tools receive the merged argument object; the host owns each
tool's argument schema. The adapter supports no redaction or wholesale content
rewrite operation. Decision substitutions are documented deployment behavior,
not a claim that the specification requires client-side substitution.

Do not return `permissionDecision: "ask"` to Codex. As documented on
2026-09-18, that value is unsupported: Codex reports a hook error and continues
the call. `PermissionRequest` is a different event and cannot implement a
universal ASK path for calls that never require approval.

Signed responses must bind both the JSON-RPC ID and ACS request ID to the
outstanding request. Only a final decision for the negotiated ACS version can
authorize execution. Signature failures, malformed messages, and refusals deny.
Transport failures and signed non-refusal RPC errors follow the configured
failure posture and emit an audit event. The shared handshake treats failed
negotiation as a startup failure; `ACS_DEFAULT_DENY=1` blocks that path.

This slice makes no claim about preventing activity through hosted tools,
ongoing process input, specialized hook-exempt paths, or edits to its own
configuration. See [README.md](README.md) for tested coverage and setup.
