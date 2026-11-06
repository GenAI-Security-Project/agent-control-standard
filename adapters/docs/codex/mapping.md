# Codex to ACS mapping: first slice

## Hook and identity mapping

| Input | ACS representation |
|---|---|
| `PreToolUse` | `steps/toolCallRequest`, a synchronous decision before the call runs |
| `tool_name` | `payload.tool.name`, with Codex's own name kept (`Bash` for shell and `exec_command`, `spawn_agent` for a subagent spawn) |
| `tool_input` object | Each argument becomes `{ "value": original_value }`, with no invented provenance |
| `session_id` | Kept when it is a UUID; otherwise a UUID5 in the `codex:session` namespace. The original goes in `metadata.codex_session_id` |
| `turn_id` | Kept as `metadata.turn_id`. No `turnStart` or `turnEnd` is sent for it |
| `tool_use_id` | A UUID5 scoped to the session becomes `request_id`; the original goes in `metadata.codex_tool_use_id` |
| `cwd`, `model`, `permission_mode` | Metadata, when they are strings |
| Any other hook event | Nothing sent; audited as `unmapped_hook_event` |

The session ID, turn ID, tool-call ID, tool name and an object input are required. An event missing any of them is denied with no traffic, under either posture, rather than sent with invented identity. The adapter never reads the transcript, whose format is not a stable hook interface.

The handshake runs on the first tool call of a session, and its result is stored under an HMAC for the session's later calls. It advertises exactly one step method, the Guardian URL's transport, no Wrapped MCP and no conformance profile. Signing alone is not ACS-Core conformance. No session or turn lifecycle, tool results, heartbeat or `steps/subagentStart` are emitted. A subagent spawn reaches the Guardian as a `steps/toolCallRequest` for `spawn_agent`, since Codex runs a spawn as a tool call and ignores `continue: false` from `SubagentStart`.

If a valid ServerHello leaves `steps/toolCallRequest` out of `methods_evaluated`, the Guardian is not evaluating tool calls. The adapter audits `method_not_evaluated`, sends no tool-call request and prints nothing, which leaves Codex's own approval policy in charge. That is not a decision failure, so neither the local nor the negotiated deny posture turns it into a denial. A ServerHello that fails its checks is still no answer, and the startup posture settles the call.

## Decision mapping

| Guardian decision | Codex `PreToolUse` output |
|---|---|
| ALLOW | Nothing, so Codex's own approval policy and sandbox still decide |
| DENY | `permissionDecision: "deny"` with the Guardian's reasoning |
| MODIFY with only `parameter_overrides` | The overrides merged onto the original arguments, as `permissionDecision: "allow"` with the complete `updatedInput` |
| Any other MODIFY | Audited DENY, never a partial edit |
| ASK or DEFER | Audited DENY, since Codex cannot hold a tool call for approval |
| A decision outside the five | DENY under either posture |

For `Bash` and `apply_patch`, only a `command` override is accepted, and the merged `command` must stay a string. Other tools get the merged argument object, and Codex owns each tool's argument schema. The adapter supports no redaction and no wholesale content rewrite.

Codex applies `updatedInput` only together with `permissionDecision: "allow"`, so a MODIFY is the one decision that prints an allow. The Codex hook documentation does not say whether that allow skips Codex's own approval prompt.

Do not return `permissionDecision: "ask"` to Codex. Codex parses it but does not support it yet: it marks the hook run as failed and continues the tool call. `PermissionRequest` is a different event, and it cannot carry an ASK for calls that never need approval.

A response must bind both the JSON-RPC `id` and the ACS `request_id` to the outstanding request, carry a valid signature under the session key, and pass `response-envelope.json`. A signature failure, a mis-bound response and a refusal code deny under either posture. A restrictive decision in a result that fails the schema denies too. Transport failures, timeouts, signed errors that are not refusals and an unreadable allow follow the failure posture, and each is audited.

This slice makes no claim about hosted tools, input written to a running process, tool paths that skip hooks, or edits to its own configuration. See [README.md](README.md) for tested coverage and setup.
