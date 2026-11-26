<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# FastMCP → ACS mapping

FastMCP exposes two interception seams for MCP tool execution:

- **Server side:** `fastmcp.server.middleware.Middleware.on_call_tool(context, call_next)` intercepts every `tools/call` arriving at a `FastMCP` server before the tool handler executes.
- **Client side:** `GovernedFastMCPClient.call_tool(name, arguments)` wraps `fastmcp.Client.call_tool` before the call leaves the client.

Both seams share `_FastMCPSession`, so wire envelopes, signing, failure posture, and session lifecycle behave identically on both sides.

## FastMCP lifecycle → ACS step method

| FastMCP event | ACS step method | Emitted today? |
|---|---|---|
| Middleware or client scope start (first call or `async with` entry) | `handshake/hello` + `steps/sessionStart` | **Yes** — once per scope; a `sessionStart` deny or refusal blocks every subsequent call in the scope. |
| `on_call_tool` (before `call_next`) or `GovernedFastMCPClient.call_tool` (before `inner.call_tool`) | `steps/toolCallRequest` | **Yes** — `tool: {name, provider: "mcp"}` and each argument wrapped as `{value: ...}`. |
| `on_call_tool` (after `call_next`) or `GovernedFastMCPClient.call_tool` (after `inner.call_tool`) | `steps/toolCallResult` | **Yes** — linked via `request_id_ref`, with `exit_status: "success"` or `"failure"` and `duration_ms`. |
| Scope exit (`__aexit__`, `aclose()`, `close()`) | `steps/sessionEnd` | **Yes** — observation-only, reporting `reason` (`completed` / `error`) and `summary.decision_failures`. |
| User prompt / assistant reply (`steps/userMessage`, `steps/agentResponse`) | — | **No.** FastMCP sits at the MCP tool boundary and does not observe LLM conversation turns. These methods are not advertised in `ClientHello.methods_implemented`. |
| Non-tool MCP methods (`protocols/MCP/*`: `resources/read`, `prompts/get`) | — | **No.** Only MCP `tools/call` is mapped (via generic tool hooks), and `record_mcp_use` emits `profile_claim_degraded` once per session. |

## Session boundaries

Each `ACSFastMCPMiddleware` instance and each `GovernedFastMCPClient` scope generates a fresh UUID `session_id` rather than reusing `fastmcp_context.session_id` (which changes per call on FastMCP's in-memory transport). Multiple tool calls — including concurrent `asyncio.gather` calls — share one `handshake/hello` and one `steps/sessionStart`. Once `aclose()` / `close()` finishes, the session is sealed and any later call is refused fail-closed without contacting the Guardian.

## ACS disposition → FastMCP behavior

| ACS disposition | Pre-execution (`steps/toolCallRequest`) | Post-execution (`steps/toolCallResult`) |
|---|---|---|
| `allow` | Proceed unchanged to `call_next` / `inner.call_tool`. | Return tool result unchanged. |
| `deny` | Raise `ACSGuardianDenied` (subclass of `fastmcp.exceptions.ToolError` when FastMCP is installed); tool never executes. | Server middleware returns `ToolResult(..., is_error=True)` with output withheld; client wrapper raises `ACSGuardianDenied`. |
| `modify` | Validate §6.3 composition rules (`modify_composition_violation`). Merge `parameter_overrides` onto tool arguments and pass copied context / arguments forward. Reject `redactions`, `modified_content`, or invalid shapes fail-closed (`modify_unsupported`). | Validate §6.3 rules. When `modified_content` is a string, rewrite `ToolResult` text content (and `structured_content["result"]` when FastMCP wrapped a scalar return). Reject unsupported structured edits fail-closed and withhold output. |
| `ask` | Substituted to `deny` (`ACSGuardianDenied`) and audited as `disposition_substituted_deny`; MCP `tools/call` middleware has no synchronous human-approval pause primitive. | Output withheld and audited as `tool_result_withheld`. |
| `defer` | Substituted to `deny` (`ACSGuardianDenied`) and audited as `disposition_substituted_deny`. | Output withheld and audited as `tool_result_withheld`. |

## Exceptions and failure modes

- **Tool exceptions are preserved:** when the Guardian allows a call and the underlying tool raises an exception, the adapter records `steps/toolCallResult` with `exit_status: "failure"` and re-raises the original exception untouched. A tool crash is never disguised as `ACSGuardianDenied`.
- **Guardian refusals always fail closed:** the six `GUARDIAN_REFUSAL_CODES` (`-32000`, `-32004`, `-32005`, `-32006`, `-32600`, `-32700`), unsigned responses, mis-bound responses, and JSON key collisions (`{1: "a", "1": "b"}`) fail closed regardless of `ACS_DEFAULT_DENY`.
- **Non-blocking async execution:** every Guardian HTTP round trip runs via `asyncio.to_thread`, so a slow Guardian never stalls FastMCP's event loop.
