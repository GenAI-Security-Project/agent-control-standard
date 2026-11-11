# Relay to ACS mapping

| Relay boundary | ACS method | Payload |
|---|---|---|
| First governed invocation or explicit `adapter.session()` | `handshake/hello`, then `steps/sessionStart` | Supported methods; empty session-start payload |
| Execution interceptor before `next_call` | `steps/toolCallRequest` | Tool name and JSON arguments as `ToolArgumentValue` objects |
| Downstream callback returns | `steps/toolCallResult` | Governed business output, duration, success status, originating ACS request ID |
| Downstream callback raises | `steps/toolCallResult` | Failure status and empty outputs; exception text withheld |
| Session scope exits | `steps/sessionEnd` | Completion/error/cancellation reason, tool-call count, decision-failure counts |

Nested calls share the current adapter session through Python context propagation. Without an explicit adapter session, the outermost tool call owns the session. Relay Agent/Function scopes are not interpreted as ACS turns, users, or subagents. The adapter advertises only the methods above and respects `methods_evaluated`.

Request changes apply to the callback arguments. Result changes apply to the value returned from Relay's managed execution API. Observability sanitizers do not enforce either property and are not used as authorization gates.

See [payload examples](payloads.json) for the four step payloads. They omit envelope fields and signatures, which the shared client constructs at runtime.
