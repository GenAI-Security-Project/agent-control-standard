# Real-world payload examples — NAT (NVIDIA Agent Toolkit)

NAT's adapter doesn't see a wire-format event the way Claude Code and Cursor adapters do. NAT calls the adapter's `pre_invoke` / `post_invoke` methods in-process with a real Python `InvocationContext` object. The examples below show:

1. **What the adapter receives** (the `InvocationContext` it gets from NAT)
2. **What the adapter sends to the Guardian** (ACS JSON-RPC, same shape as the other adapters)
3. **What the adapter does to NAT's context** (set action, mutate kwargs, etc.)

All masked. Identifying fields use placeholders.

---

## 1. What the adapter receives from NAT

NAT constructs an `InvocationContext` and passes it to `pre_invoke(ctx)`. Example for a Bash tool call:

```python
InvocationContext(
    function_context=FunctionMiddlewareContext(
        name="Bash",
        config=None,
        description=None,
        input_schema=None,
        single_output_schema=NoneType,
        stream_output_schema=NoneType,
    ),
    original_args=(),
    original_kwargs={"command": "echo hello"},
    modified_args=(),
    modified_kwargs={"command": "echo hello"},
    output=None,
    action=None,
)
```

In `post_invoke`, the same context arrives with `output` populated:

```python
InvocationContext(
    function_context=FunctionMiddlewareContext(name="Bash", ...),
    original_args=(),
    original_kwargs={"command": "echo hello"},
    modified_args=(),
    modified_kwargs={"command": "echo hello"},
    output="hello\n",
    action=None,
)
```

NAT's runtime calls `function_middleware_invoke` which orchestrates: build context → `pre_invoke` → call function → `post_invoke`. See `packages/nvidia_nat_core/src/nat/middleware/function_middleware.py`.

---

## 2. What the adapter sends to the Guardian

The same ACS JSON-RPC shape as the other adapters. The adapter constructs this from the `InvocationContext`:

### The run's start → `steps/sessionStart`

The run's session opens with its own `handshake/hello` and then its `sessionStart`, before any call of the run:

```json
{
  "jsonrpc": "2.0",
  "id": "00000000-0000-0000-0000-000000000001",
  "method": "steps/sessionStart",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "00000000-0000-0000-0000-000000000002",
    "timestamp": "2026-11-03T09:39:08.574Z",
    "metadata": {
      "agent_id": "nat:00000000",
      "session_id": "00000000-0000-4000-8000-000000000000",
      "platform": "nat",
      "adapter_version": "0.2.0"
    },
    "payload": {
      "platform_context": {
        "workflow_name": "my_workflow",
        "workflow_run_id": "00000000-0000-0000-0000-000000000003"
      }
    },
    "signature": {"algorithm": "HMAC-SHA256", "value": "<base64 HMAC>", "key_id": "2026-11"}
  }
}
```

### pre_invoke → `steps/toolCallRequest`

```json
{
  "jsonrpc": "2.0",
  "id": "00000000-0000-0000-0000-000000000004",
  "method": "steps/toolCallRequest",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "00000000-0000-0000-0000-000000000005",
    "timestamp": "2026-11-03T09:39:08.582Z",
    "metadata": {
      "agent_id": "nat:00000000",
      "session_id": "00000000-0000-4000-8000-000000000000",
      "platform": "nat",
      "adapter_version": "0.2.0"
    },
    "payload": {
      "tool": {"name": "Bash"},
      "arguments": {"command": {"value": "echo hello"}}
    },
    "signature": {"algorithm": "HMAC-SHA256", "value": "<base64 HMAC>", "key_id": "2026-11"}
  }
}
```

### post_invoke → `steps/toolCallResult`

```json
{
  "jsonrpc": "2.0",
  "id": "00000000-0000-0000-0000-000000000006",
  "method": "steps/toolCallResult",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "00000000-0000-0000-0000-000000000007",
    "timestamp": "2026-11-03T09:39:08.586Z",
    "metadata": {
      "agent_id": "nat:00000000",
      "session_id": "00000000-0000-4000-8000-000000000000",
      "platform": "nat",
      "adapter_version": "0.2.0"
    },
    "payload": {
      "tool": {"name": "Bash"},
      "exit_status": "success",
      "outputs": [{"value": "hello\n"}],
      "request_id_ref": "00000000-0000-0000-0000-000000000005"
    },
    "signature": {"algorithm": "HMAC-SHA256", "value": "<base64 HMAC>", "key_id": "2026-11"}
  }
}
```

`request_id_ref` is the `request_id` of the call's `toolCallRequest`, a uuid4 the adapter keeps on the call's invocation context. Each root NAT Runner's session gets a fresh `session_id`; a call outside any Runner uses the middleware's own.

---

## 3. What the adapter does to NAT's context after the Guardian responds

### Allow (Guardian returns `{"decision": "allow"}`)

```python
# pre_invoke returns None → NAT proceeds with the call unchanged
return None
```

### Deny on NAT dev branch (has InvocationAction.SKIP)

```python
context.action = InvocationAction.SKIP
return context
# NAT runtime: skips the function call, returns None
```

### Deny on NAT 1.7.0 (public release, no InvocationAction)

```python
raise ACSGuardianDenied("destructive Bash pattern in: rm -rf /home/u")
# NAT runtime: documented "Raises: Any exception to abort execution"
```

The adapter feature-detects which mechanism NAT exposes and prefers the action-based path when available.

### Modify input (Guardian returns `parameter_overrides`)

```python
# A field the input in context.modified_args[0] declares is rewritten there,
# an existing keyword argument in context.modified_kwargs, and a scalar input
# (a one-argument function's) in place, under its schema field name.
context.modified_args = (ShellInput(command="echo hello # sanitized"),)
return context
# NAT runtime: invokes the function with call_next(*modified_args, **modified_kwargs)
```

An override that names no field of the input and no keyword argument the call has, or one the rebuilt input does not keep, cannot be applied: the call is blocked and the MODIFY recorded as `modify_unsupported` (§6.5).

### Modify output (Guardian returns `modified_content` in post_invoke)

```python
context.output = "<sanitized output>"
return context
# NAT runtime: propagates the modified output as if the function returned it
```

---

## Masking convention used here

| Field | Real value contains | Masked as |
|---|---|---|
| `session_id` | A fresh UUID per session | `00000000-0000-4000-8000-000000000000` |
| `agent_id` | `nat:` and 8 hex digits of the target's hash | `nat:00000000` |
| `id`, `request_id`, `request_id_ref`, `workflow_run_id` | Real UUIDs (per request, per run) | `00000000-0000-0000-0000-00000000000X` |
| `signature.value` | The envelope's HMAC | `<base64 HMAC>` |
| `timestamp` | Real RFC 3339 time | Kept |
| `arguments.command.value` | Real command (sometimes preserved when benign) | Preserved or `<command>` |
| `outputs` | Real tool output | Preserved or `<tool output>` |

No real session data is committed to this repo.
