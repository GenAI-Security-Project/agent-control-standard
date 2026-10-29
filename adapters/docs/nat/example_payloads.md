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

### pre_invoke → `steps/toolCallRequest`

```json
{
  "jsonrpc": "2.0",
  "id": "00000000-0000-0000-0000-000000000001",
  "method": "steps/toolCallRequest",
  "params": {
    "session_id": "nat-00000000000000",
    "step_id": "00000000-0000-0000-0000-000000000002",
    "tool": {
      "name": "Bash",
      "arguments": {"command": "echo hello"}
    }
  },
  "acs_version": "0.1.0",
  "request_id": "00000000-0000-0000-0000-000000000003",
  "timestamp": 1718450000000,
  "metadata": {"source": "acs-adapter-nat"}
}
```

### post_invoke → `steps/toolCallResult`

```json
{
  "jsonrpc": "2.0",
  "id": "00000000-0000-0000-0000-000000000004",
  "method": "steps/toolCallResult",
  "params": {
    "session_id": "nat-00000000000000",
    "step_id": "00000000-0000-0000-0000-000000000005",
    "tool": {"name": "Bash", "arguments": {"command": "echo hello"}},
    "result": "hello\n"
  },
  "acs_version": "0.1.0",
  "request_id": "00000000-0000-0000-0000-000000000006",
  "timestamp": 1718450001234,
  "metadata": {"source": "acs-adapter-nat"}
}
```

`session_id` is auto-generated per process unless `session_id` is set in `workflow.yml`.

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
context.modified_kwargs.update({"command": "echo hello # sanitized"})
return context
# NAT runtime: invokes the function with the modified kwargs
```

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
| `session_id` | Auto-generated `nat-<hex16>` or deployment-defined | `nat-00000000000000` |
| `step_id`, `request_id`, `id` | Real UUIDs (per-request) | `00000000-0000-0000-0000-00000000000X` |
| `timestamp` | Real epoch ms | Synthetic value |
| `tool.arguments.command` | Real command (sometimes preserved when benign) | Preserved or `<command>` |
| `result` | Real tool output | Preserved or `<tool output>` |

No real session data is committed to this repo.
