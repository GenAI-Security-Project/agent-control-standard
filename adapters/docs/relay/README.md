# Govern NeMo Relay tool calls

The Relay adapter checks managed tool requests before execution and checks results before they reach the caller. It uses the shared ACS client for the handshake, signatures, response binding, timeouts, and failure auditing.

This is the managed-tool portion of issue [#543](https://github.com/GenAI-Security-Project/agent-control-standard/issues/543). Keep the NAT adapter installed until the remaining migration work is complete. LLM calls, automatic mapping of Relay Agent scopes to ACS sessions, and the full NAT behavioral-suite migration remain outside this first increment. This adapter does not claim full ACS-Core conformance.

## Install

```sh
pip install 'acs-adapters[relay]'
```

The optional extra pins `nemo-relay==0.11.1`, whose APIs are still changing. The base ACS package imports without Relay installed. Configure `ACS_HMAC_SECRET` and `ACS_HMAC_KEY_ID` as described in the [adapter setup](../../README.md). Keep keys outside plugin configuration.

## Enable the plugin

Register the ACS component once during application startup, before Relay initializes its plugin host:

```python
from acs.integrations.relay.plugin import register
register()
```

Add a component to the `plugins.toml` file your application supplies to Relay:

```toml
version = 1

[[components]]
kind = "acs_guardian"
enabled = true

[components.config]
guardian_url = "http://127.0.0.1:8787/acs"
default_deny = true
timeout_s = 5.0
agent_id = "relay-agent"
```

Activate that configuration through Relay's plugin host, and use its managed execution API:

```python
import nemo_relay as relay

async def lookup(args):
    return relay.ToolExecutionResult({"account": args["account"]})

async def run():
    async with relay.plugin.activate({"version": 1}, "plugins.toml"):
        result = await relay.tools.execute("lookup", {"account": "example"}, lookup)
        return result.result
```

Relay owns registration rollback and teardown. A validation or activation error must stop startup; do not catch it and start the agent ungoverned. The adapter registers an execution interceptor at priority 1000. Request interceptors have already run at that point. Other execution interceptors and tool implementations remain trusted; a later component can still change the arguments or bypass a callback.

Direct calls to the Python function and Relay's manual `tools.call()` spans do not traverse this interceptor. Ensure governed tools use `tools.execute()`. The adapter does not convert unmanaged application calls into managed calls.

## Group tool calls into a session

The configuration plugin opens one ACS session per top-level managed tool invocation. Nested managed tool invocations inherit the session; independent concurrent top-level calls get different sessions. Arbitrary Relay scopes do not automatically open or close ACS sessions.

Applications that need a session spanning several tool calls can register an adapter instance directly:

```python
from acs.integrations.relay.adapter import ACSRelay

adapter = ACSRelay("http://127.0.0.1:8787/acs")
relay.intercepts.register_tool_execution("acs", 1000, adapter.intercept)
try:
    async with adapter.session():
        await relay.tools.execute("lookup", {"account": "example"}, lookup)
        await relay.tools.execute("lookup", {"account": "other"}, lookup)
finally:
    relay.intercepts.deregister_tool_execution("acs")
```

Choose either plugin activation or direct registration. Join child tasks before leaving an explicit session. A child task retaining an ended session cannot start another governed call. Session exchanges are serialized; tool callbacks can execute concurrently.

Each session handshakes and sends `sessionStart` before tool hooks, then `sessionEnd` with a reason and decision-failure counts. Session teardown waits for its bounded HTTP exchange. Relay propagates caller cancellation to its Python callbacks asynchronously: the caller may stop waiting before the session-end exchange finishes. Cancellation cannot interrupt every synchronous tool or reverse effects that already happened. A denied result also leaves prior effects intact.

## Decisions and failures

| Gate | ALLOW | DENY | Supported MODIFY | ASK / DEFER |
|---|---|---|---|---|
| Request | Execute | Raise before execution | `parameter_overrides` on the arguments object | Block; no pause or approval UI |
| Result | Deliver | Withhold by raising | `modified_content` replaces caller-visible output | Withhold by raising |

Unsupported modification forms, mixed wholesale/structured modifications, and unusable dispositions fail closed. Tool arguments must be JSON objects; values must round-trip through JSON without loss. Original tool exceptions are reported as a failure with no exception text, then replaced with a generic exception so their details cannot bypass result inspection.

The default is fail closed on delivery failures. `default_deny = false` explicitly opts into proceeding when no usable decision arrives, unless the Guardian negotiates deny. Guardian refusals and untrusted signatures still block. Each bypass/failure is audited through the shared ACS client; `ACS_AUDIT_FILE` optionally persists the audit lines.

The adapter returns only the governed business result. It omits downstream annotations and pending marks that could carry the original output. Relay may already have emitted downstream telemetry; caller-visible withholding does not remove previously published events. Apply a separate telemetry policy if those sinks require redaction.

## Validate

```sh
cd adapters
uv sync --locked --extra relay --group test
uv run python run_conformance.py relay
```

The Relay suite runs the installed native runtime against a live signed programmable Guardian. It observes file-backed tool effects, caller-visible result replacement/withholding, request/result correlation, nested and concurrent sessions, plugin activation/teardown, failure postures, late responses, and callback lifetime after caller cancellation. It validates captured payloads against the bundled schemas. No model service or NVIDIA account is required.
