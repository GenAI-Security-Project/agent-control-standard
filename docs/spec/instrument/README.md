# OWASP GenAI Security Project Agent Control Standard - Instrument

AI agents make critical decisions autonomously. They collaborate, execute code, and access sensitive data. But they operate as black boxes. Enterprises can't trust what they can't see.

ACS defines a standard way to put a control point into an agent system. Before a governed step runs, the agent asks a separate Guardian Agent, and the Guardian's answer decides whether the step runs, runs changed, or stops.

## What ACS Instrumentation Delivers

**Real-time Control**: A Guardian Agent decides on every hook the Observed Agent sends and the handshake negotiates. It applies enterprise policy before the action executes, so it can block a data leak or rewrite a risky argument instead of reporting it afterwards.

**Transparency**: Each decision carries its reasoning, reason codes and policy references, and the Guardian commits each content-bearing step to a hash-chained audit record. The [Trace](../trace/README.md) vocabulary lets both parties export those steps and decisions to existing observability systems.

**Integration**: ACS defines how to wrap MCP traffic, and reserves a namespace for A2A. Frameworks join through adapters that translate their own hook or middleware events into ACS messages.

## How It Works

The agent framework fires a hook at each governed step: a session starting, a user message arriving, a tool call about to run, a tool result about to reach the model. The framework sends that step to the Guardian as a signed JSON-RPC request and waits. The Guardian answers with one of five dispositions: allow, deny, modify, ask or defer. The agent applies the answer. The [specification](./specification.md) defines the handshake, the envelope, the hooks and what the agent does when no usable answer arrives.

ACS works alongside MCP and A2A rather than replacing them:

| Standard | ACS Spec | Status |
|--|--|--|
| [MCP](https://modelcontextprotocol.io/introduction) | [ACS with MCP](./extend_mcp.md) | Specified in v0.1.0. The 0.1.5 reference adapters don't wrap MCP. They send MCP tool calls through `steps/toolCallRequest` and `steps/toolCallResult`. |
| [A2A](https://google-a2a.github.io/A2A/) | [ACS with A2A](./a2a/extend_a2a.md) | Planned. The `protocols/A2A/*` namespace is reserved, and the wrapping rules are planned for specification v0.2.0 ([D-008](../../decisions/index.md#d-008-defer-the-hardest-protocol-features-past-v01)). The page shows the intended design. |

## What runs in release 0.1.5

Release 0.1.5 ships reference implementations on both sides of the wire. They are teaching and lab code, not production systems, and none of them makes a conformance claim. Each README says what it does and does not do.

| Component | Where | What it governs | When no usable decision arrives |
|--|--|--|--|
| Claude Code, Cursor and NVIDIA NAT 1.7.0 adapters | [`adapters/`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/adapters/README.md) | The `steps/*` hooks each host can observe, wired through the host's own hook or middleware configuration. MCP tool calls go through `steps/toolCallRequest` and `steps/toolCallResult`, and the other MCP surfaces are not sent. | The step is denied, and a session whose handshake gets no answer is refused. Only the adapter's own configuration (the hook environment, or `default_deny` in NAT's `workflow.yml`) can opt into proceed. |
| Example Guardian (Python) | [`adapters/`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/adapters/docs/guardian/README.md) | Every method the client implements, with a small built-in policy. An opt-in OPA backend hands decisions to an OPA server, and every OPA failure denies. | Its ServerHello declares `deny` unless its own configuration says `proceed`. |
| OpenAI Responses API gateway | [`adapters/gateway/`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/adapters/gateway/README.md) | Each `function_call` as `steps/toolCallRequest` and each `function_call_output` as `steps/toolCallResult`, for any client that points `OPENAI_BASE_URL` at it. Governing is opt-in: the default mode, `off`, forwards traffic unchanged, `shadow` asks the Guardian without enforcing, and `enforce` applies each decision. It streams the model's text, and each Guardian exchange stays one request and one response. | Enforce denies the step, and no ServerHello can loosen that. Shadow records the failure and changes nothing. |
| TypeScript Guardian (AGT) | [`reference-implementations/agt/`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/reference-implementations/agt/README.md) | `steps/toolCallRequest` and `steps/toolCallResult`, through Claude Code and OpenCode shims, with AGT Rego policies. | Its ServerHello declares `proceed`, the specification's default. The Claude Code `PreToolUse` hook blocks the call when the hook itself fails or times out. |
| Go Guardian | [`reference-implementations/agt-go/`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/reference-implementations/agt-go/README.md) | Every native `steps/*` hook the client implements, with the same AGT Rego policies. It also works with the adapters above. | Its shipped configuration declares `deny`. |

The specification text still makes `proceed` the default posture. The project leads decided to make deny the default and to let only the Observed Agent's own configuration opt into proceed ([D-036](../../decisions/index.md#d-036-default-the-failure-posture-to-deny), [D-045](../../decisions/index.md#d-045-only-the-observed-agents-own-configuration-can-opt-into-proceed)). The specification text has not changed yet, and most of the code above already follows the decision.

The example Guardian can also sign its decisions with ML-DSA-65 as an opt-in experiment, and the gateway and the adapters can verify them. [Specification §10.1](./specification.md#101-algorithm-registry) says what that covers.

### Read Next

- [ACS Instrumentation Specification](./specification.md)
- [Supported Hooks](./hooks.md)
