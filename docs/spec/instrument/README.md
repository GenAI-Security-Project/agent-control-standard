# OWASP Agent Control Standard - Instrument

AI agents make critical decisions autonomously. They collaborate, execute code, and access sensitive data. But they operate as black boxes. Enterprises can't trust what they can't see.

ACS introduces a standard way to introduce middleware into agent systems to steer its behavior. It transforms opaque agents into transparent, controllable systems.

## What ACS Instrumentation Delivers

**Real-time Control**: Guardian Agents intercept every agent action. Apply enterprise policies. Block data leaks. Enforce compliance before actions execute.

**Complete Transparency**: Stream every decision, tool call, and reasoning step to observability systems. Full audit trail across multi-agent workflows.

**Strongly Integrated**: Works with existing protocols (MCP, A2A). Native support for popular AI agent development frameworks.

## How It Works

ACS is a standard for surfacing every decision, action, prompt, and output as structured events while simultaneously providing hooks for in-line intervention and control.
It create a standard way to insert middleware into agent execution.
Embedding lightweight call-outs at each step of an agent’s reasoning and action cycle.
ACS streams context-rich events to observability back-ends, and allows guardian agents to allow, veto or modify behavior.

ACS works even better when MCP and A2A are used.
It carries these protocols intact, allowing transparent adoption while providing observability value.

| Standard | ACS Spec | Status |
|--|--|--|
| [MCP](https://modelcontextprotocol.io/introduction) | [ACS with MCP](./extend_mcp.md) | Working draft |
| [A2A](https://google-a2a.github.io/A2A/) | [ACS with A2A](./a2a/extend_a2a.md) | Working draft |

### Read Next

- [ACS Instrumentation Specification](./specification.md)