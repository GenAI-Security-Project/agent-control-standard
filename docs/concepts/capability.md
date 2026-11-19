# Capability

A capability is an abstract permission to do something (`filesystem.delete`, `network.egress`, `process.execute`) independent of the specific tool that exercises it. Capabilities are the vocabulary in which authorization is expressed: [Intent](./intent.md) is a set of them, and a [tool](../spec/inspect/README.md) declares the one it needs.

Expressing authorization in capabilities rather than tool names lets policy reason about *what an action does* rather than *which binary does it*. Two different tools that both egress data are subject to the same `network.egress` policy.

*Example.* A `file.write` tool and a `git.commit` tool both exercise `filesystem.write`. Policy written against the capability governs both, without enumerating tools.

## Vocabulary and matching

ACS v0.1 defines no central capability registry. Capability matching between `toolCallRequest.capability`, AgBOM declarations (`tool_fields.capability`, `skill_fields.declared_capabilities`), and policy rules (`Intent.parsed`) is deployment-local exact string matching over a hierarchical `domain.verb` convention.

The core illustrative capability set covers common runtime domains:

- `filesystem.read`, `filesystem.write`, `filesystem.delete`
- `network.egress`
- `process.execute`
- `memory.read`, `memory.write`
- `subagent.spawn`

Deployments extend this vocabulary with additional `domain.verb` identifiers as needed, provided the Observed Agent, AgBOM declarations, and Guardian policies within a deployment share the same strings.

## Capability and Intent

`Intent.parsed` is a capability set: the capabilities authorized for the session. A decision-eligible step that requests a capability outside that set is the central check of intent-based control: the Guardian compares the requested capability against the authorized set and the closest match.

Capabilities enter the authorized set in exactly one way after Intent is fixed: an Approver's `intent_extension` through the ASK flow. See [Intent](./intent.md).

## Capability vs. the AgBOM `agent_capability` component

ACS distinguishes **Capability** (the abstract permission label carried on `toolCallRequest.capability`, `tool_fields.capability`, `skill_fields.declared_capabilities`, and `Intent.parsed`) from the AgBOM inventory component type `agent_capability` in [`agbom/component.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/agbom/component.json) (see [Inspect](../spec/inspect/README.md)):

- **Capability (permission label):** a `domain.verb` string (`filesystem.write`, `network.egress`) naming the abstract permission an action requires or `Intent.parsed` authorizes.
- **`agent_capability` (AgBOM inventory component):** a structural Bill of Materials record (`type: "agent_capability"`) that groups `tools[]`, `mcp_servers[]`, and `a2a_peers[]` into a named callable surface in the inventory.

The AgBOM records what callable surfaces and tools the agent *has*; `Intent.parsed` is the set of abstract capability permissions the agent is *authorized* to exercise for the session.

## Capability and identity

A capability is only meaningful against the [identity](./identity.md) it is granted to. Least privilege is the intersection of what the agent may do and what the principal it acts for may do; ACS supplies the capability vocabulary that makes that intersection expressible.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): the requested-capability check against `Intent.parsed`, exposed in `policy_data` on a mismatch.
- **Inspect**, [AgBOM](../spec/inspect/README.md): `tool.capability` and the `agent_capability` component type.
- See also [Intent](./intent.md), [Skill](./skill.md), [Identity](./identity.md), and [Agents](./agents.md).
