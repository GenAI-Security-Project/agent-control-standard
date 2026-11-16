# About ACS

OWASP Agent Control Standard (ACS) creates industry-wide transparency for AI agents.

## Mission

Transform AI agents from black boxes into trustworthy systems through standardized observability.

Enterprises need to see what agents do, understand why they act, and control their behavior. ACS provides the specifications and protocols to make this possible.

## Audience and scope

ACS serves developers, platform maintainers, and operators of enterprise production agents, coding agents, and personal agents.

- **Enterprise production agents** use ACS for runtime policy decisions, decision traces, and component inventories across instrumented services.
- **Coding agents** use the same control hooks for tool calls, shell commands, and filesystem access.
- **Personal agents** use those hooks to apply owner-selected policy to connected services and personal data access.

Coverage depends on the hooks and conformance profiles a deployment implements. ACS does not claim control over actions outside its instrumented boundaries. Human approval also needs a connected approver; ASK support does not guarantee an interactive prompt. See [who ACS is for](./README.md#who-acs-is-for) and the [conformance profiles](./spec/conformance.md).

## What We're Building

**Instrumentation Standard**: ACS standard for agent instrumentation.

**Standards Extensions**: Enhance CycloneDX, SPDX, SWID for AI agent components. Extend OCSF and OpenTelemetry with agent-specific schemas.

**Protocol Integration**: Standardize instrumentation hooks for agent platforms. Enable Guardian Agents through A2A communication. Extend MCP with observability capabilities.

**Reference Implementations**: Deliver working examples on popular platforms like CrewAI. Provide clear patterns for OCSF and OpenTelemetry integration.

**Community Adoption**: Build with the community. Open standards, open implementations, open collaboration.

## Join the Mission

ACS succeeds when the entire AI agent ecosystem adopts these standards. We're building this together.

- **Contribute**: Help shape the specifications
- **Implement**: Build ACS support in your agent platform
- **Advocate**: Spread the word about trustworthy agents

Reach us in [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions).