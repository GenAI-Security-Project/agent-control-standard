# About ACS

OWASP GenAI Security Project Agent Control Standard (ACS) is an open standard for controlling AI agents at runtime.

## Mission

Give enterprises runtime control over AI agents through an open standard.

Enterprises need to stop an agent's harmful action before it happens, see what agents do, and understand why they act. ACS began as an observability standard and became a control standard ([D-001](./decisions/index.md#d-001-rename-aos-to-acs-and-focus-on-runtime-control)). It now defines how an agent asks a Guardian before it acts, how the Guardian answers, and what record the exchange leaves.

## What We're Building

**The specification**: ACS defines the hooks, the five dispositions, the wire format, the audit chain, and the conformance profiles a deployment declares. Specification v0.1.0 is current, and v0.2.0 is planned.

**Standards extensions**: ACS maps agent steps onto OpenTelemetry and OCSF, and serializes the Agent Bill of Materials as CycloneDX, SPDX, and SWID.

**Protocol integration**: Specification v0.1.0 defines how ACS wraps MCP traffic and reserves the A2A namespace, and A2A wrapping is planned for v0.2.0.

**Reference implementations**: Release 0.1.5 ships three Guardians (Python, TypeScript, and Go), configuration-only adapters for Claude Code, Cursor, and NVIDIA NAT, and a gateway for any OpenAI Responses API client. [Run a Guardian](./topics/reference-implementations.md) shows where to start.

**Community adoption**: Build with the community. Open standards, open implementations, open collaboration.

## Join the Mission

ACS succeeds when the entire AI agent ecosystem adopts these standards. We're building this together.

- **Contribute**: Help shape the specifications
- **Implement**: Build ACS support in your agent platform
- **Advocate**: Spread the word about trustworthy agents

Reach us in [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions).