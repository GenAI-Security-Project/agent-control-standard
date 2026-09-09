# Agent Control Standard

[![Code: Apache 2.0](https://img.shields.io/badge/Code-Apache%202.0-blue.svg)](./LICENSE)
[![Docs: CC BY-SA 4.0](https://img.shields.io/badge/Docs-CC%20BY--SA%204.0-lightgrey.svg)](./LICENSE-DOCS)

![ACS Banner](docs/assets/banner.png)

**Making AI agents trustworthy by standardizing observability and control.**

## Rational
Agents must become trustworthy to enable widescale adoption.

Transparency is the foundation of trust. Whether built in-house or adopted as part of a service. Consumed on cloud, as SaaS, on-prem or on endpoints. Agents must be fully observable by the enterprise that welcomes them in. We cannot trust a magic black-box.

For agents to become trustworthy they must be **inspectable, traceable and instrumentable**.

- **Inspectable:** we don’t have to guess what’s inside. Which tools, models and capabilities are being used. What software version is running and who built it. What are the services behind them, and which data they can access. Must dynamicly adapt to account for rapid changes in agent components.
- **Traceable:** we know what the agent did and why. We can trace back any action taken to the reasoning behind it and the originating task. Even if the thread goes through multiple agents and software systems. In case of compromise, we can identify and remediate the root cause.
- **Instrumentable:** we can hook into agent execution and steer it in the right direction. We can put hard controls around agents and define their scope of action. Apply centralized enterprise logic, be it security, compliance or legal, uniformly across agent platforms. Prevent or modify behavior to comply.

### Key Components

The standard covers the following aspects
1. ACS that defines the interaction between the Observed Agent and the Guardian Agent
2. Observability requirements and implementations for tracing all ACS events using OpenTelemetry and OCSF
3. Agent BOM (AgBOM) requirements and implementations for exposing dynamic Agent's bill-of-material via CoycloneDX, SWID and SPDX

## Getting Started

- 📚 **Explore the Documentation:** Once GitHub Pages is enabled, visit the [documentation site](https://genai-security-project.github.io/agent-control-standard/docs/) for a complete overview, the full specification, tutorials, and guides. The [project landing page](https://genai-security-project.github.io/agent-control-standard/) covers what ACS is and why it exists.
- 📝 **View the Specification:** [Specification](https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/specification)

## Contributing

We welcome community contributions to enhance and evolve ACS!

- **Questions & Discussions:** Join our [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions).
- **Issues & Feedback:** Report issues or suggest improvements via [GitHub Issues](https://github.com/GenAI-Security-Project/agent-control-standard/issues).
- **Contribution Guide:** See our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## What's next

#### v0.1 (Public Preview)
- Overall documentation and requirements
- ACS definitions and schema
- Observability definitions for for OpenTelemetry and OCSF
- AgBOM requirements

#### v1
- Implementation of Agent instrumentation
- Implementation of Guardian Agent sample app with
  - ACS Support
  - ACS to OpenTelemetry mapper
  - ACS to OCSF mapper
- FastMCP client instrumentation for ACS
- A2A client instrumentation for ACS

#### v2
- Requirements for CycloneDX, SPDX, SWID
- Implementation of ACS to AgBOM mappers for CycloneDX, SPDX, SWID

#### v3
- Extending A2A and MCP to support deny and modify operations
- Implementation of Agent with deny and modify support

## About

ACS is an open project of the [OWASP GenAI Security Project](https://genai.owasp.org/), open to contributions from the community.

Code and schemas are licensed under the [Apache License 2.0](./LICENSE). Documentation is licensed under [CC BY-SA 4.0](./LICENSE-DOCS). See [LICENSING.md](./LICENSING.md) for the scope map.
