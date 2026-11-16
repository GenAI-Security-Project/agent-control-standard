# Trustworthy Agents

Everyone is moving with high urgency to adopt AI agents – capturing advancement in AI to transform our digital spaces.
Agents can act, plan, write and execute just-in-time apps to achieve their goals.
The industry is rapidly standardizing around agent tooling and interoperability protocols, with [MCP](https://modelcontextprotocol.io) and [A2A](https://google.github.io/A2A/) respectively.
We can build more complex agents, in higher quantities, and allow them to easily communicate.

But we cannot trust any of them – the biggest inhibitor to their adoption. 
LLMs are an opaque technology from the get go. 
Planning, reasoning and long-term memories make agents even more of a black box. 
Agents invent, but not always like we want them to — ignoring instructions and following other goals.
Goals can be baked-in inadvertently by the training process, or forced by an attacker exploiting the agent's gullibility.

Understanding what and why an agent performed an action is a big challenge. 
Multi-agent systems, implicit dependencies and remote tools make it worse. 
Inconsistent identity and reliance on [impersonation](https://www.jpmorgan.com/technology/technology-blog/open-letter-to-our-suppliers) adds more fuel to the fire. 
Lack of standardization makes every agent different.

Agents must become [trustworthy](https://news.microsoft.com/2012/01/11/memo-from-bill-gates/) to enable wide-scale adoption.

Transparency is the foundation of trust.
Whether built in-house or adopted as part of a service.
Consumed on cloud, as SaaS, on-prem or on endpoints.
Agents must be fully observable by the enterprise that welcomes them in.
We cannot trust a magic black-box.

Knowing when things go wrong is crucial, but it is not enough.
Enterprises must have a clear way to steer agents into the right path.
Correct course when an agent goes astray.
Agents must be instrumentable, allowing intervention at run-time and preventing bad outcomes.
Providing hard-controls, not soft-guardrails.

For agents to become trustworthy they must be instrumentable, traceable, and inspectable.

## Who ACS is for

ACS is written for agent developers, platform maintainers, and operators of:

- **Enterprise production agents**: apply organization policy at instrumented action boundaries, trace decisions, and inspect component inventories.
- **Coding agents**: govern tool execution, including shell commands and filesystem access, and trace the resulting decisions.
- **Personal agents**: govern instrumented actions involving connected services and personal data under the owner's deployment policy.

These classes use the same protocol and choose the conformance profiles their deployment needs. ACS covers actions and components exposed through its hooks and Inspect methods, not activity outside that coverage. Interactive approval requires a connected approver. ASK support alone does not guarantee a human prompt; an approver-incapable client can receive DEFER or DENY ([Specification §9.2](./spec/instrument/specification.md#92-approver-incapable-clients-normative)).

## Three pillars

**Instrumentable**: we can hook into agent execution and steer it in the right direction. 
We can put hard controls around agents and define their scope of action. 
Apply centralized enterprise logic, be it security, compliance or legal, uniformly across agent platforms. 
Prevent or modify behavior to comply.

**Traceable**: we know what the agent did and why. 
We can trace back any action taken to the reasoning behind it and the originating task. 
Even if the thread goes through multiple agents and software systems. 
In case of compromise, we can identify and remediate the root cause.

**Inspectable**: we don’t have to guess what’s inside. 
Which tools, models and capabilities are being used. 
What software version is running and who built it. 
What are the services behind them, and which data they can access.
Must dynamically adapt to account for rapid changes in agent components.

The AgBOM inventory of services and data access also aids an attacker planning reconnaissance if exposed. Restrict access to Inspect outputs to authorized operators and policy consumers; do not publish them as an unrestricted discovery endpoint.

Driven by high risk and high rewards, we are collectively thinking about these cybersecurity challenges with agents early on. 
Early standardization provides a unique opportunity to build trustworthiness into agents.

## Read Next

- [ACS](./acs.md)
- [Core Concepts](./topics/core_concepts.md)
