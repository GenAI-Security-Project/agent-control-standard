# Trustworthy Agents

ACS is a wire contract for runtime control of AI agents. Before an agent acts, it asks a separate Guardian, which answers allow, deny, modify, ask or defer, and both sides leave an audit trail. Release 0.1.5 implements specification v0.1.0 and ships Guardians, adapters and a gateway you can run today. To see it work, start with [Run a Guardian](./topics/reference-implementations.md). To learn the model, read [Core Concepts](./topics/core_concepts.md). The rest of this page explains why the standard exists.

Everyone is moving with high urgency to adopt AI agents, capturing advancement in AI to transform our digital spaces.
Agents can act, plan, write and execute just-in-time apps to achieve their goals.
The industry is rapidly standardizing around agent tooling and interoperability protocols, with [MCP](https://modelcontextprotocol.io) and [A2A](https://a2a-protocol.org/) respectively.
We can build more complex agents, in higher quantities, and allow them to easily communicate.

But we cannot trust any of them, and that is the biggest inhibitor to their adoption. 
LLMs are an opaque technology from the get go. 
Planning, reasoning and long-term memories make agents even more of a black box. 
Agents invent, but not always like we want them to. They ignore instructions and follow other goals.
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

Driven by high risk and high rewards, we are collectively thinking about these cybersecurity challenges with agents early on. 
Early standardization provides a unique opportunity to build trustworthiness into agents.

## Read Next

- [Run a Guardian](./topics/reference-implementations.md)
- [ACS](./acs.md)
- [Core Concepts](./topics/core_concepts.md)
