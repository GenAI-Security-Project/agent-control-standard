# Agent Control Standard

[![Code: Apache 2.0](https://img.shields.io/badge/Code-Apache%202.0-blue.svg)](./LICENSE)
[![Docs: CC BY-SA 4.0](https://img.shields.io/badge/Docs-CC%20BY--SA%204.0-lightgrey.svg)](./LICENSE-DOCS)

![ACS Banner](docs/assets/banner.png)

ACS is a wire specification. It lets a separate Guardian Agent inspect what an AI agent
is about to do and permit, deny, or modify that action before it happens, over an
authenticated channel, with an audit trail that reconstructs after the fact. The fastest
way to understand what that means is to make it deny something.

## Run it, and tell us where it breaks

This is the one ask that needs nothing from a maintainer first. Clone the repository,
run a real Guardian against a real policy engine, and watch it deny a command sent by a
real coding agent.

The reference implementation runs [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
(AGT) behind the ACS wire contract, with host shims for Claude Code and OpenCode. It
needs [`bun`](https://bun.sh) and nothing else to start.

```bash
git clone https://github.com/GenAI-Security-Project/agent-control-standard
cd agent-control-standard/reference-implementations/agt
bun install
bun run guardian        # second terminal: bun run inspector
```

The Guardian prints this on startup:

```
Guardian listening at http://localhost:8787/acs
Envelope log: .acs/envelopes.jsonl
Session context log: .acs/session-context.jsonl
Failure posture: proceed   (override with ACS_ON_DECISION_FAILURE=deny)
```

The `Failure posture: proceed` line matters more than it looks. Read on. In a second
terminal, the Inspector reports `last_observed_posture=(none observed)` and
`fail-open proceeds=0` until an envelope crosses the wire.

Connect a coding agent to the running Guardian:

```bash
mkdir -p .claude && cp hosts/claude-code/settings.json .claude/settings.json
claude
```

Ask Claude Code to run `echo rm -rf /`. AGT's stock destructive-pattern rule denies it,
and the Inspector prints the denial as it crosses the wire, with the reason code
`destructive_shell_command_blocked` and the policy reference `agt_stock`. Ask for
`ls -la` in the same session and it runs. No coding agent installed, no problem: pipe a
hook payload straight into the shim while the Guardian runs and get the same decision
without one.

```bash
echo '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | bun run hosts/claude-code/acs-hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."}}
```

That JSON is a real deny from a real Guardian, not a transcript. A working Guardian and
one verified deny is the whole ask. Stop here if that answered what brought you here
today.

### Two ways this breaks on the first try

`bun install` does not install `trash`, because `trash` is a system command the test and
verification scripts call, not an npm package. Running `bun test` without it on `PATH`
fails 26 of the suite's 1,111 tests, all in the conformance and upstream-watch scripts
that clean up scratch directories. Install `trash-cli` first, or expect those 26
failures and ignore them.

The Guardian's default failure posture is `proceed`. A Guardian that crashes, hangs, or
is unreachable stops governing, silently, and the host proceeds as if nothing asked.
Set `ACS_ON_DECISION_FAILURE=deny` on the Guardian before trusting it to fail closed.

### Where this reference implementation stands

Two gaps sit above the fold on purpose, because a project that hides its own gap list
forfeits the right to be trusted on the rest of it.

The wire is not authenticated. ACS-Core requires a baseline HMAC-SHA256 signature on
every envelope. The reference Guardian implements none of it, so anything that can reach
the port can read decisions and cause decisions. That gap is tracked as
[issue #70](https://github.com/GenAI-Security-Project/agent-control-standard/issues/70).
The default failure posture is fail-open, covered above and tracked as
[issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32)
and [issue #37](https://github.com/GenAI-Security-Project/agent-control-standard/issues/37).

The defensible claim for this tree is narrow: one Guardian, two agent clients, one wire
contract, plus a published matrix of what ACS v0.1.0 can and cannot express of AGT
today. Two of ACS's nineteen hook methods are evaluated live,
`steps/toolCallRequest` and `steps/toolCallResult`. This is not a claim that ACS was
benchmarked for interoperability with Microsoft AGT across the specification. The full
limits list, requirement by requirement, is in the
[reference implementation's own README](reference-implementations/agt/README.md#what-this-project-is-and-is-not),
which is the deep tutorial this section only summarizes.

### Report a disagreement

When behavior does not match the specification, open an issue at
[GenAI-Security-Project/agent-control-standard/issues](https://github.com/GenAI-Security-Project/agent-control-standard/issues)
with four things: what was run, what was expected, the specification section that set
that expectation, and what happened instead.

## A hook, on the wire

An agent that implements ACS sends a hook request before it acts. Here an agent asks
to read a file, and the Guardian says yes.

```json
{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "1",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11",
    "timestamp": "2026-09-09T14:02:11Z",
    "metadata": {
      "agent_id": "research-assistant",
      "session_id": "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"
    },
    "payload": {
      "tool": { "name": "file_read" },
      "arguments": { "path": { "value": "/reports/q3-summary.md" } }
    }
  }
}
```

The Guardian's answer:

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11",
    "decision": "allow"
  }
}
```

Both payloads validate against the schemas in this repository, `request-envelope.json`,
`hooks/tool-call-request.json`, and `response-envelope.json`. Nothing here is invented.

## Fetch a schema

Every schema in ACS v0.1.0 lives at the URL its own `$id` names. The `$id` is not a
label sitting beside the real address. It is the identity and the published location at
once, which is why a `$ref` inside one schema can resolve against the same base every
other schema in the set uses.

```bash
curl -s https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/tool-call-request.json
```

That fetches the schema behind the `toolCallRequest` payload above, published from
`specification/v0.1.0/hooks/tool-call-request.json` in this repository. All 44 schemas
resolve the same way, each under the `v0.1.0` namespace shown in that URL. A merge to
`main` republishes the full set, and the build fails before it ships if any `$id`
collides or any `$ref` fails to resolve. A separate check reruns every six hours and
confirms all 44 URIs still answer.

## A policy that edits instead of blocking

Not every verdict is a plain yes. Here the agent asks to run an unbounded query, and the
Guardian returns `modify` instead of `allow` or `deny`, rewriting the argument before
the tool ever runs.

```json
{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "2",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "c4f2d0a1-4c32-4c8b-a03f-7b7e3f7b0b33",
    "timestamp": "2026-09-09T14:03:47Z",
    "metadata": {
      "agent_id": "research-assistant",
      "session_id": "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"
    },
    "payload": {
      "tool": { "name": "database_query" },
      "arguments": { "query": { "value": "SELECT * FROM customers" } }
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "c4f2d0a1-4c32-4c8b-a03f-7b7e3f7b0b33",
    "decision": "modify",
    "reasoning": "Unbounded SELECT against customers exceeds the row-limit policy. Query capped at 100 rows.",
    "modifications": {
      "parameter_overrides": {
        "query": "SELECT id, name FROM customers LIMIT 100"
      }
    }
  }
}
```

This verdict came from the Guardian's deterministic layer alone, an engine like
OPA/Rego or Cedar evaluating a written policy against the request. The deterministic
layer always runs first. A chain config MAY delegate to a second, agent layer, an LLM,
when the deterministic layer cannot resolve the request on its own, but that LLM never
reads the policy source. It receives only the intermediate output the deterministic
layer chooses to hand over, and its answer still has to clear the deterministic layer on
the way back out. Deterministic-only deployments are fully conformant. Delegation is
optional.

```mermaid
flowchart LR
    OA["Observed Agent"] -->|"hook request<br/>JSON-RPC 2.0"| DET
    subgraph GA["Guardian Agent"]
        DET["Deterministic layer<br/>OPA/Rego, Cedar<br/>always runs first"]
        LLM["Agent layer, LLM<br/>no policy source access"]
        DET -.->|"optional delegation:<br/>intermediate output only"| LLM
        LLM -.->|"answer"| DET
    end
    DET -->|"disposition"| OA
```

## Concepts

Two parties speak ACS. The **Observed Agent** is the LLM-backed system being watched,
the one sending hook requests like the ones above. The **Guardian Agent** sits on the
other end of the wire and decides what happens next.

A **hook** is a point in the Observed Agent's execution where it stops and asks before
acting. `toolCallRequest` is one of ACS's sixteen native lifecycle hooks. Others fire at
session start and end, before and after a turn, on knowledge retrieval, and around
memory reads and writes.

The Guardian answers every hook with one of five **dispositions**: `allow`, `deny`,
`modify`, `ask` (route to a human, agent, or service approver), or `defer` (postpone the
verdict when the Guardian cannot yet reach one). The two examples above showed `allow`
and `modify`.

ACS organizes its requirements into three pillars. **Instrument** is the hook and
disposition machinery already shown. **Trace** records every hook and every decision as
an OpenTelemetry span and an OCSF event, so a security team's existing tooling reads an
ACS audit trail without new plumbing. **Inspect** produces the AgBOM, a live inventory of
an agent's models, tools, and dependencies, serialized as CycloneDX, SPDX, or SWID on
request.

```mermaid
flowchart TB
    ACS["ACS"] --> INST["Instrument<br/>hooks, five dispositions"]
    ACS --> TR["Trace<br/>OpenTelemetry spans, OCSF events"]
    ACS --> INS["Inspect<br/>AgBOM: CycloneDX, SPDX, SWID"]
```

A deployment does not have to implement all three to conform. **ACS-Core**, the
Instrument pillar plus the wire format and the audit chain, is the mandatory baseline.
Trace, Inspect, field-level Provenance, and cryptographic signing are **conformance
profiles** that a deployment declares at the handshake and adds independently.

A reader who only wants to know whether ACS fits their problem can stop here.

## Three more ways to help

Running the reference implementation is the ask that needs no maintainer decision
first. These three do, in the order they matter most right now.

### Port it: Python, Go, Rust, Codex

One Guardian exists, written in TypeScript against Bun. Python, Go, Rust, and a Codex
host shim are open and unclaimed. "Done" for a port means it passes the same
conformance harness the Bun tree does, `bun run conformance`, which prints the mapping
table, the coverage matrix, and the trace rows against a live Guardian over HTTP. The
harness measures the wire, not the language behind it.

### Harden it for production

The Guardian batches its envelope and session-context logs for asynchronous append,
with bounded queues and a drain on graceful shutdown. No OpenTelemetry collector or
exporter exists yet. The conformance harness only measures which
attributes a consumer *could* emit from the envelopes, not that anything ships them.
Start in [`reference-implementations/agt/packages/`](reference-implementations/agt/packages/).

### Go deeper

The concept pages under [`docs/concepts/`](docs/concepts/) are the source of truth for
identity, intent, capability, provenance, and trust basis, the terms every pillar's
specification references down into rather than restates. The rules a deployment's
conformance claim has to satisfy are in
[Conformance Profiles](docs/spec/conformance.md), which also says plainly that nobody
verifies a self-declared claim in v0.1.0. The requirement-by-requirement ledger the
reference implementation measures itself against is the table in
[its own README](reference-implementations/agt/README.md#what-this-project-is-and-is-not).
A second implementation would need the same kind of table.

## Contributing right now

Governance changed for the OWASP relaunch, and it matters starting today.
`CONTRIBUTING.md` now names one filter for what the project accepts: the **Current
Priority Scope**, the section at the top of that file. It states the project's one
committed outcome for the current window, then sorts every possible contribution into
in focus, deferred to the next specification release, or out of scope by design. Read it
before opening an issue. Everything below assumes you have.

Pull requests fork from and target `integration`, the default branch. `main` takes only
two kinds of change: a promotion pull request from `integration`, and an editorial fix
to a file on a short allowlist, this one included. `release/*` branches stabilize a
specification version between `integration` and a tag. Merging to `main` is what
republishes the site and every schema `$id` under it, which is why specification and
code changes go through `integration` first.

```mermaid
flowchart LR
    FORK["Fork"] --> INT["integration<br/>default branch"]
    INT --> REL["release/vX.Y.Z<br/>stabilization"]
    INT -->|"promotion PR"| MAIN["main<br/>publishes site + schema URIs"]
```

Every issue starts from one of six forms. There are no blank issues. A form applies a
`type:` label and `status:needs-triage` automatically, and nothing else. Only a
maintainer can move an issue to `status:accepted`, and only an accepted issue enters the
backlog. A pull request that changes behavior, alters normative text, or adds code
references an accepted issue. An editorial correction, a typo or a broken link, needs
none.

```mermaid
flowchart LR
    F["Issue form"] --> T["Maintainer triage"]
    T -->|"deferred"| D["scope:deferred<br/>tracked for the next spec release"]
    T -->|"accepted"| A["status:accepted<br/>enters the backlog"]
    A --> P["Pull request<br/>references the issue"]
    E["Editorial fix<br/>typo, broken link"] --> P2["Pull request<br/>needs no issue"]
```

`CONTRIBUTING.md` is the authority on the full scope list, the branch names, the label
taxonomy, and the sign-off every commit needs. Start there, not here.

## What's next

Specification v0.1.0 ships today. The tagged release is v0.1.1. The next specification
release, v0.2.0, targets March 2027. A v1.0 date has not been set.

The near term runs against four GitHub milestones: Day 14 (September 24), Day 30
(October 9), Day 60 (November 6), and Day 90 (December 4, 2026). Each carries the
project's committed outcome as its description. What is in focus for the current window
lives in one place, the Current Priority Scope in
[CONTRIBUTING.md](./CONTRIBUTING.md), reviewed at every milestone so it never drifts
from what that section says.

## Where to go next

- [AGT reference implementation](reference-implementations/agt/README.md): the deep tutorial behind the walkthrough above, the Guardian, both host shims, and the full limits list.
- [Documentation site](https://genai-security-project.github.io/agent-control-standard/docs/): the specification, concepts, and topic guides.
- [Specification](https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/specification): the JSON Schemas and normative prose in this repository.
- [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions): questions and design conversation.
- Slack: [owasp.slack.com](https://owasp.slack.com), channel `#team-genai-asi-acs-general`.
- [CONTRIBUTING.md](./CONTRIBUTING.md): how work gets accepted.
- [SECURITY.md](./SECURITY.md): how to report a vulnerability.
- [GOVERNANCE.md](./GOVERNANCE.md): who leads which workstream.
- [Project board](https://github.com/orgs/GenAI-Security-Project/projects/9): tracked work across the milestones above.

## About

ACS is an open project of the [OWASP GenAI Security Project](https://genai.owasp.org/), open to contributions from the community.

Code and schemas are licensed under the [Apache License 2.0](./LICENSE). Documentation is licensed under [CC BY-SA 4.0](./LICENSE-DOCS). See [LICENSING.md](./LICENSING.md) for the scope map.
