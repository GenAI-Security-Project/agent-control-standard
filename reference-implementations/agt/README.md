# ACS reference implementation with Microsoft's Agent Governance Toolkit

This tree shows what Microsoft's [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) (AGT) looks like when it talks to agent clients over the [Agent Control Standard](../../README.md) (ACS) wire contract.

AGT's policy engine runs unchanged. Two different agent clients send it ACS envelopes. One Guardian process answers both. No client has AGT code in it, and AGT has no client code in it.

The tree validates every envelope against the schemas in this repository's own [`specification/v0.1.0/`](../../specification/v0.1.0/), so the implementation and the specification cannot drift apart. The code reaches those schemas by a relative path, so the tree has to stay at this depth, `reference-implementations/agt`.

## Watch the demo

[![Three minutes: one Guardian denies the same command sent by OpenCode and by Claude Code, then the conformance harness prints what ACS can express of AGT](docs/demo-poster.jpg)](docs/demo.mp4)

The video is three minutes long, captioned, with no audio. Click the image to open [`docs/demo.mp4`](docs/demo.mp4). Top left is the Inspector, top right is the Guardian, and the bottom pane runs an agent client.

1. OpenCode sends a harmless `echo` whose text matches AGT's destructive-shell pattern. The Guardian answers `deny`. The Inspector prints the envelope, the reason code `destructive_shell_command_blocked`, and the policy reference `agt_stock`.
2. Claude Code sends the same command from the same directory, through a hook subprocess instead of an in-process plugin. The same Guardian answers the same `deny` under a new request id.
3. `bun run conformance` prints the mapping table, the coverage matrix and the trace rows, and runs six live checks, including a deny that must fail closed over the wire.

## The goal

Today, each policy vendor writes one module for each agent client. AGT itself ships four client packages with four different designs. Each new client costs a new module, and each new vendor costs a module for each client.

ACS is one wire contract between an agent client and a policy runtime. This tree shows that contract in use:

- One policy runtime, AGT, at a pinned upstream commit, with no source changes.
- Two agent clients, Claude Code and OpenCode, with different hook designs.
- One Guardian that translates ACS envelopes into AGT policy input and AGT verdicts into ACS decisions.
- One translation table, `mapping.yaml`, that is the single source of truth for that translation.
- Tools to read the contract, watch the events on the wire, and measure what the contract can and cannot express.

This is a demonstration and a measurement, not a product. The section [What this project is, and is not](#what-this-project-is-and-is-not) states the limits.

## The parts

```
 Claude Code ──hook subprocess──▶ hosts/claude-code/acs-hook.ts ──┐
                                                                  │  ACS envelopes
 OpenCode ─────in-process plugin─▶ hosts/opencode/acs-plugin.ts ──┤  (JSON-RPC over HTTP)
                                                                  ▼
                                   packages/host-adapter   ──▶  packages/guardian  ──▶  packages/agt-bridge  ──▶  AGT SDK + OPA
                                   (host side, no AGT code)      (ACS server)             (no host code)           policy/lib (pinned)
                                                                  │
                                                                  ▼
                                                            .acs/*.jsonl  ◀── packages/inspector reads these
```

Each part has its own README that says how to start it.

| Part | Path | What it does |
|---|---|---|
| Host shim, Claude Code | [`hosts/claude-code/`](hosts/claude-code/README.md) | Runs as a hook subprocess. Reads the hook payload on stdin. Writes the decision on stdout. |
| Host shim, OpenCode | [`hosts/opencode/`](hosts/opencode/README.md) | Runs as an in-process plugin. Mutates the live tool call object or throws. |
| Host adapter | [`packages/host-adapter/`](packages/host-adapter/README.md) | Builds envelopes, negotiates the session, applies decisions, applies the failure posture, writes the audit log. Shared by both shims. |
| Guardian | [`packages/guardian/`](packages/guardian/README.md) | Serves `POST /acs`. Validates envelopes. Assembles AGT policy input. Maps AGT verdicts to ACS decisions. Keeps session state. Records every envelope. |
| AGT bridge | [`packages/agt-bridge/`](packages/agt-bridge/README.md) | Constructs the AGT SDK runtime against the pinned policy bundle. Publishes the bundled OPA binary to the process environment. |
| Inspector | [`packages/inspector/`](packages/inspector/README.md) | Tails the Guardian's logs and renders each envelope, decision, audit entry and session chain entry. |
| Conformance harness | [`packages/conformance/`](packages/conformance/README.md) | Measures what ACS v0.1.0 can express of AGT, cell by cell. Watches upstream AGT for contract changes. |
| Policy | `policy/lib/`, `policy/manifest.yaml`, `agt.lock` | AGT's stock policy bundle, byte-identical to the pinned upstream commit, plus one configuration file. |
| Translation table | `mapping.yaml` | AGT intervention points to ACS methods. AGT verdicts to ACS decisions. How each ACS field is derived. |
| Specification | [`../../specification/v0.1.0/`](../../specification/v0.1.0/) | The ACS schemas this tree validates against. The repository's own copy, not a vendored one. |

## What this project is, and is not

**It is** a working demonstration that AGT's unchanged policy engine can govern two different agent clients over one wire contract. The tool-call path is complete: a tool call request, a decision, a tool call result, and a second decision. All five AGT verdicts cross the wire as real ACS decisions. Four of AGT's nine stock policy gate classes are live: destructive patterns, secret redaction, information-flow labels, and egress destinations.

**It is not** a complete ACS implementation. The Guardian claims one ACS profile, `acs-core`, and that claim is qualified. The table below measures this tree against the mandatory ACS-Core list in the specification's own [conformance page](../../docs/spec/conformance.md).

| ACS-Core requirement | Status in this tree |
|---|---|
| Handshake, `handshake/hello` | Served. The ServerHello is a set of constants. The Guardian does not read the ClientHello. |
| Request and response envelopes, JSON-RPC 2.0 | Implemented. Inbound envelopes are validated against the schemas. Outbound responses are checked and the check is logged, never thrown. |
| Hook taxonomy, minimum of six hooks | Two of nineteen `steps/*` methods are evaluated: `steps/toolCallRequest` and `steps/toolCallResult`. The other four minimum hooks are not evaluated. |
| Five dispositions | `allow`, `deny` and `modify` are complete. `ask` is sent without `ask_details`, so it fails the response schema. `defer` is never produced. |
| SessionContext with published `chain_hash` | The Guardian keeps a hash chain per session and writes it to a log. It does not put `chain_hash` on any response. |
| Replay protection | Not implemented. No timestamp window check. No duplicate `request_id` check. |
| Baseline HMAC-SHA256 signature | Not implemented. Nothing signs or verifies an envelope. |
| Decision honoring and `on_decision_failure` | Implemented on both hosts. Every fail-open proceed is written to the audit log. |
| Liveness, `system/ping` | Not implemented. |
| Wrapped MCP, `protocols/MCP/*` | Not implemented. |

The other six ACS profiles are not claimed.

**The wire is not secured.** The Guardian binds to loopback by default. There is no authentication, no origin check and no request signing. Anything that can reach the port can read decisions and cause decisions.

## Install

You need [`bun`](https://bun.sh). For the Claude Code walkthrough you also need the [Claude Code](https://docs.claude.com/en/docs/claude-code) CLI on your `PATH`. For the OpenCode walkthrough you need the `opencode` CLI. The scripts under `scripts/` also need `jq` and `trash`.

1. Clone the repository and move into this tree. Every command below runs from here.

```bash
git clone https://github.com/GenAI-Security-Project/agent-control-standard
cd agent-control-standard/reference-implementations/agt
```

2. Install the dependencies.

```bash
bun install
```

This installs the AGT SDK at the pinned version and the OPA binary it bundles. No other binary is necessary.

## Run

### Start the Guardian

Open a terminal at `reference-implementations/agt`. Start the Guardian.

```bash
bun run guardian
```

```
Guardian listening at http://localhost:8787/acs
Envelope log: .acs/envelopes.jsonl
Session context log: .acs/session-context.jsonl
Failure posture: proceed   (override with ACS_ON_DECISION_FAILURE=deny)
```

Leave it running. The Guardian constructs the AGT runtime once against `policy/lib` and serves ACS on `POST /acs`. The [Guardian README](packages/guardian/README.md) lists what it reads and what it writes.

### Start the Inspector

Open a second terminal at the same directory. Start the Inspector after the Guardian, because the Guardian creates the `.acs/` directory.

```bash
bun run inspector
```

```
Envelope Inspector — tailing .acs/envelopes.jsonl, .acs/audit.jsonl, and .acs/session-context.jsonl
Ctrl-C to stop.

last_observed_posture=(none observed)  fail-open proceeds=0
```

The Inspector prints each envelope as it crosses the wire. See [View the events](#view-the-events) and the [Inspector README](packages/inspector/README.md).

### Connect Claude Code

1. Copy the shipped hook settings into the project you will run Claude Code in.

```bash
mkdir -p .claude
cp hosts/claude-code/settings.json .claude/settings.json
```

This registers `hosts/claude-code/acs-hook.ts` on two Claude Code hook events. `PreToolUse` fires for the `Bash` and `WebFetch` tools, before the tool runs. `PostToolUse` fires for the `Bash` tool, after the tool runs. Both matchers are anchored, so no other tool is intercepted. The shipped file names the hook through `$CLAUDE_PROJECT_DIR`, which resolves when the project is this tree. From any other project, replace that variable with this tree's absolute path. The [Claude Code host README](hosts/claude-code/README.md) has the details.

2. Start Claude Code.

```bash
claude
```

3. Ask Claude Code to run a destructive command, for example `echo rm -rf /`. The hook sends the call to the Guardian. AGT's stock pattern rule denies it. Claude Code shows the policy reason in the transcript. Ask for `ls -la` in the same session and it runs.

Use `echo rm -rf /` rather than `rm -rf /` when you script this. The pattern matches at offset 5 and the command is inert if the hook ever fails.

With the shipped configuration, a `Bash` command whose text contains a URL outside the egress allowlist is also denied. `git clone https://github.com/openai/whisper` is denied. `npm install` is allowed. The allowlist is the `cfg.egress.allowlist` key in `policy/lib/data.json`.

### Connect OpenCode

The same Guardian governs OpenCode at the same time. Do not restart anything.

1. Point OpenCode at the plugin. The `opencode.json` at the root of this tree already does, with a relative path, so an `opencode` started from `reference-implementations/agt` needs no edit. From another project, add the plugin to that project's `opencode.json` by absolute path.

```json
{
  "plugin": ["/absolute/path/to/agent-control-standard/reference-implementations/agt/hosts/opencode/acs-plugin.ts"]
}
```

2. Start `opencode` from that project directory.

The plugin hooks `tool.execute.before` for the `bash` and `webfetch` tools and `tool.execute.after` for the `bash` tool. A deny before the tool runs is a thrown error that carries the Guardian's reason. A deny after the tool runs replaces the result object, because OpenCode discards a throwing hook's changes. The [OpenCode host README](hosts/opencode/README.md) shows how to drive OpenCode against a local stub model with no paid account.

### Drive one hook by hand

You do not need Claude Code to see a decision. Pipe a hook payload into the shim while the Guardian runs.

```bash
echo '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | bun run hosts/claude-code/acs-hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."}}
```

The shim never runs the command. It only asks the Guardian.

## View the contract

The contract has four layers in this tree. Read them in this order.

**1. The ACS specification.** [`../../specification/v0.1.0/`](../../specification/v0.1.0/) holds the JSON schemas: the request and response envelopes, the handshake, the modifications object, and one payload schema for each hook method. [`../../docs/spec/`](../../docs/spec/) holds the normative text and the conformance profiles.

**2. The translation table.** `mapping.yaml` declares how AGT and ACS map to each other. The Guardian reads it at decision time. The conformance harness reads the same file to publish the mapping. The two cannot disagree.

| AGT intervention point | ACS method |
|---|---|
| `pre_tool_call` | `steps/toolCallRequest` |
| `post_tool_call` | `steps/toolCallResult` |
| `agent_startup` | `steps/sessionStart` (mapped, not evaluated) |
| `agent_shutdown` | `steps/sessionEnd` (mapped, not evaluated) |
| `input` | `steps/userMessage` (mapped, not evaluated) |
| `output` | `steps/agentResponse` (mapped, not evaluated) |
| `pre_model_call` | none in ACS v0.1.0 |
| `post_model_call` | none in ACS v0.1.0 |

| AGT verdict | ACS decision |
|---|---|
| `allow` | `allow` |
| `deny` | `deny` |
| `escalate` | `ask` |
| `transform` | `modify` |
| `warn` | `allow` with a non-empty `policy_references` |

**3. The per-host hookmaps.** `hosts/claude-code/claude-code.hookmap.yaml` and `hosts/opencode/opencode.hookmap.yaml` declare which host hook fires which ACS method, where the tool name and arguments are in the host payload, and how each ACS decision renders in that host's own output format. `policy/manifest.yaml` is the AGT manifest. It names the policy bundle, the tools AGT knows, and the egress annotator.

**4. The handshake.** The first hook in a session sends `handshake/hello`. The Guardian's answer names exactly the methods it evaluates. A method absent from that list is allow-by-default on the client, in the specification's own words. This is what the Guardian sends today:

```json
{
  "negotiated_version": "0.1.0",
  "methods_evaluated": ["steps/toolCallRequest", "steps/toolCallResult"],
  "selected_transport": "http",
  "timeout_config": { "default_ms": 5000 },
  "on_decision_failure": "proceed"
}
```

**Print the measured contract.** The conformance harness prints the mapping table, an eight-by-five matrix of AGT intervention points against AGT verdicts, and the Trace-pillar rows. Each matrix cell is `expressed`, `guardian_only`, or `unexpressed` with a reason. This needs network access to GitHub and `trash` on your `PATH`.

```bash
bun run conformance
```

The [conformance README](packages/conformance/README.md) explains each table and the exit code.

## View the events

The Guardian records every envelope to `.acs/envelopes.jsonl` before it validates the envelope. Nothing is stripped or redacted, so the file holds raw tool arguments. It is gitignored. Do not commit it.

One denied `Bash` call produces four envelopes: the handshake request and response, then the tool call request and its decision. The Inspector renders them like this.

```
── #3  16:00:37.966  → REQUEST   steps/toolCallRequest  id=6a22a0f7-5547-448a-add7-3327aed144df
{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "6a22a0f7-5547-448a-add7-3327aed144df",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "6a22a0f7-5547-448a-add7-3327aed144df",
    "timestamp": "2026-09-07T16:00:37.962Z",
    "metadata": {
      "agent_id": "claude-code",
      "session_id": "6ccc72b8-a167-5573-b3ea-a310262ea93f"
    },
    "payload": {
      "tool": { "name": "Bash" },
      "arguments": { "command": { "value": "rm -rf /" } },
      "raw_command": "rm -rf /"
    }
  }
}

── #4  16:00:39.853  ← RESPONSE  steps/toolCallRequest  id=6a22a0f7-5547-448a-add7-3327aed144df
● DENY  reason_codes=[destructive_shell_command_blocked]  policy_references=[agt_stock#destructive_shell_command_blocked]
{
  "jsonrpc": "2.0",
  "id": "6a22a0f7-5547-448a-add7-3327aed144df",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "6a22a0f7-5547-448a-add7-3327aed144df",
    "decision": "deny",
    "reasoning": "This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0.",
    "reason_codes": ["destructive_shell_command_blocked"],
    "policy_references": [{ "policy_id": "agt_stock", "rule_id": "destructive_shell_command_blocked" }]
  }
}

#1  Bash  hash=ab7697786128  session_id=6ccc72b8-a167-5573-b3ea-a310262ea93f
```

The last line is the session chain entry for that step. An allowed `Bash` call produces two more envelopes after the command runs: `steps/toolCallResult` and its decision.

Run `bun run inspector -- --from-start` to replay a session that is already recorded.

The `.acs/` directory holds four kinds of local file. None is ever committed.

| File | Written by | Holds |
|---|---|---|
| `envelopes.jsonl` | Guardian | Every envelope, both directions, before validation |
| `session-context.jsonl` | Guardian | One hash-chain entry per governed step |
| `audit.jsonl` | Host shim | Every fail-open proceed and every posture-driven block |
| `sessions/<session_id>.json` | Host shim, Claude Code only | The negotiated ServerHello, so the next hook subprocess finds it |

The Inspector reads the first three. Its banner shows the last posture an audit entry carried and a count of fail-open proceeds. This is an audit entry, written when the Guardian was not reachable under the default posture:

```json
{"seq":1,"recorded_at":"2026-09-07T16:00:57.216Z","session_id":"demo","method":"steps/toolCallRequest","rpc_id":"dd3a9076-eb7c-45c5-bee8-24bbc33aaa72","posture":"proceed","posture_source":"default","outcome":"proceeded","failure":{"kind":"transport","message":"Unable to connect. Is the computer able to access the url?"},"session_failure":{"kind":"handshake_failed","message":"Unable to connect. Is the computer able to access the url?"}}
```

The audit log and the envelope log cannot be joined on `session_id`. The audit log keeps the host's raw session id. The envelope carries a UUID derived from it, because the ACS schema requires a UUID.

## The scenarios the tests check

The suite has 68 test files. Most of them drive a real Guardian, the real host shim and the pinned policy bundle. The scenarios below are grouped by what they prove. The file names are the place to read the exact assertions.

**Policy decisions over the wire**

- A destructive shell command is denied. A benign command is allowed. The reason text is AGT's own. (`hosts/claude-code/test/hook.test.ts`)
- All five AGT verdicts arrive as ACS decisions from the pinned bundle, driven by configuration only. `warn` arrives as `allow` with a non-empty `policy_references`. (`test/dispositions.test.ts`)
- A secret in tool output is redacted at the result gate. Every sibling field of the output survives. Clean output is untouched. (`test/redaction.test.ts`, `hosts/claude-code/test/post-tool-use.test.ts`)
- A `transform` verdict lands as the host's actual rewritten argument, keyed by that tool's own argument name. (`packages/guardian/test/map-verdict.test.ts`, `test/path-dialects.test.ts`)
- An egress destination is extracted from a shell command and decided by AGT's stock egress gate. A `WebFetch` URL reaches the same gate with no extraction. Six coexistence rows are driven through a live Guardian. (`packages/guardian/test/annotate-egress.test.ts`, `packages/guardian/test/server.test.ts`)
- Information-flow labels that AGT emits at one step come back as its input at the next step. A flow the configured clearance does not dominate is denied. (`test/ifc-round-trip.test.ts`)

**Host behaviour, Claude Code**

- A deny, an ask or a defer at the result gate withholds the output, because `block` alone withholds nothing after the tool has run. (`hosts/claude-code/test/post-tool-use.test.ts`)
- A modification the host cannot apply, or a `modified_content` replacement, is refused and the refusal withholds. (same file)
- Each ACS decision renders to the exact `permissionDecision` shape Claude Code accepts. A `defer` renders as `deny`, because Claude Code has no deferral state. (`hosts/claude-code/test/wire-shape.test.ts`)
- The shim exits with the blocking code on a payload it cannot parse, a missing session id, a traversal-shaped session id, or a hookmap that declares an output the host does not accept. (`hosts/claude-code/test/posture.test.ts`)

**Host behaviour, OpenCode**

- A deny before the tool runs is a throw. A deny after the tool runs is a replacement. (`hosts/opencode/test/request-gate.test.ts`, `hosts/opencode/test/result-gate.test.ts`)
- A redaction patches the output leaf and its `metadata` mirror together, so no plaintext stays in OpenCode's session record. (`hosts/opencode/test/result-gate.test.ts`)
- The plugin refuses to register a hookmap whose deny or modify cannot land, and the measured fail-open shapes are each pinned. (`hosts/opencode/test/acs-plugin.test.ts`, `hosts/opencode/test/hookmap.test.ts`)

**Failure handling**

- When no decision arrives, the negotiated posture applies: `proceed` proceeds and audits, `deny` blocks. A decision that does arrive is never touched by the posture. (`hosts/claude-code/test/posture.test.ts`, `packages/host-adapter/test/failure-posture.test.ts`)
- A Guardian refusal, a schema-invalid envelope, or an evaluation that throws is an honoured `deny`, whatever the posture. (`packages/guardian/test/deny-on-invalid-envelope.test.ts`, `packages/conformance/test/failure-domains.test.ts`)
- A timeout, a transport failure, and an error without a decision are three different audit entries. (`packages/host-adapter/test/govern-step.test.ts`)
- An expired `ask` or `defer` falls to its own timeout default. Malformed `modifications` fail closed. (`packages/host-adapter/test/validate-decision.test.ts`)
- A proceed that cannot be audited is a block. (`packages/host-adapter/test/failure-posture.test.ts`)
- A bridge built in a process with no `opa` on its `PATH` still evaluates policy. An explicit `ACS_OPA_PATH` that names nothing stops construction. (`packages/agt-bridge/test/opa-path.test.ts`)

**The wire itself**

- The ServerHello names exactly the methods the Guardian dispatches, measured in both directions against a live Guardian. (`test/handshake-declares-what-it-evaluates.test.ts`)
- Every response the Guardian sends is checked against the response schema and the result is logged. (`packages/guardian/test/check-response.test.ts`)
- Every envelope is recorded before validation and the Inspector renders each one. (`test/envelope-log-sink-roundtrip.test.ts`, `packages/inspector/test/`)
- Session chain entries and audit entries survive the write and the read unchanged. An evicted session that comes back reads as a broken chain. (`test/session-context-roundtrip.test.ts`, `test/audit-sink-roundtrip.test.ts`)

**Architecture**

- The host adapter has no AGT vocabulary. The AGT bridge has no host vocabulary. The Inspector imports nothing from the Guardian, the bridge, or the adapter. Each host shim imports the adapter only. Ten such gates are enforced. (`test/invariants.test.ts`)
- The policy bundle is byte-identical to the pinned upstream commit, plus one `data.json`. (`test/pin.test.ts`, `bun run verify:pin`)
- The manifest and the mapping address the same snapshot leaf, in AGT's path dialect and in ACS's. (`test/path-dialects.test.ts`)
- The two startup banners in this README are compared with what the processes print. (`test/readme-captures.test.ts`)

**The conformance harness**

- The matrix axes come from the AGT SDK's own constants, not from a list kept here. Every cell has a status. (`packages/conformance/test/`)
- The policy input the Guardian sends validates against AGT's own schema at the pinned commit and at upstream `main`. (`packages/conformance/test/policy-input-schema.test.ts`, `bun run watch:upstream`)
- Each of AGT's eight declared contract surfaces is diffed against upstream `main`, field by field. (`packages/conformance/test/diff-surfaces.test.ts`)

## Operational debt

These are known limits of the tree as it stands. None is fixed.

- **Memory and disk grow without bound.** The Guardian's session store never evicts a session. The envelope log, the audit log and the session-context log have no rotation and no size cap. A long-lived Guardian grows until something else stops it.
- **Log writes sit on the decision path.** The Guardian writes two synchronous file appends per request in a single-threaded server. A slow disk blocks every in-flight decision.
- **The wire is unauthenticated.** See [What this project is, and is not](#what-this-project-is-and-is-not). Loopback by default is the only protection.
- **The egress gate has three measured soft spots.** A shell command whose destination the extractor cannot parse falls through to `allow`, not `deny`. With the shipped allowlist, any command whose text contains an off-list URL is denied, whether or not it reaches that URL. A `WebFetch` URL reaches AGT's gate with no parsing, so four userinfo-style URL shapes pass on the fetch route and fail on the shell route. Closing the last one means editing a `.rego` file, which this project does not do.
- **An `ask` never carries `ask_details`.** The Guardian's decision type has no such field. Every `ask` fails the response schema. A `defer` would fail the same way if any AGT verdict mapped to it.
- **The handshake is not negotiated.** The Guardian returns constants and never reads the ClientHello. Neither side declares ACS profiles.
- **The result gate assumes one output shape per hook.** A `WebFetch` result has no `stdout`, so the result gate is not widened to it. Under the default posture, widening it would proceed on every fetch result with an audit entry. This is recorded and unassigned.
- **`modified_content` has no builder.** The Guardian never emits it and both hosts refuse it.
- **The audit sequence number can collide.** Two Claude Code hooks that run at the same time read the same log length and write the same `seq`.
- **Session state is measured in pieces.** No single test drives a real Guardian over two steps against the real bundle and asserts the labels, because AGT propagates the labels it is given and originates none.
- **The upstream watch never fails a build.** It reports what moved in AGT. Nothing reaches this tree until a human moves the pin.

## Open review findings

These findings are open on this tree. They are recorded here so a reader does not rediscover them.

**From the last review in the standalone repository** ([afogel/ACS_reference_implementation#30](https://github.com/afogel/ACS_reference_implementation/pull/30)):

1. `annotateEgressDestination` in `packages/guardian/src/annotate-egress.ts` takes two parameters it never reads and a third typed `unknown`. The ask is a pure collaborator that takes `{ rawCommand, args }` and returns a typed answer, with a thin AGT-shaped adapter around it.
2. The same module owns command-to-origin extraction and a hand-copied list of four destination paths that `egress.rego` also reads. The two lists can drift. The ask is to split the stand-down check out of the extractor.
3. The shared assemble callback in `packages/guardian/src/server.ts` passes a `policyTargetArgument` that the result-gate assembler must ignore. The ask is two evaluate helpers, or a discriminated message per gate.
4. `resolveInterventionPoint(acsMethod, mapping)` and `resolvePolicyTargetArgument(mapping, point, toolName)` disagree on argument order, and `PolicyTargetArgument` is not exported beside its resolver. The ask is one order, `(mapping, ...keys)`, and the export.
5. `packages/conformance/src/main.ts` and `policy-input-schema.ts` build literal snapshots by hand instead of calling the shipped assemblers, so the harness can measure a replica rather than the Guardian. The ask is to call `assemblePreToolCallSnapshot` and `assemblePostToolCallSnapshot`.

**Older findings that are still open:**

- The Guardian's decision type has no `ask_details`, so every `ask` fails the response schema. It is listed under operational debt above.
- A `steps/skillLoad` hook that drives AGT's `content_hash` gate is planned, not built. No code for it exists in the tree, and the ServerHello does not name it.
- Two AGT intervention points, `pre_model_call` and `post_model_call`, have no ACS v0.1.0 method. Whether this project proposes `steps/modelCall` for ACS v0.2 is open.
- Whether to report a fail-open to AGT upstream is open: a `./`-prefixed `bundle:` path silently disables all policy and returns `allow`. This tree throws on that path as a backstop.
- Six required Trace-pillar attributes exist on the wire but are optional there. Requiring them is an ask for v0.2. The Guardian also leaves `AcsResult.metadata` empty, which it could fill today.

## Verify

```bash
bun test              # the whole suite; exactly one test skips, the byte-identity
                      # check, which needs UPSTREAM_BUNDLE
bun run typecheck     # strict TypeScript across the workspace, zero errors
bun run verify:pin    # re-clones AGT at the pinned ref and byte-diffs policy/lib; needs network
bun run conformance   # prints the mapping table, the coverage matrix and the trace rows; needs network
bun run watch:upstream # diffs AGT's eight contract surfaces against upstream main; needs network
```

The suite reads this repository's own schemas. It expects `specification/v0.1.0/response-envelope.json` to accept a ServerHello as a result, which the envelope does from specification v0.1.2. On a tree whose envelope predates that change, exactly one test fails, in `packages/guardian/test/check-response.test.ts`, and every other test passes.

`bun run verify:zero-diff` is also shipped. It measured, between two branches of the standalone repository, that adding the second host cost zero changed lines in the Guardian, the bridge or AGT. Its base branch does not exist in this repository, so here it exits 1 before it diffs anything.

The scripts and five test files delete their scratch directories with `trash`, never with a recursive remove, and refuse to run without it.

## Configuration

Everything above runs with no configuration. These are the variables each process reads.

**The Claude Code shim** (`hosts/claude-code/acs-hook.ts`):

| Variable | Default | What it does |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://localhost:8787/acs` | Where the shim sends envelopes |
| `ACS_SESSION_DIR` | `.acs/sessions` | Where the negotiated ServerHello is stored, one file per session |
| `ACS_AUDIT_LOG` | `.acs/audit.jsonl` | Where fail-open proceeds and posture-driven blocks are written |
| `ACS_HOOKMAP_PATH` | `hosts/claude-code/claude-code.hookmap.yaml` | Which hookmap to load. This changes what governance means for the host. Leave it unset in a deployment |

**The OpenCode plugin** (`hosts/opencode/acs-plugin.ts`) reads `ACS_GUARDIAN_URL`, `ACS_AUDIT_LOG` and `ACS_HOOKMAP_PATH` with the same meanings. Its hookmap default is `hosts/opencode/opencode.hookmap.yaml`. It has no `ACS_SESSION_DIR`, because the plugin lives for the whole session and keeps the ServerHello in memory. It also reads `ACS_DEBUG`. When that variable holds any value other than empty or `0`, the plugin prints the decision's reason text on stderr, because OpenCode has no field that reads a reason back.

**The Guardian** (`bun run guardian`):

| Variable | Default | What it does |
|---|---|---|
| `ACS_ON_DECISION_FAILURE` | `proceed` | The posture the ServerHello declares. `deny` fails closed. Any other value stops the Guardian at startup |
| `ACS_GUARDIAN_PORT` | `8787` | The port for `POST /acs` |
| `ACS_GUARDIAN_HOST` | `127.0.0.1` | The interface to bind. Set `0.0.0.0` only when you accept an unauthenticated routable endpoint |
| `ACS_MANIFEST_PATH` | `policy/manifest.yaml` | The AGT manifest. `policy/manifest.drift.yaml` is the second manifest, used to reach the `warn` verdict |
| `ACS_ENVELOPE_LOG` | `.acs/envelopes.jsonl` | Where every envelope is recorded |
| `ACS_SESSION_CONTEXT_LOG` | `.acs/session-context.jsonl` | Where each session's hash chain is written |

**The Inspector** (`bun run inspector`) reads `ACS_ENVELOPE_LOG`, `ACS_AUDIT_LOG` and `ACS_SESSION_CONTEXT_LOG` with the same defaults. The flags `--envelope-log`, `--audit-log` and `--session-context-log` override them. It honours `NO_COLOR` and prints no colour when stdout is not a terminal.

## Where to read next

| Document | What it holds |
|---|---|
| [`packages/guardian/README.md`](packages/guardian/README.md) | How to start the Guardian, what it reads, what it writes, and how each request moves through it |
| [`packages/agt-bridge/README.md`](packages/agt-bridge/README.md) | How the AGT SDK is constructed, how OPA is reached, and what the pin guarantees |
| [`packages/host-adapter/README.md`](packages/host-adapter/README.md) | What a host shim calls, the hookmap format, and the failure-handling table |
| [`packages/inspector/README.md`](packages/inspector/README.md) | The flags and what each rendered line means |
| [`packages/conformance/README.md`](packages/conformance/README.md) | The three tables, the cell statuses, the exit rule, and the upstream watch |
| [`hosts/claude-code/README.md`](hosts/claude-code/README.md) | Registering the hook, the exit codes, and driving it by hand |
| [`hosts/opencode/README.md`](hosts/opencode/README.md) | Registering the plugin, how each decision lands, and a stub model for a run with no paid account |
| [`../../docs/spec/conformance.md`](../../docs/spec/conformance.md) | The ACS profiles and the ACS-Core baseline this tree is measured against |
| [`../../LICENSING.md`](../../LICENSING.md) | Which license covers which path, including the MIT bundle under `policy/lib/` |
| [`../../SECURITY.md`](../../SECURITY.md) | How to report a bypass privately |
| [afogel/ACS_reference_implementation](https://github.com/afogel/ACS_reference_implementation) | The standalone repository this tree was built in. It holds the ten slice records, the captured demo runbooks, and the shaping documents |

## License

Apache License 2.0, with the rest of this repository's code. `policy/lib/` is Microsoft's stock AGT policy bundle, redistributed unchanged under the MIT License with its own notices. The full text is in [`policy/LICENSE-AGT`](policy/LICENSE-AGT). See [`../../LICENSING.md`](../../LICENSING.md).
