# Cursor → ACS hook mapping

Schema sources: the official Cursor hooks documentation at docs.cursor.com (as of 2026-08-22) and Cursor's bundled `create-hook` skill (`~/.cursor/skills-cursor/create-hook/SKILL.md`). Every input field the adapter reads and every output field it emits appears in those documents — an earlier revision read fields Cursor never sends (`workspace_path`, `mcp_server`, `mcp_tool`, `exit_code`, `execution_id`, `response`, `thought`), so MCP/shell/agent envelopes reached the Guardian with empty identity and content (PR #22 host-contract audit).

Each Cursor hook event maps to an ACS `steps/*` method. The adapter (`src/acs/integrations/cursor/adapter.py`) does the translation in both directions.

## Hook event mapping

| Cursor hook | ACS step method | Notes |
|---|---|---|
| `sessionStart` | `steps/sessionStart` | Session bounds. `platform_context` carries the real fields: `workspace_roots`, `composer_mode`, `is_background_agent`, `cursor_version`. Session-level — no `turn_id`. |
| `sessionEnd` | `steps/sessionEnd` | Session close (chain seal). Cursor reasons map onto the ACS enum: `completed`→`completed`, `aborted`→`cancelled`, `error`→`error`, `window_close`/`user_close`→`abandoned`. Session-level — no `turn_id`. |
| `stop` | `steps/turnEnd` | End of a **turn** (each reply), not the session. `steps/sessionEnd` seals the chain once per session, so mapping `stop` there sealed it every reply; `steps/turnEnd` (audit-only) is the per-turn boundary and echoes the open turn's `turn_id`. Cursor's `status` maps to the outcome enum: `completed`→`completed`, `aborted`→`interrupted`, `error`→`error`. A `stop` with no open turn is skipped + audited rather than fabricating a `turn_id`. |
| `preToolUse` | `steps/toolCallRequest` | Principal interception point; fires for ALL tool types (Shell, Read, Write, MCP, Task, …). `request_id` pinned to uuid5 of `tool_use_id` so the matching result correlates. Carries `metadata.turn_id`. |
| `postToolUse` | `steps/toolCallResult` | `tool_output` is a JSON-STRINGIFIED result payload ("not raw terminal text"); the adapter parses it into `outputs`, maps a nonzero `exitCode` inside it to `exit_status: failure`, coerces `duration`→`duration_ms` (integer), and cites `request_id_ref` from `tool_use_id`. |
| `postToolUseFailure` | `steps/toolCallResult` | Real failure fields: `error_message` flows into `outputs`; `failure_type` maps onto the ACS enum — `error`→`failure`, `timeout`→`timeout`, `permission_denied`→`blocked`. |
| `subagentStart` | `steps/subagentStart` | Confused-deputy spawn gate. Lineage from real fields: `parent_step_id` = uuid5 of the event's `tool_call_id` (the delegating Task tool call — the same id its preToolUse pinned as request_id), falling back to the session state's last recorded step, else (audited) the spawn envelope's own request_id. `subagent_model` → descriptor `model_id`. |
| `subagentStop` | — not forwarded | Deliberately unmapped (`KNOWN_UNMAPPED`): `final_chain_hash` is genuinely unknowable — Cursor maintains no session-chain. A separate schema PR proposes making the field optional for chain-less frameworks; honest wiring resumes when the spec owners approve it. Never emit a fabricated hash. |
| `beforeShellExecution` | `steps/toolCallRequest` (tool name = "Shell") | Shell-specific gate. Input: `command`, `cwd`, `sandbox`. Cursor exposes NO correlation id on this hook, so its request_id is random. |
| `afterShellExecution` | `steps/toolCallResult` | Input: `command`, `output`, `duration`, `sandbox` — NO exit code and NO id exist on this hook, so `exit_status` is `success` (the schema requires a value; the Shell result WITH an `exitCode` also flows through `postToolUse`, which does discriminate) and `request_id_ref` is omitted. Documented gap, not an oversight. |
| `beforeMCPExecution` | `steps/toolCallRequest` | Input: `tool_name`, `tool_input` (JSON-stringified params — parsed into `arguments`), plus `url` (remote) or `command` (stdio) → `tool.provider`. |
| `afterMCPExecution` | `steps/toolCallResult` | Input: `tool_name`, `tool_input`, `result_json` (JSON-stringified response — parsed into `outputs`), `duration`. No id on this hook → `request_id_ref` omitted; MCP calls also flow through pre/postToolUse, which carry `tool_use_id` correlation. |
| `beforeReadFile` | — not forwarded | Deliberately unmapped (`KNOWN_UNMAPPED`). This IS a blockable gate upstream (output `permission: allow\|deny` — "Use for access control to block sensitive files"); a `steps/knowledgeRetrieval` mapping is the tracked candidate. Until wired, reads are a documented Guardian visibility gap. |
| `beforeTabFileRead` | — not forwarded | Same as `beforeReadFile`, for Tab inline completions (no `attachments` field). |
| `afterFileEdit` | `steps/toolCallResult` | Input: `file_path` + `edits` [{old_string, new_string}] — both flow into `outputs` so the Guardian sees WHAT changed. |
| `afterTabFileEdit` | `steps/toolCallResult` | Same shape as `afterFileEdit`, from Tab. |
| `beforeSubmitPrompt` | `steps/turnStart` **then** `steps/userMessage` | A prompt OPENS a turn: the adapter first emits a decision-eligible `steps/turnStart` (`triggered_by: user_message`; a Guardian MAY `deny` to block the whole turn), then the `steps/userMessage` carrying `prompt`. Both — and every in-turn step — carry `metadata.turn_id` until the matching `stop`. |
| `preCompact` | `steps/preCompact` | `trigger` (`auto`\|`manual`) maps to the ACS enum (`framework_initiated`\|`manual`); `entries_to_compact` = real observed step_ids, and the emission is skipped + audited when none exist (never a placeholder). |
| `afterAgentResponse` | `steps/agentResponse` | Input field is `text` (the assistant's final text). |
| `afterAgentThought` | `steps/agentResponse` | Input field is `text` (aggregated thinking); modeled as an agent emission. |
| `workspaceOpen` | — not forwarded | App-lifecycle event outside any agent session (no `conversation_id`) — there is no ACS session to attach it to. |

**Deliberately not mapped — the skill lifecycle set (`steps/skillRegister`, `steps/skillLoad`, `steps/skillUnload`).** Cursor's hook surface exposes no skill registration, activation, or unload events, so there is nothing to translate; wiring becomes possible when the platform adds skill lifecycle hooks.

## Disposition mapping

Cursor's documented response keys are event-specific. The adapter translates ACS dispositions accordingly:

### Permission events (`preToolUse`, `subagentStart`, `beforeShellExecution`, `beforeMCPExecution`)

| ACS disposition | Cursor output | Notes |
|---|---|---|
| `allow` | `{"permission": "allow"}` | |
| `deny` | `{"permission": "deny", "user_message": reasoning, "agent_message": reasoning}` | Cursor displays user_message in UI; agent_message is fed back to the agent's context. |
| `ask` | `{"permission": "ask", "user_message": reasoning, "agent_message": reasoning}` | Upstream caveat: Cursor documents `ask` as "accepted by the schema but not enforced for preToolUse today", and `subagentStart` treats `ask` as `deny`. On those events ask is a soft signal, not a hard pause. |
| `defer` | `{"permission": "ask", ...}` | Deployment substitution (not spec-mandated; §9.2 places substitution on the Guardian): Cursor has no defer. |
| `modify` | `{"permission": "allow", "updated_input": original ⊕ parameter_overrides, "user_message": reasoning}` on `preToolUse` only | `updated_input` REPLACES the whole input, so the adapter MERGES the overrides onto the original arguments. Other permission events have no documented updated-input field; modify substitutes to deny with audit. A contradictory `modifications` object fails closed to deny (§6.3:146). |

### `postToolUse` — the only post-tool event with documented output fields

| ACS disposition | Cursor output |
|---|---|
| `allow` | `{}` (no output; proceed) |
| `deny` | `{"additional_context": "ACS Guardian denied this result: …"}` + `unenforceable_decision` audit (the tool already ran; feedback is the only channel) |
| `modify` with `modified_content` | `{"updated_mcp_tool_output": <parsed content>}` — "For MCP tools only: replaces the tool output seen by the model" |
| any other decision with reasoning | `{"additional_context": reasoning}` |

### Other post-tool events (`postToolUseFailure`, `afterShellExecution`, `afterMCPExecution`, `afterFileEdit`, `afterTabFileEdit`)

"No output fields currently supported" (Cursor docs) — the adapter emits nothing; an arrived restrictive decision is recorded as an `unenforceable_decision` audit event.

### `beforeSubmitPrompt`

Cursor's documented output is `{"continue": bool, "user_message": str}`; exit code 2 also blocks (documented as Claude Code-compatible behavior). The adapter emits BOTH — the native JSON and the exit code — so either mechanism suffices:

| ACS disposition | Adapter behavior |
|---|---|
| `allow` | `{"continue": true}`, exit 0 |
| `deny` | `{"continue": false, "user_message": reasoning}`, exit 2 |
| `ask` / `defer` / `modify` | same as deny (substituted to block + audit; the prompt hook can't pause or edit) |

### Lifecycle events (`sessionStart`, `sessionEnd`, `stop`, `preCompact`, `afterAgentResponse`, `afterAgentThought`)

**Observation-only.** The adapter emits empty output. Cursor fires these after the fact (or fire-and-forget), so a Guardian `deny` / `modify` cannot undo the side effect; ACS records the event in the audit chain. Enforcement on prompts belongs at `beforeSubmitPrompt` (turn gate), on tools at `preToolUse` / `beforeShellExecution` / `beforeMCPExecution`, on spawns at `subagentStart`. ACS-Core §hooks.md describes `agentResponse` as decision-eligible; the framework constraint forces this adapter's mapping to honest observation-only.

## Matchers

Cursor's `hooks.json` supports `matcher` regex per hook entry. The adapter does not require any matcher; the Guardian filters server-side. Use matchers in `hooks.json` only if you want to scope which calls reach the Guardian (a deployment optimization, not a correctness concern).

## Exit codes (Cursor's protocol)

| Exit code | Cursor behavior | When the adapter uses it |
|---|---|---|
| 0 | Success; parse stdout as JSON | Normal case for every event except a blocked `beforeSubmitPrompt` |
| 2 | Block (documented Claude Code-compatible behavior) | `beforeSubmitPrompt` block (alongside the native `{"continue": false}` JSON); any event when fail-closed and Guardian unreachable and stdout JSON not viable |
| Other nonzero | Fail open unless `failClosed: true` | Not used by the adapter (errors are converted to deny via posture) |

## failClosed

Cursor's per-hook `failClosed: true` makes Cursor block when the hook crashes, times out, or returns invalid JSON. The adapter's `ACS_DEFAULT_DENY`, the negotiated posture and `ACS_STARTUP_POSTURE` decide the failures the adapter handles, and every step the adapter decides answers in Cursor's native shape: an explicit allow when it proceeds, a deny when it does not. Use both in production: `failClosed: true` in `hooks.json` for a failed hook process, `ACS_DEFAULT_DENY=1` for a Guardian that cannot decide.

## Concurrency

Cursor's documentation does not say whether hooks of one session overlap, so every session-state update (`record_step` for each step sent, opening or closing a turn, and a signed session's first MCP call's `profile_claim_degraded` record) is one locked read-modify-write through a temp file of its own; no lock is held during a Guardian round trip. The shell and MCP `before`/`after` events carry no call id (see the table above), so parallel shell or MCP calls cannot be paired with their results. The Guardian's rolling `chain_hash` orders steps by arrival, so the order of concurrent steps is the order they reach the Guardian. `acs-cursor-wire` refuses to wire when another copy of the adapter is wired in an enterprise, project or user `hooks.json`, or in the Claude Code settings Cursor's third-party import runs.

## Conformance posture

The Cursor adapter implements ACS-Core's mandatory floor in the same shape as the Claude Code adapter:

- Handshake: `handshake/hello` performed on the first event of a session, and its answer decides the session (§4.1): a verified ServerHello negotiates; a refusal, or an answer that fails its checks, refuses every step; and no answer leaves the session with no negotiated Guardian, so each hook's `ACS_STARTUP_POSTURE` applies (`proceed` lets the step run with nothing sent to the Guardian; `refuse` denies it). The decision is stored in `~/.cache/acs-adapter-handshake/` with an HMAC under the session key over the decision, the session and the Guardian URL, and holds for the session's lifetime, so a dead Guardian costs one timeout per session; a record that fails its checks, or a decision that cannot be stored, refuses the session. ServerHello signature-verified, bound to the ClientHello, its `on_decision_failure` combines with `ACS_DEFAULT_DENY` (deny wins over proceed), and its `timeout_config` replaces the local decision timeout, per method where `per_method_ms` names one (§6.4). The ServerHello must answer the ClientHello: a `negotiated_version` sharing a major version the adapter offered, a `methods_evaluated` list, the one transport the adapter offers (its Guardian URL's scheme), a positive `timeout_config.default_ms`, an `on_decision_failure` of `proceed` or `deny`, and only profiles the adapter claimed; otherwise the session has no negotiated Guardian (`invalid_server_hello`). Its `methods_evaluated` bounds what is sent: a method the Guardian omits resolves as ALLOW-by-default without being sent (handshake.json), recorded as `method_not_evaluated`; permission events and `beforeSubmitPrompt` return their explicit allow shapes, since `failClosed` reads an empty reply as a failed hook. With no negotiated list, every mapped event is sent. `ACS_HANDSHAKE=0` skips the handshake, and the startup posture settles every step.
- Turns: a `beforeSubmitPrompt` opens a turn with an explicit `steps/turnStart` (decision-eligible) before the `steps/userMessage`; `stop` closes it with `steps/turnEnd`. `turn_id` is held in per-session state and stamped on `metadata.turn_id` of every in-turn step.
- Hook taxonomy minimum: all covered, plus many additional Cursor events. `subagentStop`, `beforeReadFile`, `beforeTabFileRead`, `workspaceOpen` deliberately unmapped with documented reasons; unknown events emit an `unmapped_hook_event` audit line rather than going quiet.
- Dispositions: ALLOW / DENY / ASK supported on permission events (see the upstream ask-enforcement caveat); MODIFY supported on `preToolUse` (merged overrides); DEFER → ASK substitution (deployment behavior, not spec-mandated).
- SessionContext: session_id sent every request (non-UUID `conversation_id` coerced deterministically).
- Replay protection: ✓
- Baseline integrity: HMAC-SHA256 per §10 over the RFC 8785 (JCS) canonical envelope, HKDF per-session key (`ACS_HMAC_SECRET_FILE` / `ACS_HMAC_SECRET`); `rfc8785` is a hard dependency. Responses signature-verified and bound to their request under any HTTP status; refusals, binding mismatches, bad response signatures, and responses that cannot be verified fail closed regardless of posture (deliberately stricter than the current §6.4 text — spec issue #32). Unsigned mode is announced with a loud `unsigned_mode` audit event.
- Decision honoring: ✓ (Cursor enforces the permission verdict; the prompt gate emits the documented `continue:false` JSON plus exit 2)
