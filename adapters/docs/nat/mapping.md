# NVIDIA Agent Toolkit (NAT) → ACS mapping

Schema source: NAT public repo (`packages/nvidia_nat_core/src/nat/middleware/`).

NAT's architecture differs from Claude Code and Cursor: rather than firing events at named lifecycle points, NAT wraps every Function (tool / sub-workflow / LLM / retriever / memory operation / etc.) with a `Middleware` chain. The middleware's `pre_invoke` is called before the function executes, `post_invoke` after.

The ACS adapter is implemented as a `FunctionMiddleware` that, for each wrapped call, emits an ACS step request.

## NAT lifecycle → ACS step method

**What the adapter emits** (the code is ground truth; this table describes it):

| NAT concept | ACS step method | Emitted by the adapter today? |
|---|---|---|
| Any wrapped function `pre_invoke` (tools, LLMs, retrievers, memory — all of them) | `steps/toolCallRequest` | **Yes** — every wrapped call, with the function name as the tool name |
| Any wrapped function `post_invoke` | `steps/toolCallResult` | **Yes** |
| A root Runner's workflow start (via the `acs_lifecycle` exporter NAT starts for every Runner) | `steps/sessionStart` + `steps/userMessage` | **Yes** — a `sessionStart` deny refuses the run's calls, and a `userMessage` verdict other than allow blocks them; see below |
| The root Runner's workflow end (same exporter), for a run that returns | `steps/agentResponse` + `steps/sessionEnd` | **Yes** — observation-only, see below |
| The end of a run that raises or is cancelled (NAT cleans up the run's exporter) | `steps/sessionEnd` with `reason: error` or `cancelled` | **Yes** — observation-only, see below |
| Retriever calls as `steps/knowledgeRetrieval` | — | **No.** Retrievers surface as `toolCallRequest` with the retriever's function name; the Guardian dispatches on name. A dedicated `knowledgeRetrieval` emission is possible future work. |
| Memory read / write as `steps/memoryContextRetrieval` / `steps/memoryStore` | — | **No.** Same status: memory functions surface as generic tool calls. Documented gap — a Guardian keying policy on the memory-specific hooks will not see them from this adapter. |
| Sub-workflow invocation as `steps/subagentStart` / `steps/subagentStop` | — | **No.** A nested Runner joins its parent run's session, and its calls reach the Guardian there as tool calls. ACS-Core requires `subagentStart` only of a subagent-capable client, and the Guardian determines that capability by deployment-defined means. The requirement is vacuous for NAT only when sub-workflows are genuinely not distinguishable at this seam. Otherwise this is a mapping gap. |

The Guardian can dispatch on the tool name to apply retriever-, memory-, or subagent-specific policy to the generic `toolCallRequest` stream; what it cannot get from this adapter is the dedicated ACS step methods for those events.

### The run's input is gated; its output is recorded

The builder registers an `acs_lifecycle` telemetry exporter, and NAT starts a copy of it for every Runner before the Runner's `WORKFLOW_START` and cleans the copy up when the Runner ends. A root Runner's copy sends `steps/sessionStart` + `steps/userMessage` at its `WORKFLOW_START`, `steps/agentResponse` at its `WORKFLOW_END`, and `steps/sessionEnd` at its cleanup. A middleware built without NAT's builder subscribes to each run's step stream on the run's first call instead and reports that run from the call on. hooks.md makes `userMessage` and `agentResponse` decision-eligible (ALLOW / DENY / MODIFY). Each call of a run waits until its `userMessage` has been answered, so the verdict on the input is applied: a verdict other than allow blocks every later call of the run (`workflow_input_refused`), as does a `userMessage` with no decision under `default_deny`, or one whose envelope the signer refuses (`envelope_not_signable`, whatever the posture). A MODIFY on the input is that DENY, recorded as `modify_unsupported` with `reason_codes: ["modify_unsupported"]` (§6.5): NAT has already handed the input to the workflow. `agentResponse` goes out after the run has returned its output, and NAT's exporter is a notification stream that cannot veto an event after it fires, so the verdict on the output is recorded, not applied: a verdict other than allow as `unenforceable_decision`, a MODIFY also as `modify_unsupported`. Enforcement on outputs belongs at `pre_invoke` / `post_invoke` of the function that produced them, or in a review function the workflow calls before returning.

**Each root NAT Runner is one ACS session.** `sessionStart` fires once per session, before any other `steps/*` hook for its `session_id`, and `sessionEnd` seals it (hooks.md), and the per-session HMAC key derives from the `session_id` (§10). So every run's session gets a fresh UUID for its `session_id`, never derived from NAT's ids, and no run's `session_id` is used twice, across runs, processes or restarts. The session opens at the root Runner's `WORKFLOW_START` with its own `handshake/hello` and then its `steps/sessionStart`, and its `steps/sessionEnd` waits for the session's Guardian exchanges still in flight, a cancelled call's included. Its stored records are removed then, and a later step of the run is refused and sends nothing, however many runs have passed.

**A workflow started inside a run stays in that run's session.** The middleware recognizes a run by the session it sets in the root Runner's context, not by NAT's `workflow_run_id`: every nested Runner inherits that id, `nat serve` takes it from the request's `workflow-run-id` header, and steps replayed from a remote workflow carry the caller's. A Runner that starts while a session is open in its context, a nested workflow or sub-agent, joins that session: its calls are gated there, and its own input and output are not sent as the user's message or the agent's response. Steps replayed from a remote workflow neither start nor end the session. Two requests that share a `workflow-run-id` header are two sessions. NAT's `workflow_run_id` and `conversation_id` go in `sessionStart`'s `platform_context` for correlation; under `nat serve` the run id is the client's to choose.

A call outside any NAT Runner uses the middleware's own session, whose `session_id` is the configured `session_id`, or a fresh UUID when none is set; a configured value is the same in every process and after a restart, so leave it unset unless one process uses it once. Its first call sends its `handshake/hello` and `sessionStart`, and NAT's shutdown of the middleware sends its `sessionEnd`, waiting for a session still opening, and removes its records. A step after that is refused and sends nothing.

**The run's `sessionStart` decides the run.** The Guardian's `deny` of a run's `steps/sessionStart`, or a refusal of that request, refuses the run's session (hooks.md sessionStart: a Guardian MAY refuse a session): each later call of the run is blocked and its output withheld, and nothing more of the run is sent, `sessionEnd` included. A `sessionStart` that gets no decision is counted once, and each later step of the run follows the fail posture: under `default_deny` it is blocked, and otherwise it goes to the Guardian. The run's `sessionEnd`, which is audit-only, goes out under either posture and reports that count (§6.4). A call waits until the run's `sessionStart` has been answered.

**Every run ends once.** NAT cleans up a Runner's exporter copy whether the run completed, raised or was cancelled, so the root Runner's session ends then: `reason: completed` after its `WORKFLOW_END`, `cancelled` when the run's task was cancelled, and `error` otherwise, carrying the session's decision failures. A run that raises or is cancelled reaches no `WORKFLOW_END`, so it sends no `steps/agentResponse`. A nested Runner's end never ends its parent's session. A middleware built without NAT's builder ends a run when NAT completes the run's step stream, which NAT does when the run returns or raises; a run cancelled in that mode ends when NAT shuts the middleware down, with `reason: abandoned`. NAT's shutdown of the middleware ends every session still open the same way, after the hooks it already queued.

**Run a nested workflow in its own task.** NAT 1.7.0 gives a nested Runner a new step stream and does not restore its parent's when it returns (`Runner.__aenter__` sets `event_stream` without resetting it), so a Runner awaited directly inside another run's function hides the parent's later NAT events from every exporter, the parent's `WORKFLOW_END` included. The parent's calls are still gated in its session, and its session still ends, but with `reason: error` and no `steps/agentResponse`, even when the run completed. A nested workflow run in its own task, `asyncio.create_task` or `asyncio.gather`, leaves the parent's stream in place, and the parent ends with `reason: completed`. A NAT `Workflow` object built during a run copies that run's context and restores it whenever it runs later, so build workflows when the application starts: a workflow built inside a run and run in a later one finds the earlier run's ended session, and its calls are refused.

**Front ends verified.** The tests drive these through NAT's own objects: `nat run` (a `SessionManager` session and run built from a workflow config, with the middleware applied by NAT's function middleware chain), `nat serve` (a `SessionManager` session for an HTTP request, as NAT's HTTP routes open it; NAT runs each websocket message in a task of its own the same way), nested Runners, replayed remote steps, and a middleware built without the builder. The MCP, A2A and eval front ends are separate NAT packages that are not installed here, so they are unverified.

**Deliberately not mapped — the skill lifecycle set (`steps/skillRegister`, `steps/skillLoad`, `steps/skillUnload`).** NAT composes workflows from functions declared in the workflow YAML; the middleware surface exposes no runtime skill registration, activation, or unload events. Function *invocations* are governed at `pre_invoke`/`post_invoke` (`steps/toolCallRequest`/`toolCallResult`); lifecycle wiring becomes possible when NAT exposes lifecycle events for loadable components.

## ACS disposition → NAT behavior

| ACS disposition | NAT action |
|---|---|
| `allow` | `pre_invoke` returns `None` (proceed unchanged) |
| `deny` | `pre_invoke` raises `ACSGuardianDenied` (NAT 1.7.0) or sets `context.action = InvocationAction.SKIP` (NAT dev). NAT's runtime documents both: *"Raises: Any exception to abort execution"* and the action-based equivalent. |
| `modify` | If `modifications.parameter_overrides` is present and is a dict, the adapter rewrites each overridden field where NAT reads it: a field the input model, dataclass or dict in `context.modified_args[0]` declares is rewritten there, a keyword argument the call already has in `context.modified_kwargs`, and a scalar input, which NAT's function middleware chain passes for a one-argument function, under the input schema's field name at its position, the name the Guardian saw it under. NAT runs `call_next(*modified_args, **modified_kwargs)`, so each field is written in one slot only. If `modified_content` is present on a post-tool result, the adapter sets `context.output`. An override that names neither, a field the rebuilt input does not keep, redactions, a call's MODIFY without a `parameter_overrides` object, and structured edits on a result cannot be applied: the call is blocked or the output withheld, recorded as `modify_unsupported` with `reason_codes: ["modify_unsupported"]` (§6.5). |
| `ask` | Substituted to block at the middleware boundary in v1 (NAT has no native pause primitive at the function-middleware layer). Deployments wanting ASK should compose with NAT's HITL middleware (`nat.middleware.hitl`) and have the Guardian resolve before responding. |
| `defer` | Substituted to block in v1 (same reason). On a tool result, `ask` and `defer` both withhold the output (`context.output = None`) and are audited as `post_invoke_redacted`: the tool already ran, and nothing can pause its output for a person. |

## Configuration

Middleware is registered with NAT via the `name=` class kwarg on the config:

```python
class ACSMiddlewareConfig(FunctionMiddlewareBaseConfig, name="acs_guardian"):
    ...
```

NAT picks this up via its `register_middleware` registration mechanism (the adapter ships with `@register_middleware(config_type=ACSMiddlewareConfig)` applied to a factory function).

YAML wiring:

```yaml
middleware:
  acs:
    _type: acs_guardian             # matches the name= kwarg above
    guardian_url: http://127.0.0.1:8787/acs
    default_deny: true
    target_function_or_group: my_tools   # optional; otherwise applied via group/workflow membership
    target_location: input          # NAT-standard field
    session_id: null                # session of calls outside any NAT run; generated if unset. Each run's session gets a fresh id

function_groups:
  my_tools:
    middleware: [acs]

workflow:
  _type: react_agent
  middleware: [acs]
```

## Composition with NAT's defense middleware

NAT ships `nvidia-nat-security` with `defense_middleware` for content-level checks (PII, output verification, pre-tool LLM gating). The ACS adapter does NOT replace these — both can be attached to the same group. Ordering is by list position in YAML; place ACS first if you want the policy gate before content filters, last if you want content rewrites to be visible to ACS as the final state.

## Concurrency

NAT can invoke several wrapped functions at once in one process. A session opens off the event loop at its first step, and every later step of the session reuses that decision, a refusal or no answer included. Each step's Guardian round trip runs in a worker thread (`asyncio.to_thread`), so a slow Guardian leaves the event loop running while the call waits for its decision. Each session's lifecycle hooks go out from a worker thread of their own in the order NAT reports them, and each call waits only until its own session's earlier hooks have gone out, so a slow hook in one run never holds another run's calls. When NAT shuts the middleware down, every session's queued hooks go out first, in order, and then each open session ends. A hook reported after its session ended is audited as `lifecycle_hook_not_sent`. The middleware correlates each call through its own invocation context and keeps no per-call file state. The Guardian's rolling `chain_hash` orders steps by arrival, so the order of concurrent steps is the order they reach the Guardian.

## Conformance posture

The NAT adapter covers ACS-Core's mandatory floor. This is the floor the tests check, not a full ACS-Core conformance claim (see `adapters/README.md`). The floor it covers:

- Hook taxonomy: every wrapped function call surfaces as `toolCallRequest` + `toolCallResult`.
- Dispositions: ALLOW / DENY / MODIFY supported normatively; ASK / DEFER substituted to DENY with audit (HITL composition is the recommended path).
- SessionContext: `session_id` sent on every request: the root Runner's session's, or the middleware's own for a call outside any run.
- Replay protection: `request_id` UUID + timestamp.
- Handshake: each session performs `handshake/hello` once, a run's at its start and the middleware's own at its first call outside a run, and its answer decides the session (§4.1). The ServerHello must answer the ClientHello: a `negotiated_version` sharing a major version the adapter offered, a `methods_evaluated` list, the one transport the adapter offers (its Guardian URL's scheme), a positive `timeout_config.default_ms`, an `on_decision_failure` of `proceed` or `deny`, and only profiles the adapter claimed; otherwise the session has no negotiated Guardian (`invalid_server_hello`). Per-method timeouts bound their own methods. The answer: a refusal blocks every call, and no answer leaves the session with no negotiated Guardian for its lifetime, so `ACS_STARTUP_POSTURE` (unset follows `default_deny`) settles each call with no Guardian traffic.
- Decision honoring: NAT's middleware contract guarantees the function does not execute if `pre_invoke` raises or sets SKIP. The fail posture is `workflow.yml`'s `default_deny` OR the ServerHello's `on_decision_failure` (most-restrictive-wins); Guardian refusals (signature invalid, replay, malformed/oversized envelope) fail closed regardless of posture, on both the input gate (block) and the output gate (redact) — spec issue #32. Methods absent from the ServerHello's `methods_evaluated` resolve as ALLOW-by-default without being sent (handshake.json) and are recorded as `method_not_evaluated`. Before signing, every step replaces what RFC 8785 cannot encode: a lone surrogate becomes U+FFFD, and an integer past 2^53 - 1, NaN or an infinity becomes a string, recorded as `envelope_normalized`, so the Guardian still sees the step. An envelope that still cannot be signed is denied whatever the posture (`envelope_not_signable`) on `pre_invoke` and the workflow input, and its output is withheld on `post_invoke`. Every decision failure is audited under either posture with its `failure_class` (`timeout`, `unreachable`, `malformed_response`, `guardian_error`, `observed_agent_error`, `signature_invalid`, `handshake_failure`, `other`) and `posture`, and each session's `sessionEnd` reports that session's count per class in `summary.decision_failures` (§6.4, #273). A handshake that gets no answer is audited as `handshake_failure`; that session sends the Guardian nothing, `sessionEnd` included (§4.1).
- Baseline integrity: HMAC-SHA256 per §10 over the RFC 8785 (JCS) canonical envelope with an HKDF-derived per-session key (`ACS_HMAC_SECRET_FILE` / `ACS_HMAC_SECRET`); `rfc8785` is a hard runtime dependency. The signature names the configured label `ACS_HMAC_KEY_ID` as `key_id`, and a response under any other label fails verification with no other secret tried; an unsigned `SIGNATURE_INVALID`, a Guardian's answer to a label it does not hold, is recorded as `key_id_rejected` and fails closed. Responses are signature-verified and bound to their request under any HTTP status; a mis-bound, badly-signed or unverifiable response fails closed regardless of posture. A middleware with no secret, a secret under 32 bytes, or no label refuses its session, so every call is denied, and sends nothing (`secret_missing`, `secret_too_short`, `key_id_missing`), whatever the posture: ACS-Core signs every request.
