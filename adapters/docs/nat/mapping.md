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
| Workflow start (via the `acs_lifecycle` exporter NAT starts for every run) | `steps/sessionStart` + `steps/userMessage` | **Yes** — a `sessionStart` deny refuses the run's calls; see below |
| Workflow end (same exporter), for a run that returns | `steps/agentResponse` + `steps/sessionEnd` | **Yes** — observation-only, see below |
| The end of a run that raises or is cancelled (NAT stops the run's exporter) | `steps/sessionEnd` with `reason: error` or `cancelled` | **Yes** — observation-only, see below |
| Retriever calls as `steps/knowledgeRetrieval` | — | **No.** Retrievers surface as `toolCallRequest` with the retriever's function name; the Guardian dispatches on name. A dedicated `knowledgeRetrieval` emission is possible future work. |
| Memory read / write as `steps/memoryContextRetrieval` / `steps/memoryStore` | — | **No.** Same status: memory functions surface as generic tool calls. Documented gap — a Guardian keying policy on the memory-specific hooks will not see them from this adapter. |
| Sub-workflow invocation as `steps/subagentStart` / `steps/subagentStop` | — | **No.** Nested workflow functions surface as generic tool calls; NAT exposes no distinct spawn boundary to the middleware. ACS-Core requires `subagentStart` only of a subagent-capable client, and the Guardian determines that capability by deployment-defined means. The requirement is vacuous for NAT only when sub-workflows are genuinely not distinguishable at this seam. Otherwise this is a mapping gap. |

The Guardian can dispatch on the tool name to apply retriever-, memory-, or subagent-specific policy to the generic `toolCallRequest` stream; what it cannot get from this adapter is the dedicated ACS step methods for those events.

### Lifecycle hooks after `sessionStart` are observation-only

The adapter's `_on_intermediate_step` callback emits `steps/sessionStart` + `steps/userMessage` on `WORKFLOW_START` and `steps/agentResponse` + `steps/sessionEnd` on `WORKFLOW_END` via `_emit_lifecycle_hook`. NAT creates a new step stream for each run, so the builder registers an `acs_lifecycle` telemetry exporter that NAT starts for every run before `WORKFLOW_START`; a middleware built without NAT's builder subscribes on each run's first call instead and reports that run from the call on. **This path is fire-and-forget.** NAT's `IntermediateStepManager` subscription model is a notification stream — a subscriber callback cannot veto the event after the fact. So although ACS-Core §hooks.md lists `agentResponse` as decision-eligible (ALLOW / DENY / MODIFY), the adapter cannot actually block or rewrite the workflow's output through this path. The envelopes are for trace + audit; enforcement on outputs must be placed at `pre_invoke` / `post_invoke` of the function that produced them, or as a separate review function in the YAML the workflow calls before returning.

**The run's `sessionStart` decides the run.** The Guardian's `deny` of a run's `steps/sessionStart`, or a refusal of that request, refuses the run (hooks.md sessionStart: ALLOW / DENY): each later call of the run is blocked and its output withheld, and nothing more of the run is sent, `sessionEnd` included (§4.1). A `sessionStart` that gets no decision is counted once, and each later step of the run follows the fail posture: under `default_deny` it is blocked and nothing more is sent, and otherwise it goes to the Guardian. A call waits until the run's `sessionStart` has been answered.

**A failed run still ends.** NAT 1.7.0 pushes `WORKFLOW_END` only after the workflow returns, so a run that raises or is cancelled sends no `steps/agentResponse`. NAT stops the run's `acs_lifecycle` exporter either way, and for a run with no `WORKFLOW_END` the adapter then sends `steps/sessionEnd` with `reason: cancelled` when the run's task was cancelled and `reason: error` otherwise, carrying the run's decision failures. A middleware built without NAT's builder has no exporter to stop, so its failed runs send no `sessionEnd`.

**Deliberately not mapped — the skill lifecycle set (`steps/skillRegister`, `steps/skillLoad`, `steps/skillUnload`).** NAT composes workflows from functions declared in the workflow YAML; the middleware surface exposes no runtime skill registration, activation, or unload events. Function *invocations* are governed at `pre_invoke`/`post_invoke` (`steps/toolCallRequest`/`toolCallResult`); lifecycle wiring becomes possible when NAT exposes lifecycle events for loadable components.

## ACS disposition → NAT behavior

| ACS disposition | NAT action |
|---|---|
| `allow` | `pre_invoke` returns `None` (proceed unchanged) |
| `deny` | `pre_invoke` raises `ACSGuardianDenied` (NAT 1.7.0) or sets `context.action = InvocationAction.SKIP` (NAT dev). NAT's runtime documents both: *"Raises: Any exception to abort execution"* and the action-based equivalent. |
| `modify` | If `modifications.parameter_overrides` is present and is a dict, the adapter updates `context.modified_kwargs` in place and returns the context. NAT's runtime invokes the function with the modified kwargs. If `modified_content` is present on a post-tool result, the adapter sets `context.output`. Redactions, a call's MODIFY without a `parameter_overrides` object, and structured edits on a result cannot be applied: the call is blocked or the output withheld, recorded as `modify_unsupported` with `reason_codes: ["modify_unsupported"]` (§6.5). |
| `ask` | Substituted to block at the middleware boundary in v1 (NAT has no native pause primitive at the function-middleware layer). Deployments wanting ASK should compose with NAT's HITL middleware (`nat.middleware.hitl`) and have the Guardian resolve before responding. |
| `defer` | Substituted to block in v1 (same reason). |

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
    session_id: null                # adapter generates one per process

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

NAT can invoke several wrapped functions at once in one process. The builder opens the session off the event loop before NAT gets the middleware, unless `ACS_DISABLED=1`, and every call reuses that decision, a refusal or no answer included. Each step's Guardian round trip runs in a worker thread (`asyncio.to_thread`), so a slow Guardian leaves the event loop running while the call waits for its decision. Lifecycle hooks go out from one worker thread in the order NAT reports them, each step waits until the hooks reported before it have gone out, and when NAT shuts the middleware down, every queued hook goes out first, in order, including one reported during the shutdown. A hook reported after that is audited as `lifecycle_hook_not_sent`. The middleware correlates each call through its own invocation context and keeps no per-call file state. The Guardian's rolling `chain_hash` orders steps by arrival, so the order of concurrent steps is the order they reach the Guardian.

## Conformance posture

The NAT adapter covers ACS-Core's mandatory floor. This is the floor the tests check, not a full ACS-Core conformance claim (see `adapters/README.md`). The floor it covers:

- Hook taxonomy: every wrapped function call surfaces as `toolCallRequest` + `toolCallResult`.
- Dispositions: ALLOW / DENY / MODIFY supported normatively; ASK / DEFER substituted to DENY with audit (HITL composition is the recommended path).
- SessionContext: `session_id` sent on every request.
- Replay protection: `request_id` UUID + timestamp.
- Handshake: the first `pre_invoke` of a session performs `handshake/hello`, and its answer decides the session (§4.1). The ServerHello must answer the ClientHello: a `negotiated_version` sharing a major version the adapter offered, a `methods_evaluated` list, the one transport the adapter offers (its Guardian URL's scheme), a positive `timeout_config.default_ms`, an `on_decision_failure` of `proceed` or `deny`, and only profiles the adapter claimed; otherwise the session has no negotiated Guardian (`invalid_server_hello`). Per-method timeouts bound their own methods. The answer: a refusal blocks every call, and no answer leaves the session with no negotiated Guardian for its lifetime, so `ACS_STARTUP_POSTURE` (unset follows `default_deny`) settles each call with no Guardian traffic.
- Decision honoring: NAT's middleware contract guarantees the function does not execute if `pre_invoke` raises or sets SKIP. The fail posture is `workflow.yml`'s `default_deny` OR the ServerHello's `on_decision_failure` (most-restrictive-wins); Guardian refusals (signature invalid, replay, malformed/oversized envelope) fail closed regardless of posture, on both the input gate (block) and the output gate (redact) — spec issue #32. Methods absent from the ServerHello's `methods_evaluated` resolve as ALLOW-by-default without being sent (handshake.json) and are recorded as `method_not_evaluated`. Every decision failure is audited under either posture with its `failure_class` (`timeout`, `unreachable`, `malformed_response`, `guardian_error`, `observed_agent_error`, `signature_invalid`, `handshake_failure`, `other`) and `posture`, and each run's `sessionEnd` reports that run's count per class in `summary.decision_failures` (§6.4, #273). A handshake that gets no answer is audited as `handshake_failure`; that session sends the Guardian nothing, `sessionEnd` included (§4.1).
- Baseline integrity: HMAC-SHA256 per §10 over the RFC 8785 (JCS) canonical envelope with an HKDF-derived per-session key (`ACS_HMAC_SECRET_FILE` / `ACS_HMAC_SECRET`); `rfc8785` is a hard runtime dependency. The signature names the configured label `ACS_HMAC_KEY_ID` as `key_id`, and a response under any other label fails verification with no other secret tried; an unsigned `SIGNATURE_INVALID`, a Guardian's answer to a label it does not hold, is recorded as `key_id_rejected` and fails closed. Responses are signature-verified and bound to their request under any HTTP status; a mis-bound, badly-signed or unverifiable response fails closed regardless of posture. A middleware with no secret, a secret under 32 bytes, or no label refuses its session, so every call is denied, and sends nothing (`secret_missing`, `secret_too_short`, `key_id_missing`), whatever the posture: ACS-Core signs every request.
