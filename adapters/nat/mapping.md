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
| Workflow start (via `IntermediateStepManager` subscription) | `steps/sessionStart` + `steps/userMessage` | **Yes** — observation-only, see below |
| Workflow end (same subscription) | `steps/agentResponse` + `steps/sessionEnd` | **Yes** — observation-only, see below |
| Retriever calls as `steps/knowledgeRetrieval` | — | **No.** Retrievers surface as `toolCallRequest` with the retriever's function name; the Guardian dispatches on name. A dedicated `knowledgeRetrieval` emission is possible future work. |
| Memory read / write as `steps/memoryContextRetrieval` / `steps/memoryStore` | — | **No.** Same status: memory functions surface as generic tool calls. Documented gap — a Guardian keying policy on the memory-specific hooks will not see them from this adapter. |
| Sub-workflow invocation as `steps/subagentStart` / `steps/subagentStop` | — | **No.** Nested workflow functions surface as generic tool calls; NAT exposes no distinct spawn boundary to the middleware. PR #21 (open; not in this branch) proposes a conditional subagent floor. If that proposal lands, NAT satisfies the condition vacuously only when sub-workflows are genuinely not distinguishable at this seam; otherwise this remains a mapping gap. |

The Guardian can dispatch on the tool name to apply retriever-, memory-, or subagent-specific policy to the generic `toolCallRequest` stream; what it cannot get from this adapter is the dedicated ACS step methods for those events.

### Lifecycle hooks are observation-only

The adapter's `_on_intermediate_step` subscriber emits `steps/sessionStart` + `steps/userMessage` on `WORKFLOW_START` and `steps/agentResponse` + `steps/sessionEnd` on `WORKFLOW_END` via `_emit_lifecycle_hook`. **This path is fire-and-forget.** NAT's `IntermediateStepManager` subscription model is a notification stream — a subscriber callback cannot veto the event after the fact. So although ACS-Core §hooks.md lists `agentResponse` as decision-eligible (ALLOW / DENY / MODIFY), the adapter cannot actually block or rewrite the workflow's output through this path. The envelopes are for trace + audit; enforcement on outputs must be placed at `pre_invoke` / `post_invoke` of the function that produced them, or as a separate review function in the YAML the workflow calls before returning.

**Deliberately not mapped — the skill lifecycle set (`steps/skillRegister`, `steps/skillLoad`, `steps/skillUnload`).** NAT composes workflows from functions declared in the workflow YAML; the middleware surface exposes no runtime skill registration, activation, or unload events. Function *invocations* are governed at `pre_invoke`/`post_invoke` (`steps/toolCallRequest`/`toolCallResult`); lifecycle wiring becomes possible when NAT exposes lifecycle events for loadable components.

## ACS disposition → NAT behavior

| ACS disposition | NAT action |
|---|---|
| `allow` | `pre_invoke` returns `None` (proceed unchanged) |
| `deny` | `pre_invoke` raises `ACSGuardianDenied` (NAT 1.7.0) or sets `context.action = InvocationAction.SKIP` (NAT dev). NAT's runtime documents both: *"Raises: Any exception to abort execution"* and the action-based equivalent. |
| `modify` | If `modifications.parameter_overrides` is present and is a dict, the adapter updates `context.modified_kwargs` in place and returns the context. NAT's runtime invokes the function with the modified kwargs. If `modified_content` is present on a post-tool result, the adapter sets `context.output`. |
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

## Conformance posture

The NAT adapter implements ACS-Core's mandatory floor:

- Hook taxonomy: every wrapped function call surfaces as `toolCallRequest` + `toolCallResult`.
- Dispositions: ALLOW / DENY / MODIFY supported normatively; ASK / DEFER substituted to DENY with audit (HITL composition is the recommended path).
- SessionContext: `session_id` sent on every request.
- Replay protection: `request_id` UUID + timestamp.
- Decision honoring: NAT's middleware contract guarantees the function does not execute if `pre_invoke` raises or sets SKIP. The fail posture is `workflow.yml`'s `default_deny` OR the ServerHello's `on_decision_failure` (most-restrictive-wins); Guardian refusals (signature invalid, replay, malformed/oversized envelope) fail closed regardless of posture, on both the input gate (block) and the output gate (redact) — spec issue #32.
- Baseline integrity: HMAC-SHA256 per §10 over the RFC 8785 (JCS) canonical envelope with an HKDF-derived per-session key (`ACS_HMAC_SECRET_FILE` / `ACS_HMAC_SECRET`); `rfc8785` is a hard runtime dependency. Responses are signature-verified and bound to their request. Unsigned mode (no secret) is announced with a loud `unsigned_mode` audit event.
