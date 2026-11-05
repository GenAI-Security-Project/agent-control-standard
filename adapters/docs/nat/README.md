# ACS adapter: NVIDIA Agent Toolkit (NAT)

A drop-in middleware that wires [NVIDIA NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) to an ACS Guardian. No agent code changes; YAML configuration only.

## How it works

NAT exposes a `FunctionMiddleware` abstraction that wraps any function — tools, sub-workflows, LLM calls, retrievers, memory operations — at the call site. This adapter is that middleware. On every call NAT routes through a wired attachment point, the adapter:

1. Receives the `InvocationContext` (function name, arguments, output) from NAT's middleware pipeline.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET` or `ACS_HMAC_SECRET_FILE`, under the label `ACS_HMAC_KEY_ID`).
4. POSTs to the Guardian.
5. Verifies the response signature and the JSON-RPC error/result shape.
6. Applies the verdict: `allow` passes through; `deny` raises `ACSGuardianDenied` (or sets `InvocationAction.SKIP` on NAT releases that expose it); `modify` rewrites each overridden field where NAT reads it, a field the input in `context.modified_args[0]` declares, a keyword argument the call has in `context.modified_kwargs`, or a scalar input under its schema field name, and is denied when an override names none of them; `ask`/`defer` substitute to deny at the middleware boundary.
7. Records a `steps/toolCallResult` envelope in `post_invoke` and redacts the output on deny, and on ask or defer, since nothing can pause the output for a person. Inputs and outputs go to the Guardian in JSON form: a model dumped in JSON mode, and a value such as a `datetime` as its string. A call whose input has two keys that become the same JSON key, such as `1` and `"1"`, is denied and such an output is withheld, under either posture, so the Guardian never sees less than the function does.

Each root NAT Runner is its own ACS session, with a fresh `session_id`; its `handshake/hello` fires once, at the run's start, and the decision is kept in process state for the run's calls. A Runner started inside a run, a nested workflow or sub-agent, joins that run's session. A call outside any NAT Runner uses the middleware's own session, which gets its own `sessionStart` before the first such call and its `sessionEnd` when NAT shuts the middleware down (`mapping.md`).

Independently of the middleware path, the adapter reports each run's `WORKFLOW_START` / `WORKFLOW_END` events as `steps/sessionStart` + `steps/userMessage` (on workflow start with input) and `steps/agentResponse` + `steps/sessionEnd` (on workflow end with output). A run that raises or is cancelled reaches no workflow end, so it sends no `agentResponse`, and its `sessionEnd` carries `reason: error` or `cancelled` (see `mapping.md`). A Guardian that denies a run's `sessionStart` refuses that run's calls. When NAT builds the middleware, it registers an `acs_lifecycle` telemetry exporter, which NAT starts for every Runner before its `WORKFLOW_START` and cleans up when the Runner ends. A middleware built without NAT's builder subscribes on each run's first call instead, so it reports that run from the call on. **The run's `sessionStart` and `userMessage` verdicts are applied to the run's calls; `agentResponse` and `sessionEnd` are observation-only**, and a verdict on the output is recorded as `unenforceable_decision`. Enforcement on the calls themselves is the middleware path's job.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. NAT provides this through `function_middleware_invoke`: `pre_invoke` must complete before `call_next(...)` runs, so a Guardian deny (whether surfaced as `ACSGuardianDenied` or `InvocationAction.SKIP`) is applied before the wrapped function would execute. Verified in `tests/integrations/nat/test_live.py` (deny tests assert `executed["count"] == 0`).

## Install — five steps

You need: a running Guardian, a shared HMAC secret, and a NAT `workflow.yml` with `acs_guardian` wired at every attachment point. `acs-nat-wire` does step 3 for you and `--check` keeps it true forever after.

Commands below assume `$ACS_REPO` points at your local clone of `GenAI-Security-Project/agent-control-standard`. Export it once:

```bash
export ACS_REPO=/path/to/your/clone   # e.g., $HOME/code/ACS
pip install "$ACS_REPO/adapters[nat]"   # into the environment your NAT workflow runs in
```

The `nat` extra installs NAT itself, the middleware (NAT finds `_type: acs_guardian` through the package's `nat.components` entry point), `acs-nat-wire` and `acs-example-guardian`.

### 1. Generate the shared HMAC secret

Both the adapter and the Guardian read this file. Mode 0600 is enforced — anything looser and the adapter refuses to start.

```bash
mkdir -p ~/.acs
openssl rand -hex 32 > ~/.acs/hmac.key
chmod 600 ~/.acs/hmac.key
```

### 2. Run the Guardian

The example Guardian is for testing; a production Guardian is the same wire protocol with a real policy engine attached.

```bash
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
  acs-example-guardian --port 8787
```

Keep this terminal open. You should see `[guardian] listening on 127.0.0.1:8787`.

### 3. Wire `workflow.yml`

```bash
cd /path/to/your/project   # where your workflow.yml lives

# Preview the change (dry-run, no file write)
acs-nat-wire \
  --workflow=workflow.yml \
  --guardian-url=http://127.0.0.1:8787/acs \
  --default-deny

# Apply (timestamped backup at workflow.yml.bak.<timestamp>)
acs-nat-wire \
  --workflow=workflow.yml \
  --guardian-url=http://127.0.0.1:8787/acs \
  --default-deny \
  --write
```

`acs-nat-wire` finds the ACS middleware by its `_type: acs_guardian`, under whatever name you gave it, and lists that name at every attachment point. With no such middleware it adds one named `acs_guardian`:

| YAML location | What `acs-nat-wire` does |
|---|---|
| top-level `middleware:` block | adds the `acs_guardian:` definition with your guardian_url, default_deny, timeout_s, unless a middleware with `_type: acs_guardian` is already there |
| `workflow.middleware` | prepends that name (policy gate runs before content filters) |
| every `function_groups.*.middleware` | prepends that name |
| every `functions.*.middleware` | prepends that name, creating the list when the function has none |

Every line we add carries a `# acs-adapter-wired` marker. Re-running is a no-op. `--unwire --write` removes exactly what we added and nothing else.

To remove later: `acs-nat-wire --workflow=workflow.yml --unwire --write`.

### 4. Restart your NAT process

NAT loads `workflow.yml` at startup. Existing processes keep their pre-wiring config until restart.

### 5. Verify the install

```bash
# Lint — exits non-zero if any attachment point is missing acs_guardian
acs-nat-wire --workflow=workflow.yml --check

# Run the live tests against your installed adapter + Guardian
cd "$ACS_REPO/adapters"
uv sync --locked --extra nat --group test
uv run python -m unittest tests.integrations.nat.test_live -v
```

`acs-nat-wire --check` is the load-bearing CI gate — see [Coverage discipline](#coverage-discipline-the-yaml-only-rule) below.

## Prerequisites

- **NAT**: `nvidia-nat-core` 1.7.x, installed with the `nat` extra (`pip install "$ACS_REPO/adapters[nat]"`).
- **Python 3.11+**. The `nat` extra also brings `ruamel.yaml` for `acs-nat-wire`. To run the test suites: `cd "$ACS_REPO/adapters" && uv sync --locked --extra nat --group test`.
- **Canonical ACS schemas**: bundled in the package, and read from `specification/v0.1.0/` when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Coverage discipline (the YAML-only rule)

NAT's middleware fires per attachment point: the workflow, each function group and each function, and gates only the calls to that point. A function the workflow or another function calls is gated by its own `middleware:` list, so every function needs `acs_guardian` there. If an attachment point is not wired, every call routed through it bypasses the Guardian. This is a structural property of NAT, not a bug in the adapter — Cursor and Claude Code get framework-wide interception for free; NAT does not.

**The three rules for ACS-conformant NAT deployments:**

1. **Define every tool in YAML.** Functions registered at runtime in Python code (not in `workflow.yml`) cannot be wired by `acs-nat-wire` and will not be gated by the middleware path. If you need full gating, every function lives in the YAML.
2. **Run `acs-nat-wire --check` in CI** on every workflow YAML you ship. It exits non-zero if any attachment point is missing `acs_guardian`. Treat that as a build failure.
3. **Re-run `acs-nat-wire --write` after any YAML edit** that adds or restructures `function_groups`, `workflow`, or individual `functions`. The marker comments make it idempotent.

What this gives you: **the same hard-stop guarantee Cursor's `failClosed: true` gives.** The middleware runs *before* the function executes and waits for the Guardian's decision, off the event loop; a Guardian deny raises `ACSGuardianDenied` (or sets `InvocationAction.SKIP`) and NAT does not call the function.

**The lifecycle observer reports workflow boundaries only.** It sends `sessionStart` and `userMessage` for each run, `agentResponse` for each run that returns, `sessionEnd` for each run whose session the Guardian did not refuse, and no tool calls, so a function the middleware is not wired to reaches the Guardian neither as a decision nor as an observation. Steps 1 and 2 close that gap: define every function in YAML, and run `acs-nat-wire --check` in CI.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (~10s)

```bash
cd "$ACS_REPO/adapters"
uv run python run_conformance.py nat
# Runs the shared Guardian, _common, core, client and package checks, then NAT's suite.
```

Sync with the `nat` extra first (`uv sync --locked --extra nat --group test`). A missing NAT dependency produces an unexpected skip and fails the command.

### Smoke #2 — `acs-nat-wire --check` (CI gate)

```bash
acs-nat-wire \
  --workflow=/path/to/your/workflow.yml --check
```

Exit 0 → every attachment point in the YAML is wired with `acs_guardian`. Exit 1 → at least one gap; the output names the file path, line number, and which kind of attachment point (workflow / function_group / function). Wire this into CI as a build gate.

### Smoke #3 — end-to-end conformance (e2e_check.py)

```bash
cd "$ACS_REPO/adapters"
uv run python tests/integrations/nat/e2e_check.py
```

Five fully-automated scenarios against the **real `example_guardian.evaluate_step` policy** (same one the production example Guardian uses), wired through a recording Guardian so the script can assert on every wire envelope:

| # | Scenario | What it verifies |
|---|---|---|
| 1 | ALLOW | benign Bash function executes; return value flows back; handshake + toolCallRequest received; every envelope HMAC-signed; every envelope validates against the canonical ACS JSON Schema |
| 2 | DESTRUCTIVE | `rm -rf` on a victim dir with a canary file → real policy denies via `destructive_command` regex; `ACSGuardianDenied` raised; **canary file still on disk** (counterproof — the unit-test counter alone can false-pass if the function returns early for any reason) |
| 3 | READ-TOOL | different tool, same wire contract; arguments wrapped per `tool-call-request.json:26-37`; envelope.arguments.file_path.value matches probe path |
| 4 | HANDSHAKE-ONCE | 3 sequential invocations on the same middleware → exactly 1 `handshake/hello` envelope arrived |
| 5 | LIFECYCLE | A NAT Runner's `WORKFLOW_START`/`WORKFLOW_END`, reported by the middleware's exporter → emits `steps/sessionStart` + `steps/userMessage` + `steps/agentResponse` + `steps/sessionEnd` envelopes with the workflow input/output in the payload (workflow boundaries only: the run's input and output, never its tool calls) |

The final line is `ACS-CORE SMOKE PASS (nat)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

Schema validation is against the canonical `request-envelope.json` from `ACS_SPEC_DIR` — adapter ↔ spec, not adapter ↔ test fixture. A drift between adapter and the spec fails this check, not the other way around.

### Smoke #4 — disposition matrix (test_dispositions_live.py)

```bash
cd "$ACS_REPO/adapters"
uv run python -m unittest tests.integrations.nat.test_dispositions_live -v
```

End-to-end verification that EVERY ACS disposition (ALLOW, DENY, MODIFY, ASK, DEFER, post_invoke DENY) is honored on the LangChain-shaped input path NAT's runtime actually uses (input captured as `modified_args[0]` Pydantic model, not `modified_kwargs`). Catches the silent-bypass class of bug where MODIFY overrides drop or post_invoke redaction crashes on Pydantic strict-fields.

### Smoke #5 — alternate live tests (test_live.py)

```bash
cd "$ACS_REPO/adapters"
uv run python -m unittest tests.integrations.nat.test_live -v
```

Six tests spin up the example Guardian (subprocess, not in-process), construct a real NAT middleware invocation, and assert side-effect counters: a benign function executes, a destructive function is denied, write-to-protected-path is denied, `default_deny: true` blocks on Guardian unreachable, an unanswered handshake blocks by default, and `ACS_STARTUP_POSTURE=proceed` lets the call through with an audit event. `e2e_check.py` (Smoke #3) is the broader assertion surface; `test_live.py` is the minimal unit-style guarantee that the enforcement contract holds.

### Smoke #6 — audit-cause differentiation

Verifies the adapter's audit log distinguishes "Guardian unreachable" (ops issue), "Guardian rejected the envelope" (clock skew, signature, replay), and "adapter exception" (bug). Same fail-posture in all three; different remediation.

Trigger an unreachable Guardian (with `default_deny: true` in the middleware config):

```python
# In a script with NAT installed
from acs.integrations.nat.adapter import ACSMiddleware, ACSMiddlewareConfig
# Point at a dead port to force transport_failure
cfg = ACSMiddlewareConfig(guardian_url="http://127.0.0.1:1/dead", default_deny=True)
mw = ACSMiddleware(cfg)
# Call mw.pre_invoke(context) — observe stderr for:
#   ACS_AUDIT {"acs_audit_event": "decision_failure_fail_closed", "cause": "transport_failure", ...}
```

Send a malformed envelope (Guardian returns -32600 Invalid Request):
```
ACS_AUDIT {"acs_audit_event": "decision_failure_fail_closed", "cause": "malformed_envelope_response", ...}
```

Send a stale request (Guardian returns -32006 timestamp out of window):
```
ACS_AUDIT {"acs_audit_event": "decision_failure_fail_closed", "cause": "timestamp_out_of_window_response", ...}
```

Same `acs_audit_event`; the `cause` field is what operators grep on.

### Smoke #7 — coverage-gap detection

Have your Guardian log the `tool.name` of every `steps/toolCallRequest` it receives. After a typical workflow run, every function the workflow calls should appear there; a function that never appears is not wired (run `acs-nat-wire --check` to locate it).

## Files

- `src/acs/integrations/nat/adapter.py`: the middleware class, its config and the NAT registration. Stdlib + nvidia-nat-core only.
- `src/acs/integrations/nat/wire.py`: comment-preserving YAML installer and linter, installed as `acs-nat-wire` (`--check`, `--write`, `--unwire`). Requires `ruamel.yaml`.
- `tests/integrations/nat/e2e_check.py`: automated end-to-end conformance check (5 scenarios, real `example_guardian` policy, canary-based assertions).
- `docs/nat/workflow.yml.example`: drop-in NAT workflow YAML wiring the middleware.
- `pyproject.toml`'s `nat` extra: runtime deps (`nvidia-nat-core`, `ruamel.yaml`).
- `docs/nat/mapping.md`: NAT lifecycle point → ACS step method table.
- `tests/integrations/nat/test_adapter.py` — integration tests against the real NAT API + the `_extract_arguments` regression set covering the LangChain-shape input bug.
- `tests/integrations/nat/test_live.py` — 5 live workflow tests exercising NAT's `function_middleware_invoke` orchestration end-to-end.
- `tests/integrations/nat/test_dispositions_live.py` — every ACS disposition (ALLOW, DENY, MODIFY, ASK, DEFER, post_invoke DENY) verified on the `modified_args[0]` Pydantic-model path the LangChain react_agent uses in production.
- `tests/integrations/nat/test_envelope_schema.py` — JSON-RPC envelope shape validation against canonical schemas.
- `tests/integrations/nat/test_lifecycle.py`: a run's function and LLM steps add no lifecycle hooks.
- `tests/integrations/nat/test_sessions.py`: each root Runner is one session, through NAT's builder, session manager, request path and Runner.
- `tests/integrations/nat/test_runner_lifecycle.py`: each run's hooks, decisions, failure counts and end, through NAT's Runner.
- `tests/integrations/nat/test_failure_modes.py` — transport failures, signature checks, replay, timestamp skew, JSON-RPC errors.
- `docs/nat/example_payloads.md` — masked real-world payload examples showing the in-process `InvocationContext` shape and what the adapter sends.

The adapter shares `acs.core` (signing, decision rules, JSON-RPC error code → cause mapping) and `acs.client` (handshake cache, audit events, URL allowlist) with the Claude Code and Cursor adapters.

## How it differs from the Claude Code / Cursor adapters

| Aspect | Claude Code / Cursor | NAT |
|---|---|---|
| Interception mechanism | Shell-command-with-stdin-JSON (process spawn per hook) | In-process Python middleware class (`FunctionMiddleware`) |
| Configuration | `settings.json` / `hooks.json` | NAT workflow YAML `middleware:` block |
| Coverage default | Framework-wide (every hook event fires) | Opt-in per attachment point (YAML must wire each) |
| Block mechanism | JSON stdout deny shape, or `exit 2` | Raise `ACSGuardianDenied` (NAT 1.7.0) or set `InvocationAction.SKIP` (NAT dev) |
| Modify mechanism | Updated input field in JSON response | Rewrite each overridden field in `context.modified_args[0]` or `context.modified_kwargs`, wherever NAT reads it / `context.output` |
| Lifecycle coverage | Whatever events the framework's hook surface exposes | Every function NAT wraps — tools, LLMs, retrievers, memory, sub-workflows — **for observability**; enforcement still per-attachment-point |
| Headless CLI for tests | `claude --print` (Claude); none (Cursor — semi-automated) | None needed — NAT runs in-process; `test_live.py` is fully automated |

The shared protocol layer is identical: the Guardian sees the same ACS JSON-RPC shape from every adapter.

## Configuration

### YAML config (the middleware block — `acs-nat-wire` populates this)

| Field | Default | Purpose |
|---|---|---|
| `_type` | `acs_guardian` (required) | Registers the middleware via NAT's `register_middleware` decorator. |
| `guardian_url` | `http://127.0.0.1:8787/acs` | Guardian endpoint. http/https only. |
| `default_deny` | `true` | `true`: a call with no usable decision is denied; `acs-nat-wire` writes `true`, and `--all-fail-open` writes `false`. `false`: the call proceeds, audited, unless the ServerHello declares `on_decision_failure: deny` (most-restrictive-wins); this is the only setting that opts into proceed. Guardian refusals (bad signature, replay, malformed/oversized envelope) always fail closed regardless — input gate blocks, output gate redacts. See spec issue #32. |
| `timeout_s` | `5.0` | Per-request Guardian round-trip timeout. A ServerHello `timeout_config` replaces it for the session, per method where `per_method_ms` names one. |
| `target_function_or_group` | (unset) | Optional metadata label; derives `agent_id` if `ACS_AGENT_ID` env is unset. |

### Environment variables (read by the adapter at runtime)

| Variable | Default | Purpose |
|---|---|---|
| `ACS_HMAC_SECRET_FILE` | (unset) | Path to a 0600 file holding the shared HMAC secret. |
| `ACS_HMAC_SECRET` | (unset) | Inline secret. Less secure (visible in `ps eauxw`). Prefer the file. |
| `ACS_HMAC_KEY_ID` | (unset) | The label that names the secret (§10); the Guardian holds the same one. Required with a secret: a secret without a label refuses the session, and a response signed under another label fails verification. |
| `ACS_AGENT_ID` | derived from `target_function_or_group` | Stable agent identifier sent in `metadata.agent_id`. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |
| `ACS_AUDIT_FILE` | (unset) | Append every `ACS_AUDIT` event to this file (created 0600) in addition to stderr. |
| `ACS_DISABLED` | (unset) | `1` = incident kill switch: every call passes through with no Guardian traffic and an `acs_disabled_bypass` audit event. Read when NAT builds the middleware, so set it before the workflow starts. |
| `ACS_STARTUP_POSTURE` | `refuse` | `proceed` or `refuse`: what a call does in a session with no negotiated Guardian, because its handshake got no answer (§4.1). `proceed` lets the call run, audited, with nothing sent to the Guardian, until the session ends; `refuse` blocks it. The session keeps no negotiated Guardian for its lifetime. Any other value refuses. Read when NAT builds the middleware. |
| `ACS_REQUIRE_PROFILES` | (unset) | Comma-separated conformance profiles the Guardian must accept, such as `acs-core`. When the session's negotiation leaves one out, this hook's steps are refused; the stored record keeps what the Guardian answered, so each hook applies its own setting. |
| `ACS_HANDSHAKE` | `1` | Set to `0` to skip the handshake; the session then counts as unanswered, and `ACS_STARTUP_POSTURE` settles every call. Read when NAT builds the middleware. |

## On-disk state

NAT runs the adapter in-process. The middleware keeps each session's handshake decision in memory and stores it in `~/.cache/acs-adapter-handshake/` like the other adapters, and removes a session's records once its `sessionEnd` has been handled. Each run's session has a fresh `session_id`, so a restarted process opens new sessions. The Guardian-side state (`~/.cache/acs-guardian-state/<sha256(session_id)>.json`) is the same as for the other adapters — chain head + replay set, survives Guardian restart.

## Conformance status

Honest, item-by-item against the ACS-Core baseline in `docs/spec/conformance.md`. Some Core items are conditional or SHOULD-level: `subagentStart` binds subagent-capable clients, MODIFY and `system/ping` are SHOULD, and Wrapped MCP binds sessions that involve MCP. The row notes say how each one applies here.

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ once per session: each root Runner's at its start, and the middleware's own at its first call outside a run; the decision (negotiated, refused, or no answer under `ACS_STARTUP_POSTURE`) holds for the session's lifetime (§4.1) |
| Profiles (`profiles_supported` / `profiles_accepted`) | ✓ always claims `acs-core`: the middleware refuses a session with no usable secret and label before the handshake. A ServerHello accepting a profile the adapter did not claim is not a valid answer, a claimed profile the Guardian leaves out is audited as `profile_not_accepted`, and a hook's `ACS_REQUIRE_PROFILES` turns a left-out profile into a refusal of that hook's steps. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema (`test_envelope_schema.py`) |
| Hook taxonomy (Core minimum set) | ⚠ emitted, but read the enforcement split. **Decision-eligible** coverage: `toolCallRequest` / `toolCallResult`, via the `FunctionMiddleware` path — these can actually block/redact. `sessionStart` (ALLOW / DENY) and `userMessage` are applied too: a deny refuses the run's calls. `agentResponse` and `sessionEnd` are emitted **observation-only** by the lifecycle exporter: a verdict on `agentResponse` is recorded as `unenforceable_decision`, not applied, so they provide audit and trace coverage, **not** enforcement, and should not be counted as decision-eligible Core coverage. ACS-Core requires a subagent-capable client to emit `subagentStart` when it spawns a sub-agent, and a framework with no sub-agent abstraction has nothing to emit. The adapter emits no `subagentStart`: a nested Runner's calls reach the Guardian as tool calls in its parent run's session. The Guardian decides by deployment-defined means whether a NAT deployment counts as subagent-capable. Where sub-workflows act as sub-agents, this is a known gap. See `mapping.md`. Verified in `test_lifecycle.py`. |
| Dispositions | ALLOW / DENY / MODIFY supported on **function-middleware (pre-execution)** hooks (`pre_invoke` for every wrapped function — tools, sub-workflows, LLM, retrievers). ASK/DEFER substituted to DENY at the middleware boundary; deployments wanting pause-and-resume should compose with NAT's HITL middleware (`nat.middleware.hitl`). Of the lifecycle hooks, the run's `steps/sessionStart` and `steps/userMessage` verdicts are applied: a deny refuses the run's calls, and a MODIFY on the input is that deny, recorded as `modify_unsupported`. **`steps/agentResponse` and `steps/sessionEnd` are observation-only**: the exporter reports a NAT event after it fires and cannot veto it, so a verdict on the output is recorded as `unenforceable_decision`, a MODIFY also as `modify_unsupported`. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ |
| Post-tool deny redaction | ✓ `post_invoke` clears `context.output = None` and emits an `ACS_AUDIT` `post_invoke_redacted` event, so the caller never receives a result the Guardian denied (§6.4: the Observed Agent applies the verdict). (NAT's `InvocationContext` is a strict Pydantic model with `validate_assignment=True` — ad-hoc attributes like `acs_post_invoke_redacted` would crash; downstream consumers MUST read the audit event for the redaction signal, not an extra attribute.) |
| SessionContext + published `chain_hash` | ✓ every session's `session_id` is a UUID; Guardian computes rolling chain |
| Replay protection | ✓ Guardian enforcement (REPLAY_DETECTED -32005, TIMESTAMP_OUT_OF_WINDOW -32006); audit cause distinguishes both |
| Baseline integrity (HMAC-SHA256) | ✓ every request and response signed under `ACS_HMAC_KEY_ID`; a middleware with no secret of at least 32 bytes, or no label, refuses its session and denies every call; signed responses verified by adapter (pre_invoke + post_invoke reject SIGNATURE_INVALID) |
| Decision honoring (§6.4) | ✓ NAT's middleware contract guarantees the function will not execute if `pre_invoke` raises or sets SKIP — verified in `test_live.py` (deny tests assert `executed["count"] == 0`); every decision failure emits an `ACS_AUDIT` event under either posture |
| `cause` field on every audit event | ✓ `transport_failure`, `adapter_exception`, `response_signature_invalid`, plus a cause for every §17 JSON-RPC error code (for example `session_refused_response`, `signature_invalid_response`, `replay_detected_response`, `internal_error_response`) with `guardian_error_response` as the catch-all fallback for unknown codes |
| Liveness `system/ping` | ⚠ Guardian-side only. ACS-Core says `system/ping` SHOULD be implemented: the Observed Agent declares it in `methods_implemented` and sends it, and the Guardian answers it (§13). The example Guardian answers ping as an always-allow method outside the chain, replay, and signature checks. The adapter does not declare or send `system/ping`, so a deployment that uses it must name an alternative liveness mechanism in its configuration, such as continuous observed hook traffic. Omitting both is non-conformant. |
| Wrapped MCP `protocols/MCP/*` | ✗ not implemented. ACS-Core requires `protocols/MCP/*` for any session that involves MCP, and MCP `tools/call` MAY instead flow through the generic tool hooks. The adapter emits no `protocols/MCP/*` traffic. The function middleware sees an MCP tool only as an ordinary NAT function, so a wired MCP tool call can reach the Guardian only as `steps/toolCallRequest` and `steps/toolCallResult`. This suite does not exercise that path. No other MCP surface is wrapped, so a NAT session that uses MCP falls short of ACS-Core there. Known limitation. |
| `request_id_ref` correlation | ✓ `post_invoke` sets it to the `request_id` of the call's `toolCallRequest`, a uuid4 kept on the call's invocation context, linking result to request |
| **Coverage of every tool call** | ⚠ **opt-in via YAML wiring** — see [Coverage discipline](#coverage-discipline-the-yaml-only-rule) above. `acs-nat-wire --check` is the CI gate that makes this enforceable. |

## How NAT's defense middleware composes with this

NAT ships `defense_middleware` (in `nvidia-nat-security`) for prompt-injection and PII checks. The ACS adapter does not replace those — it composes with them. A NAT YAML can list multiple middlewares per group, and they execute in order. `acs-nat-wire` always prepends `acs_guardian` to the chain so the policy gate runs before content filters — denied calls short-circuit before expensive content analysis. Recommended composition: ACS first, then NAT defense middleware, then the function.

## Compatibility

The adapter works across multiple NAT releases by feature-detecting the block mechanism:

- **NAT 1.7.0 (public release):** blocks by raising `ACSGuardianDenied` (NAT documents "Raises: Any exception to abort execution" for `pre_invoke`).
- **NAT dev branch (with `InvocationAction.SKIP`):** prefers setting `context.action = InvocationAction.SKIP` (cleaner, no exception in logs). The adapter detects the symbol's availability at import time.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `acs-nat-wire --check` reports gaps after wiring | YAML was edited after acs-nat-wire ran. Re-run `acs-nat-wire --write`. |
| `acs-nat-wire --check` keeps reporting gaps for the same function | That function is defined in Python code, not YAML, so acs-nat-wire can't reach it. Move the definition into YAML, or add `acs_guardian` to its `middleware` list in code; until then its calls reach the Guardian neither as a decision nor as an observation. |
| `acs-nat-wire` errors out with "ruamel.yaml" missing | Install the `nat` extra: `pip install "$ACS_REPO/adapters[nat]"`. |
| NAT runs functions as if no Guardian exists | NAT loaded the workflow before `acs-nat-wire --write` ran. **Restart your NAT process.** |
| Every call gets denied | Likely the Guardian is down: a session whose handshake gets no answer refuses its calls unless `ACS_STARTUP_POSTURE=proceed`, and a call with no usable decision is denied unless the YAML sets `default_deny: false`. Check the Guardian process is running. |
| Adapter says `SecretFilePermissionsError` | HMAC secret file is mode > 0600. `chmod 600 ~/.acs/hmac.key`. |
| Guardian returns `-32004 SIGNATURE_INVALID` | Adapter and Guardian aren't reading the same secret. `cat ~/.acs/hmac.key` on both sides should match. Audit log shows `cause=signature_invalid_response`. |
| Guardian returns `-32005 REPLAY_DETECTED` | Same `request_id` sent twice. Audit log shows `cause=replay_detected_response`. Usually a retry loop bug. |
| Guardian returns `-32006 TIMESTAMP_OUT_OF_WINDOW` | Clock skew between adapter and Guardian > 5 minutes. Sync time. Audit log shows `cause=timestamp_out_of_window_response`. |
| `lifecycle_subscribe_failed` audit event | No active NAT Context (called middleware directly outside a workflow). Test-only path; harmless in production. |

Everything the adapter does that's not policy decision-making is audited on stderr as a JSON line prefixed `ACS_AUDIT`. The `cause` field tells you which failure mode fired.

## Running the tests

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --extra nat --group test
uv run python -m unittest discover -s tests/integrations/nat -t . -v
```

If NAT is not installed, NAT-dependent test classes are skipped cleanly (`@unittest.skipUnless`).
