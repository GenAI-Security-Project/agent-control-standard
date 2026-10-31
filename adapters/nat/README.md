# ACS adapter: NVIDIA Agent Toolkit (NAT)

A drop-in middleware that wires [NVIDIA NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) to an ACS Guardian. No agent code changes; YAML configuration only.

## How it works

NAT exposes a `FunctionMiddleware` abstraction that wraps any function — tools, sub-workflows, LLM calls, retrievers, memory operations — at the call site. This adapter is that middleware. On every call NAT routes through a wired attachment point, the adapter:

1. Receives the `InvocationContext` (function name, arguments, output) from NAT's middleware pipeline.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET` or `ACS_HMAC_SECRET_FILE`).
4. POSTs to the Guardian.
5. Verifies the response signature and the JSON-RPC error/result shape.
6. Applies the verdict: `allow` passes through; `deny` raises `ACSGuardianDenied` (or sets `InvocationAction.SKIP` on NAT releases that expose it); `modify` mutates `context.modified_kwargs`; `ask`/`defer` substitute to deny at the middleware boundary.
7. Records a `steps/toolCallResult` envelope in `post_invoke` and redacts the output on deny.

The handshake/hello fires once per session, cached in process state so subsequent events skip the round-trip.

Independently of the middleware path, the adapter subscribes to NAT's `IntermediateStepManager` for `WORKFLOW_START` / `WORKFLOW_END` events and emits `steps/sessionStart` + `steps/userMessage` (on workflow start with input) and `steps/agentResponse` + `steps/sessionEnd` (on workflow end with output). The observer is auto-subscribed on the first `pre_invoke` call. **The lifecycle stream is observation-only; it cannot block calls.** Enforcement is the middleware path's job.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. NAT provides this through `function_middleware_invoke`: `pre_invoke` must complete before `call_next(...)` runs, so a Guardian deny (whether surfaced as `ACSGuardianDenied` or `InvocationAction.SKIP`) is applied before the wrapped function would execute. Verified in `tests/test_live.py` (deny tests assert `executed["count"] == 0`).

## Install — five steps

You need: a running Guardian, a shared HMAC secret, and a NAT `workflow.yml` with `acs_guardian` wired at every attachment point. `wire.py` does step 3 for you and `--check` keeps it true forever after.

Commands below assume `$ACS_REPO` points at your local clone of `GenAI-Security-Project/agent-control-standard`. Export it once:

```bash
export ACS_REPO=/path/to/your/clone   # e.g., $HOME/code/ACS
```

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
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key \
  python3 "$ACS_REPO/adapters/example-guardian/example_guardian.py" \
  --port 8787
```

Keep this terminal open. You should see `[guardian] listening on 127.0.0.1:8787`.

### 3. Wire `workflow.yml`

```bash
cd /path/to/your/project   # where your workflow.yml lives
pip install nvidia-nat-core ruamel.yaml

# Preview the change (dry-run, no file write)
python3 "$ACS_REPO/adapters/nat/wire.py" \
  --workflow=workflow.yml \
  --guardian-url=http://127.0.0.1:8787/acs \
  --default-deny

# Apply (timestamped backup at workflow.yml.bak.<timestamp>)
python3 "$ACS_REPO/adapters/nat/wire.py" \
  --workflow=workflow.yml \
  --guardian-url=http://127.0.0.1:8787/acs \
  --default-deny \
  --write
```

`wire.py` walks every attachment point in your YAML and inserts `acs_guardian`:

| YAML location | What `wire.py` does |
|---|---|
| top-level `middleware:` block | adds the `acs_guardian:` definition with your guardian_url, default_deny, timeout_s |
| `workflow.middleware` | prepends `acs_guardian` (policy gate runs before content filters) |
| every `function_groups.*.middleware` | prepends `acs_guardian` |
| every `functions.*.middleware` that overrides its group | prepends `acs_guardian` |

Every line we add carries a `# acs-adapter-wired` marker. Re-running is a no-op. `--unwire --write` removes exactly what we added and nothing else.

To remove later: `python3 wire.py --workflow=workflow.yml --unwire --write`.

### 4. Restart your NAT process

NAT loads `workflow.yml` at startup. Existing processes keep their pre-wiring config until restart.

### 5. Verify the install

```bash
# Lint — exits non-zero if any attachment point is missing acs_guardian
python3 "$ACS_REPO/adapters/nat/wire.py" --workflow=workflow.yml --check

# Run the live tests against your installed adapter + Guardian
cd "$ACS_REPO/adapters/nat"
python3 -m unittest tests.test_live -v
```

`wire.py --check` is the load-bearing CI gate — see [Coverage discipline](#coverage-discipline-the-yaml-only-rule) below.

## Prerequisites

- **NAT installed** — `pip install nvidia-nat-core` (>=1.7.0)
- **Python 3.10+** with `ruamel.yaml`, `jsonschema`, `rfc8785` — `pip install -r requirements.txt -r ../requirements-test.txt`
- **Canonical ACS schemas** — the in-repo copy at `specification/v0.1.0/` is the default, so no setup is needed when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Coverage discipline (the YAML-only rule)

NAT's middleware fires per-attachment-point: workflow, function_groups, and individual functions with their own `middleware:` block. If an attachment point is not wired, every call routed through it bypasses the Guardian. This is a structural property of NAT, not a bug in the adapter — Cursor and Claude Code get framework-wide interception for free; NAT does not.

**The three rules for ACS-conformant NAT deployments:**

1. **Define every tool in YAML.** Functions registered at runtime in Python code (not in `workflow.yml`) cannot be wired by `wire.py` and will not be gated by the middleware path. If you need full gating, every function lives in the YAML.
2. **Run `wire.py --check` in CI** on every workflow YAML you ship. It exits non-zero if any attachment point is missing `acs_guardian`. Treat that as a build failure.
3. **Re-run `wire.py --write` after any YAML edit** that adds or restructures `function_groups`, `workflow`, or individual `functions`. The marker comments make it idempotent.

What this gives you: **the same hard-stop guarantee Cursor's `failClosed: true` gives.** The middleware fires synchronously *before* the function executes; a Guardian deny raises `ACSGuardianDenied` (or sets `InvocationAction.SKIP`) and NAT does not call the function.

**Backstop for the dynamic-registration caveat:** the adapter also subscribes to NAT's `IntermediateStepManager`, which fires for every call NAT routes regardless of middleware wiring. The Guardian therefore *observes* every call (audit trail + trace), even ones the middleware path missed. Subscribers can't *block* — they're notification-only — so this is detection, not enforcement. Audit Guardian logs for `toolCallRequest` envelopes that arrived via lifecycle but never via middleware; that delta is your coverage gap.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (~10s)

```bash
cd "$ACS_REPO/adapters"
nat/.nat-venv/bin/python run_conformance.py nat
# Runs the shared Guardian and _common checks, then NAT's suite.
```

Use an interpreter with `nvidia-nat-core` installed. A missing NAT dependency produces an unexpected skip and fails the command.

### Smoke #2 — `wire.py --check` (CI gate)

```bash
python3 "$ACS_REPO/adapters/nat/wire.py" \
  --workflow=/path/to/your/workflow.yml --check
```

Exit 0 → every attachment point in the YAML is wired with `acs_guardian`. Exit 1 → at least one gap; the output names the file path, line number, and which kind of attachment point (workflow / function_group / function). Wire this into CI as a build gate.

### Smoke #3 — end-to-end conformance (e2e_check.py)

```bash
cd "$ACS_REPO/adapters/nat"
python3 e2e_check.py
```

Five fully-automated scenarios against the **real `example_guardian.evaluate_step` policy** (same one the production example Guardian uses), wired through a recording Guardian so the script can assert on every wire envelope:

| # | Scenario | What it verifies |
|---|---|---|
| 1 | ALLOW | benign Bash function executes; return value flows back; handshake + toolCallRequest received; every envelope HMAC-signed; every envelope validates against the canonical ACS JSON Schema |
| 2 | DESTRUCTIVE | `rm -rf` on a victim dir with a canary file → real policy denies via `destructive_command` regex; `ACSGuardianDenied` raised; **canary file still on disk** (counterproof — the unit-test counter alone can false-pass if the function returns early for any reason) |
| 3 | READ-TOOL | different tool, same wire contract; arguments wrapped per `tool-call-request.json:26-37`; envelope.arguments.file_path.value matches probe path |
| 4 | HANDSHAKE-ONCE | 3 sequential invocations on the same middleware → exactly 1 `handshake/hello` envelope arrived |
| 5 | LIFECYCLE | `WORKFLOW_START`/`WORKFLOW_END` pushed through `IntermediateStepManager` → emits `steps/sessionStart` + `steps/userMessage` + `steps/agentResponse` + `steps/sessionEnd` envelopes with the workflow input/output in the payload (the observability backstop must actually backstop) |

The final line is `ACS-CORE SMOKE PASS (nat)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

Schema validation is against the canonical `request-envelope.json` from `ACS_SPEC_DIR` — adapter ↔ spec, not adapter ↔ test fixture. A drift between adapter and the spec fails this check, not the other way around.

### Smoke #4 — disposition matrix (test_dispositions_live.py)

```bash
cd "$ACS_REPO/adapters/nat"
python3 -m unittest tests.test_dispositions_live -v
```

End-to-end verification that EVERY ACS disposition (ALLOW, DENY, MODIFY, ASK, DEFER, post_invoke DENY) is honored on the LangChain-shaped input path NAT's runtime actually uses (input captured as `modified_args[0]` Pydantic model, not `modified_kwargs`). Catches the silent-bypass class of bug where MODIFY overrides drop or post_invoke redaction crashes on Pydantic strict-fields.

### Smoke #5 — alternate live tests (test_live.py)

```bash
cd "$ACS_REPO/adapters/nat"
python3 -m unittest tests.test_live -v
```

Five tests spin up the example Guardian (subprocess, not in-process), construct a real NAT middleware invocation, and assert side-effect counters: a benign function executes, a destructive function is denied, write-to-protected-path is denied, fail-closed blocks on Guardian unreachable, fail-open lets the call through with an audit event. `e2e_check.py` (Smoke #3) is the broader assertion surface; `test_live.py` is the minimal unit-style guarantee that the enforcement contract holds.

### Smoke #6 — audit-cause differentiation

Verifies the adapter's audit log distinguishes "Guardian unreachable" (ops issue), "Guardian rejected the envelope" (clock skew, signature, replay), and "adapter exception" (bug). Same fail-posture in all three; different remediation.

Trigger an unreachable Guardian (with `default_deny: true` in the middleware config):

```python
# In a script with NAT installed
from acs_adapter import ACSMiddleware, ACSMiddlewareConfig
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

Have your Guardian log every received envelope's `method` and the source (middleware-routed via `steps/toolCallRequest` vs lifecycle-routed via `steps/toolCallRequest` from `WORKFLOW_START`). After a typical workflow run, every tool call should appear in both streams. A call appearing in lifecycle but not middleware → that function is not wired (re-run `wire.py --check` to locate it).

## Files

- `acs_adapter.py` — the middleware class + config + NAT registration. Stdlib + nvidia-nat-core only.
- `wire.py` — comment-preserving YAML installer + linter (`--check`, `--write`, `--unwire`). Requires `ruamel.yaml`.
- `e2e_check.py` — automated end-to-end conformance check (5 scenarios, real `example_guardian` policy, canary-based assertions).
- `workflow.yml.example` — drop-in NAT workflow YAML wiring the middleware.
- `requirements.txt` — runtime deps (`nvidia-nat-core`, `ruamel.yaml`).
- `mapping.md` — NAT lifecycle point → ACS step method table.
- `tests/test_adapter.py` — integration tests against the real NAT API + the `_extract_arguments` regression set covering the LangChain-shape input bug.
- `tests/test_live.py` — 5 live workflow tests exercising NAT's `function_middleware_invoke` orchestration end-to-end.
- `tests/test_dispositions_live.py` — every ACS disposition (ALLOW, DENY, MODIFY, ASK, DEFER, post_invoke DENY) verified on the `modified_args[0]` Pydantic-model path the LangChain react_agent uses in production.
- `tests/test_envelope_schema.py` — JSON-RPC envelope shape validation against canonical schemas.
- `tests/test_lifecycle.py` — `IntermediateStepManager` subscription emits the 6-minimum hooks.
- `tests/test_failure_modes.py` — transport failures, signature checks, replay, timestamp skew, JSON-RPC errors.
- `tests/example_payloads.md` — masked real-world payload examples showing the in-process `InvocationContext` shape and what the adapter sends.

The adapter shares `adapters/_common/` with the Claude Code and Cursor adapters (signing, handshake cache, audit events, URL allowlist, JSON-RPC error code → cause mapping).

## How it differs from the Claude Code / Cursor adapters

| Aspect | Claude Code / Cursor | NAT |
|---|---|---|
| Interception mechanism | Shell-command-with-stdin-JSON (process spawn per hook) | In-process Python middleware class (`FunctionMiddleware`) |
| Configuration | `settings.json` / `hooks.json` | NAT workflow YAML `middleware:` block |
| Coverage default | Framework-wide (every hook event fires) | Opt-in per attachment point (YAML must wire each) |
| Block mechanism | JSON stdout deny shape, or `exit 2` | Raise `ACSGuardianDenied` (NAT 1.7.0) or set `InvocationAction.SKIP` (NAT dev) |
| Modify mechanism | Updated input field in JSON response | Mutate `context.modified_kwargs` / `context.output` |
| Lifecycle coverage | Whatever events the framework's hook surface exposes | Every function NAT wraps — tools, LLMs, retrievers, memory, sub-workflows — **for observability**; enforcement still per-attachment-point |
| Headless CLI for tests | `claude --print` (Claude); none (Cursor — semi-automated) | None needed — NAT runs in-process; `test_live.py` is fully automated |

The shared protocol layer is identical: the Guardian sees the same ACS JSON-RPC shape from every adapter.

## Configuration

### YAML config (the middleware block — `wire.py` populates this)

| Field | Default | Purpose |
|---|---|---|
| `_type` | `acs_guardian` (required) | Registers the middleware via NAT's `register_middleware` decorator. |
| `guardian_url` | `http://127.0.0.1:8787/acs` | Guardian endpoint. http/https only. |
| `default_deny` | `false` | Fail-open with audit (§6.4 default). Set `true` for fail-closed. The ServerHello's `on_decision_failure: deny` also flips it (most-restrictive-wins). Guardian refusals (bad signature, replay, malformed/oversized envelope) always fail closed regardless — input gate blocks, output gate redacts. See spec issue #32. |
| `timeout_s` | `5.0` | Per-request Guardian round-trip timeout. |
| `session_id` | (auto, per-process) | UUID; auto-generated and stable for the process lifetime. |
| `target_function_or_group` | (unset) | Optional metadata label; derives `agent_id` if `ACS_AGENT_ID` env is unset. |

### Environment variables (read by the adapter at runtime)

| Variable | Default | Purpose |
|---|---|---|
| `ACS_HMAC_SECRET_FILE` | (unset) | Path to a 0600 file holding the shared HMAC secret. |
| `ACS_HMAC_SECRET` | (unset) | Inline secret. Less secure (visible in `ps eauxw`). Prefer the file. |
| `ACS_AGENT_ID` | derived from `target_function_or_group` | Stable agent identifier sent in `metadata.agent_id`. |
| `ACS_SESSION_ID` | derived | Overrides the auto-generated session_id. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |

## On-disk state

NAT runs the adapter in-process; there is no per-event subprocess state to persist. The handshake is cached in the middleware instance's memory for the process lifetime; restarting the process triggers a fresh handshake on the next call. The Guardian-side state (`~/.cache/acs-guardian-state/<sha256(session_id)>.json`) is the same as for the other adapters — chain head + replay set, survives Guardian restart.

## Conformance status

Honest, item-by-item against `docs/spec/conformance.md`. (PR #21 — open, not in this branch — proposes relaxing some items to SHOULD/conditional; the row notes say which. Against this branch's spec text those items remain as written.)

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ on first `pre_invoke`; cached per session in process memory |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema (`test_envelope_schema.py`) |
| Hook taxonomy (Core minimum set) | ⚠ emitted, but read the enforcement split. **Decision-eligible** coverage: `toolCallRequest` / `toolCallResult`, via the `FunctionMiddleware` path — these can actually block/redact. The other four — `sessionStart`, `userMessage`, `agentResponse`, `sessionEnd` — are emitted **observation-only** from the `IntermediateStepManager` subscription (fire-and-forget; the Guardian's verdict is not applied), so they provide audit/trace coverage, **not** enforcement, and should not be counted as decision-eligible Core coverage. PR #21 (open; not in this branch) proposes a conditional `subagentStart` floor for subagent-capable clients. If that proposal lands, NAT's lack of a distinct spawn boundary needs an explicit applicability decision: the condition is vacuous only when sub-workflows are genuinely not distinguishable at the middleware seam. See `mapping.md`. Verified in `test_lifecycle.py`. |
| Dispositions | ALLOW / DENY / MODIFY supported on **function-middleware (pre-execution)** hooks (`pre_invoke` for every wrapped function — tools, sub-workflows, LLM, retrievers). ASK/DEFER substituted to DENY at the middleware boundary; deployments wanting pause-and-resume should compose with NAT's HITL middleware (`nat.middleware.hitl`). **Lifecycle hooks from the `IntermediateStepManager` subscription (`steps/sessionStart`, `steps/userMessage`, `steps/agentResponse`, `steps/sessionEnd`) are observation-only** — subscription callbacks cannot veto a NAT event after it fires. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ |
| Post-tool deny redaction | ✓ `post_invoke` clears `context.output = None` and emits an `ACS_AUDIT` `post_invoke_redacted` event per §6.4 output-redaction gate. (NAT's `InvocationContext` is a strict Pydantic model with `validate_assignment=True` — ad-hoc attributes like `acs_post_invoke_redacted` would crash; downstream consumers MUST read the audit event for the redaction signal, not an extra attribute.) |
| SessionContext + published `chain_hash` | ✓ session_id coerced to UUID; Guardian computes rolling chain |
| Replay protection | ✓ Guardian enforcement (REPLAY_DETECTED -32005, TIMESTAMP_OUT_OF_WINDOW -32006); audit cause distinguishes both |
| Baseline integrity (HMAC-SHA256) | ✓ when `ACS_HMAC_SECRET[_FILE]` is set; signed responses verified by adapter (pre_invoke + post_invoke reject SIGNATURE_INVALID) |
| Decision honoring (§6.4) | ✓ NAT's middleware contract guarantees the function will not execute if `pre_invoke` raises or sets SKIP — verified in `test_live.py` (deny tests assert `executed["count"] == 0`); fail-open emits `ACS_AUDIT` events |
| `cause` field on every audit event | ✓ `transport_failure`, `adapter_exception`, `response_signature_invalid`, plus 7 JSON-RPC error code → cause mappings (`unsupported_version_response`, `provenance_required_response`, `signature_invalid_response`, `replay_detected_response`, `timestamp_out_of_window_response`, `malformed_envelope_response`, `parse_error_response`) with `guardian_error_response` as the catch-all fallback for unknown codes |
| Liveness `system/ping` | ✓ Guardian-side only — the adapter does NOT emit system/ping; liveness is the Guardian answering probes (§13). |
| `request_id_ref` correlation | ✓ `post_invoke` populates with a deterministic uuid5 derived from session + function + kwargs, linking result to request |
| **Coverage of every tool call** | ⚠ **opt-in via YAML wiring** — see [Coverage discipline](#coverage-discipline-the-yaml-only-rule) above. `wire.py --check` is the CI gate that makes this enforceable. |

## How NAT's defense middleware composes with this

NAT ships `defense_middleware` (in `nvidia-nat-security`) for prompt-injection and PII checks. The ACS adapter does not replace those — it composes with them. A NAT YAML can list multiple middlewares per group, and they execute in order. `wire.py` always prepends `acs_guardian` to the chain so the policy gate runs before content filters — denied calls short-circuit before expensive content analysis. Recommended composition: ACS first, then NAT defense middleware, then the function.

## Compatibility

The adapter works across multiple NAT releases by feature-detecting the block mechanism:

- **NAT 1.7.0 (public release):** blocks by raising `ACSGuardianDenied` (NAT documents "Raises: Any exception to abort execution" for `pre_invoke`).
- **NAT dev branch (with `InvocationAction.SKIP`):** prefers setting `context.action = InvocationAction.SKIP` (cleaner, no exception in logs). The adapter detects the symbol's availability at import time.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `wire.py --check` reports gaps after wiring | YAML was edited after wire.py ran. Re-run `wire.py --write`. |
| `wire.py --check` keeps reporting gaps for the same function | That function is defined in Python code, not YAML. wire.py can't reach it. Move the definition into YAML, or accept the coverage gap and rely on the lifecycle-stream backstop. |
| `wire.py` errors out with "ruamel.yaml" missing | `pip install ruamel.yaml`. |
| NAT runs functions as if no Guardian exists | NAT loaded the workflow before `wire.py --write` ran. **Restart your NAT process.** |
| Every call gets denied | Likely `default_deny: true` in middleware config + Guardian down. Check the Guardian process is running. |
| Adapter says `SecretFilePermissionsError` | HMAC secret file is mode > 0600. `chmod 600 ~/.acs/hmac.key`. |
| Guardian returns `-32004 SIGNATURE_INVALID` | Adapter and Guardian aren't reading the same secret. `cat ~/.acs/hmac.key` on both sides should match. Audit log shows `cause=signature_invalid_response`. |
| Guardian returns `-32005 REPLAY_DETECTED` | Same `request_id` sent twice. Audit log shows `cause=replay_detected_response`. Usually a retry loop bug. |
| Guardian returns `-32006 TIMESTAMP_OUT_OF_WINDOW` | Clock skew between adapter and Guardian > 5 minutes. Sync time. Audit log shows `cause=timestamp_out_of_window_response`. |
| `lifecycle_subscribe_failed` audit event | No active NAT Context (called middleware directly outside a workflow). Test-only path; harmless in production. |

Everything the adapter does that's not policy decision-making is audited on stderr as a JSON line prefixed `ACS_AUDIT`. The `cause` field tells you which failure mode fired.

## Running the tests

```bash
# Tests that don't need NAT (schema, wire format) run anywhere
cd "$ACS_REPO/adapters/nat"
python3 -m unittest discover tests

# Tests that drive real NAT need it installed
pip install -r requirements.txt
python3 -m unittest tests.test_live -v
```

If NAT is not installed, NAT-dependent test classes are skipped cleanly (`@unittest.skipUnless`).
