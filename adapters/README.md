# ACS Adapters

Reference implementations that wire popular agent frameworks to an ACS Guardian. The goal: a framework adopts ACS through **configuration only**, with no agent code changes.

## What is a Guardian?

The **Guardian** is the policy enforcement point: a long-running HTTP service that receives every ACS envelope from the adapter, evaluates it against the deployment's policy, and returns one of five dispositions (allow / deny / modify / ask / defer). It's the "decider"; the adapter is the "messenger."

Two roles in any deployment:

- **Production Guardian** — your real policy engine. Typically OPA/Rego, Cedar, or a vendor SDK plugged in behind an HTTP server that speaks the ACS wire protocol. The adapter doesn't care what's inside; only the wire contract matters.
- **`example-guardian/example_guardian.py`** in this repo — a teaching artifact and test substrate. Implements the full wire protocol (handshake, envelope schema validation, HMAC signing, rolling chain, replay protection, skew rejection, dispositions, `system/ping`) but with a deliberately tiny deterministic policy: denies a short list of destructive Bash patterns + writes to system paths, allows everything else. Useful for local testing; **not for production**.

Production deployments swap the policy code in the example Guardian's `evaluate(method, params)` function with their real engine and keep the wire-protocol scaffolding.

Running the Guardian — terminal window, `launchd`, `systemd`, container — is the operator's responsibility. The adapter expects it to be reachable at `$ACS_GUARDIAN_URL`; if it isn't, the §6.4 fail posture applies and an `ACS_AUDIT` event is emitted.

## ACS v0.1.0 emission-conformance check

**What this proves — and what it does not.** This suite proves **emission conformance**: the reference adapters, driven through their real production entry points, emit schema-valid, signed ACS v0.1.0 Core traffic and honor the decisions it tests. It is **not** a requirement-by-requirement audit of every ACS-Core MUST — `docs/spec/conformance.md` and the sections it cites contain far more normative requirements (handshake/negotiation edge cases, full decision semantics, two-sided live payload validation, hook-completeness, Wrapped MCP) than are checked here. A full ACS-Core deployment-conformance claim also spans the Guardian, the framework wiring, and production configuration — not the adapter alone. That larger program is tracked as a separate milestone (requirement ledger + behavioral tests); do not read a green run here as "ACS-Core conformant."

Known limitations kept in view: Cursor's real-framework wiring is a manual GUI procedure; Wrapped MCP is validated for namespace shape only, not full wrapping. PR #21 proposes relaxing its Core status to SHOULD/MAY, but this branch does **not** contain that change; against the current branch specification, Wrapped MCP remains a Core gap. Milestone #33 tracks the reference-stack side.

One authoritative command runs the shared Guardian checks, shared-library tests, and the adapter suites you name. At least one platform is required; there is no implicit run-all default. Name one, two, or all three platforms in any order:

```bash
cd adapters

# One platform
python3 run_conformance.py cursor

# Two platforms
python3 run_conformance.py claude cursor

# All platforms. Use an interpreter with nvidia-nat-core when NAT is
# selected, or the NAT suite's skips count as unexpected and fail.
nat/.nat-venv/bin/python run_conformance.py claude cursor nat
```

`claude-code` is also accepted as an alias for `claude`. Repeating a platform does not run it twice. Guardian and `_common` checks run once for every command, regardless of the platform selection.

It prints every skip by name + reason and fails on any failure **or any _unexpected_ skip** — a skip not on the exact allowlist. The allowlist tolerates only real-framework smoke tests that need an interactive product no runner has (the Cursor GUI, an authenticated `claude` CLI); a dependency-gated test (NAT when `nvidia-nat-core` is installed) that silently skips is a failure, never green. `--strict` additionally fails on the allowlisted skips too, for a fully-provisioned gate.

Under the hood it drives two complementary layers:

**Scope of the single-file Core suite:** `test_acs_core_conformance.py` drives the **claude-code and cursor** adapters end-to-end (its live-disposition and prompt-gate classes spawn those two subprocesses). **NAT is covered separately**: its conformance evidence lives in `adapters/nat/tests/` (emission, live dispositions, lifecycle, security — run against the real `nvidia-nat-core`) and runs in CI's `authoritative` and NAT matrix jobs, which install the NVIDIA runtime. Adding NAT to the single-file Core suite is a tracked follow-up — it needs in-process middleware harnessing where the suite today drives shell subprocesses, and the conformance CI job would then install the NVIDIA runtime too.

**1. Guardian checks** — `python -m unittest test_acs_core_conformance` exercises the Core requirements enumerated in `docs/spec/conformance.md`'s summary (handshake incl. forward-compat + malformed-ClientHello refusal, envelope shape, the minimum hook set, dispositions, rolling chain, replay + skew rejection, HMAC-SHA256 baseline incl. signed errors, decision honoring + fail-open audit + audit-cause differentiation) **plus reference-stack coverage of SHOULD/conditional items** (MODIFY, system/ping, the `protocols/MCP/*` namespace shape). These are the summary-level Core checks, **not** an enumeration of all normative MUST occurrences in the linked sections — the requirement-by-requirement ledger is the separate milestone. A deployment that legitimately omits a SHOULD/conditional item is not non-conformant for failing those specific tests. Each test docstring quotes the spec line it falsifies, and a `CitationGuard` class pins every cited line so spec edits that move or rewrite them turn the suite red.

**2. Emission conformance** — each adapter's `tests/test_emission.py` runs the **production adapter** (the real subprocess for Claude Code / Cursor; the real `pre_invoke` / `post_invoke` / lifecycle-observer middleware for NAT) against a validating **CaptureGuardian** and asserts the *exact bytes it sends* pass the canonical schemas. Two layers of checks:

- *Per-event:* each Core method is emitted exactly once, envelope + payload validate against the canonical schemas, and per-envelope invariants hold — UUID `request_id`, RFC 3339 `timestamp`, `agent_id`/`session_id`/`platform` metadata, the `{value: …}` argument wrapper, and an **independently-recomputed** HMAC-SHA256 signature (a from-scratch HKDF+HMAC+JCS verifier in `capture_guardian.py`, *not* the adapter's own `acs_common` code, so a shared signing+verifying bug can't pass both sides; pinned by a frozen known-answer vector).
- *Per-session* (`*SequentialSession`, one Guardian + one handshake cache across an ordered sequence): the handshake fires exactly once, all `request_id`s are unique, `toolCallResult.request_id_ref` links back to its `toolCallRequest`, and — the real honesty check — the handshake's advertised `methods_implemented` **equals** the set of methods **actually emitted in the run** (equality, not just subset: catches over- *and* under-advertising), not merely methods that happen to have a schema.

Breaking any adapter's method mapping, envelope/payload field, or signing turns the suite red against the schema files themselves. The oracle is proven non-vacuous by `_common/tests/test_capture_guardian.py` (feed it broken envelopes, assert it flags each defect class + the signature KAT). Schemas load from the in-repo `specification/v0.1.0/` by default (`ACS_SPEC_DIR` overrides); missing schemas are a hard FAIL. Format checking (`uuid`, `date-time`) is enforced via `rfc3339-validator`.

**Where each adapter's emission is actually exercised:** Claude Code and Cursor run headless here and in CI (real subprocess). NAT's emission tests drive the real middleware and require `nvidia-nat-core`; they run in the CI `authoritative` job (which installs it) and `skipUnless` it locally — a skip is never counted as a pass (`run_conformance.py nat` and the CI job both fail on an unexpected NAT skip). Cursor's *end-to-end framework* wiring (real Cursor GUI in the loop) remains a manual procedure in `tests/live_verification.md`; the emission suite proves the adapter, the manual test proves the wiring.

**Wrapped MCP caveat.** The suite verifies the wire-format *shape* of `protocols/MCP/*` only (a harness-built envelope validates, the Guardian returns a structured response, no crash). Nothing here demonstrates real MCP **wrapping**: the adapters flatten MCP onto `steps/toolCallRequest`/`Result` (Cursor's `beforeMCPExecution`, Claude's `mcp__*` tools) rather than emitting the wrapped `protocols/MCP/*` form, and the reference Guardian does not implement intact wrapping, version negotiation, or request/result correlation for it. **Do not read any of this as "we wrap MCP."** Whether Wrapped MCP belongs in ACS-Core at all — vs. generic tool-call collapsing being explicitly conformant — is under decision in PR #21, which proposes relaxing it to SHOULD/MAY (that change is **not** in this branch, so against this branch's spec text the collapse remains a Core gap); the reference-stack side is tracked in milestone #33. A green run here doesn't settle it either way. See `test_acs_core_conformance.py::Core10_WrappedMcp`.

## How adapters work

The adapters are **translators**. Each one speaks its framework's hook protocol on one side and ACS JSON-RPC on the other. The framework's agent code is untouched. The Guardian's policy code is untouched. The adapter is the bilingual layer between them.

### The general pattern (same for all three adapters)

For each event the framework fires:

```
   framework                  adapter                   Guardian
      │                          │                         │
      │  hook event (framework   │                         │
      │  native JSON / call)     │                         │
      │ ───────────────────────► │                         │
      │                          │  ACS JSON-RPC request   │
      │                          │ ──────────────────────► │
      │                          │                         │   evaluate
      │                          │                         │   policy
      │                          │  ACS decision           │
      │                          │ ◄────────────────────── │
      │   decision (framework    │                         │
      │   native response shape) │                         │
      │ ◄─────────────────────── │                         │
      │                          │                         │
      ▼                          ▼                         ▼
   applies the                                          appends
   decision                                           audit chain
```

Six steps:

1. Framework fires its hook with a payload in its own format.
2. Adapter receives that payload, translates to an ACS JSON-RPC request.
3. Adapter POSTs to the Guardian endpoint.
4. Guardian evaluates against policy, returns an ACS decision (`allow` / `deny` / `modify` / `ask` / `defer`).
5. Adapter translates that decision back to whatever the framework expects to receive.
6. Framework applies the decision (run / block / modify the action).

### Concrete walkthrough: Claude Code, ALLOW path

You ask Claude Code to `echo hello`.

For brevity, this walkthrough shows the envelope SHAPES and omits the
HMAC-SHA256 `signature` block on each envelope and the once-per-session
`handshake/hello` round-trip that precedes the first content-bearing
event. Both are present in real envelopes — run `python3 adapters/claude-code/e2e_check.py`
to see verbatim envelopes including signatures.

**Step 1.** Claude Code is about to call its Bash tool. Before it runs, Claude Code's hook system fires `PreToolUse`. Your `settings.json` configures `PreToolUse` to run `python3 acs_adapter.py`. Claude Code spawns that process and pipes the event to stdin:

```json
{
  "session_id": "abc-123",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "echo hello"},
  "tool_use_id": "...",
  "cwd": "/tmp/...",
  "permission_mode": "default"
}
```

**Step 2.** The adapter reads that JSON, builds an ACS JSON-RPC request conforming to v0.1.0 `request-envelope.json` and `hooks/tool-call-request.json`:

```json
{
  "jsonrpc": "2.0",
  "id": "<uuid>",
  "method": "steps/toolCallRequest",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "<uuid>",
    "timestamp": "2026-06-17T12:34:56.789Z",
    "metadata": {
      "agent_id": "claude-code:a1b2c3d4",
      "session_id": "abc-123",
      "cwd": "/tmp/...",
      "platform": "claude-code"
    },
    "payload": {
      "tool": {"name": "Bash"},
      "arguments": {"command": {"value": "echo hello"}}
    }
  }
}
```

Notice the shape: `acs_version` / `request_id` / `timestamp` / `metadata` live inside `params`, not at the envelope root (the envelope schema's `additionalProperties: false` rejects unknown top-level keys). Each tool argument is wrapped as `{value: ...}` so ACS-Provenance can attach provenance per-argument without changing the schema.

**Step 3.** The adapter POSTs to the Guardian endpoint (`http://127.0.0.1:8787/acs`).

**Step 4.** The Guardian evaluates. Our example Guardian's deterministic policy: `echo hello` doesn't match the destructive-Bash regex. Returns a response conforming to `response-envelope.json`:

```json
{
  "jsonrpc": "2.0",
  "id": "<uuid>",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "<uuid>",
    "decision": "allow",
    "chain_hash": "..."
  }
}
```

**Step 5.** The adapter translates back to Claude Code's expected shape:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
```

**Step 6.** Claude Code reads stdout, sees `permissionDecision: "allow"`, executes the Bash tool. You see `hello` printed.

**What this costs, measured honestly.** For the shell-spawned adapters (Claude Code, Cursor), the dominant cost is NOT the Guardian round-trip — it's the per-event Python process spawn: interpreter start plus imports. Measured on an M-series MacBook (warm cache, local Guardian): ~60–90 ms per hook event end-to-end, of which the Guardian's policy evaluation is single-digit milliseconds. Your numbers will differ with hardware and Python version; measure with `/usr/bin/time` before quoting any. The first event of a session additionally pays the `handshake/hello` round-trip (cached afterward). NAT's adapter runs in-process and pays no spawn cost — its overhead is the HTTP round-trip alone.

**Degraded-Guardian behavior.** A Guardian that accepts connections but never responds costs one handshake timeout (default 5s, `ACS_HANDSHAKE_TIMEOUT_SECONDS`) on the first event; the failure is then negative-cached (default 30s, `ACS_HANDSHAKE_FAILURE_CACHE_TTL_SECONDS`) so subsequent events fail fast to the deployment's posture instead of hanging per event. **Incident procedure:** set `ACS_DISABLED=1` in the adapter's environment to bypass all hooks immediately (one stderr line per event, no Guardian traffic); unset to re-enable. This is faster and more reversible than editing hook config files per machine mid-incident.

### DENY path differs only in steps 4–6

Same as above, but with `command: "rm -rf /home/u"`:

- **Step 4:** Guardian returns `{"decision": "deny", "reasoning": "destructive Bash pattern in: rm -rf /home/u"}`
- **Step 5:** Adapter emits `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "destructive Bash pattern..."}}`
- **Step 6:** Claude Code reads `permissionDecision: "deny"`, does not execute the Bash tool, and surfaces the reason: *"The command was blocked — a policy denied the Bash tool call, so it never ran."*

### What changes across the three adapters

The general pattern is identical. The framework-specific translation differs:

| | Claude Code | Cursor | NAT |
|---|---|---|---|
| **Where the adapter lives** | Separate shell process spawned per hook | Separate shell process spawned per hook | In-process Python class, same memory space as the agent |
| **How the framework sends the event** | JSON on stdin; event type is a field inside the JSON (`hook_event_name`) | JSON on stdin; event type passed as a CLI argument (one command per event in `hooks.json`) | Python method call: `pre_invoke(context)` with `context.function_context.name` |
| **Native event field names** | `tool_name`, `tool_input`, `tool_response` | `tool_name`, `tool_input`, `tool_output`, `command` (for shell) | `context.function_context.name`, `context.modified_kwargs` |
| **Native allow/deny output** | `{"hookSpecificOutput": {"permissionDecision": "allow"|"deny"}}` on stdout | `{"permission": "allow"|"deny"}` on stdout, or `exit 2` to block | Set `context.action = InvocationAction.SKIP` to block, or raise `ACSGuardianDenied` |
| **Native modify mechanism** | `hookSpecificOutput.updatedInput` | `updated_input` | Mutate `context.modified_kwargs` (input) or `context.output` (output) |
| **Process model** | OS spawns a Python process for every hook event | OS spawns a Python process for every hook event | Zero IPC; everything in the same Python interpreter |

The Guardian-side wire format is **the same** for all three. The adapter is bilingual: it knows the framework's protocol on one side and ACS on the other.

### Decision honoring is a framework property

Every adapter relies on its framework providing the §6.4 guarantee: the framework MUST wait for the verdict and apply it before the action executes. If a framework fired the hook fire-and-forget and continued the action without waiting, the adapter would still send to the Guardian and the audit chain would still record the decision — but the framework wouldn't apply it. That would be non-conformant. None of the three frameworks here does that; how each one delivers the guarantee is in the per-adapter README.

### The key insight

ACS standardizes the wire format and the decision contract. Adapters live where the boundary is: between the framework and the Guardian. Each adapter:

1. Knows the framework's hook protocol (the framework's JSON shape, response field names, exit codes).
2. Knows ACS (always the same).
3. Translates between them.

The framework's agent code is untouched. The Guardian's policy code is untouched. The adapter is the bilingual translator that makes them speak. **One Guardian, one ACS contract, three adapters that translate three different protocols into that contract.** Add a new framework, write a new adapter, the Guardian doesn't change.

---

## Directory layout (identical across all three adapters)

Each adapter follows the same structure. Files differ only where the framework's native naming requires it (config example file extension, etc.):

```
adapters/<framework>/
├── README.md                    # overview + quick start + conformance status
├── acs_adapter.py               # the adapter (same filename across all three)
├── mapping.md                   # framework event → ACS step method table
├── <config>.example             # drop-in framework-native config:
│                                #   claude-code/settings.json.example
│                                #   cursor/hooks.json.example
│                                #   nat/workflow.yml.example
└── tests/
    ├── __init__.py
    ├── test_adapter.py          # unit / integration tests against real types
    ├── test_live.py             # automated live test (Cursor: skipped placeholder pointing at live_verification.md)
    ├── example_payloads.md      # masked real-world payload examples
    └── live_verification.md     # (Cursor only) manual reproduction procedure
```

Plus the shared:

```
adapters/example-guardian/
├── README.md
└── example_guardian.py          # used by all three adapters' tests
```

---

## Contributing a new adapter

1. Create `adapters/<framework-name>/`.
2. Write `mapping.md` documenting how the framework's hook events map to ACS `steps/*` methods, and how the framework's response shape relates to ACS dispositions.
3. (Optional but encouraged) Write the adapter itself, plus tests. The Claude Code adapter is the template.
4. Add a row to the status table above.
5. Open a PR against `GenAI-Security-Project/agent-control-standard`.

The bar for "reference implementation" status is: round-trip tests pass against the example Guardian, documented configuration for users, and an explicit conformance posture statement matching the format in the Claude Code adapter's README.
