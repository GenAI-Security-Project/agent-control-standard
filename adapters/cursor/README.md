# ACS adapter: Cursor

A drop-in adapter that wires [Cursor](https://cursor.com) hooks to an ACS Guardian. No agent code changes; configuration only.

## How it works

Cursor fires a hook (e.g. `preToolUse`) by running a shell command from `hooks.json`. The command receives the hook event as JSON on stdin and emits Cursor-shaped JSON on stdout (or exit code 2 for some events).

This adapter is that command. On every hook event Cursor spawns it as a subprocess; the adapter:

1. Reads the Cursor hook event from stdin.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET_FILE`).
4. POSTs to the Guardian.
5. Verifies the response signature.
6. Translates the verdict back to Cursor's expected output shape and writes to stdout (or exits with code 2 for `beforeSubmitPrompt`).
7. Exits.

The handshake/hello fires once per session, cached on disk so subsequent events skip the round-trip.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. Cursor provides this guarantee through its hook protocol: like Claude Code, the adapter is invoked as a blocking subprocess and Cursor reads its stdout (or exit code, for `beforeSubmitPrompt`) for the decision before the action runs. Cursor also provides a native `failClosed: true` flag per hook entry that we set on gate hooks for defense in depth.

## Install — five steps

You need three pieces co-located on the same machine: a running Guardian, a shared HMAC secret, and a `hooks.json` that wires the adapter into Cursor's hooks. `wire.py` does step 3 for you.

Commands below assume `$ACS_REPO` points at your local clone of `GenAI-Security-Project/agent-control-standard` (or your fork). Export it once:

```bash
export ACS_REPO=/path/to/your/clone   # e.g., $HOME/code/ACS
```

### 1. Generate the shared HMAC secret

Both the adapter and the Guardian read this file. Mode 0600 is enforced by the adapter — anything looser and it refuses to start.

```bash
mkdir -p ~/.acs
openssl rand -hex 32 > ~/.acs/hmac.key
chmod 600 ~/.acs/hmac.key
```

### 2. Run the Guardian

Use the example Guardian for testing; a production Guardian is the same wire protocol with a real policy engine attached.

```bash
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key \
  python3 "$ACS_REPO/adapters/example-guardian/example_guardian.py" \
  --port 8787
```

Keep this terminal open. You should see `[guardian] listening on 127.0.0.1:8787`.

(For long-running setups: a `launchd` plist on macOS or a `systemd` unit on Linux. Out of scope here.)

### 3. Wire `hooks.json`

`wire.py` does this safely — dry-run by default, atomic write with a timestamped backup when you pass `--write`.

Cursor reads from two locations:
- `~/.cursor/hooks.json` — **user-level** (every workspace)
- `<workspace>/.cursor/hooks.json` — **project-level** (this workspace only; overrides user-level)

```bash
cd "$ACS_REPO/adapters/cursor"

# Preview wiring into ~/.cursor/hooks.json (default — user-level)
python3 wire.py \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key

# Apply user-level wiring
python3 wire.py \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --write

# OR — project-level wiring for a specific workspace
python3 wire.py \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --settings=./.cursor/hooks.json \
  --write
```

What it wires by default: this branch's six-hook ACS-Core minimum set, plus the `subagentStart` gate proposed by PR #21 (open; not in this branch).

| Cursor event | ACS step method | Posture |
|---|---|---|
| `sessionStart` | sessionStart | fail-open (observational) |
| `beforeSubmitPrompt` | userMessage | **fail-CLOSED** (gate) |
| `preToolUse` | toolCallRequest | **fail-CLOSED** (gate) |
| `postToolUse` | toolCallResult | fail-open |
| `afterAgentResponse` | agentResponse | fail-open |
| `sessionEnd` | sessionEnd | fail-open |
| `subagentStart` | subagentStart | **fail-CLOSED** (gate — confused-deputy spawn gate; PR #21 proposes it for the Core floor) |

Gate hooks get **both** `ACS_DEFAULT_DENY=1` (our env var) AND `failClosed: true` (Cursor's native flag) — defense in depth: two independent mechanisms that both must fail open for a gate to leak.

Override with `--default-deny` (fail-closed on every hook) or `--all-fail-open` (strict §6.4 default everywhere).

To remove the wiring later: `python3 wire.py --unwire --write`.

### 4. Restart Cursor

Cursor reads `hooks.json` at startup, not live. Existing windows keep their pre-wiring config until restart.

### 5. Verify the install

```bash
cd "$ACS_REPO/adapters/cursor"
python3 e2e_check.py
```

Cursor is a GUI app — it has no headless CLI like `claude --print`. The e2e check is therefore **semi-automated**: the script does everything programmatic (Guardian setup, hooks wiring into a temp workspace, validation of envelopes) and prints precise instructions for actions you perform in Cursor. Wall-clock ~5-10 minutes total.

The final line is `ACS-CORE SMOKE PASS (cursor)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

You can also do an in-session manual smoke test (see [Smoke tests](#smoke-tests) below).

## Prerequisites

- **Cursor** installed — <https://cursor.com>
- **Python 3.10+** with `rfc8785` (the adapter's one runtime dependency) — `pip install -r requirements.txt`. For running the test suites you also need `jsonschema`: `pip install -r ../requirements-test.txt`
- **Canonical ACS schemas** — the in-repo copy at `specification/v0.1.0/` is the default, so no setup is needed when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (unit + integration, ~30s)

Run from `adapters/`:

```bash
cd "$ACS_REPO/adapters"
python3 run_conformance.py cursor
# Runs the shared Guardian and _common checks, then Cursor's suite.
```

The command reports passes, skips, and failures separately. It fails on any test failure or unexpected skip. The manual Cursor procedure is an expected skip in headless runs.

### Smoke #2 — semi-automated Cursor end-to-end (~5-10 minutes)

```bash
cd "$ACS_REPO/adapters/cursor"
python3 e2e_check.py
```

Sets up a temp workspace with project-level `.cursor/hooks.json`, starts a recording Guardian wired to the real `example_guardian` policy, and walks you through 6 steps (SETUP, ALLOW, READ-TOOL, DESTRUCTIVE, USER-MESSAGE, HANDSHAKE-ONCE). The same shipping policy is active across every step — running `rm -rf` during any prompt gets the real destructive-Bash regex applied. At each step it tells you exactly what to do in Cursor, then validates the envelopes that arrived.

### Smoke #3 — in-session manual test

Open a Cursor workspace where hooks are wired. In the Agent panel try:

```
Use the shell to run: echo hello
```

In your Guardian terminal you should see roughly this sequence:

```
[guardian] handshake/hello        session=<uuid>...
[guardian] steps/sessionStart     session=<uuid>...
[guardian] steps/userMessage      session=<uuid>...
[guardian] steps/toolCallRequest  session=<uuid>...
[guardian] steps/toolCallResult   session=<uuid>...
[guardian] steps/agentResponse    session=<uuid>...
```

Then ask Cursor for a denied command:

```
Use the shell to run: rm -rf /tmp/some-fake-path
```

The example Guardian's regex matches `rm -rf /...`; Cursor surfaces the Guardian's `reasoning` to the user and the command never runs.

### Smoke #4 — audit-cause differentiation

Verifies the adapter's audit log distinguishes "Guardian unreachable" (ops issue) from "Guardian rejected the envelope" (client/operator bug).

Unsigned envelope to a signing-required Guardian:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:8787/acs" \
ACS_HMAC_SECRET="" \
python3 "$ACS_REPO/adapters/cursor/acs_adapter.py" preToolUse 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected stderr — a signature refusal fails CLOSED regardless of
posture (a refusal is an alive Guardian rejecting the envelope; spec
issue #32), and stdout carries `{"permission": "deny", ...}`:

```
acs-adapter: Guardian returned JSON-RPC error -32004 (signature_invalid_response): SIGNATURE_INVALID
ACS_AUDIT {"acs_audit_event": "guardian_refusal_fail_closed", "cause": "signature_invalid_response", ...}
```

Guardian unreachable (a decision FAILURE, not a refusal — this one
follows the §6.4 posture, fail-open by default):

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:1/dead" \
python3 "$ACS_REPO/adapters/cursor/acs_adapter.py" preToolUse 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected:

```
acs-adapter: Guardian unreachable: <urlopen error ...>
ACS_AUDIT {"acs_audit_event": "fail_open_bypass", "cause": "transport_failure", ...}
```

Distinct `acs_audit_event` AND distinct `cause`: refusals are always
`guardian_refusal_fail_closed`; failures carry the posture
(`fail_open_bypass` / `decision_failure_fail_closed`). Operators grep
on either to triage.

### Smoke #5 — pre-flight inventory (paranoid)

If you're debugging, this is the fastest "where did I go wrong" sweep:

```bash
echo "=== Guardian listening? ==="
lsof -i :8787 | head -3 || echo "NOT RUNNING"

echo "=== Secret file 0600? ==="
ls -la ~/.acs/hmac.key

echo "=== Hooks wired? ==="
python3 -c "import json, os; d=json.load(open(os.path.expanduser('~/.cursor/hooks.json'))); print(list(d.get('hooks',{}).keys()))"

echo "=== Guardian responds to system/ping? ==="
cd "$ACS_REPO/adapters" && python3 -c "
import sys; sys.path.insert(0, '_common')
from acs_common import ping; import json
r = ping('http://127.0.0.1:8787/acs'); print(json.dumps(r, indent=2)[:200] if r else 'no response')
"
```

## Files

- `acs_adapter.py` — the adapter itself. Stdlib + `rfc8785` for JCS canonicalization.
- `wire.py` — `hooks.json` wiring CLI (dry-run by default; `--write` to apply).
- `e2e_check.py` — semi-automated Cursor end-to-end verifier (6 steps, real `example_guardian` policy).
- `hooks.json.example` — reference wiring (`wire.py` produces a more comprehensive one).
- `mapping.md` — Cursor hook → ACS step method table, plus disposition translation.
- `tests/` — round-trip + schema tests + manual-procedure placeholder.
- `tests/example_payloads.md` — masked real-world payload examples showing exactly what Cursor emits.
- `tests/live_verification.md` — manual reproduction procedure (Cursor has no headless mode).

The adapter shares `adapters/_common/` with the Claude Code and NAT adapters (signing, handshake cache, audit events, URL allowlist).

## How it differs from the Claude Code adapter

Same architectural pattern (shell-stdin/stdout, JSON in, JSON out), different protocol:

| Aspect | Claude Code | Cursor |
|---|---|---|
| Event dispatch | Single command, event type in `hook_event_name` field | One command per event, event name passed as `argv[1]` |
| Allow/deny field | `hookSpecificOutput.permissionDecision` | `permission` (top-level) |
| Modify input field | `hookSpecificOutput.updatedInput` | `updated_input` |
| Block via exit code | Optional (`exit 2`) | Supported (`exit 2`); `beforeSubmitPrompt` uses exit code rather than JSON output |
| Fail-closed flag | env var `ACS_DEFAULT_DENY` | hook-level `failClosed: true` in `hooks.json`, PLUS env var |
| Per-event output keys | Mostly uniform via `hookSpecificOutput` | Event-specific (`permission`, `additional_context`, `updated_mcp_tool_output`, `followup_message`, ...) |
| Headless CLI for tests | `claude --print` | None — Cursor is a desktop GUI; e2e is semi-automated |

The adapter handles all these protocol differences internally; the Guardian sees the same ACS JSON-RPC shape from both.

## Configuration

The adapter is configured by environment variables, typically set per-hook by `wire.py`:

| Variable | Default | Purpose |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/acs` | Guardian endpoint. http/https only; SSRF allowlist refuses other schemes. |
| `ACS_HMAC_SECRET_FILE` | (unset) | Path to a 0600 file holding the shared HMAC secret. |
| `ACS_HMAC_SECRET` | (unset) | Inline secret. Less secure (visible in `ps eauxw`). Prefer the file. |
| `ACS_DEFAULT_DENY` | `0` | Fail-open with audit (§6.4 default). Set to `1` for fail-closed. The ServerHello's `on_decision_failure: deny` also flips it (most-restrictive-wins). Guardian refusals (bad signature, replay, malformed/oversized envelope) always fail closed regardless of this setting — see spec issue #32. |
| `ACS_HANDSHAKE` | `1` | Set to `0` to disable the handshake/hello call on first use. |
| `ACS_AGENT_ID` | derived from cwd | Stable agent identifier sent in `metadata.agent_id`. |
| `ACS_HANDSHAKE_CACHE` | `~/.cache/acs-adapter-handshake/` | Per-session ServerHello cache dir. |
| `ACS_HANDSHAKE_TIMEOUT_SECONDS` | `5` | Network timeout for handshake/hello. |
| `ACS_HANDSHAKE_FAILURE_CACHE_TTL_SECONDS` | `30` | Failed handshakes are negative-cached this long, so a dead Guardian costs one timeout, not one per hook event. |
| `ACS_AUDIT_FILE` | (unset) | Append every `ACS_AUDIT` event to this file (created 0600) in addition to stderr. |
| `ACS_DISABLED` | (unset) | `1` = incident kill switch: bypass all hooks immediately, no Guardian traffic. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |

The adapter is invoked as `python3 acs_adapter.py <event_name>`, where `<event_name>` is one of: `sessionStart`, `sessionEnd`, `stop`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `afterFileEdit`, `afterTabFileEdit`, `beforeSubmitPrompt`, `preCompact`, `afterAgentResponse`, `afterAgentThought`.

## On-disk state

- `~/.cache/acs-adapter-handshake/<sha256(session_id+url)>.json` — cached ServerHello per session. Mode 0600; refreshed when older than 1 hour.
- `~/.cache/acs-adapter-session/<sha256(workspace+session_id)>.json` — session-state cache (last step_id, seen step_ids). Used by `subagentStart` and `preCompact` to populate real `parent_step_id` / `entries_to_compact` from session history.
- `~/.cache/acs-guardian-state/<sha256(session_id)>.json` — Guardian-side per-session chain head + replay set; survives Guardian restart.

## Conformance status

Honest, item-by-item against `docs/spec/conformance.md`. (PR #21 — open, not in this branch — proposes relaxing some items to SHOULD/conditional; the row notes say which. Against this branch's spec text those items remain as written.)

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ on first session call; cached per-session |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (emission suite), with format checking |
| Hook taxonomy (Core minimum set) | ✓ this branch's six-hook minimum set is covered. `subagentStart` is also covered as the gate proposed by PR #21 (open; not in this branch). Seventeen Cursor events are mapped in total; `subagentStop` is intentionally omitted — see the honesty table below. |
| Dispositions | ALLOW / DENY / ASK supported on **permission (pre-execution) events** (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeSubmitPrompt`, `subagentStart`). DEFER substituted to ASK (Cursor has no defer). MODIFY supported on `preToolUse` via `updated_input`. **Lifecycle / post-execution hooks (`afterAgentResponse → steps/agentResponse`, `sessionStart`, `sessionEnd`, `afterShellExecution`, etc.) are observation-only** — Cursor fires them after the message / side effect has occurred; a Guardian `deny` cannot undo it. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ |
| SessionContext + published `chain_hash` | ✓ session_id coerced to UUID; Guardian computes rolling SHA-256 chain |
| Replay protection | ✓ Guardian enforcement (REPLAY_DETECTED -32005, TIMESTAMP_OUT_OF_WINDOW -32006) |
| Baseline integrity (HMAC-SHA256) | ✓ when `ACS_HMAC_SECRET[_FILE]` is set; SIGNATURE_INVALID -32004 on tamper |
| Decision honoring (§6.4) | ✓ Cursor blocks on permission deny; adapter uses exit-2 where stdout JSON is not available; fail-open emits `ACS_AUDIT` event; audit `cause` field distinguishes failure modes (transport vs signature vs malformed envelope vs replay vs skew) |
| Liveness `system/ping` | ✓ Guardian-side only — the adapter does NOT emit system/ping; liveness is the Guardian answering probes (§13). |
| `nonce` (optional replay field) | ✗ adapter does not emit `nonce`; the envelope field is OPTIONAL in v0.1 |
| Wrapped MCP `protocols/MCP/*` | ⚠ partial — Cursor's `beforeMCPExecution` is mapped to `steps/toolCallRequest`, not to the `protocols/MCP/*` wrapped form. Real wrapping requires forwarding the full MCP request shape, not flattening it; this adapter does not do that. |

### Per-hook honesty table

Cursor does not expose every field the ACS v0.1.0 hook schemas require. Where the schema is strict and Cursor is silent, the adapter populates fields from real session state where possible — and omits the hook entirely when the missing field can only be fabricated.

| Cursor event → ACS hook | What we fill from real data | What's hardcoded | What's omitted |
|---|---|---|---|
| `subagentStart` → `steps/subagentStart` | `subagent_session_id` (deterministic uuid5 of `parent_session + subagent_id`); `parent_session_id` (the envelope's actual `session_id`); `parent_step_id` (last step_id the adapter has seen in this session, tracked in `~/.cache/acs-adapter-session/`); `subagent_descriptor.{agent_id,agent_name}` (from Cursor's `subagent_id` / `subagent_type`) | `intent_derivation = "derived_from_parent"` (defensible default for IDE-spawned subagents) | — |
| `preCompact` → `steps/preCompact` | `entries_to_compact` (list of step_ids the adapter has observed in this session, snapshotted from session state); `triggered_by` (Cursor's `trigger` field) | `triggered_by = "framework_initiated"` only when Cursor omits `trigger` | — |
| `subagentStop` → `steps/subagentStop` | — | — | **Not forwarded** (`KNOWN_UNMAPPED` in the adapter). `final_chain_hash` is genuinely unknowable (Cursor maintains no chain) — better to omit than fabricate. A separate schema PR proposes making the field optional for chain-less frameworks; honest wiring resumes when the spec owners approve it. |

These hooks are emitted only when Cursor's `hooks.json` wires them to the adapter. Per-session state for `parent_step_id` / `entries_to_compact` requires the adapter to be wired to at least one earlier hook in the same session (typically `preToolUse`); the adapter records each step's `request_id` to the session-state file on every invocation.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Cursor's agent runs commands as if no Guardian exists | Cursor reads `hooks.json` at startup. **Restart Cursor** after `wire.py --write`. |
| Adapter exits 0 with empty stdout; Guardian terminal silent | Adapter pointed at the wrong URL (check `ACS_GUARDIAN_URL` in your hooks.json); check stderr for `ACS_AUDIT cause=transport_failure`. |
| Every tool call gets denied | Likely `ACS_DEFAULT_DENY=1` + Guardian down. Check the Guardian process is running. |
| Adapter says `SecretFilePermissionsError` | The HMAC secret file is mode > 0600. `chmod 600 ~/.acs/hmac.key`. |
| Guardian returns `-32004 SIGNATURE_INVALID` | Adapter and Guardian aren't reading the same secret. `cat ~/.acs/hmac.key` on both sides should match. |
| Guardian returns `-32006 TIMESTAMP_OUT_OF_WINDOW` | Clock skew between adapter and Guardian > 5 minutes. Sync time. |
| Guardian returns `-32600 Invalid Request` for `metadata.session_id` | Session ID wasn't coerced to a UUID. Cursor sends conversation_ids that aren't UUIDs; the adapter coerces them via uuid5. If you see this error, file a bug — the coercion is unconditional in `_session_id`. |

Everything the adapter does that's not policy decision-making is audited on stderr as a JSON line prefixed `ACS_AUDIT`. The `cause` field tells you which failure mode fired.
