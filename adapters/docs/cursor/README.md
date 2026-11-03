# ACS adapter: Cursor

A drop-in adapter that wires [Cursor](https://cursor.com) hooks to an ACS Guardian. No agent code changes; configuration only.

## How it works

Cursor fires a hook (e.g. `preToolUse`) by running a shell command from `hooks.json`. The command receives the hook event as JSON on stdin and emits Cursor-shaped JSON on stdout.

This adapter is that command. On every hook event Cursor spawns it as a subprocess; the adapter:

1. Reads the Cursor hook event from stdin.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET_FILE`, under the label `ACS_HMAC_KEY_ID`).
4. POSTs to the Guardian.
5. Verifies the response signature.
6. Translates the verdict back to Cursor's expected output shape and writes to stdout (or exits with code 2 for `beforeSubmitPrompt`).
7. Exits.

The handshake/hello fires once per session, cached on disk so subsequent events skip the round-trip.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. Cursor provides this guarantee through its hook protocol: like Claude Code, the adapter is invoked as a blocking subprocess and Cursor reads its stdout (or exit code, for `beforeSubmitPrompt`) for the decision before the action runs. Cursor also provides a native `failClosed: true` flag per hook entry that we set on gate hooks for defense in depth.

## Install — five steps

You need three pieces co-located on the same machine: a running Guardian, a shared HMAC secret, and a `hooks.json` that wires the adapter into Cursor's hooks. `acs-cursor-wire` does step 3 for you.

Commands below assume `$ACS_REPO` points at your local clone of `GenAI-Security-Project/agent-control-standard` (or your fork). Export it once:

```bash
export ACS_REPO=/path/to/your/clone   # e.g., $HOME/code/ACS
uv tool install "$ACS_REPO/adapters"  # or: pipx install "$ACS_REPO/adapters"
```

Installing the package puts `acs-cursor-hook`, `acs-cursor-wire` and `acs-example-guardian` on your PATH.

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
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
  acs-example-guardian --port 8787
```

Keep this terminal open. You should see `[guardian] listening on 127.0.0.1:8787`.

(For long-running setups: a `launchd` plist on macOS or a `systemd` unit on Linux. Out of scope here.)

### 3. Wire `hooks.json`

`acs-cursor-wire` does this safely: dry-run by default, atomic write with a timestamped backup when you pass `--write`. The backup is 0600 with any inline secret replaced by `<redacted>`, and a settings file that holds an inline secret is made 0600. It refuses to wire when another copy of the adapter is already wired in a hook file the host may load, and lists where, since two copies would send every step twice, and both requests for one tool call would carry the same `request_id`. It checks the enterprise, project and user `hooks.json` listed below and, unless you pass `--cursor-third-party-imports-off` because Cursor's **Include Third-Party Plugins, Skills, and Other Configs** setting is off, the Claude Code settings Cursor imports. It wires the absolute path of the installed `acs-cursor-hook`, and stops if that command is not installed, or if a `--hook-command` you pass is not an absolute path to an executable file.

Cursor runs the hooks from every source below and merges their answers, with any deny winning:
- `~/.cursor/hooks.json`: **user-level** (every workspace)
- `<workspace>/.cursor/hooks.json`: **project-level** (this workspace only)
- the enterprise `hooks.json` (`/Library/Application Support/Cursor/` on macOS, `/etc/cursor/` on Linux, `C:\ProgramData\Cursor\` on Windows), team hooks and plugin hooks
- with **Include Third-Party Plugins, Skills, and Other Configs** on, the default: the Claude Code hooks in `~/.claude/settings.json` and the project's `.claude/settings.json` and `.claude/settings.local.json`

```bash
# Preview wiring into ~/.cursor/hooks.json (default — user-level)
acs-cursor-wire \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --key-id=2026-11 \
  --audit-file=~/.acs/audit.log

# Apply user-level wiring
acs-cursor-wire \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --key-id=2026-11 \
  --audit-file=~/.acs/audit.log \
  --write

# OR — project-level wiring for a specific workspace
acs-cursor-wire \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --key-id=2026-11 \
  --audit-file=~/.acs/audit.log \
  --settings=./.cursor/hooks.json \
  --write
```

What it wires by default: the six unconditional hooks of the ACS-Core minimum set, plus `subagentStart`, which ACS-Core requires of a subagent-capable client such as Cursor, `postToolUseFailure`, which carries a failed tool's error text, and `stop`, which closes the turn.

| Cursor event | ACS step method | Posture |
|---|---|---|
| `sessionStart` | sessionStart | fail-open (§6.4 default); a Guardian `deny` refuses the session |
| `beforeSubmitPrompt` | userMessage | **fail-CLOSED** (gate) |
| `preToolUse` | toolCallRequest | **fail-CLOSED** (gate) |
| `postToolUse` | toolCallResult | fail-open |
| `postToolUseFailure` | toolCallResult | fail-open |
| `afterAgentResponse` | agentResponse | fail-open |
| `stop` | turnEnd | fail-open |
| `sessionEnd` | sessionEnd | fail-open |
| `subagentStart` | subagentStart | **fail-CLOSED** (gate. The confused-deputy spawn gate, required by ACS-Core for subagent-capable clients.) |

Gate hooks get **both** `ACS_DEFAULT_DENY=1` (our env var) AND `failClosed: true` (Cursor's native flag), and each covers a different failure. `failClosed: true` blocks when the hook process itself fails: it crashes, times out, or returns invalid JSON. `ACS_DEFAULT_DENY` and the negotiated posture decide the failures the adapter handles, such as an unreachable Guardian. Once the adapter decides a step proceeds, it answers in Cursor's explicit allow shape, so `failClosed` never turns a decided proceed into a block.

Override with `--default-deny` (fail-closed on every hook) or `--all-fail-open` (strict §6.4 default everywhere).

To remove the wiring later: `acs-cursor-wire --unwire --write`.

### 4. Restart Cursor

Cursor reads `hooks.json` at startup, not live. Existing windows keep their pre-wiring config until restart.

### 5. Verify the install

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --group test
uv run python tests/integrations/cursor/e2e_check.py
```

Cursor is a GUI app — it has no headless CLI like `claude --print`. The e2e check is therefore **semi-automated**: the script does everything programmatic (Guardian setup, hooks wiring into a temp workspace, validation of envelopes) and prints precise instructions for actions you perform in Cursor. Wall-clock ~5-10 minutes total.

The final line is `ACS-CORE SMOKE PASS (cursor)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

You can also do an in-session manual smoke test (see [Smoke tests](#smoke-tests) below).

## Prerequisites

- **Cursor** installed — <https://cursor.com>
- **Python 3.11+** and the `acs-adapters` package (`uv tool install "$ACS_REPO/adapters"`). Its runtime dependencies are `rfc8785` and `jsonschema`. To run the test suites: `cd "$ACS_REPO/adapters" && uv sync --locked --group test`.
- **Canonical ACS schemas**: bundled in the package, and read from `specification/v0.1.0/` when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (unit + integration, ~30s)

Run from `adapters/`:

```bash
cd "$ACS_REPO/adapters"
uv run python run_conformance.py cursor
# Runs the shared Guardian, _common, core, client and package checks, then Cursor's suite.
```

The command reports passes, skips, and failures separately. It fails on any test failure or unexpected skip. The manual Cursor procedure is an expected skip in headless runs.

### Smoke #2 — semi-automated Cursor end-to-end (~5-10 minutes)

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --group test
uv run python tests/integrations/cursor/e2e_check.py
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

Verifies that the adapter's audit log distinguishes a Guardian that rejected the request (a configuration error) from a Guardian it could not reach (an ops issue). Both commands run against the Guardian started above, on `127.0.0.1:8787` under the label `2026-11`.

A secret the Guardian does not hold, under the Guardian's label:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:8787/acs" \
ACS_HMAC_SECRET="$(openssl rand -hex 32)" ACS_HMAC_KEY_ID=2026-11 \
acs-cursor-hook preToolUse 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected: the Guardian answers the handshake with `-32004 SIGNATURE_INVALID`, signed with its own secret. The hook cannot verify that answer, so it refuses the session whatever the posture (spec issue #32), and stdout carries a deny:

```
ACS_AUDIT {"acs_audit_event": "session_refused", "cause": "error_signature_invalid", "claimed_cause": "signature_invalid_response", "claimed_error_code": -32004, ...}
ACS_AUDIT {"acs_audit_event": "session_refused_fail_closed", "cause": "error_signature_invalid", ..., "event": "preToolUse", ...}
{"permission": "deny", "user_message": "ACS adapter: session refused (error_signature_invalid)", "agent_message": "ACS adapter: session refused (error_signature_invalid)"}
```

Guardian unreachable, with the Guardian's secret and label:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:1/dead" \
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
acs-cursor-hook preToolUse 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected: the handshake gets no answer, so the session has no negotiated Guardian, and the hook's startup posture settles the step (fail-open when the hook sets no `ACS_DEFAULT_DENY`); stdout carries `{"permission": "allow"}`:

```
ACS_AUDIT {"acs_audit_event": "session_without_negotiated_guardian", "cause": "transport_failure", "failure_class": "handshake_failure", "posture": "fail_open", ...}
ACS_AUDIT {"acs_audit_event": "unguarded_session_bypass", "cause": "transport_failure", ..., "event": "preToolUse", ...}
```

Distinct `acs_audit_event` and `cause`: a rejection refuses the session (`session_refused_fail_closed`) whatever the posture, and an unreachable Guardian follows the startup posture (`unguarded_session_bypass`, or `session_not_started_fail_closed` under a deny posture). Operators grep on either to triage. A hook with no secret sends nothing and refuses the session with `secret_missing`.

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
cd "$ACS_REPO/adapters" && uv run python -c "
from acs.client import ping; import json
r = ping('http://127.0.0.1:8787/acs'); print(json.dumps(r, indent=2)[:200] if r else 'no response')
"
```

## Files

- `src/acs/integrations/cursor/hook.py`: the entry point installed as `acs-cursor-hook`. Stdlib only, so it can still audit and apply the configured posture when the adapter's dependencies are missing.
- `src/acs/integrations/cursor/adapter.py`: the adapter itself, which `hook.py` loads. Stdlib + `rfc8785` for JCS canonicalization.
- `src/acs/integrations/cursor/wire.py`: the `hooks.json` wiring CLI, installed as `acs-cursor-wire` (dry-run by default; `--write` to apply).
- `tests/integrations/cursor/e2e_check.py`: semi-automated Cursor end-to-end verifier (6 steps, real `example_guardian` policy).
- `docs/cursor/hooks.json.example`: reference wiring (`acs-cursor-wire` produces a more comprehensive one).
- `docs/cursor/mapping.md`: Cursor hook → ACS step method table, plus disposition translation.
- `tests/integrations/cursor/`: round-trip and schema tests, plus the manual-procedure placeholder.
- `docs/cursor/example_payloads.md`: masked real-world payload examples showing exactly what Cursor emits.
- `docs/cursor/live_verification.md`: manual reproduction procedure (Cursor has no headless mode).

The adapter shares `acs.core` (signing, decision rules, error codes) and `acs.client` (handshake cache, session state, audit events, URL allowlist) with the Claude Code and NAT adapters.

## How it differs from the Claude Code adapter

Same architectural pattern (shell-stdin/stdout, JSON in, JSON out), different protocol:

| Aspect | Claude Code | Cursor |
|---|---|---|
| Event dispatch | Single command, event type in `hook_event_name` field | One command per event, event name passed as `argv[1]` |
| Allow/deny field | `hookSpecificOutput.permissionDecision` | `permission` (top-level) |
| Modify input field | `hookSpecificOutput.updatedInput` | `updated_input` |
| Block via exit code | Optional (`exit 2`) | Supported (`exit 2`); the adapter answers `beforeSubmitPrompt` with `{"continue": false, "user_message"}` and exit 0 instead, so Cursor shows the message |
| Fail-closed flag | env var `ACS_DEFAULT_DENY` | hook-level `failClosed: true` in `hooks.json`, PLUS env var |
| Per-event output keys | Mostly uniform via `hookSpecificOutput` | Event-specific (`permission`, `additional_context`, `updated_mcp_tool_output`, `followup_message`, ...) |
| Headless CLI for tests | `claude --print` | None — Cursor is a desktop GUI; e2e is semi-automated |

The adapter handles all these protocol differences internally; the Guardian sees the same ACS JSON-RPC shape from both.

## Configuration

The adapter is configured by environment variables, typically set per-hook by `acs-cursor-wire`:

| Variable | Default | Purpose |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/acs` | Guardian endpoint. http/https only; SSRF allowlist refuses other schemes. |
| `ACS_HMAC_SECRET_FILE` | (unset) | Path to a 0600 file holding the shared HMAC secret. |
| `ACS_HMAC_SECRET` | (unset) | Inline secret. Less secure (visible in `ps eauxw`). Prefer the file. |
| `ACS_HMAC_KEY_ID` | (unset) | The label that names the secret (§10); the Guardian holds the same one. Required with a secret: a secret without a label refuses the session, and a response signed under another label fails verification. |
| `ACS_DEFAULT_DENY` | `0` | Fail-open with audit (§6.4 default). Set to `1` for fail-closed. The ServerHello's `on_decision_failure: deny` also flips it (most-restrictive-wins). Guardian refusals (bad signature, replay, malformed/oversized envelope) always fail closed regardless of this setting — see spec issue #32. |
| `ACS_STARTUP_POSTURE` | follows `ACS_DEFAULT_DENY` | `proceed` or `refuse`: what this hook does in a session with no negotiated Guardian, because its handshake got no answer (§4.1). `proceed` lets the step run, audited, with nothing sent to the Guardian; `refuse` denies it. The session keeps no negotiated Guardian for its lifetime, and the next session handshakes again. Any other value refuses. |
| `ACS_REQUIRE_PROFILES` | (unset) | Comma-separated conformance profiles the Guardian must accept, such as `acs-core`. When the session's negotiation leaves one out, this hook's steps are refused and it sends no `sessionStart`; the stored record keeps what the Guardian answered, so each hook applies its own setting, and a later hook without the requirement starts the session. |
| `ACS_HANDSHAKE` | `1` | Set to `0` to skip the handshake; the session then counts as unanswered, and `ACS_STARTUP_POSTURE` settles every step. |
| `ACS_AGENT_ID` | derived from cwd | Stable agent identifier sent in `metadata.agent_id`. |
| `ACS_HANDSHAKE_CACHE` | `~/.cache/acs-adapter-handshake/` | Each session's handshake decision, kept for the session's lifetime. |
| `ACS_HANDSHAKE_TIMEOUT_SECONDS` | `5` | Deadline for the whole handshake/hello exchange, including a response that arrives slowly. A value that is not a positive number is replaced by `5` and recorded as `invalid_setting`. |
| `ACS_AUDIT_FILE` | (unset) | Append every `ACS_AUDIT` event to this file (created 0600) in addition to stderr. |
| `ACS_DISABLED` | (unset) | `1` = incident kill switch: bypass all hooks immediately, no Guardian traffic. Each gate answers with its explicit allow, since `failClosed` blocks a hook that prints nothing. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |

The adapter is invoked as `acs-cursor-hook <event_name>`, where `<event_name>` is one of: `sessionStart`, `sessionEnd`, `stop`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `afterFileEdit`, `afterTabFileEdit`, `beforeSubmitPrompt`, `preCompact`, `afterAgentResponse`, `afterAgentThought`.

## On-disk state

- `~/.cache/acs-adapter-handshake/<sha256(session_id+url)>.json` — the session's handshake decision (negotiated ServerHello, refusal, or no answer) with an HMAC under the session key over the decision, the session and the Guardian URL. Mode 0600; kept for the session's lifetime. A record that is modified, damaged, copied from another endpoint or written by an earlier adapter refuses the session, and so does a decision that cannot be stored.
- `~/.cache/acs-adapter-session/<sha256(workspace+session_id)>.json` — session-state cache (last step_id, seen step_ids). Used by `subagentStart` and `preCompact` to populate real `parent_step_id` / `entries_to_compact` from session history.
- `~/.cache/acs-guardian-state/<sha256(session_id)>.json` — Guardian-side per-session chain head + replay set; survives Guardian restart.

## Conformance status

Honest, item-by-item against the ACS-Core baseline in `docs/spec/conformance.md`. Some Core items are conditional or SHOULD-level: `subagentStart` binds subagent-capable clients, MODIFY and `system/ping` are SHOULD, and Wrapped MCP binds sessions that involve MCP. The row notes say how each one applies here.

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ on the first event of a session; the decision (negotiated, refused, or no answer under `ACS_STARTUP_POSTURE`) holds for the session's lifetime (§4.1) |
| Profiles (`profiles_supported` / `profiles_accepted`) | ✓ always claims `acs-core`: a hook with no usable secret and label refuses its session before the handshake. A ServerHello accepting a profile the adapter did not claim is not a valid answer, a claimed profile the Guardian leaves out is audited as `profile_not_accepted`, and a hook's `ACS_REQUIRE_PROFILES` turns a left-out profile into a refusal of that hook's steps. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (emission suite), with format checking |
| Hook taxonomy (Core minimum set) | ✓ the six unconditional hooks are covered, and so is `subagentStart`, which ACS-Core requires of a subagent-capable client. Cursor exposes the spawn boundary, and the default wiring gates it fail-closed. Seventeen Cursor events are mapped in total; `subagentStop` is intentionally omitted — see the honesty table below. |
| Dispositions | ALLOW / DENY supported on **permission (pre-execution) events** (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeSubmitPrompt`, `subagentStart`). ASK holds on `beforeShellExecution` and `beforeMCPExecution`; on `preToolUse` Cursor accepts `ask` without enforcing it, so ASK and DEFER deny there, audited as `unenforceable_decision`. DEFER is substituted to ASK where ASK holds (Cursor has no defer). MODIFY supported on `preToolUse` via `updated_input`. A `deny` on `sessionStart` refuses the session, so every later step of it is denied. **Lifecycle / post-execution hooks (`afterAgentResponse → steps/agentResponse`, `sessionEnd`, `afterShellExecution`, etc.) are observation-only** — Cursor fires them after the message / side effect has occurred; a Guardian `deny` cannot undo it. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ |
| SessionContext + published `chain_hash` | ✓ session_id coerced to UUID; Guardian computes rolling SHA-256 chain |
| Replay protection | ✓ Guardian enforcement (REPLAY_DETECTED -32005, TIMESTAMP_OUT_OF_WINDOW -32006) |
| Baseline integrity (HMAC-SHA256) | ✓ every request and response signed under `ACS_HMAC_KEY_ID`; a hook with no secret of at least 32 bytes, or no label, refuses its session and sends nothing; SIGNATURE_INVALID -32004 on tamper |
| Decision honoring (§6.4) | ✓ Cursor blocks on permission deny; adapter answers every decided step in Cursor's documented JSON; fail-open emits `ACS_AUDIT` event; audit `cause` field distinguishes failure modes (transport vs signature vs malformed envelope vs replay vs skew) |
| Liveness `system/ping` | ⚠ Guardian-side only. ACS-Core says `system/ping` SHOULD be implemented: the Observed Agent declares it in `methods_implemented` and sends it, and the Guardian answers it (§13). The example Guardian answers ping as an always-allow method outside the chain, replay, and signature checks. The adapter does not declare or send `system/ping`, so a deployment that uses it must name an alternative liveness mechanism in its configuration, such as continuous observed hook traffic. Omitting both is non-conformant. |
| `nonce` (optional replay field) | ✗ adapter does not emit `nonce`; the envelope field is OPTIONAL in v0.1 |
| Wrapped MCP `protocols/MCP/*` | ⚠ partial. ACS-Core requires `protocols/MCP/*` for any session that involves MCP, and MCP `tools/call` MAY instead flow through the generic tool hooks. The adapter covers only that case: it maps `beforeMCPExecution` to `steps/toolCallRequest` and `afterMCPExecution` to `steps/toolCallResult`. It wraps no other MCP surface (`initialize`, `prompts/get`, `resources/read`, notifications), so a session that uses MCP falls short of ACS-Core there. The first MCP tool a signed session uses records `profile_claim_degraded` once, whether it arrives through the MCP hooks or through `preToolUse` and `postToolUse` as `MCP:<tool>`. Known limitation. |

### Per-hook honesty table

Cursor does not expose every field the ACS v0.1.0 hook schemas require. Where the schema is strict and Cursor is silent, the adapter populates fields from real session state where possible — and omits the hook entirely when the missing field can only be fabricated.

| Cursor event → ACS hook | What we fill from real data | What's hardcoded | What's omitted |
|---|---|---|---|
| `subagentStart` → `steps/subagentStart` | `subagent_session_id` (deterministic uuid5 of `parent_session + subagent_id`); `parent_session_id` (the envelope's actual `session_id`); `parent_step_id` (last step_id the adapter has seen in this session, tracked in `~/.cache/acs-adapter-session/`); `subagent_descriptor.{agent_id,agent_name}` (from Cursor's `subagent_id` / `subagent_type`) | `intent_derivation = "derived_from_parent"` (defensible default for IDE-spawned subagents) | — |
| `preCompact` → `steps/preCompact` | `entries_to_compact` (list of step_ids the adapter has observed in this session, snapshotted from session state); `triggered_by` (Cursor's `trigger` field) | `triggered_by = "framework_initiated"` only when Cursor omits `trigger` | — |
| `subagentStop` → `steps/subagentStop` | — | — | **Not forwarded** (`KNOWN_UNMAPPED` in the adapter). Cursor's `subagentStop` carries no identifier of the subagent it ends, so it cannot name the `subagent_session_id` `steps/subagentStop` requires (`mapping.md`). |

These hooks are emitted only when Cursor's `hooks.json` wires them to the adapter. Per-session state for `parent_step_id` / `entries_to_compact` requires the adapter to be wired to at least one earlier hook in the same session (typically `preToolUse`); the adapter records each step's `request_id` to the session-state file on every invocation.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Cursor's agent runs commands as if no Guardian exists | Cursor reads `hooks.json` at startup. **Restart Cursor** after `acs-cursor-wire --write`. |
| Adapter exits 0 with empty stdout; Guardian terminal silent | Adapter pointed at the wrong URL (check `ACS_GUARDIAN_URL` in your hooks.json); check stderr for `ACS_AUDIT cause=transport_failure`. |
| Every tool call gets denied | Likely `ACS_DEFAULT_DENY=1` + Guardian down. Check the Guardian process is running. |
| Adapter says `SecretFilePermissionsError` | The HMAC secret file is mode > 0600. `chmod 600 ~/.acs/hmac.key`. |
| Guardian returns `-32004 SIGNATURE_INVALID` | Adapter and Guardian aren't reading the same secret. `cat ~/.acs/hmac.key` on both sides should match. |
| Guardian returns `-32006 TIMESTAMP_OUT_OF_WINDOW` | Clock skew between adapter and Guardian > 5 minutes. Sync time. |
| Guardian returns `-32600 Invalid Request` for `metadata.session_id` | Session ID wasn't coerced to a UUID. Cursor sends conversation_ids that aren't UUIDs; the adapter coerces them via uuid5. If you see this error, file a bug — the coercion is unconditional in `_session_id`. |

Everything the adapter does that's not policy decision-making is audited on stderr as a JSON line prefixed `ACS_AUDIT`. The `cause` field tells you which failure mode fired.
