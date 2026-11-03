# ACS adapter: Claude Code

A drop-in adapter that wires [Claude Code](https://docs.claude.com/claude-code) hooks to an ACS Guardian. No agent code changes; configuration only.

## How it works

Claude Code fires a hook (e.g. `PreToolUse`) by running a shell command and passing the hook event as JSON on stdin. The command's stdout becomes the hook's decision.

This adapter is that command. On every hook event Claude Code spawns the adapter as a subprocess; the adapter:

1. Reads the Claude Code hook event from stdin.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET_FILE`, under the label `ACS_HMAC_KEY_ID`).
4. POSTs to the Guardian.
5. Verifies the response signature.
6. Translates the verdict back to Claude Code's expected output shape and writes to stdout.
7. Exits.

The handshake/hello fires once per session, cached on disk so subsequent events skip the round-trip.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. Claude Code provides this guarantee through its hook protocol: the adapter is invoked as a blocking subprocess and the framework reads its stdout for the decision, so the tool can't run until the adapter exits with a verdict. The adapter relies on this — without it, a Guardian deny would arrive after the side effect.

## Install — five steps

You need three pieces co-located on the same machine: a running Guardian, a shared HMAC secret, and a `~/.claude/settings.json` that wires the adapter into Claude Code's hooks. `acs-claude-code-wire` does step 3 for you.

Commands below assume `$ACS_REPO` points at your local clone of `GenAI-Security-Project/agent-control-standard` (or your fork). Export it once:

```bash
export ACS_REPO=/path/to/your/clone   # e.g., $HOME/code/ACS
uv tool install "$ACS_REPO/adapters"  # or: pipx install "$ACS_REPO/adapters"
```

Installing the package puts `acs-claude-code-hook`, `acs-claude-code-wire` and `acs-example-guardian` on your PATH.

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

### 3. Wire `~/.claude/settings.json`

`acs-claude-code-wire` does this safely: dry-run by default, atomic write with a timestamped backup when you pass `--write`. It refuses to wire when another copy of the adapter is already wired in a hook file the host may load, and lists where, since two copies would send every step twice, and both requests for one tool call would carry the same `request_id`. It checks user, project, local and managed settings, and the hooks of each installed plugin that `enabledPlugins` turns on for the project. Cursor also runs the Claude Code hooks in user, project and local settings, so wiring one of those files also checks the `hooks.json` files Cursor loads; with Cursor's **Include Third-Party Plugins, Skills, and Other Configs** setting off, pass `--cursor-third-party-imports-off` to skip that check. It wires the absolute path of the installed `acs-claude-code-hook`, and stops if that command is not installed, or if a `--hook-command` you pass is not an absolute path to an executable file.

```bash
# Preview the change without touching the file
acs-claude-code-wire \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --key-id=2026-11 \
  --audit-file=~/.acs/audit.log

# Apply it (creates ~/.claude/settings.json.bak.<timestamp>)
acs-claude-code-wire \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --key-id=2026-11 \
  --audit-file=~/.acs/audit.log \
  --write
```

What it wires by default:

| Hook | Posture |
|---|---|
| `PreToolUse` | **fail-CLOSED** (gate — silent fail-open is a policy hole) |
| `UserPromptSubmit` | **fail-CLOSED** (gate) |
| `SessionStart` | fail-open (§6.4 default); a Guardian `deny` refuses the session |
| `PostToolUse` | fail-open |
| `Stop` | fail-open; sends the reply (`agentResponse`) and closes the turn |
| `SessionEnd` | fail-open |

Override with `--default-deny` (fail-closed on every hook) or `--all-fail-open` (strict §6.4 default everywhere). Every fail-closed hook also carries `"onFailure": "block"`, so Claude Code v2.1.295 or later blocks the action when the hook itself crashes, times out or cannot start; Claude Code ignores it on `Stop`.

To remove the wiring later: `acs-claude-code-wire --unwire --write`.

### 4. Restart any open Claude Code session

Claude Code reads `~/.claude/settings.json` at session start, not live. Existing sessions keep their pre-wiring config.

### 5. Verify the install

Two complementary checks. The end-to-end check is the one to run if you only have time for one:

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --group test
uv run python tests/integrations/claude_code/e2e_check.py
```

Real Claude is driven through five scenarios — allow, deny, Read tool, multi-tool handshake-once, withheld output — every envelope is printed verbatim, you read PASS/FAIL per scenario. Wall-clock ~60-90s because real Claude is in the loop. The final line is either `ACS-CORE SMOKE PASS (claude-code)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

You can also do an in-session manual smoke test (see [Smoke tests](#smoke-tests) below).

## Prerequisites

- **`claude` CLI** installed and authenticated — install guide: <https://docs.claude.com/claude-code>
- **Python 3.11+** and the `acs-adapters` package (`uv tool install "$ACS_REPO/adapters"`). Its runtime dependencies are `rfc8785` and `jsonschema`. To run the test suites: `cd "$ACS_REPO/adapters" && uv sync --locked --group test`.
- **Canonical ACS schemas**: bundled in the package, and read from `specification/v0.1.0/` when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (unit + integration, ~30s)

Run from `adapters/`:

```bash
cd "$ACS_REPO/adapters"
uv run python run_conformance.py claude
# Runs the shared Guardian, _common, core, client and package checks, then Claude Code's suite.
```

The command reports passes, skips, and failures separately. It fails on any test failure or unexpected skip. The live tests, which drive the real `claude` CLI on your account, run only with `ACS_LIVE_CLAUDE=1`:

```bash
ACS_LIVE_CLAUDE=1 uv run python run_conformance.py claude
```

### Smoke #2 — real Claude end-to-end (~60-90s)

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --group test
uv run python tests/integrations/claude_code/e2e_check.py
```

Drives real Claude through 5 scenarios with a recording Guardian. Prints every envelope on the wire plus per-scenario PASS/FAIL.

### Smoke #3 — in-session manual test

Open a real Claude Code session. Try:

```
echo hello via Bash
```

The Guardian allows it and the hook prints nothing, so Claude Code's own permission rules decide; `echo` is one of its read-only commands, which run without a prompt.

In your Guardian terminal you should see roughly this sequence (one new entry per hook Claude fires):

```
[guardian] handshake/hello       session=<uuid>...
[guardian] steps/sessionStart    session=<uuid>...
[guardian] steps/turnStart       session=<uuid>...
[guardian] steps/userMessage     session=<uuid>...
[guardian] steps/toolCallRequest session=<uuid>...
[guardian] steps/toolCallResult  session=<uuid>...
[guardian] steps/agentResponse   session=<uuid>...
[guardian] steps/turnEnd         session=<uuid>...
[guardian] steps/sessionEnd      session=<uuid>...
```

Then try a denied command in the same session:

```
Run: rm -rf /home/some-fake-path
```

Claude should refuse and surface the Guardian's `reasoning` field. The example Guardian's regex catches `rm -rf /...`; the Bash never runs.

### Smoke #4 — audit-cause differentiation

Verifies that the adapter's audit log distinguishes a Guardian that rejected the request (a configuration error) from a Guardian it could not reach (an ops issue). Both commands run against the Guardian started above, on `127.0.0.1:8787` under the label `2026-11`.

A secret the Guardian does not hold, under the Guardian's label:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:8787/acs" \
ACS_HMAC_SECRET="$(openssl rand -hex 32)" ACS_HMAC_KEY_ID=2026-11 \
acs-claude-code-hook 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","transcript_path":"/tmp/t","cwd":"/tmp","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected: the Guardian answers the handshake with `-32004 SIGNATURE_INVALID`, signed with its own secret. The hook cannot verify that answer, so it refuses the session whatever the posture (spec issue #32), and stdout carries a deny:

```
ACS_AUDIT {"acs_audit_event": "session_refused", "cause": "error_signature_invalid", "claimed_cause": "signature_invalid_response", "claimed_error_code": -32004, ...}
ACS_AUDIT {"acs_audit_event": "session_refused_fail_closed", "cause": "error_signature_invalid", ..., "hook": "PreToolUse", ...}
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "ACS adapter: session refused (error_signature_invalid)"}}
```

Guardian unreachable, with the Guardian's secret and label:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:1/dead" \
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
acs-claude-code-hook 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","transcript_path":"/tmp/t","cwd":"/tmp","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected: the handshake gets no answer, so the session has no negotiated Guardian, and the hook's startup posture settles the step (fail-open when the hook sets no `ACS_DEFAULT_DENY`); stdout is empty, which Claude Code reads as proceed:

```
ACS_AUDIT {"acs_audit_event": "session_without_negotiated_guardian", "cause": "transport_failure", "failure_class": "handshake_failure", "posture": "fail_open", ...}
ACS_AUDIT {"acs_audit_event": "unguarded_session_bypass", "cause": "transport_failure", ..., "hook": "PreToolUse", ...}
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
python3 -c "import json, os; d=json.load(open(os.path.expanduser('~/.claude/settings.json'))); print(list(d.get('hooks',{}).keys()))"

echo "=== Guardian responds to system/ping? ==="
cd "$ACS_REPO/adapters" && uv run python -c "
from acs.client import ping; import json
r = ping('http://127.0.0.1:8787/acs'); print(json.dumps(r, indent=2)[:200] if r else 'no response')
"
```

## Files

- `src/acs/integrations/claude_code/hook.py`: the entry point installed as `acs-claude-code-hook`. Stdlib only, so it can still audit and apply the configured posture when the adapter's dependencies are missing.
- `src/acs/integrations/claude_code/adapter.py`: the adapter itself, which `hook.py` loads. Stdlib + `rfc8785` for JCS canonicalization.
- `src/acs/integrations/claude_code/wire.py`: the settings.json wiring CLI, installed as `acs-claude-code-wire` (dry-run by default; `--write` to apply).
- `tests/integrations/claude_code/e2e_check.py`: real-Claude end-to-end verifier (5 scenarios).
- `docs/claude_code/settings.json.example`: reference wiring (`acs-claude-code-wire` produces a more comprehensive one).
- `docs/claude_code/mapping.md`: Claude Code hook → ACS step method table, plus disposition translation.
- `tests/integrations/claude_code/`: round-trip, schema and live integration tests.
- `docs/claude_code/example_payloads.md`: masked real-world payload examples showing exactly what Claude Code emits.

The adapter shares `acs.core` (signing, decision rules, error codes) and `acs.client` (handshake cache, session state, audit events, URL allowlist) with the Cursor and NAT adapters.

## Configuration

The adapter is configured by environment variables, typically set per-hook by `acs-claude-code-wire`:

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
| `ACS_AGENT_ID` | derived from `CLAUDE_PROJECT_DIR`, or the session's first `cwd` | Stable agent identifier sent in `metadata.agent_id`. |
| `ACS_HANDSHAKE_CACHE` | `~/.cache/acs-adapter-handshake/` | Each session's handshake decision, kept for the session's lifetime. |
| `ACS_HANDSHAKE_TIMEOUT_SECONDS` | `5` | Deadline for the whole handshake/hello exchange, including a response that arrives slowly. A value that is not a positive number is replaced by `5` and recorded as `invalid_setting`. |
| `ACS_AUDIT_FILE` | (unset) | Append every `ACS_AUDIT` event to this file (created 0600) in addition to stderr — the durable audit half of §6.4's fail-open trade. |
| `ACS_DISABLED` | (unset) | `1` = incident kill switch: bypass all hooks immediately, no Guardian traffic. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |

## On-disk state

- `~/.cache/acs-adapter-handshake/<sha256(session_id+url)>.json` — the session's handshake decision (negotiated ServerHello, refusal, or no answer) with an HMAC under the session key over the decision, the session and the Guardian URL. Mode 0600; kept for the session's lifetime. A record that is modified, damaged, copied from another endpoint or written by an earlier adapter refuses the session, and so does a decision that cannot be stored.
- `~/.cache/acs-guardian-state/<sha256(session_id)>.json` — Guardian-side per-session chain head + replay set; survives Guardian restart.

## Conformance status

Honest, item-by-item against the ACS-Core baseline in `docs/spec/conformance.md`. Some Core items are conditional or SHOULD-level: `subagentStart` binds subagent-capable clients, MODIFY and `system/ping` are SHOULD, and Wrapped MCP binds sessions that involve MCP. The row notes say how each one applies here.

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ adapter sends ClientHello on the first event of a session; the decision (negotiated, refused, or no answer under `ACS_STARTUP_POSTURE`) holds for the session's lifetime (§4.1). |
| Profiles (`profiles_supported` / `profiles_accepted`) | ✓ always claims `acs-core`: a hook with no usable secret and label refuses its session before the handshake. A ServerHello accepting a profile the adapter did not claim is not a valid answer, a claimed profile the Guardian leaves out is audited as `profile_not_accepted`, and a hook's `ACS_REQUIRE_PROFILES` turns a left-out profile into a refusal of that hook's steps. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (`tests/test_envelope_schema.py`); format checking enforces `uuid` and `date-time`. |
| Hook taxonomy (Core minimum set) | ✓ `sessionStart`, `userMessage`, `toolCallRequest`, `toolCallResult`, `agentResponse` (the reply `Stop` carries in `last_assistant_message`), `sessionEnd`; plus `subagentStart`, which ACS-Core requires of a subagent-capable client. Claude Code spawns subagents through the Agent tool (legacy `Task`), and the adapter remaps that PreToolUse to `steps/subagentStart` (see mapping.md). `subagentStop`, which ACS-Core lists as SHOULD-emit, stays deliberately unmapped (see mapping.md). The adapter also emits the turn boundary: `turnStart` (emitted on UserPromptSubmit) / `turnEnd` (Stop). `preCompact` deliberately unmapped — the platform exposes no entry list (mapping.md). |
| Dispositions (ALLOW/DENY/ASK/DEFER) | ✓ on **pre-execution** hooks (`PreToolUse`, `UserPromptSubmit`, `turnStart`). On `PreToolUse` an ALLOW prints nothing, so Claude Code's own permission rules and prompt still decide, and MODIFY is partial: an `ask` carrying `updatedInput` (`parameter_overrides` merged onto the original input), so the user approves the rewritten call. On `PostToolUse` a DENY, ASK, DEFER or unusable MODIFY replaces the output Claude sees for `Bash` and MCP tools, and is recorded as `unenforceable_decision` for other tools. **Lifecycle hooks (`Stop → agentResponse, turnEnd`, `SessionEnd`) are observation-only**: Claude Code fires them after the reply / turn / session has completed, and a Guardian `deny` on them is recorded. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ a verdict outside the five dispositions is denied under either posture and counted as `malformed_response`. |
| SessionContext + published `chain_hash` | ✓ session_id propagated; Guardian computes rolling SHA-256 chain per §8.2 (`adapters/test_acs_core_conformance.py::Core05_SessionContext`). |
| Replay protection (`request_id` + `timestamp`) | ✓ adapter sends both; Guardian rejects duplicate `request_id` (REPLAY_DETECTED -32005) and timestamps outside skew window (TIMESTAMP_OUT_OF_WINDOW -32006) per §10.3. |
| Baseline integrity (HMAC-SHA256 signature) | ✓ HKDF-derived per-session key signs every request and response under `ACS_HMAC_KEY_ID`; a hook with no secret of at least 32 bytes, or no label, refuses its session and sends nothing. The Guardian rejects an unsigned or tampered request with SIGNATURE_INVALID -32004. |
| Decision honoring (§6.4) | ✓ adapter blocks on subprocess return; spec-default fail-open posture emits structured `ACS_AUDIT` event on every bypass; audit `cause` field distinguishes failure modes. |
| Liveness `system/ping` | ⚠ Guardian-side only. ACS-Core says `system/ping` SHOULD be implemented: the Observed Agent declares it in `methods_implemented` and sends it, and the Guardian answers it (§13). The example Guardian answers ping as an always-allow method outside the chain, replay, and signature checks. The adapter does not declare or send `system/ping`, so a deployment that uses it must name an alternative liveness mechanism in its configuration, such as continuous observed hook traffic. Omitting both is non-conformant. |
| `nonce` (optional replay field) | ✗ adapter does not emit `nonce`; the envelope field is OPTIONAL in v0.1. |
| Wrapped MCP `protocols/MCP/*` | ⚠ partial. ACS-Core requires `protocols/MCP/*` for any session that involves MCP, and MCP `tools/call` MAY instead flow through the generic tool hooks. The adapter covers only that case: Claude Code surfaces MCP tool calls as `mcp__*` tools, and the adapter sends them as `steps/toolCallRequest` and `steps/toolCallResult`. It wraps no other MCP surface (`initialize`, `prompts/get`, `resources/read`, notifications), so a session that uses MCP falls short of ACS-Core there. The first MCP tool a signed session uses records `profile_claim_degraded` once. Known limitation. |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Adapter exits 0 with empty stdout; Guardian terminal silent | Adapter pointed at the wrong URL (check `ACS_GUARDIAN_URL` in your settings.json); check stderr for `ACS_AUDIT cause=transport_failure`. |
| Every hook gets denied | Likely `ACS_DEFAULT_DENY=1` + Guardian down. Check the Guardian process is running. |
| Adapter says `SecretFilePermissionsError` | The HMAC secret file is mode > 0600. `chmod 600 ~/.acs/hmac.key`. |
| Guardian returns `-32004 SIGNATURE_INVALID` | Adapter and Guardian aren't reading the same secret. `cat ~/.acs/hmac.key` on both sides should match. |
| Guardian returns `-32006 TIMESTAMP_OUT_OF_WINDOW` | Clock skew between adapter and Guardian > 5 minutes. Sync time (`sudo sntp -sS time.apple.com` on macOS). |
| Guardian returns `-32600 Invalid Request` for `metadata.session_id` | Session ID isn't a UUID. Real Claude Code always sends UUIDs; if you're hand-crafting envelopes for testing, fix the fixture. |

Everything the adapter does that's not policy decision-making is audited on stderr as a JSON line prefixed `ACS_AUDIT`. The `cause` field tells you which failure mode fired.
