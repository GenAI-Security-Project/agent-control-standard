# ACS adapter: Claude Code

A drop-in adapter that wires [Claude Code](https://docs.claude.com/claude-code) hooks to an ACS Guardian. No agent code changes; configuration only.

## How it works

Claude Code fires a hook (e.g. `PreToolUse`) by running a shell command and passing the hook event as JSON on stdin. The command's stdout becomes the hook's decision.

This adapter is that command. On every hook event Claude Code spawns the adapter as a subprocess; the adapter:

1. Reads the Claude Code hook event from stdin.
2. Translates it to an ACS JSON-RPC envelope ([mapping.md](./mapping.md)).
3. Signs it with HMAC-SHA256 (`ACS_HMAC_SECRET_FILE`).
4. POSTs to the Guardian.
5. Verifies the response signature.
6. Translates the verdict back to Claude Code's expected output shape and writes to stdout.
7. Exits.

The handshake/hello fires once per session, cached on disk so subsequent events skip the round-trip.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. Claude Code provides this guarantee through its hook protocol: the adapter is invoked as a blocking subprocess and the framework reads its stdout for the decision, so the tool can't run until the adapter exits with a verdict. The adapter relies on this — without it, a Guardian deny would arrive after the side effect.

## Install — five steps

You need three pieces co-located on the same machine: a running Guardian, a shared HMAC secret, and a `~/.claude/settings.json` that wires the adapter into Claude Code's hooks. `wire.py` does step 3 for you.

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
  python3 $ACS_REPO/adapters/example-guardian/example_guardian.py \
  --port 8787
```

Keep this terminal open. You should see `[guardian] listening on 127.0.0.1:8787`.

(For long-running setups: a `launchd` plist on macOS or a `systemd` unit on Linux. Out of scope here.)

### 3. Wire `~/.claude/settings.json`

The `wire.py` CLI does this safely — dry-run by default, atomic write with a timestamped backup when you pass `--write`.

```bash
cd "$ACS_REPO/adapters/claude-code"

# Preview the change without touching the file
python3 wire.py \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key

# Apply it (creates ~/.claude/settings.json.bak.<timestamp>)
python3 wire.py \
  --guardian-url=http://127.0.0.1:8787/acs \
  --secret-file=~/.acs/hmac.key \
  --write
```

What it wires by default:

| Hook | Posture |
|---|---|
| `PreToolUse` | **fail-CLOSED** (gate — silent fail-open is a policy hole) |
| `UserPromptSubmit` | **fail-CLOSED** (gate) |
| `SessionStart` | fail-open (observational; §6.4 default) |
| `PostToolUse` | fail-open |
| `Notification` | fail-open |
| `SessionEnd` | fail-open |

Override with `--default-deny` (fail-closed on every hook) or `--all-fail-open` (strict §6.4 default everywhere).

To remove the wiring later: `python3 wire.py --unwire --write`.

### 4. Restart any open Claude Code session

Claude Code reads `~/.claude/settings.json` at session start, not live. Existing sessions keep their pre-wiring config.

### 5. Verify the install

Two complementary checks. The end-to-end check is the one to run if you only have time for one:

```bash
cd "$ACS_REPO/adapters/claude-code"
python3 e2e_check.py
```

Real Claude is driven through four scenarios — allow, deny, Read tool, multi-tool handshake-once — every envelope is printed verbatim, you read PASS/FAIL per scenario. Wall-clock ~60-90s because real Claude is in the loop. The final line is either `ACS-CORE SMOKE PASS (claude-code)` (exit 0) — a smoke verdict, not a conformance certification — or a per-scenario failure list (exit 1).

You can also do an in-session manual smoke test (see [Smoke tests](#smoke-tests) below).

## Prerequisites

- **`claude` CLI** installed and authenticated — install guide: <https://docs.claude.com/claude-code>
- **Python 3.10+** with `rfc8785` (the adapter's one runtime dependency) — `pip install -r requirements.txt`. For running the test suites you also need `jsonschema`: `pip install -r ../requirements-test.txt`
- **Canonical ACS schemas** — the in-repo copy at `specification/v0.1.0/` is the default, so no setup is needed when running from a clone of this repo. Set `ACS_SPEC_DIR` only to validate against a different spec checkout.

## Smoke tests

Five tests, ordered from broadest to most specific. Run any/all.

### Smoke #1 — automated test suite (unit + integration, ~30s)

Run from `adapters/`:

```bash
cd "$ACS_REPO/adapters"
python3 run_conformance.py claude
# Runs the shared Guardian and _common checks, then Claude Code's suite.
```

The command reports passes, skips, and failures separately. It fails on any test failure or unexpected skip.

### Smoke #2 — real Claude end-to-end (~60-90s)

```bash
cd "$ACS_REPO/adapters/claude-code"
python3 e2e_check.py
```

Drives real Claude through 4 scenarios with a recording Guardian. Prints every envelope on the wire plus per-scenario PASS/FAIL.

### Smoke #3 — in-session manual test

Open a real Claude Code session. Try:

```
echo hello via Bash
```

In your Guardian terminal you should see roughly this sequence (one new entry per hook Claude fires):

```
[guardian] handshake/hello       session=<uuid>...
[guardian] steps/sessionStart    session=<uuid>...
[guardian] steps/userMessage     session=<uuid>...
[guardian] steps/toolCallRequest session=<uuid>...
[guardian] steps/toolCallResult  session=<uuid>...
[guardian] steps/agentResponse   session=<uuid>...
[guardian] steps/sessionEnd      session=<uuid>...
```

Then try a denied command in the same session:

```
Run: rm -rf /home/some-fake-path
```

Claude should refuse and surface the Guardian's `reasoning` field. The example Guardian's regex catches `rm -rf /...`; the Bash never runs.

### Smoke #4 — audit-cause differentiation

Verifies that the adapter's audit log distinguishes "Guardian unreachable" (ops issue) from "Guardian rejected the envelope" (client/operator bug).

Unsigned envelope to a signing-required Guardian:

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:8787/acs" \
ACS_HMAC_SECRET="" \
python3 $ACS_REPO/adapters/claude-code/acs_adapter.py 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","transcript_path":"/tmp/t","cwd":"/tmp","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo test"}}
EOF
```

Expected stderr — note the `cause` field, and that a signature refusal
fails CLOSED regardless of posture (a refusal is an alive Guardian
rejecting the envelope; spec issue #32):

```
acs-adapter: Guardian returned JSON-RPC error -32004 (signature_invalid_response): SIGNATURE_INVALID
ACS_AUDIT {"acs_audit_event": "guardian_refusal_fail_closed", "cause": "signature_invalid_response", ...}
```

And stdout carries a real deny:

```
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", ...}}
```

Guardian unreachable (different cause, same disposition):

```bash
ACS_GUARDIAN_URL="http://127.0.0.1:1/dead" \
python3 $ACS_REPO/adapters/claude-code/acs_adapter.py 2>&1 <<'EOF'
{"session_id":"11111111-1111-4111-8111-111111111111","transcript_path":"/tmp/t","cwd":"/tmp","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo test"}}
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
python3 -c "import json, os; d=json.load(open(os.path.expanduser('~/.claude/settings.json'))); print(list(d.get('hooks',{}).keys()))"

echo "=== Guardian responds to system/ping? ==="
cd "$ACS_REPO/adapters" && python3 -c "
import sys; sys.path.insert(0, '_common')
from acs_common import ping; import json
r = ping('http://127.0.0.1:8787/acs'); print(json.dumps(r, indent=2)[:200] if r else 'no response')
"
```

## Files

- `acs_adapter.py` — the adapter itself. Stdlib + `rfc8785` for JCS canonicalization.
- `wire.py` — settings.json wiring CLI (dry-run by default; `--write` to apply).
- `e2e_check.py` — real-Claude end-to-end verifier (4 scenarios).
- `settings.json.example` — reference wiring (`wire.py` produces a more comprehensive one).
- `mapping.md` — Claude Code hook → ACS step method table, plus disposition translation.
- `tests/` — round-trip + schema + live integration tests.
- `tests/example_payloads.md` — masked real-world payload examples showing exactly what Claude Code emits.

The adapter shares `adapters/_common/` with the Cursor and NAT adapters (signing, handshake cache, audit events, URL allowlist).

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
| `ACS_AUDIT_FILE` | (unset) | Append every `ACS_AUDIT` event to this file (created 0600) in addition to stderr — the durable audit half of §6.4's fail-open trade. |
| `ACS_DISABLED` | (unset) | `1` = incident kill switch: bypass all hooks immediately, no Guardian traffic. |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | (unset) | Optional comma-separated hostname allowlist (defense in depth). |

## On-disk state

- `~/.cache/acs-adapter-handshake/<sha256(session_id+url)>.json` — cached ServerHello per session. Adapter creates with mode 0600; refreshed when older than 1 hour.
- `~/.cache/acs-guardian-state/<sha256(session_id)>.json` — Guardian-side per-session chain head + replay set; survives Guardian restart.

## Conformance status

Honest, item-by-item against `docs/spec/conformance.md`. (PR #21 — open, not in this branch — proposes relaxing some items to SHOULD/conditional; the row notes say which. Against this branch's spec text those items remain as written.)

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ adapter sends ClientHello on first session call; cached in `~/.cache/acs-adapter-handshake/`. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (`tests/test_envelope_schema.py`); format checking enforces `uuid` and `date-time`. |
| Hook taxonomy (Core minimum set) | ✓ `sessionStart`, `userMessage`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd`; plus `subagentStart` via the PreToolUse(Agent — legacy Task) remap (proposed Core floor in PR #21, which is not part of this branch; see mapping.md), with `subagentStop` deliberately unmapped (final_chain_hash required by the current schema and unknowable — see mapping.md), and the turn boundary: `turnStart` (emitted on UserPromptSubmit) / `turnEnd` (Stop). `preCompact` deliberately unmapped — the platform exposes no entry list (mapping.md). |
| Dispositions (ALLOW/DENY/ASK/DEFER) | ✓ on **pre-execution** hooks (`PreToolUse`, `UserPromptSubmit`, `turnStart`); MODIFY partial (`PreToolUse` with `parameter_overrides`, merged onto the original input). **Post-execution and lifecycle hooks (`PostToolUse`, `Notification → agentResponse`, `Stop → turnEnd`, `SessionEnd`) are observation-only** — Claude Code fires them after the side effect / message / turn has occurred; a Guardian `deny` on those cannot undo it. See `mapping.md`. |
| Unknown-disposition fail posture | ✓ default-deny honored on unknown verdicts when `ACS_DEFAULT_DENY=1`; spec-default fail-open path emits audit event. |
| SessionContext + published `chain_hash` | ✓ session_id propagated; Guardian computes rolling SHA-256 chain per §8.2 (`adapters/test_acs_core_conformance.py::Core05_SessionContext`). |
| Replay protection (`request_id` + `timestamp`) | ✓ adapter sends both; Guardian rejects duplicate `request_id` (REPLAY_DETECTED -32005) and timestamps outside skew window (TIMESTAMP_OUT_OF_WINDOW -32006) per §10.3. |
| Baseline integrity (HMAC-SHA256 signature) | ✓ HKDF-derived per-session key signs every request and response when `ACS_HMAC_SECRET[_FILE]` is set; Guardian rejects unsigned/tampered with SIGNATURE_INVALID -32004. |
| Decision honoring (§6.4) | ✓ adapter blocks on subprocess return; spec-default fail-open posture emits structured `ACS_AUDIT` event on every bypass; audit `cause` field distinguishes failure modes. |
| Liveness `system/ping` | ✓ Guardian-side only — Guardian implements an always-allow ping bypassing chain/replay/signature (§13); the adapter does NOT emit it. |
| `nonce` (optional replay field) | ✗ adapter does not emit `nonce`; the envelope field is OPTIONAL in v0.1. |
| Wrapped MCP `protocols/MCP/*` | ✗ not implemented; Claude Code's MCP traffic flows through its own mechanism and would need a separate wrapping path. |

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
