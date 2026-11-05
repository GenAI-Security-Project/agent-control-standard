# Example Guardian (shared)

A minimal, deterministic Guardian that all three reference adapters use for their integration tests and quick local demos.

**This is a teaching artifact, not a production Guardian.** Real Guardians plug in OPA / Rego, Cedar, or a vendor's policy engine, and live behind whatever identity / mTLS / audit infrastructure the deployment runs. This one answers ACS JSON-RPC requests with a few hard-coded rules, enough to make every adapter's round trip work end to end.

## What it does

HTTP server on `127.0.0.1:8787` (`--host`, `--port`) that answers JSON-RPC 2.0 POST requests on any path; the adapters' default URL is `http://127.0.0.1:8787/acs`. For every request except `system/ping` it verifies the HMAC-SHA256 signature under the per-session key (§10) and signs its answer; a request under another `key_id` gets an unsigned `SIGNATURE_INVALID` (-32004). Every `steps/*` request is also checked against `request-envelope.json`, and a replayed `request_id` gets -32005 and a timestamp outside the skew window (`ACS_SKEW_WINDOW_MS`, default 5 minutes) gets -32006.

## Policy implemented

Tool names compare case-insensitively, so `Bash` (Claude Code), `Shell` (Cursor) and `shell` (NAT) take the same branch.

| Hook method | Rule |
|---|---|
| `steps/toolCallRequest`, tool `bash` or `shell`, command matching a destructive pattern (`rm -rf` on `/`, `~` or `$HOME`, `rm --no-preserve-root`, `mkfs`, `dd of=/dev/`, a fork bomb, `> /dev/sd*`, `find` on `/` or home with `-delete` or `-exec rm`, `chmod 777` on `/etc`, `/usr`, `/bin` or `/sbin`) | `deny`, `destructive_command` |
| `steps/toolCallRequest`, tool `bash` or `shell`, command longer than 8 KiB | `deny`, `input_too_large` |
| `steps/toolCallRequest`, tool `write`, `file_path` under `/etc/`, `/usr/`, `/bin/`, `/sbin/` or `/boot/` | `deny`, `protected_path` |
| `steps/toolCallRequest`, tool `task` | `deny`, `subagent_gated`; `allow` with `ACS_ALLOW_SUBAGENT=1` |
| Any other `steps/toolCallRequest` | `allow` |
| `steps/subagentStart` | `deny`, `subagent_gated` (`subagent_fresh_intent_gated` when `intent_derivation` is `fresh`); `allow` with `ACS_ALLOW_SUBAGENT=1` |
| `steps/sessionStart`, `steps/sessionEnd`, `steps/turnStart`, `steps/turnEnd`, `steps/userMessage`, `steps/agentResponse`, `steps/agentTrigger`, `steps/toolCallResult`, `steps/preCompact`, `steps/postCompact`, `steps/subagentStop`, `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval` | `allow` |
| `handshake/hello` | a ServerHello (§4) declaring `on_decision_failure: deny`, or `proceed` with `ACS_ON_DECISION_FAILURE=proceed` |
| `system/ping` | `allow` with `{status, echo, server_timestamp}` (§13); unsigned and outside the chain |
| Any other method | `deny`, `unknown_method` |

Every step response carries `chain_hash`, the head of the session's rolling SHA-256 audit chain (§8.2, `entry_hash = sha256(JCS(entry) || previous_hash)`). The chain head and the seen `request_id`s persist per session under `ACS_GUARDIAN_STATE_DIR` (default `~/.cache/acs-guardian-state/`), so a restart keeps replay protection; `ACS_GUARDIAN_STATE_DIR=""` keeps them in memory, for development.

## Why it's shared

All three reference adapters (Claude Code, Cursor and NAT, under `src/acs/integrations/`) speak the same ACS JSON-RPC wire format. Their integration tests all need a Guardian that:

- Accepts ACS JSON-RPC requests
- Returns deterministic decisions (so tests can assert specific outcomes)
- Logs to stderr so a human running it locally can see what's happening

## How to run it

The Guardian starts only with a secret of at least 32 bytes and the label that names it, the same pair the adapters use:

```bash
openssl rand -hex 32 > ~/.acs-hmac.key && chmod 600 ~/.acs-hmac.key
export ACS_HMAC_SECRET_FILE=~/.acs-hmac.key ACS_HMAC_KEY_ID=local-dev

# default: 127.0.0.1:8787
acs-example-guardian

# custom port; --port 0 binds a free one
acs-example-guardian --port 8788
```

It prints `ACS_GUARDIAN_LISTENING port=<port>` on stdout once bound, and logs each request and its verdict to stderr:

```
[guardian] listening on 127.0.0.1:8787 (case-insensitive-tool-policy)
[guardian] steps/toolCallRequest session=3f2a9c1e req=8d41b7a0
[guardian] → allow
```

## How to extend

The policy is in the `evaluate_step(method, params, request_id, chain_hash)` function. To add a rule, add a pattern to `DESTRUCTIVE_BASH_PATTERNS` (`src/acs/examples/destructive_bash.py`), add a branch in `evaluate_step`, or add a method to `INFORMATIONAL_METHODS`.

Production deployments replace this whole file with their actual policy engine. The wire shape (request format, response format) stays the same.

## What this is NOT

- **Not a production Guardian.** One shared HMAC secret is its only authentication: no per-agent identity, no TLS, no rate limiting, and the policy is the hard-coded table above.
- **Not the only Guardian.** Anyone can write one: the spec defines the wire contract, the implementation is the deployment's choice.
- **Not an SDK.** Just an HTTP server with hard-coded rules. If you want an SDK to build Guardians, that's a separate workstream.
