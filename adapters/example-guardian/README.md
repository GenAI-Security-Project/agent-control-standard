# Example Guardian (shared)

A minimal, deterministic Guardian that all three reference adapters use for their integration tests and quick local demos.

**This is a teaching artifact, not a production Guardian.** Real Guardians plug in OPA / Rego, Cedar, or a vendor's policy engine, and live behind whatever identity / mTLS / audit infrastructure the deployment runs. This one is a hundred lines of stdlib Python that responds to ACS JSON-RPC requests with hard-coded rules — enough to make every adapter's round-trip work end-to-end without external dependencies.

## What it does

HTTP server on `127.0.0.1:8787` (configurable via `--port`) that accepts JSON-RPC 2.0 POST requests at `/acs` and returns ACS decision envelopes.

## Policy implemented

| Hook method | Rule |
|---|---|
| `steps/toolCallRequest` with `tool.name in {"Bash", "Shell"}` and `command` matching a destructive regex (`rm -rf /...`, `mkfs`, `dd if=`, fork-bomb pattern, `> /dev/sda`) | `deny` with reasoning |
| `steps/toolCallRequest` with `tool.name == "Write"` and `file_path` under `/etc/` or `/usr/` | `deny` with reasoning |
| Any other `steps/toolCallRequest` | `allow` |
| `steps/sessionStart`, `steps/sessionEnd`, `steps/userMessage`, `steps/toolCallResult`, `steps/agentResponse`, `steps/preCompact`, `steps/postCompact`, `steps/subagentStart`, `steps/subagentStop`, `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval` | `allow` |
| Any other method | `deny` with `reasoning: "unknown method: ..."` |

Every response carries a `chain_hash` field derived from `session_id + method + step_id` (SHA-256). Real Guardians would maintain a rolling chain across the session; this one computes a per-request hash so the adapter can observe the field shape.

## Why it's shared

All three reference adapters (`adapters/claude-code/`, `adapters/cursor/`, `adapters/nat/`) speak the same ACS JSON-RPC wire format. Their integration tests all need a Guardian that:

- Accepts ACS JSON-RPC requests
- Returns deterministic decisions (so tests can assert specific outcomes)
- Logs to stderr so a human running it locally can see what's happening

One shared Guardian satisfies all three. The previous arrangement (`adapters/claude-code/example_guardian.py`, imported by NAT and Cursor tests via `../../claude-code/`) was a smell.

## How to run it

```bash
# default: 127.0.0.1:8787
python3 example_guardian.py

# custom port
python3 example_guardian.py --port 8788
```

The server logs every received request to stderr in one line:

```
[guardian] listening on 127.0.0.1:8787
[guardian] steps/toolCallRequest session=abc-123 step=def4567
```

## How to extend

The policy is in the `evaluate(method, params)` function. To add a new rule, either add to the destructive regex, add a new branch in the toolCallRequest handler, or add a method to the allow-list.

Production deployments replace this whole file with their actual policy engine. The wire shape (request format, response format) stays the same.

## What this is NOT

- **Not a production Guardian.** No identity verification, no authentication, no signed envelopes, no audit chain that survives a restart, no rate limiting.
- **Not the only Guardian.** Anyone can write one — the spec defines the wire contract, the implementation is the deployment's choice.
- **Not an SDK.** Just an HTTP server with hard-coded rules. If you want an SDK to build Guardians, that's a separate workstream.
