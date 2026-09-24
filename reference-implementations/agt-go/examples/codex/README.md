# Codex example

This example sends Codex `PreToolUse` events for `Bash` to the Go Guardian as signed
`steps/toolCallRequest` messages. ACS ALLOW completes the hook, ACS DENY becomes
Codex's native `permissionDecision: deny`, and ACS MODIFY supplies `updatedInput`.
ASK and DEFER become DENY because Codex does not support either response at
`PreToolUse`.

The checked-in [`.codex`](../../.codex) configuration belongs to this Go module. Codex
loads it when it starts from the module root. It does not change the user's Codex
configuration or the configuration at the repository root.

Prerequisites are Go 1.27.1 or newer, Make, OpenSSL, curl and an installed,
authenticated `codex` command. This example was tested with Codex CLI 0.154.0.

Run from `reference-implementations/agt-go`:

```bash
cd agent-control-standard/reference-implementations/agt-go
make codex-example
```

The command creates a local development HMAC secret on first run, builds the Guardian
and adapter, starts the Guardian on a free local port, and opens Codex. The Guardian
stops when Codex exits, including an error or interrupt.
Each invocation has its own temporary Guardian logs, so this example can run
at the same time as the OpenCode example.
You can use the Codex session normally. The command uses the account already configured
by `codex login`; it does not supply an API key or create separate model billing.
The target enables this checkout's project hook without a trust prompt and grants
workspace network access so the hook can reach the loopback Guardian. Both settings
apply only to the Codex process started by this command. Network access is not
limited to the hook: it also opens the network to the commands Codex itself
runs in that session, so the policy alone decides what may leave the machine.
Inspect [`.codex/hooks.json`](../../.codex/hooks.json) before running it.

The hook reads `ACS_GUARDIAN_URL` when it is set and otherwise uses
`http://127.0.0.1:8787/acs`. `make codex-example` sets the temporary endpoint
for the Codex process it starts.

Ask Codex to run `ls -la`; the checked-in policy allows it. Ask Codex to run
`echo rm -rf /`; the checked-in policy denies it before Bash runs.

For a deployment, provide a separate Guardian configuration and HMAC secret. The hook
state contains only the negotiated ServerHello. It holds no keying material. When a
negotiated `proceed` failure posture lets a tool call continue without a verified
decision, the hook appends a local event to `.acs/codex-audit.jsonl`.
If the initial handshake produces no ServerHello, this example uses the ACS startup
posture `refuse` and denies the tool call.
