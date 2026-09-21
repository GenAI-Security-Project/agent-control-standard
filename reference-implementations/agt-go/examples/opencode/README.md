# OpenCode example

This example sends OpenCode V2 `execute.before` and `execute.after` tool events to
the Go Guardian as signed `steps/toolCallRequest` and `steps/toolCallResult`
messages. The checked-in [plugin](../../.opencode/plugins/acs.ts) is local to this
module and does not change the user's OpenCode configuration.

Prerequisites are Go 1.27.1 or newer, Make, OpenSSL, curl and an installed
`opencode` command with an available model. The model may come from a connected
provider or from the free models in OpenCode's catalog. This example was tested
with OpenCode 2.0.11.

Run from `reference-implementations/agt-go`:

```bash
cd agent-control-standard/reference-implementations/agt-go
make opencode-example
```

The command creates a local development HMAC secret on first run, builds the
Guardian and adapter, starts the Guardian on a free local port, and opens
OpenCode. The Guardian stops when OpenCode exits, including an error or
interrupt. Each invocation has its own temporary Guardian logs, so this
example can run at the same time as the Codex example. No JavaScript package
installation is required.

Ask OpenCode to run `printf ACS_OPENCODE_OK`; the checked-in policy allows it.
Ask it to run `echo rm -rf /`; the checked-in policy denies it before the shell
runs.

The request gate applies ALLOW, DENY and MODIFY before a tool executes. ASK and
DEFER block because OpenCode has no ACS approval or deferral channel. The result
gate sends completed and failed results to the Guardian before the model sees them.
DENY, ASK or DEFER replaces the result or error with the Guardian's reason. MODIFY
is applied only when its replacement fits the original result status; an unusable
replacement fails closed.

To connect the plugin to a Guardian already running elsewhere, build the adapter
and set the endpoint for the OpenCode process:

```bash
go build -o .acs/bin/acs-opencode-hook ./examples/opencode/cmd/acs-opencode-hook
ACS_GUARDIAN_URL=http://127.0.0.1:8788/acs opencode
```

`ACS_OPENCODE_HMAC_SECRET_FILE` selects the matching shared-secret file. The
defaults are `http://127.0.0.1:8787/acs` and `.acs/hmac-secret`.
If the initial handshake produces no ServerHello, this example uses the ACS startup
posture `refuse` and blocks the tool event.
