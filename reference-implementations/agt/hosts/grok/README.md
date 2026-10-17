# Grok Build TUI host shim

`acs-hook.ts` is Grok's hook subprocess. Grok starts it once per hook event, writes the hook payload to its stdin, and reads one JSON decision from its stdout. The shim builds an ACS envelope from that payload with the [host adapter](../../packages/host-adapter/README.md), posts it to the Guardian, and renders the decision in the shape Grok accepts. It never runs the command, and it contains no AGT code.

This is a third host against an unchanged adapter. The Claude Code shim is the subprocess template. Grok's measured payload uses `run_terminal_command` and a tagged `tool_response`; Grok also accepts native `defer` on PreToolUse. See [#107](https://github.com/GenAI-Security-Project/agent-control-standard/issues/107) and [#108](https://github.com/GenAI-Security-Project/agent-control-standard/issues/108).

## Get started

1. Start the Guardian from `reference-implementations/agt`. The [tree README](../../README.md#start-the-guardian) shows the command.

2. Register the hook. Grok's `workspaceRoot` is the git workspace, not this `agt/` tree, so `$GROK_PROJECT_DIR/hosts/grok/acs-hook.ts` does not resolve. Copy the shipped file into Grok's global hooks directory (always trusted) when the Grok workspace is this repository:

```bash
cp hosts/grok/hooks.json ~/.grok/hooks/acs-agt.json
```

The shipped `hooks.json` names the hook as `bun run "$GROK_PROJECT_DIR/reference-implementations/agt/hosts/grok/acs-hook.ts"`. That resolves when Grok's workspace is the ACS git root. From any other workspace, replace that path with this file's absolute path.

It registers two events. `PreToolUse` and `PostToolUse` both fire for `run_terminal_command`. The shipped Claude matcher `^(Bash|WebFetch)$` does not block Grok's PreToolUse; do not use it here.

3. Start Grok from a shell where the Guardian is reachable, with folder trust if you used a project hook:

```bash
grok --trust
```

Ask it to run `echo rm -rf /`. The hook sends the call to the Guardian. AGT's stock pattern rule denies it. `ls -la` in the same session runs.

Use `echo rm -rf /` rather than `rm -rf /` when you script this. The pattern matches at offset 5 and the command is inert if the hook ever fails.

## Drive it by hand

You do not need Grok to see a decision. Pipe a payload into the shim while the Guardian runs.

```bash
echo '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"run_terminal_command","tool_input":{"command":"rm -rf /"}}' \
  | bun run hosts/grok/acs-hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."}}
```

A payload that only carries Grok's camelCase (`sessionId`, `hookEventName: "pre_tool_use"`) is also complete. The first hook of a session sends `handshake/hello` and stores the Guardian's answer under `.acs/sessions/<session_id>.json`, so the next subprocess for that session finds it and skips the handshake.

## What it reads

| Variable | Default | What it does |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://localhost:8787/acs` | Where the shim sends envelopes |
| `ACS_SESSION_DIR` | `.acs/sessions` | Where the negotiated ServerHello is stored, one file per session |
| `ACS_AUDIT_LOG` | `.acs/audit.jsonl` | Where fail-open proceeds and posture-driven blocks are written |
| `ACS_HOOKMAP_PATH` | `grok.hookmap.yaml`, beside the shim | Which hookmap to load. This changes what governance means for the host. Leave it unset in a deployment |

## Exit codes

Grok treats PreToolUse exit 2 as an explicit deny. A crash, timeout, or malformed output is fail-open. The shim uses exactly two exits.

| Exit | When |
|---|---|
| `0`, with a decision on stdout | Every real outcome, including `deny`. The deny travels in the JSON body, not the exit code. A Guardian that is down, a timeout, or a decision the host cannot render are all resolved by the negotiated `on_decision_failure` posture and audited |
| `2`, with stderr only | The shim cannot trust its own input or configuration: stdin is not JSON, the payload has no string session id (`session_id` or `sessionId`) or hook event name, the session id is unsafe as a path segment, the hookmap fails to load, or the hookmap declares an output Grok does not accept |

Exit `1` never appears.

## The result gate

At `PostToolUse` the tool has already run, and Grok's `block` alone withholds nothing. So a `deny`, an `ask` or a `defer` at the result gate replaces the tagged output, and a `modify` applies the redaction to `output_for_prompt`. A modification the host cannot apply, or a `modified_content` replacement, is refused, and the refusal withholds. A `defer` on PreToolUse renders as `defer`, because Grok has native deferral. At the result gate, `defer` still withholds: the tool has already run.

Grok validates `updatedToolOutput` against its tagged result object (`type: Bash`, `output_for_prompt`, `exit_code`, ...). A replacement that is only a string is dropped.

`tool_response.output` is a byte array of the raw output. This hookmap does not declare a mirror for it, so a redaction patches `output_for_prompt` (what the model reads) and leaves the byte array as it was.

## The hookmap

`grok.hookmap.yaml` is the only file in this tree, besides the shim, that is specific to Grok. It is pure data. It maps `PreToolUse` to `steps/toolCallRequest` and `PostToolUse` to `steps/toolCallResult`, says where the tool name, the arguments and the output sit in Grok's payload, and declares how each ACS decision renders at each event. Its comments record what was measured about Grok's hook protocol.

## What this host does not map

Fetch, skills, compact, subagent lifecycle, and a handshake from the host. This tree evaluates two live hooks. Match that.

## Files

| File | What it holds |
|---|---|
| `acs-hook.ts` | The shim |
| `grok.hookmap.yaml` | The hookmap |
| `hooks.json` | The hook registration to copy into `~/.grok/hooks/` |

## Tests

```bash
bun test hosts/grok
```

Four files. `hook.test.ts` drives the shim as a real subprocess against a live Guardian and the pinned bundle. `post-tool-use.test.ts` covers the result gate. `posture.test.ts` covers every failure and its audit entry. `wire-shape.test.ts` pins the exact output shape Grok accepts at each event, including native `defer`.
