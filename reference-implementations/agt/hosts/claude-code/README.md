# Claude Code host shim

`acs-hook.ts` is Claude Code's hook subprocess. Claude Code starts it once per hook event, writes the hook payload to its stdin, and reads one JSON decision from its stdout. The shim builds an ACS envelope from that payload with the [host adapter](../../packages/host-adapter/README.md), posts it to the Guardian, and renders the decision in the shape Claude Code accepts. It never runs the command, and it contains no AGT code.

## Get started

1. Start the Guardian from `reference-implementations/agt`. The [tree README](../../README.md#start-the-guardian) shows the command.

2. Register the hook in the project you run Claude Code in.

```bash
mkdir -p .claude
cp hosts/claude-code/settings.json .claude/settings.json
```

The shipped `settings.json` names the hook as `bun run "$CLAUDE_PROJECT_DIR/hosts/claude-code/acs-hook.ts"`. That resolves when the project is this tree. From any other project, replace `$CLAUDE_PROJECT_DIR/hosts/claude-code/acs-hook.ts` with this file's absolute path.

It registers two events. `PreToolUse` fires for `Bash` and `WebFetch`, before the tool runs. `PostToolUse` fires for `Bash`, after the tool has run. Both matchers are anchored, so no other tool is intercepted.

3. Start `claude` and ask it to run `echo rm -rf /`. The hook sends the call to the Guardian, AGT's stock pattern rule denies it, and Claude Code shows the reason in the transcript. `ls -la` in the same session runs.

## Drive it by hand

You do not need Claude Code to see a decision. Pipe a payload into the shim while the Guardian runs.

```bash
echo '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | bun run hosts/claude-code/acs-hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."}}
```

The first hook of a session sends `handshake/hello` and stores the Guardian's answer under `.acs/sessions/<session_id>.json`, so the next subprocess for that session finds it and skips the handshake.

## What it reads

| Variable | Default | What it does |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://localhost:8787/acs` | Where the shim sends envelopes |
| `ACS_SESSION_DIR` | `.acs/sessions` | Where the negotiated ServerHello is stored, one file per session |
| `ACS_AUDIT_LOG` | `.acs/audit.jsonl` | Where fail-open proceeds and posture-driven blocks are written |
| `ACS_HOOKMAP_PATH` | `claude-code.hookmap.yaml`, beside the shim | Which hookmap to load. This changes what governance means for the host. Leave it unset in a deployment |

## Exit codes

Claude Code reads the exit code before it reads stdout, so the shim uses exactly two.

| Exit | When |
|---|---|
| `0`, with a decision on stdout | Every real outcome, including `deny`. The deny travels in the JSON body, not the exit code. A Guardian that is down, a timeout, or a decision the host cannot render are all resolved by the negotiated `on_decision_failure` posture and audited |
| `2`, with stderr only | The shim cannot trust its own input or configuration: stdin is not JSON, the payload has no string `hook_event_name` or `session_id`, the session id is unsafe as a path segment, the hookmap fails to load, or the hookmap declares an output Claude Code does not accept |

Exit `1` never appears. Claude Code reads it as "the hook did not fire" and proceeds ungoverned.

## The result gate

At `PostToolUse` the tool has already run, and Claude Code's `block` alone withholds nothing. So a `deny`, an `ask` or a `defer` at the result gate replaces the output, and a `modify` applies the redaction to the output the model will see. A modification the host cannot apply, or a `modified_content` replacement, is refused, and the refusal withholds. A `defer` renders as `deny` at both gates, because Claude Code has no deferral state.

## The hookmap

`claude-code.hookmap.yaml` is the only file in this tree, besides the shim, that is specific to Claude Code. It is pure data. It maps `PreToolUse` to `steps/toolCallRequest` and `PostToolUse` to `steps/toolCallResult`, says where the tool name, the arguments and the output sit in Claude Code's payload, and declares how each ACS decision renders at each event. Its comments record what was measured about Claude Code's hook protocol.

## Files

| File | What it holds |
|---|---|
| `acs-hook.ts` | The shim |
| `claude-code.hookmap.yaml` | The hookmap |
| `settings.json` | The hook registration to copy into a project |

## Tests

```bash
bun test hosts/claude-code
```

Four files. `hook.test.ts` drives the shim as a real subprocess against a live Guardian and the pinned bundle. `post-tool-use.test.ts` covers the result gate. `posture.test.ts` covers every failure and its audit entry. `wire-shape.test.ts` pins the exact output shape Claude Code accepts at each event.
