# ACS adapter: Codex

This first slice for [#89](https://github.com/GenAI-Security-Project/agent-control-standard/issues/89) lets an ACS Guardian allow, deny or rewrite a Codex tool call before it runs. Codex runs `acs-codex-hook` as its `PreToolUse` hook, and the command sends the call to the Guardian as a signed `steps/toolCallRequest`.

```text
Codex PreToolUse -> signed steps/toolCallRequest -> Guardian
Codex runs, blocks or rewrites the call <- signed decision
```

The adapter advertises only `steps/toolCallRequest`, the Guardian URL's transport, and no conformance profile. Session and turn lifecycle, tool results, compaction, subagent lifecycle and Wrapped MCP are outside this slice. See [mapping.md](mapping.md).

## Install and run a local demo

The live procedure below passed on **Codex CLI 0.142.5, macOS**, on 2026-11-03. That is a tested version, not a minimum.

Commands below assume `$ACS_REPO` points at your clone of `GenAI-Security-Project/agent-control-standard`:

```bash
export ACS_REPO=/path/to/your/clone
uv tool install "$ACS_REPO/adapters"  # or: pipx install "$ACS_REPO/adapters"
```

Installing the package puts `acs-codex-hook` and `acs-example-guardian` on your PATH.

### 1. Generate the shared HMAC secret

The adapter and the Guardian read the same file. §10 requires at least 32 bytes, and the adapter refuses a file that is a symlink or readable by anyone but its owner.

```bash
mkdir -p ~/.acs
openssl rand -hex 32 > ~/.acs/hmac.key
chmod 600 ~/.acs/hmac.key
```

### 2. Run the Guardian

`ACS_HMAC_KEY_ID` is the label both sides give the secret. A request signed under a label the Guardian does not hold gets an unsigned `-32004`, and the adapter denies the call.

```bash
ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
  acs-example-guardian --port 8787
```

The example Guardian's policy is a teaching policy, not a complete shell policy.

### 3. Add the hook

Merge the `PreToolUse` entry from [hooks.json.example](hooks.json.example) into your project's `.codex/hooks.json`, keeping any hooks already there. Replace each path with an absolute one, and quote any path that contains spaces. `command -v acs-codex-hook` prints the installed command's path.

The example sets `ACS_DEFAULT_DENY=1` and matches only `Bash`, which covers Codex's `exec_command` path. It runs synchronously, so do not add `async: true`.

### 4. Trust the hook

Review the exact hook with Codex `/hooks` and trust the project configuration. Codex skips an untrusted hook. Then try a harmless command such as `printf hello`.

## Configuration

| Setting | Behavior |
|---|---|
| `ACS_GUARDIAN_URL` | The Guardian, over HTTP(S); defaults to `http://127.0.0.1:8787/acs` |
| `ACS_HMAC_SECRET_FILE` | The shared signing secret, at least 32 bytes, mode `0600`. `ACS_HMAC_SECRET` also works, but prefer the file |
| `ACS_HMAC_KEY_ID` | The label that names the secret (§10). Without it, or without a secret, every call is denied before anything is sent |
| `ACS_DEFAULT_DENY` | `0` lets a call that gets no usable decision proceed, audited. Unset, or any other value, denies it |
| `ACS_STARTUP_POSTURE` | What happens when no Guardian answers the handshake: `proceed` lets the call run, audited, with nothing sent to the Guardian. Unset, or any other value, denies it |
| `ACS_AUDIT_FILE` | A durable audit file, written as well as stderr |
| `ACS_HANDSHAKE_CACHE` | Where session decisions are stored |
| `ACS_AGENT_ID` | The deployment's own agent identity |
| `ACS_DISABLED` | `1` sends nothing and lets every call proceed, audited as `acs_disabled_bypass` |

A Guardian's negotiated `on_decision_failure: deny` also denies, and neither side can weaken the other's deny. A missing or unreadable secret, invalid hook input, an invalid signature, a mis-bound response and a refusal code deny under either posture. Each substitution and failure writes an `ACS_AUDIT` line.

When a valid ServerHello leaves `steps/toolCallRequest` out of `methods_evaluated`, the Guardian has not agreed to evaluate tool calls. The adapter records `method_not_evaluated`, sends no tool-call request, and leaves the decision to Codex's own permissions, even with `ACS_DEFAULT_DENY=1`.

The handshake gets 5 seconds. A negotiated decision timeout up to 10 seconds is supported, and a longer one denies before the step is sent. Keep the hook's own timeout above both (the example uses 30). A hook that Codex kills, disables or does not trust cannot deny anything, so a fail-closed adapter does not make Codex a fail-closed enforcement boundary.

## Run the tests

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --group test
uv run python run_conformance.py codex
```

This runs the shared checks and the Codex suite with no model account or Codex install. The suite runs the adapter as a subprocess against `CaptureGuardian`, which checks the bytes it sends against the repository schemas and recomputes their signatures. It covers each decision, input preservation, request binding, both postures, timeouts, malformed messages, the hook command's own fallback and the declared capabilities.

## Verify enforcement in the real Codex CLI

```bash
cd "$ACS_REPO/adapters"
uv run python tests/integrations/codex/live_verify.py --evidence-dir /tmp/acs-codex-evidence
```

This check needs the Codex CLI, and it fails rather than skips when the CLI is missing or any assertion fails. It runs the real CLI, the installed `acs-codex-hook` and a signed test Guardian. A scripted Responses endpoint on localhost emits exactly one `exec_command` call per case and then finishes, so there is no model inference and no external model request.

The fixture uses a dummy provider credential, ignores user config and rules, disables plugins, and supplies the reviewed test hook on each run. Its `--dangerously-bypass-hook-trust` flag applies only to these runs; normal setup uses `/hooks` review. System-managed hooks can still affect the run, so use a test machine or session.

| Guardian decision | Required result |
|---|---|
| ALLOW | Only `original.marker` exists, with its expected content |
| DENY | Neither marker exists, and Codex returns the Guardian's reason to the model |
| MODIFY | Only `replacement.marker` exists, with its expected content |

The check also requires exactly one signed, schema-valid tool request per case and a completed CLI run. It saves a summary, the wire captures and the CLI logs. It proves the `exec_command`/`Bash` path, not every tool path or a hosted-model session.

## Coverage limits

The example configuration covers shell commands. Object-valued MCP and other local-function arguments, and `apply_patch`, are covered by the subprocess tests but not the live check. Include them in a deployment's coverage claim only after changing the matcher and verifying them on the platform. A non-object tool input is denied, because the adapter cannot represent it as ACS named arguments without inventing meaning.

Hosted tools such as web search bypass these hooks. `write_stdin` does not run `PreToolUse` again when it feeds a running process, and some specialized tool paths can opt out. Hook files, the adapter, the shared secret and the stored session decisions also need protection from the observed agent at the deployment level. This adapter does not isolate processes or mediate every action.

The hook contract was checked against the [Codex hook documentation](https://learn.chatgpt.com/docs/hooks) on 2026-11-03. See its tool coverage and trust sections when you configure a runtime.
