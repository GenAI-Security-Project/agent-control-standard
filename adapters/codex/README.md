# Codex PreToolUse adapter

This first slice for [#89](https://github.com/GenAI-Security-Project/agent-control-standard/issues/89)
lets an ACS Guardian allow, deny, or rewrite a Codex command before execution.
It builds on the shared infrastructure in [#22](https://github.com/GenAI-Security-Project/agent-control-standard/pull/22).

```text
Codex PreToolUse -> signed steps/toolCallRequest -> Guardian
Codex execution <- allow / deny / updatedInput  <- signed decision
```

The adapter advertises only `steps/toolCallRequest`, HTTP transport, and no
conformance profile. Session/turn lifecycle, results, compaction, subagent
lifecycle, and Wrapped MCP are outside this slice. See [mapping.md](mapping.md).

## Set up a local demo

Use Python 3.10+ and a Codex CLI with the documented `PreToolUse` contract.
The live procedure has been verified on **Codex CLI 0.142.5, macOS**; this is
a tested version, not a claim about the minimum supported release.

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r adapters/codex/requirements.txt
```

Provision the same secret file for the Guardian and adapter (readable only by
the service user; mode `0600`). The adapter requires signing and denies when
the secret is missing or unreadable. `ACS_HMAC_SECRET` is also supported by
the shared library; prefer `ACS_HMAC_SECRET_FILE` for ordinary use.

Start the teaching Guardian in a separate terminal:

```sh
ACS_HMAC_SECRET_FILE=/absolute/path/to/guardian.key \
  .venv/bin/python adapters/example-guardian/example_guardian.py --port 8787
```

Merge the `PreToolUse` entry from [hooks.json.example](hooks.json.example) into
your project's `.codex/hooks.json`, preserving any existing hook entries.
Replace the secret, interpreter, and adapter paths with absolute paths; quote
each path inside `command` if it contains spaces. The command explicitly sets
`ACS_DEFAULT_DENY=1`. The example matches only `Bash`, including Codex's
`exec_command` path. It runs synchronously: do not add `async: true`.

Trust the project configuration and review the exact hook using Codex `/hooks`.
An untrusted hook is skipped. Then try a harmless command such as `printf hello`.
The example Guardian's policy is a teaching policy, not a complete shell policy.

Relevant environment settings:

| Setting | Behavior |
|---|---|
| `ACS_GUARDIAN_URL` | HTTP(S) Guardian; defaults to `http://127.0.0.1:8787/acs` |
| `ACS_HMAC_SECRET_FILE` | Shared signing key file, mode `0600` |
| `ACS_DEFAULT_DENY` | `1` denies on decision failure; `0` (library pattern/spec default) permits with an audit event |
| `ACS_AUDIT_FILE` | Optional durable audit file in addition to stderr |
| `ACS_HANDSHAKE_CACHE` | Optional isolated handshake cache directory |
| `ACS_AGENT_ID` | Optional deployment-supplied agent identity |

The Guardian's negotiated `on_decision_failure: deny` also requires denial;
neither side can weaken the other's deny posture. Startup handshake failures
use the local posture. Missing dependencies, invalid input, invalid signatures,
misbound decisions, unsupported decisions, and HTTP refusals deny independently
of that posture. Each substitution or failure emits an `ACS_AUDIT` event.

When a valid ServerHello excludes `steps/toolCallRequest` from
`methods_evaluated`, the Guardian has not agreed to evaluate tool calls. The
adapter records `method_not_evaluated`, sends no tool-call request, and leaves
the decision to Codex's own permissions, even with `ACS_DEFAULT_DENY=1`.

The handshake timeout is five seconds. A positive negotiated decision timeout
up to ten seconds is supported; larger or invalid values deny before the step
is sent. Keep the host hook timeout above these budgets (the example uses 30s).
A host-killed, disabled, or untrusted hook cannot emit a denial; a fail-closed
adapter does not make the whole Codex process a fail-closed enforcement boundary.

## Run the adapter gate

```sh
.venv/bin/python -m pip install -r adapters/requirements-test.txt
cd adapters
../.venv/bin/python run_conformance.py codex --strict
```

This runs the shared checks and Codex subprocess tests, without a model account
or Codex installation. `CaptureGuardian` checks the actual emitted bytes against
the repository schemas and independently recomputes their signatures. Tests
exercise decisions, input preservation, request binding, failure postures,
timeouts, malformed messages, and the honest capability declaration.

## Check TypeScript Guardian compatibility

The separate `typescript-interop` CI job starts the repository's actual
TypeScript Guardian and validates its direct `result` against the ServerHello
schema. It also checks that the shared signed helper rejects the unsigned reply
without caching it, and that the Codex adapter with `ACS_DEFAULT_DENY=1` emits a
native denial before sending a tool request. A nonempty key is configured and
signature verification remains enabled throughout.

From the repository root, with Python test dependencies and Bun 1.3.14 installed:

```sh
(cd reference-implementations/agt && bun install --frozen-lockfile --ignore-scripts)
.venv/bin/python adapters/_common/tests/test_serverhello_contract.py
.venv/bin/python adapters/interop/test_typescript_guardian.py
```

Missing Bun or workspace dependencies fail this explicit check; they do not
produce a skip. The TypeScript Guardian currently returns unsigned responses,
as described in its [security boundary](../../reference-implementations/agt/packages/guardian/README.md).
Passing these tests establishes wire-shape compatibility and rejection of an
unsigned peer. Successful signed end-to-end interoperability still requires
TypeScript signing support. The Codex test runs the production adapter as a
subprocess; it does not run the Codex CLI or execute a tool.

## Verify real Codex enforcement

From the repository root:

```sh
.venv/bin/python adapters/codex/live_verify.py --evidence-dir /tmp/acs-codex-evidence
```

This separate, explicit check requires the Codex CLI. It fails if the CLI is
missing or any assertion fails; the normal gate does not count it as a pass or
a skip. It runs the real CLI, adapter, and signed test Guardian. A scripted
Responses endpoint on localhost emits exactly one `exec_command` call per case,
then finishes. There is no model inference or external model request. The
fixture uses an explicit dummy provider credential, ignores user config/rules,
disables plugins, and supplies the reviewed test hook for each invocation.
Its one-shot `--dangerously-bypass-hook-trust` flag applies to these test runs;
normal setup uses `/hooks` review. Existing system-managed hooks can still affect
the test, so use a test machine/session where the fixture can run as configured.

| Guardian decision | Required filesystem result |
|---|---|
| ALLOW | Only `original.marker` exists, with its expected content |
| DENY | Neither marker exists; Codex returns the Guardian's reason to the model |
| MODIFY | Only `replacement.marker` exists, with its expected content |

The harness also requires exactly one signed, schema-valid tool request for
each case and a completed CLI run. It saves a versioned summary, wire captures,
and CLI logs; temporary marker directories are removed. This proves the
`exec_command`/`Bash` hook path, not every tool path or a hosted-model session.

## Coverage limits

The configuration demonstrates shell commands. Object-valued MCP and other
local-function arguments and `apply_patch` are covered by subprocess translation
tests, not the live procedure. They require deliberate matcher changes and
platform verification before being included in a deployment's coverage claim.
Non-object tool inputs deny because this slice cannot represent them as ACS
named arguments without inventing semantics.

Hosted tools such as web search bypass these hooks. `write_stdin` does not run
`PreToolUse` again when feeding an existing process. Some specialized tool paths
can opt out. Hook files, adapter code, shared secrets, and caches also need
deployment-level protection from the observed agent; this adapter does not
provide process isolation or complete mediation.

Contract checked against the [official Codex hook documentation](https://learn.chatgpt.com/docs/hooks)
on 2026-09-18. See its tool coverage and trust sections when configuring a runtime.
