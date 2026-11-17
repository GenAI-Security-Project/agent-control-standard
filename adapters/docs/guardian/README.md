# Example Guardian (shared)

A minimal, deterministic Guardian that all three reference adapters use for their integration tests and quick local demos.

**This is a teaching artifact, not a production Guardian.** Real Guardians plug in OPA / Rego, Cedar, or a vendor's policy engine, and live behind whatever identity / mTLS / audit infrastructure the deployment runs. This one answers ACS JSON-RPC requests with a few hard-coded rules, enough to make every adapter's round trip work end to end.

## What it does

HTTP server on `127.0.0.1:8787` (`--host`, `--port`) that answers JSON-RPC 2.0 POST requests on any path; the adapters' default URL is `http://127.0.0.1:8787/acs`. For every request except `system/ping` it verifies the HMAC-SHA256 signature under the per-session key (§10) and signs its answer; a request under another `key_id` gets an unsigned `SIGNATURE_INVALID` (-32004). Every `steps/*` request is also checked against `request-envelope.json`, and a replayed `request_id` gets -32005 and a timestamp outside the skew window (`ACS_SKEW_WINDOW_MS`, default 5 minutes) gets -32006. Every request gets a JSON-RPC answer, and the connection is never dropped except in one case: a client that stops sending its body. The Guardian takes each request through one order: the `Content-Length`, reading the body, parsing, the `key_id` check, the structure check, the depth bound, schema validation, the signature, the skew window, replay and nonce checks, and then the step. A missing, negative, non-digit, or overlong `Content-Length` gets -32600 before anything is read, and one past the body cap gets -32600 with HTTP 413. The body has 30 seconds in total to arrive. A client that runs out of time is cut off and the connection closed without an answer. A body that isn't UTF-8 or JSON, holds an integer too long to parse, or is nested past the JSON parser's limit gets the parse error -32700. A signature object under a `key_id` this Guardian holds no secret for gets -32004 before the structure and depth checks, so the client always sees that its key was refused. A request whose JSON-RPC or ACS structure is the wrong shape gets -32600. The `id` has to be a string, an integer within 2^53 - 1, a finite float, or null, because JCS can't sign a larger integer. `params`, `params.metadata`, and `params.payload` have to be objects, and `null` in `params`, `metadata`, `request_id`, or `session_id` reads as absent. A request nested deeper than 128 levels gets -32600 from the depth bound. A schema error gets -32600, and a signature that doesn't verify gets -32004. Nothing before the signature check changes replay or chain state.

These errors and every later one are signed, as spec section 10 requires, with the request's `id` when it passed the id rule and null otherwise. Six kinds of answer are unsigned, and these are all of them. `system/ping` is unsigned by design (§13). The -32004 for a `key_id` this Guardian holds no secret for is the section 10 exemption. A refused `Content-Length`, an oversized body, and a parse error come before any session is known. A structure error is unsigned when no `session_id` string was readable, since there is no key to sign with. The -32603 catch-all answers when signing itself fails, as for a `session_id` that isn't valid UTF-8, with a fixed message and the id when it passed the id rule. Because errors before the signature check are signed, an unauthenticated sender can obtain an HMAC under a session key of its choosing, over an error envelope with an `id` it chose. An attacker on the network path of a plain-HTTP connection could swap such an error in for a deny, which the client then treats as a decision failure. That attacker can already drop the connection or tamper with any response, with the same result, so on-path attackers are out of scope without TLS. The default posture denies on a decision failure, and only a deployment that opts into `proceed` over plain HTTP is exposed, as it already is to a dropped connection. Whether errors before verification should be signed is a question for the spec.

## Policy implemented

Tool names compare case-insensitively, so `Bash` (Claude Code), `Shell` (Cursor) and `shell` (NAT) take the same branch. This table is the default backend. Under the [OPA backend](#opa-backend-lab-convention), OPA decides `steps/toolCallRequest` and `steps/toolCallResult` instead, and every other row stays as written.

| Hook method | Rule |
|---|---|
| `steps/toolCallRequest`, tool `bash` or `shell`, command matching a destructive pattern (`rm -rf` on `/`, `~` or `$HOME`, `rm --no-preserve-root`, `mkfs`, `dd of=/dev/`, a fork bomb, `> /dev/sd*`, `find` on `/` or home with `-delete` or `-exec rm`, `chmod 777` on `/etc`, `/usr`, `/bin` or `/sbin`) | `deny`, `destructive_command` |
| `steps/toolCallRequest`, tool `bash` or `shell`, command longer than 8 KiB | `deny`, `input_too_large` |
| Any request whose `params.payload` is present but isn't an object | JSON-RPC error -32600 on the wire, refused before any rule runs. A direct caller of `evaluate_step`, such as `acs.testing`'s `real_policy_handler`, gets `deny`, `argument_type_invalid` |
| `steps/toolCallRequest` with a `tool` that's present but isn't an object, a `tool.name` that isn't a string, or an `arguments` that's present but isn't an object. A present `[]`, `""`, `0`, `false`, or `null` denies too. Only an absent field reads as empty | `deny`, `argument_type_invalid` |
| `steps/toolCallRequest`, tool `bash` or `shell` with a `command` that isn't a string, or a file tool (below) with a path argument (below) that isn't a string, or with a `paths` that isn't a non-empty list of strings. Falsy values such as `0`, `false`, `[]`, and `{}` deny too. Only `null` reads as absent, the same as a missing argument | `deny`, `argument_type_invalid` |
| `steps/toolCallRequest`, a file tool, a path argument (below) under `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/boot/`, or `/proc/`. The path is POSIX-normalized and case-folded. A leading `/System/Volumes/Data` comes off, and `/private/etc` counts as `/etc`, as they do on macOS. The Guardian applies both on every platform, which elsewhere only over-denies a path nobody uses. So `/tmp/../etc/passwd`, `//etc/passwd`, `/ETC/passwd`, `/private/etc/passwd`, `/System/Volumes/Data/usr/bin/x`, and `/proc/self/root/etc/passwd` all count | `deny`, `protected_path` |
| `steps/toolCallRequest`, a file tool, a relative path argument (below) that normalizes outside its starting directory, such as `../../etc/passwd` | `deny`, `path_traversal` |
| `steps/toolCallRequest`, tool `task` | `deny`, `subagent_gated`; `allow` with `ACS_ALLOW_SUBAGENT=1` |
| Any other `steps/toolCallRequest` | `allow` |
| `steps/subagentStart` | `deny`, `subagent_gated` (`subagent_fresh_intent_gated` when `intent_derivation` is `fresh`); `allow` with `ACS_ALLOW_SUBAGENT=1`. An `intent_derivation` that is present and not a string or null denies with `argument_type_invalid` |
| `steps/sessionStart`, `steps/sessionEnd`, `steps/turnStart`, `steps/turnEnd`, `steps/userMessage`, `steps/agentResponse`, `steps/agentTrigger`, `steps/toolCallResult`, `steps/preCompact`, `steps/postCompact`, `steps/subagentStop`, `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval` | `allow` |
| `handshake/hello` | a ServerHello (§4) declaring `on_decision_failure: deny`, or `proceed` with `ACS_ON_DECISION_FAILURE=proceed` |
| `system/ping` | `allow` with `{status, echo, server_timestamp}` (§13); unsigned and outside the chain |
| Any other method | `deny`, `unknown_method` |

A file tool is one whose case-folded name is `write`, `edit`, `multiedit`, `notebookedit`, `delete`, `remove`, `move`, or `rename`. That covers Claude Code's `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`. Cursor's adapter maps `preToolUse` for every tool, and its file writes arrive as `Write` ([Cursor mapping](../cursor/mapping.md)). Cursor's `afterFileEdit` and `afterTabFileEdit` arrive after the edit, as `steps/toolCallResult` with tool `Edit`, so no tool-call deny applies to them. The list is fixed. A file tool under any other name, an MCP file tool included, meets none of these path denies, and a policy has to cover it.

The path arguments of every file tool are `file_path`, `notebook_path`, `path`, `target_file`, `paths`, the destination names `destination`, `new_path`, `target`, and `to`, and the source names `source`, `from`, `old_path`, and `src`. Every name counts on every file tool, so a move out of `/etc` is caught as well as a move into it, and so is a delete that names its target. On `Edit`, `target` or `to` can be ordinary text, and text that names a protected path is denied too. That over-deny fails closed. Only `paths` takes a list, and it has to be a non-empty list of strings. Every other path argument is a string. Any other value denies with `argument_type_invalid`, and `null` reads as absent.

The built-in path denies are a best-effort lexical check, not a security boundary. They compare the spelling of a path, and the Guardian may not even share the agent's filesystem, so it can't resolve one. A symlink or firmlink spelling gets past them, such as `/Volumes/Macintosh HD/etc/passwd` on macOS or a link the agent created under `/tmp`. A policy is the real control for file access.

When a decision can't be signed, because JCS (RFC 8785) can't encode something in it, the Guardian answers with a signed `deny` instead, with reason code `response_not_signable` and a fixed reasoning. JCS refuses a lone surrogate in a reasoning that echoes the request, an integer beyond 2^53, NaN, infinity, and a value nested past the interpreter's recursion limit.

Every step response carries `chain_hash`, the head of the session's rolling SHA-256 audit chain (§8.2, `entry_hash = sha256(JCS(entry) || previous_hash)`). The chain head and the seen `request_id`s persist per session under `ACS_GUARDIAN_STATE_DIR` (default `~/.cache/acs-guardian-state/`), so a restart keeps replay protection; `ACS_GUARDIAN_STATE_DIR=""` keeps them in memory, for development.

## OPA backend (lab convention)

The Guardian can hand its tool decisions to [Open Policy Agent](https://www.openpolicyagent.org/). The input document and the verdict shape below are a lab convention, not part of the specification, until issue #531 (Specify or drop the Guardian's two-layer decision path and the OPA/Rego binding) settles the OPA binding. The backend is off by default. With `ACS_POLICY_BACKEND` unset, the Guardian decides exactly as the table above says, and the Claude Code, Cursor, and NAT adapters see the same decisions as before.

| Setting | Meaning |
|---|---|
| `ACS_POLICY_BACKEND` | `opa` turns the backend on. Unset, empty, or only spaces keeps the built-in rules. Any other value stops the Guardian at startup. The Guardian reads this once, when its module is imported, and refuses to start if the value has changed by the time `main()` runs. |
| `ACS_OPA_URL` | The OPA data API URL of the rule that returns the verdict, for example `http://opa:8181/v1/data/finbot/verdict`. Required with `opa`. Only `http` and `https` are accepted, and a malformed host or port stops the Guardian at startup. Name an IP address, or a host the Guardian resolves locally (a container name on its network, or an `/etc/hosts` entry). The name lookup runs before the Guardian can abort a slow query, so a slow DNS server can hold a query's worker thread past `ACS_OPA_TIMEOUT_MS`, although the step itself still denies on time. |
| `ACS_OPA_TIMEOUT_MS` | How long the Guardian waits for OPA, from 1 to 4000. Default 2000. The cap leaves the Guardian a second of the 5000 ms the ServerHello advertises to validate, sign, and answer. A value outside the range stops the Guardian at startup. |

The Guardian reads these settings once, at startup, and refuses to start when the backend is named but its settings can't be used. Steps follow the backend name read at import and the settings startup loaded, never the live environment, so changing `ACS_POLICY_BACKEND` while the Guardian runs changes nothing. A Guardian served without its `main()`, whose name was set at import but whose settings were never loaded, denies both tool methods with `policy_backend_misconfigured` instead of falling back to the built-in rules.

The OPA host is not restricted. The operator sets `ACS_OPA_URL`, the Guardian ignores proxy variables for the policy call, and it never follows a redirect, so the request goes only where the setting points. Logs print the URL without its userinfo.

Under the backend, `steps/toolCallRequest` and `steps/toolCallResult` go to OPA after the signature, skew, replay, and nonce checks pass and the step is on the chain. The built-in denies for `steps/toolCallRequest` in the table above (destructive Bash, an oversized command, an argument of the wrong type, the Task tool, protected writes, and path traversal) still run first, so OPA decides only the calls they allow and never sees one they deny. When OPA answers a tool call with a modify, the Guardian applies its `redactions` and `parameter_overrides` to a copy of the call's arguments and runs the same built-in denies again. An override value is the raw tool value, exactly as the Claude Code and Cursor adapters merge it into the tool input, and it is never unwrapped from `{"value": ...}`. If one of them denies, that deny replaces the modify, so a policy can't rewrite `ls` into `rm -rf /`. `steps/toolCallResult` is judged instead of allowed, so a result can be denied or redacted. Every other method keeps its row in the table above. The Guardian sends one POST per step:

```json
{
  "input": {
    "method": "steps/toolCallResult",
    "payload": {
      "tool": {"name": "get_vendor_details"},
      "exit_status": "success",
      "outputs": [{"value": {"name": "Acme", "bank_account_number": "111-222"}}]
    },
    "metadata": {"agent_id": "finbot", "session_id": "<uuid>", "platform": "lab"}
  }
}
```

`payload` and `metadata` are the request's own, unchanged. The signature, nonce, and timestamp stay out because the Guardian has already checked them. OPA answers `{"result": verdict}`:

```json
{
  "decision": "modify",
  "reasoning": "Bank account numbers are withheld",
  "reason_codes": ["sensitive_field_redacted"],
  "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}
}
```

A verdict may carry `decision`, `reasoning`, `reason_codes`, `modifications`, `ask_details`, `policy_references`, and `policy_data`, and nothing else. The Guardian adds `type`, `acs_version`, `request_id`, and `chain_hash`, then signs the result. Before it does, the verdict has to pass these checks:

- `decision` is `allow`, `deny`, `modify`, or `ask`. The lab has no use for `defer`.
- The verdict nests no deeper than 64 levels. NaN and Infinity in the body make it `opa_response_malformed`. Any other number JCS can't sign, such as an integer beyond 2^53, gets the `response_not_signable` deny described under the table above.
- The merged result validates against `AcsResult` in `response-envelope.json`, which applies `modifications.json` and `ask-details.json` and requires `reasoning` on deny, modify, and ask.
- `modifications` appears only on modify, and `ask_details` only on ask.
- A modify changes only `/arguments/...` on a tool call and only `/outputs/...` on a tool result. A redaction path anywhere else, `/tool/name`, `/exit_status`, a bare `/arguments` or `/outputs`, and `/` included, makes the verdict invalid. That keeps a modify from renaming the tool after the built-in denies judged the original name.
- A modify follows the section 6.3 composition rules, with each `parameter_overrides` key compared as `/arguments/<key>` against the redaction paths, which are rooted at the payload.
- On a tool call, a modify uses `parameter_overrides`, and each key names an argument the call carries. `modified_content` isn't accepted on a tool call.
- On a tool result, a modify uses `redactions` or `modified_content`. `parameter_overrides` isn't accepted on a tool result.
- `redactions` and `parameter_overrides`, when present, aren't empty. Every redaction path names a value in the payload, so a typo can't leave the value in place. A path starts with `/` and uses only the `~0` and `~1` escapes RFC 6901 allows, checked by the one pointer parser every path goes through. No path repeats, and none sits inside another, compared after decoding.
- A redaction covers every array index that holds the same field. For each array index in a redaction path, whether the index of an output or of an array inside a value, the same path at every other index must also be redacted wherever it names a value. Redacting `/outputs/0` needs every output redacted, and redacting `/outputs/0/value/rows/0/ssn` needs `ssn` redacted in every row of every output that has one. This closes the gap in issue #469 (The reference Guardian allows a call whose policy-target argument is not a string, and redacts only the first output of a result). There, redacting only the first output let the rest through.
- A redacting modify carries at most 2,000 redactions, each path at most 64 tokens deep, on a result of at most 1,000 outputs, which keeps validation inside the decision timeout.
- An ask leaves `timeout_disposition` unset or sets it to `deny`. Under [D-043 (Treat ASK as a soft deny)](../../../docs/decisions/index.md#d-043-treat-ask-as-a-soft-deny) the Guardian owns the ASK timeout, and nothing in the Guardian turns an ask into an allow.

The Guardian never reads an OPA failure as allow. Each failure becomes a signed `deny` whose reason code says which. Its `reasoning` is one short fixed sentence per code, because it reaches the agent. The details, such as the HTTP status or the check a verdict failed, go to the Guardian's stderr log. This follows [D-036 (Default the failure posture to deny)](../../../docs/decisions/index.md#d-036-default-the-failure-posture-to-deny) and [D-040 (Split decision failures from refusals)](../../../docs/decisions/index.md#d-040-split-decision-failures-from-refusals):

| Reason code | Raised when |
|---|---|
| `opa_unreachable` | The connection to OPA fails |
| `opa_timeout` | OPA doesn't answer within `ACS_OPA_TIMEOUT_MS` |
| `opa_http_error` | OPA answers with any status but 200, a redirect included |
| `opa_response_malformed` | The body isn't a JSON object, nests past the JSON parser's limit, or is larger than 1 MiB |
| `opa_result_missing` | The body has no `result`, which is how OPA reports an undefined rule |
| `opa_verdict_invalid` | The verdict fails a check above, or validating it fails unexpectedly |
| `policy_backend_misconfigured` | `ACS_POLICY_BACKEND` named a backend at import, but `main()` never loaded its settings |

`tests/guardian/policy/lab_test.rego` is a minimal policy for the tests, with its entry point at `data.lab.verdict`. `tests/guardian/test_guardian_real_opa.py` runs it against a real `opa` 1.x binary when one is on `PATH`, and skips otherwise, so adapter CI skips it. The lab's policy pack replaces this policy.

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

The policy is in the `evaluate_step(method, params, request_id, chain_hash)` function. The OPA backend plugs in there, in `src/acs/guardian/opa_backend.py`. To add a rule, add a pattern to `DESTRUCTIVE_BASH_PATTERNS` (`src/acs/examples/destructive_bash.py`), add a branch in `evaluate_step`, or add a method to `INFORMATIONAL_METHODS`.

Production deployments replace this whole file with their actual policy engine. The wire shape (request format, response format) stays the same.

## What this is NOT

- **Not a production Guardian.** One shared HMAC secret is its only authentication: no per-agent identity, no TLS, no rate limiting, and the policy is the hard-coded table above.
- **Not the only Guardian.** Anyone can write one: the spec defines the wire contract, the implementation is the deployment's choice.
- **Not an SDK.** Just an HTTP server with hard-coded rules. If you want an SDK to build Guardians, that's a separate workstream.
