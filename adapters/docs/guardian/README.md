# Example Guardian (shared)

A minimal, deterministic Guardian that all three reference adapters use for their integration tests and quick local demos.

**This is a teaching artifact, not a production Guardian.** Real Guardians plug in OPA / Rego, Cedar, or a vendor's policy engine, and live behind whatever identity / mTLS / audit infrastructure the deployment runs. This one answers ACS JSON-RPC requests with a few hard-coded rules, enough to make every adapter's round trip work end to end.

## What it does

HTTP server on `127.0.0.1:8787` (`--host`, `--port`) that answers JSON-RPC 2.0 POST requests on any path; the adapters' default URL is `http://127.0.0.1:8787/acs`. For every request except `system/ping` it verifies the HMAC-SHA256 signature under the per-session key (§10) and signs its answer; a request under another `key_id` gets an unsigned `SIGNATURE_INVALID` (-32004). Every `steps/*` request is also checked against `request-envelope.json`, and a replayed `request_id` gets -32005 and a timestamp outside the skew window (`ACS_SKEW_WINDOW_MS`, default 5 minutes) gets -32006.

## Policy implemented

Tool names compare case-insensitively, so `Bash` (Claude Code), `Shell` (Cursor) and `shell` (NAT) take the same branch. This table is the default backend. Under the [OPA backend](#opa-backend-lab-convention), OPA decides `steps/toolCallRequest` and `steps/toolCallResult` instead, and every other row stays as written.

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

## OPA backend (lab convention)

The Guardian can hand its tool decisions to [Open Policy Agent](https://www.openpolicyagent.org/). The input document and the verdict shape below are a lab convention, not part of the specification, until issue #531 (Specify or drop the Guardian's two-layer decision path and the OPA/Rego binding) settles the OPA binding. The backend is off by default. With `ACS_POLICY_BACKEND` unset, the Guardian decides exactly as the table above says, and the Claude Code, Cursor, and NAT adapters see the same decisions as before.

| Setting | Meaning |
|---|---|
| `ACS_POLICY_BACKEND` | `opa` turns the backend on. Unset or empty keeps the built-in rules. Any other value is an error. |
| `ACS_OPA_URL` | The OPA data API URL of the rule that returns the verdict, for example `http://opa:8181/v1/data/finbot/verdict`. Required with `opa`. Only `http` and `https` are accepted. |
| `ACS_OPA_TIMEOUT_MS` | How long the Guardian waits for OPA, from 1 to 4000. Default 2000. The cap leaves the Guardian a second of the 5000 ms the ServerHello advertises to validate, sign, and answer. A value outside the range stops the Guardian at startup. |

The Guardian reads these settings once, at startup, and refuses to start when the backend is named but its settings can't be used. As a backstop, a Guardian that sees a backend named in its environment without settings loaded at startup denies both tool methods with `policy_backend_misconfigured`.

The OPA host is not restricted. The operator sets `ACS_OPA_URL`, the Guardian ignores proxy variables for the policy call, and it never follows a redirect, so the request goes only where the setting points. Logs print the URL without its userinfo.

Under the backend, `steps/toolCallRequest` and `steps/toolCallResult` go to OPA after the signature, skew, replay, and nonce checks pass and the step is on the chain. The built-in denies for `steps/toolCallRequest` in the table above (destructive Bash, an oversized command, the Task tool, and protected writes) still run first, so OPA decides only the calls they allow and never sees one they deny. `steps/toolCallResult` is judged instead of allowed, so a result can be denied or redacted. Every other method keeps its row in the table above. The Guardian sends one POST per step:

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
- The verdict nests no deeper than 64 levels, since the Guardian canonicalizes and signs it.
- The merged result validates against `AcsResult` in `response-envelope.json`, which applies `modifications.json` and `ask-details.json` and requires `reasoning` on deny, modify, and ask.
- `modifications` appears only on modify, and `ask_details` only on ask.
- A modify follows the section 6.3 composition rules, with each `parameter_overrides` key compared as `/arguments/<key>` against the redaction paths, which are rooted at the payload.
- On a tool call, a modify uses `parameter_overrides`, and each key names an argument the call carries. `modified_content` isn't accepted on a tool call.
- On a tool result, a modify uses `redactions` or `modified_content`. `parameter_overrides` isn't accepted on a tool result.
- `redactions`, when present, isn't empty. Every redaction path names a value in the payload, so a typo can't leave the value in place.
- A redaction at `/outputs/N/value/<field>` is repeated at `/outputs/M/value/<field>` for every other output whose value carries that field. Redacting only the first output let the rest through in issue #469 (The reference Guardian allows a call whose policy-target argument is not a string, and redacts only the first output of a result).
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
| `policy_backend_misconfigured` | `ACS_POLICY_BACKEND` is set, but no OPA settings were loaded at startup |

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
