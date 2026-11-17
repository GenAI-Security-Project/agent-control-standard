# acs-gateway

Version 0.1.0. Owner: Rock Lambros (@rocklambros). Issue #577.

An agent you can't modify can still be governed. Point its `OPENAI_BASE_URL` at this gateway, change nothing else, and every tool call it receives has already passed an ACS Guardian. The gateway sits at the model boundary of an OpenAI Responses API client and acts as that client's ACS Observed Agent.

It's built for the ACS Guided Lab, where OWASP FinBot runs unmodified behind it, and it works with any client that sends non-streamed `POST /v1/responses` requests.

## What it does

The gateway forwards `POST /v1/responses` to a model upstream. In shadow and enforce modes it also talks to a Guardian:

- Before a model response reaches the client, each new `function_call` in it goes to the Guardian as `steps/toolCallRequest`.
- Before a request reaches the model, each new `function_call_output` in it goes to the Guardian as `steps/toolCallResult`.
- In enforce mode the gateway applies each decision. In shadow mode it records each decision and changes nothing.

Shadow and enforce gate function tools only. A request whose `tools` declares any other type (custom, shell, apply_patch, computer use, or a hosted tool such as mcp, code_interpreter, web_search or file_search, which runs upstream where no hook reaches it) answers 501. As a backstop, enforce removes any other `*_call` or `mcp_approval_request` item from a model response, replaces the output of any non-function `*_call_output` item with the neutral line, and turns an `mcp_approval_response` into a refusal. Each case writes an `unsupported_tool_type` audit line. Off forwards every tool type.


In shadow and enforce, any `stream` value other than an absent field or `false` counts as a stream request. A compressed request body answers 415, the gateway asks the upstream for gzip or deflate only, and a 2xx answer that isn't a JSON object with an `output` list answers 502, since it could carry calls the gateway never gated. Off relays requests and answers verbatim, encodings and headers included.

Every other path answers 404. Off mode relays a streamed request (`"stream": true`) as the upstream sends it. Shadow and enforce answer a streamed request with 501 until issue #578 adds governed streaming.

## Run it

```bash
cd adapters/gateway
uv sync --locked

# A Guardian to talk to, with the same secret and label as the gateway
export ACS_HMAC_SECRET_FILE=/path/to/hmac.key ACS_HMAC_KEY_ID=lab   # file is 0600, at least 32 bytes
uv run acs-example-guardian --port 8787 &

ACS_LAB_MODE=enforce ACS_GUARDIAN_URL=http://127.0.0.1:8787/ \
  ACS_UPSTREAM_URL=https://api.openai.com/v1 uv run acs-gateway
```

Then point the client at `http://127.0.0.1:8080/v1`. The client's own `Authorization` header goes upstream unchanged.

Run the tests with `uv run pytest -v`. They start the example Guardian and a fake model upstream on free localhost ports.

## Modes

`ACS_LAB_MODE` picks one of three modes. **Unset means off**, so nothing is governed, or blocked, by accident.

| Mode | Hooks sent | Transcript | What reaches the client and the model |
|---|---|---|---|
| `off` | None | None | Exactly what each side sent, byte for byte, streamed answers included |
| `shadow` | Every one | Yes | Unchanged. Each decision is recorded as `shadow_decision` |
| `enforce` | Every one | Yes | Each decision applied, as below |

Shadow mode isn't decision honoring under specification section 6.4. It shows what enforce would have done.

## How enforce applies a decision

| Decision | A `function_call` from the model | A `function_call_output` from the client |
|---|---|---|
| allow | Delivered unchanged | Forwarded unchanged |
| modify | `parameter_overrides` rewrite the arguments | `redactions` (JSON Pointers into the payload, such as `/outputs/0/value/bank_account_number`) or `modified_content` rewrite the output |
| deny, ask, defer | Removed | Output replaced by the neutral line |
| Any decision failure | Removed | Output replaced by the neutral line |

A decision failure is an error, any non-2xx status (429 included), a timeout, a refusal, or a response that fails verification (D-040, D-046). A MODIFY the gateway can't apply in full, such as a redaction path that doesn't resolve, denies.

When removing calls leaves a response with no message and no call, the gateway adds one assistant message: `I couldn't complete that action.` That line is the one artifact of governance the client or the model ever sees. No session id, request id, reason code, signature or lab header reaches either side.

The gateway's own configuration always denies on a decision failure. A ServerHello that declares `proceed`, or names no posture at all, can't loosen it (D-045).

## Sessions and resends

Each agent run is one ACS session, keyed on the SHA-256 of the system text (the `instructions` field, or the first system or developer item) and the first user message. The gateway opens it with the handshake and then `steps/sessionStart`, so the session's chain roots there. One lock per session keeps its steps in order.

FinBot's agents resend their whole history every turn. The gateway caches each gated item's outcome on (session_id, call_id) and reapplies it on every resend, so a redacted value never reappears and no item is governed twice.

A call_id that comes back with different content (another tool name, other arguments, or another output) is never served from the cache. Enforce withholds it, removing the call or replacing the output with the neutral line, and every mode audits `call_id_reused`.

An epoch bump forgets every session and every cached outcome, so a call_id seen before is gated afresh under a new session. Send `POST /epoch` with `Authorization: Bearer <token>` to the admin port.

## Records

**Transcript.** In shadow and enforce modes the gateway appends every signed request envelope and every response envelope to `ACS_TRANSCRIPT_DIR/<session_id>.jsonl`, one JSON object per line:

```json
{"dir": "req", "envelope": {"jsonrpc": "2.0", "method": "steps/toolCallRequest", "params": {"...": "..."}}}
{"dir": "resp", "envelope": {"jsonrpc": "2.0", "result": {"decision": "deny", "...": "..."}}}
```

Each request line is written before the request is sent, so the file holds the chain in the order the Guardian built it. When a request gets no usable answer (a timeout, an HTTP error, a refusal, a malformed or tampered answer), its response line is `{"dir": "resp", "envelope": null, "cause": "<cause>"}`. acs.client doesn't hand back the rejected answer itself, so the line can't carry it until LAB-03 (issue #576) adds that hook. The handshake isn't in the file, since acs.client sends it internally.

**Audit.** The gateway writes audit lines through acs.client `audit_event`, as `ACS_AUDIT {json}` on stderr and in `ACS_AUDIT_FILE`. The `acs_audit_event` field names the event:

| Event | When |
|---|---|
| `session_opened` | A session finished its handshake and sessionStart. `handshake` says Negotiated, SessionRefused or NoAnswer |
| `decision_applied` | Enforce mode settled a step. `decision` is what the gateway did, `guardian_decision` what the Guardian said, `cause` why a step denied without a Guardian deny (for example `decision_timeout`, `http_429_error`, `response_signature_invalid`, `modify_unsupported`) |
| `shadow_decision` | Shadow mode recorded a step, with the same fields |
| `verification_failed` | A Guardian response failed its signature check |
| `guardian_http_error` | The Guardian answered with a non-2xx status |
| `upstream_error` | An unknown path (`route_not_found`), an unreachable model (`upstream_unreachable`), a non-2xx model answer (`upstream_status`), or a 2xx answer the gateway can't read (`upstream_unparseable`) |
| `call_id_reused` | A cached call_id came back with different content |
| `unsupported_tool_type` | A non-function tool declaration, call or output, with `item_type` and `direction` |
| `epoch_bumped` | The epoch moved |

**Model input log.** When `ACS_MODEL_INPUT_LOG` is set, every request body forwarded upstream is appended there, one per line, in every mode, off included.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `ACS_LAB_MODE` | `off` | `off`, `shadow` or `enforce` |
| `ACS_UPSTREAM_URL` | `https://api.openai.com/v1` | Model base URL. The gateway posts to `<base>/responses` |
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/` | Guardian endpoint |
| `ACS_HMAC_SECRET_FILE` or `ACS_HMAC_SECRET` | None | Request signing secret, at least 32 bytes. The file must be 0600 or 0400 |
| `ACS_HMAC_KEY_ID` | None | The label that names the secret |
| `ACS_DECISION_TIMEOUT_MS` | `5000` | Longest wait for one decision. A ServerHello can shorten it, never lengthen it |
| `ACS_GUARDIAN_READY_TIMEOUT_S` | `60` | How long startup waits for the Guardian's `system/ping`. The gateway exits if it never answers |
| `ACS_GATEWAY_STATE_DIR` | A new private temp directory | The gateway's own state |
| `ACS_SESSION_STATE_DIR`, `ACS_HANDSHAKE_CACHE` | `<state dir>/sessions`, `<state dir>/handshakes` | acs.client's session and handshake records. A path under the home directory is refused |
| `ACS_TRANSCRIPT_DIR` | `<state dir>/transcripts` | Where transcripts go |
| `ACS_AUDIT_FILE` | None | Where audit lines go, besides stderr |
| `ACS_MODEL_INPUT_LOG` | None | Where the model input log goes |
| `ACS_AGENT_ID` | `openai-responses-gateway` | `agent_id` in every envelope |
| `ACS_GATEWAY_HOST`, `ACS_GATEWAY_PORT` | `127.0.0.1`, `8080` | The model port |
| `ACS_GATEWAY_ADMIN_HOST`, `ACS_GATEWAY_ADMIN_PORT` | `127.0.0.1`, unset | The admin port, off unless set |
| `ACS_GATEWAY_ADMIN_TOKEN_FILE` | None | Bearer token for the admin port, 0600, at least 32 bytes. Required with the admin port |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | None | Read by acs.client: Guardian hosts it may contact |
| `ACS_HANDSHAKE_TIMEOUT_SECONDS` | `5` | Read by acs.client: handshake timeout |
| `NO_PROXY` | None | acs.client honors proxy variables on every call, so list the Guardian here when a proxy is set |

The gateway ignores `ACS_DEFAULT_DENY`, `ACS_STARTUP_POSTURE` and `ACS_DISABLED`, which the hook adapters read. Its posture is always fail closed, and the mode is its off switch.

## Lab conventions

Each of these is the gateway's own choice where the specification is silent or a later item takes over. None changes the Claude Code, Cursor or NAT adapters.

| Convention | Settled by |
|---|---|
| The three modes and `ACS_LAB_MODE` | This issue, #577. Shadow isn't decision honoring under section 6.4 |
| A decision after the timeout is discarded, and the step is audited as `decision_timeout` | Issue #435 |
| The gateway denies on any decision failure whatever the ServerHello says, a missing posture included | D-045 and issue #32 |
| The neutral line stands in for a removed call or a denied output | This issue, #577 |
| ASK and DEFER deny | LAB-08, issue #581, adds the approver |
| Streamed requests answer 501 in shadow and enforce. Off relays them untouched | LAB-05, issue #578 |
| Responses are verified with acs.client's HMAC-SHA256 check inside its round trip. LAB-03 changes the algorithm dispatch inside acs.client to verify by key_id from the key document | LAB-03, issue #576, and issue #460 |
| `tool.version` is not sent yet | LAB-07, issue #580, sends the tool digest (issue #38) |
| `previous_response_id` and `conversation` answer 501 in shadow and enforce, since server-side history would hide items from the gateway. FinBot never sends either | This issue, #577 |
| The admin port and `POST /epoch` | LAB-15, issue #588, wires the lab CLI to it |
| `ACS_MODEL_INPUT_LOG` names the model input log path | LAB-15, issue #588, sets it in the bundle |

Replay and capture (LAB-06, issue #579) and spans (LAB-09, issue #582) build on this gateway as separate modules.
