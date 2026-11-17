# acs-gateway

Version 0.1.0. Owner: Rock Lambros (@rocklambros). Built for issue #577, [RefImpl] An OpenAI Responses API gateway that makes an unmodified client an Observed Agent, with off, shadow, and enforce modes.

An agent you can't modify can still be governed. Point its `OPENAI_BASE_URL` at this gateway, change nothing else, and every tool call it receives has already passed an ACS Guardian. The gateway sits at the model boundary of an OpenAI Responses API client and acts as that client's ACS Observed Agent.

It's built for the ACS Guided Lab, where OWASP FinBot runs unmodified behind it, and it works with any client that sends non-streamed `POST /v1/responses` requests.

## What it does

The gateway forwards `POST /v1/responses` to a model upstream. In shadow and enforce modes it also talks to a Guardian:

- Before a model response reaches the client, each new `function_call` in it goes to the Guardian as `steps/toolCallRequest`.
- Before a request reaches the model, each new `function_call_output` in it goes to the Guardian as `steps/toolCallResult`.
- In enforce mode the gateway applies each decision. In shadow mode it records each decision and changes nothing.

Shadow and enforce accept only what they can gate, by allowlist, so anything new fails closed. Off forwards everything.

- **Request fields:** `model`, `input`, `instructions`, `tools`, `tool_choice`, `stream`, `max_output_tokens`, `reasoning`, `text`, `metadata`, `parallel_tool_calls`, `store`, `user`, `temperature`, `top_p`. FinBot sends a subset of these. Any other field, such as `prompt`, `previous_response_id`, `conversation`, `background` or `include`, answers 501 naming the field and is audited as `unsupported_field`, since server-side history or a stored prompt would hide items or tools from the gateway.
- **Input items:** `message` (any role), `function_call`, `function_call_output`, `reasoning`. Any other type, such as `item_reference`, a hosted tool's `*_call`, or a non-function `*_call_output`, answers 501 naming the type before anything goes upstream, audited as `unsupported_item_type`.
- **Tool declarations:** `function` only. Any other type, hosted tools that run upstream where no hook reaches them included, answers 501, audited as `unsupported_tool_type`.
- **Output items:** `message`, `function_call`, `reasoning`. Enforce removes any other item from a model response and adds the neutral line if nothing else is left. Shadow forwards it. Both audit `unsupported_item_type`.


In shadow and enforce, any `stream` value other than an absent field or `false` counts as a stream request. A compressed request body answers 415, the gateway asks the upstream for gzip or deflate only, and a 2xx answer that isn't a JSON object with an `output` list answers 502, since it could carry calls the gateway never gated. Off relays requests and answers verbatim, encodings and headers included, except that every mode strips `x-acs-*` lab headers in both directions.

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

The gateway's own configuration always denies on a decision failure. A ServerHello that leaves `steps/toolCallRequest` or `steps/toolCallResult` out of `methods_evaluated` doesn't switch gating off: those steps deny, audited as `method_not_evaluated`. A ServerHello that declares `proceed`, or names no posture at all, can't loosen it (D-045).

## Sessions and resends

Each agent run is one ACS session, keyed on the SHA-256 of the system text (the `instructions` field, or the first system or developer item) and the first user message. The gateway opens it with the handshake and then `steps/sessionStart`, so the session's chain roots there. One lock per session keeps its steps in order.

A session whose handshake or sessionStart failed denies every step, and the next request for it retries once under a fresh session_id, audited as `session_retried`.

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
| `upstream_error` | An unknown path (`route_not_found`), an unreachable model (`upstream_unreachable`), a non-2xx model answer (`upstream_status`), a 2xx answer the gateway can't read (`upstream_unparseable`), or a body over the size limit (`request_too_large`, `upstream_too_large`) |
| `result_name_from_client` | A tool output arrived for a call the gateway never gated, so the tool name came from the client's resent history |
| `call_id_reused` | A cached call_id came back with different content |
| `unsupported_field` | A request field outside the allowlist, with `field` |
| `unsupported_item_type` | An input or output item outside the allowlist, with `item_type` and `direction` |
| `unsupported_tool_type` | A tool declaration that isn't a function tool |
| `gateway_step_error` | A fault in the gateway's own gating code. Shadow forwards the traffic unchanged, enforce answers 500 |
| `session_retried` | A failed handshake or sessionStart was retried under a new session_id |
| `session_evicted` | The session cap evicted the least recently used session |
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
| `ACS_GATEWAY_MAX_SESSIONS` | `256` | Sessions held at once. The least recently used one is evicted and audited as `session_evicted` |
| `ACS_GATEWAY_MAX_BODY_BYTES` | `8388608` (8 MiB) | Largest request body (413 above it) and, in shadow and enforce, largest upstream answer (502 above it) |
| `ACS_GATEWAY_WORKERS` | `16` | Worker threads for Guardian calls. Time a step waits for a worker counts against its decision timeout |
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
| The three modes and `ACS_LAB_MODE` | Issue #577. Shadow isn't decision honoring under section 6.4 |
| A decision after the timeout is discarded, and the step is audited as `decision_timeout` | Issue #435 |
| The gateway denies on any decision failure whatever the ServerHello says, a missing posture included | D-045 and issue #32 |
| The neutral line stands in for a removed call or a denied output | Issue #577 |
| ASK and DEFER deny | LAB-08, issue #581, adds the approver |
| Streamed requests answer 501 in shadow and enforce. Off relays them untouched | LAB-05, issue #578 |
| Responses are verified with acs.client's HMAC-SHA256 check inside its round trip. LAB-03 changes the algorithm dispatch inside acs.client to verify by key_id from the key document | LAB-03, issue #576, and issue #460 |
| An output or argument holding an integer above 2**53 - 1, a non-finite number or a lone surrogate denies its whole step, since RFC 8785 (JCS) can't encode it and the signed bytes would differ from the transcript line | Issue #577 |
| `tool.version` is not sent yet | LAB-07, issue #580, sends the tool digest (issue #38) |
| The request field, input item and output item allowlists. FinBot sends only fields and items on them | Issue #577 |
| The admin port and `POST /epoch` | LAB-15, issue #588, wires the lab CLI to it |
| `ACS_MODEL_INPUT_LOG` names the model input log path | LAB-15, issue #588, sets it in the bundle |

Replay and capture (LAB-06, issue #579) and spans (LAB-09, issue #582) build on this gateway as separate modules.

## Issues this README names

| Issue | Type | Title |
|---|---|---|
| #32 | Bug | §6.4 conflates Guardian refusal with decision failure; refusals are attacker-reachable and should fail closed |
| #38 | Bug | Tool declarations have no integrity binding, so a same-version redefinition is invisible to Inspect-Dynamic |
| #435 | Conformance | §6.4 does not say what a host does with a decision that arrives after the timeout |
| #460 | Bug | An asymmetric key_id has no defined binding to an identity, no publication, and no revocation |
| #576 | RefImpl | Example Guardian: sign decisions with ML-DSA-65, publish a key document, and refuse an HMAC fallback |
| #577 | RefImpl | An OpenAI Responses API gateway that makes an unmodified client an Observed Agent, with off, shadow, and enforce modes |
| #578 | RefImpl | Gateway: stream model responses while a tool call waits for its decision |
| #579 | RefImpl | Gateway: replay, live, and capture modes for the model upstream |
| #580 | RefImpl | Gateway: carry a digest of each tool declaration in tool.version so a redefinition is visible |
| #581 | RefImpl | Gateway: resolve an ASK through an approver page and return the answer to the Guardian |
| #582 | RefImpl | Gateway: emit OpenTelemetry spans for model calls, hooks, and decisions, with a collector configuration for Jaeger |
| #588 | RefImpl | FinBot guided lab: compose file, container images, and the lab CLI |
