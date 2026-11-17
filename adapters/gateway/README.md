# acs-gateway

Version 0.1.0. Owner: Rock Lambros (@rocklambros). Built for issue #577, [RefImpl] An OpenAI Responses API gateway that makes an unmodified client an Observed Agent, with off, shadow, and enforce modes.

An agent you can't modify can still be governed. Point its `OPENAI_BASE_URL` at this gateway, change nothing else, and every tool call it receives has already passed an ACS Guardian. The gateway sits at the model boundary of an OpenAI Responses API client and acts as that client's ACS Observed Agent.

It's built for the ACS Guided Lab, where OWASP FinBot runs unmodified behind it, and it works with any client that sends `POST /v1/responses` requests, streamed or not.

## What it does

The gateway forwards `POST /v1/responses` to a model upstream. In shadow and enforce modes it also talks to a Guardian:

- Before a model response reaches the client, each new `function_call` in it goes to the Guardian as `steps/toolCallRequest`.
- Before a request reaches the model, each new `function_call_output` in it goes to the Guardian as `steps/toolCallResult`.
- In enforce mode the gateway applies each decision. In shadow mode it records each decision and changes nothing.

Enforce accepts only what it can gate, by allowlist, so anything new fails closed. Shadow checks the same allowlists but only records what falls outside them, audited the same way, and forwards the traffic unchanged, so shadow doesn't block a run, with one exception. A new conversation gets 503 when every session is busy, in shadow too, since that limit protects the gateway itself. Off forwards everything and checks nothing.

- **Request fields:** `model`, `input`, `instructions`, `tools`, `tool_choice`, `stream`, `max_output_tokens`, `reasoning`, `text`, `metadata`, `parallel_tool_calls`, `store`, `user`, `temperature`, `top_p`. FinBot sends a subset of these. Any other field, such as `prompt`, `previous_response_id`, `conversation`, `background` or `include`, answers 501 in enforce naming the field, and is audited as `unsupported_field`, since server-side history or a stored prompt would hide items or tools from the gateway.
- **Input items:** `message` (any role), `function_call`, `function_call_output`, `reasoning`. Any other type, such as `item_reference`, a hosted tool's `*_call`, or a non-function `*_call_output`, answers 501 in enforce before anything goes upstream, audited as `unsupported_item_type`.
- **Content parts:** a message's `content` may hold `input_text`, `output_text` and `refusal`. A reasoning item's `summary` may hold `summary_text` and its `content` may hold `reasoning_text`. A function_call_output's `output`, when it is an array, may hold `input_text` and `output_text`. Any other part, such as `input_file`, `input_image` or `input_audio`, which can pull stored content in by file_id, answers 501 in enforce, audited as `unsupported_content_part`. Each of these fields is a string or a list of parts, and any other value, such as an object, is unsupported the same way. FinBot sends string content only.
- **Tool declarations:** `function` only. Any other type, hosted tools that run upstream where no hook reaches them included, answers 501 in enforce, audited as `unsupported_tool_type`.
- **tool_choice:** `auto`, `none`, `required`, or `{"type": "function", "name": ...}` naming a declared function tool. Anything else answers 501 in enforce, audited as `unsupported_tool_choice`.
- **Output items:** `message`, `function_call`, `reasoning`. Enforce removes any other item from a model response and adds the neutral line if nothing else is left. Shadow forwards it. Both audit `unsupported_item_type`.
- **Message parts:** a model message may hold `output_text` and `refusal` parts, each rebuilt from its known fields (an `output_text` part's annotations go out empty). One allowlist decides this for whole answers and streams. A message holding any other part, such as one shaped like a function call, is withheld in enforce, with the neutral line if nothing else is left, and recorded in shadow, both audited as `unsupported_content_part` with `direction: output`.


A function_call or function_call_output without a non-empty string `call_id` has no cache key and no call to match, so enforce refuses the request with 400 and shadow records it, audited as `call_id_invalid`. Every refusal is decided before a Guardian session opens and before any session is created or evicted, so a refused request opens, creates, evicts and gates nothing. It may still refresh its own conversation's place in eviction order, since an existing session is touched when the request takes it.

A lone surrogate, which UTF-8 can't encode, never crashes the gateway and isn't refused on its own. Message and reasoning text is never signed, so it passes, including text the gateway relayed from the model and the client resends. A value that must be signed, in a call's arguments or a tool's output, denies its step as `envelope_not_signable`, since RFC 8785 can't encode it. Error bodies and every log and transcript line are written ASCII-escaped, so nothing can fail to encode. A 501 names the unsupported field or type in its message and in the Responses API's `param` slot.

A JSON key repeated in the request body's own structure, or inside the arguments of a resent call the session can't restore (one it never delivered, or one it removed), is refused in enforce with 400 and recorded in shadow, audited as `duplicate_json_key`. The call check runs first against the conversation's current session. When the session the request ends up using isn't that one (it was retired, evicted or bumped, or another request replaced it), the check runs again against the real calls of the session used: under its lock if it already exists, or against no calls before a new one is created, so a refused request creates and evicts nothing. Tool output is third-party data, so a repeated key inside a function_call_output's output denies only that result: enforce gives the model the neutral line in its place, the run goes on, and every resend reapplies that outcome. A resent call the gateway did deliver goes back as delivered, whatever its arguments say. Parsers disagree on which copy of a repeated key wins, so the gateway could gate one copy while the model read the other. A call whose arguments repeat a key is denied. An upstream answer that repeats a key is audited as `upstream_rejected` with cause `duplicate_json_key`, one line for the whole answer in both modes, and enforce answers 502 while shadow relays it ungated.

In shadow and enforce, any `stream` value other than an absent field, `null` or `false` counts as a stream request. The gateway asks the upstream for gzip or deflate only. A compressed request body can't be read, so enforce answers 415 and shadow forwards it unchanged with nothing gated, both audited as `compressed_request`. In shadow that includes a compressed streamed request, which reaches the upstream as an ungoverned stream. The model input log records `{"compressed": <encoding>, "bytes": <size>}` in place of a body it can't read. A 2xx answer that isn't a JSON object with an `output` list could carry calls the gateway never gated, so enforce answers 502 and shadow relays it as it came, both audited as `upstream_unparseable`. Off relays requests and answers verbatim, encodings and headers included, except that every mode strips `x-acs-*` lab headers in both directions.

Every other path answers 404. Off mode relays a streamed request (`"stream": true`) as the upstream sends it. Shadow and enforce govern it, as [Streaming](#streaming) describes.

## Streaming

In shadow and enforce, a streamed request (`"stream": true`) gets a governed Server-Sent Events stream. The request side is gated exactly as a non-streamed one, so each new `function_call_output` is decided before anything goes upstream.

On the answer side, enforce never relays an upstream byte. Every event the client gets is one the gateway built:

- Only message text streams live. For an item announced as a message, the gateway passes on exactly eight event types, `response.output_item.added`, `response.content_part.added`, `response.output_text.delta`, `response.output_text.done`, `response.refusal.delta`, `response.refusal.done`, `response.content_part.done` and `response.output_item.done`, each rebuilt from its known fields. Parts pass the message-part allowlist above. A text or refusal event must name a part already announced by `response.content_part.added`, of the same type. Any other event for that item, or a done item that isn't such a message, ends the stream.
- Every other item, a `function_call`, reasoning, or anything else, is never relayed. Its events are only counted while the stream runs. When the upstream's final event arrives, the gateway takes that event's output list as the authoritative copy, sends each `function_call` through the same per-item gate a non-streamed answer uses, and builds each surviving item's events from the decided item: `response.output_item.added`, the arguments as one `response.function_call_arguments.delta`, `response.function_call_arguments.done`, and `response.output_item.done`. A reasoning item is rebuilt from its id, its summary text and its encrypted content, and is removed with its turn when every item of the turn was removed. Its private reasoning text never goes out. Anything outside the output allowlist is removed.
- When removals leave no message and no call, the neutral line goes out as one assistant message before the final event.
- The final event is honored whenever it arrives. On `response.completed` the buffered items are gated and built. On `response.incomplete` or `response.failed` they are dropped and the neutral line rule applies. The upstream's own `error` event is rebuilt from its code, message and param, and nothing buffered goes out.
- `response.created`, `response.in_progress` and the final event are rebuilt with only what a client needs: `id`, `object`, `created_at`, `status`, `model`, the token counts of `usage`, `error` as a code and a message, and `output` set to exactly the items sent so far, so the final response matches the stream. `tools`, `metadata`, `instructions`, `text`, `reasoning` and every other Response field the upstream sends are dropped.

Text therefore reaches the client as the model writes it, before any call is decided, and calls follow at the end. The gateway numbers every event it sends from its own counter, 0, 1, 2 and up, and `output_index` is its own dense count. FinBot reads only `response.output_text.delta` and `response.output_item.done` (PREMORTEM P21), and a client that builds the response from events, as the OpenAI SDK's `responses.stream()` does, always gets each item's full event set. An upstream that interleaves items or sends no `sequence_number` streams the same way.

A stream the gateway can't accept ends in enforce with one `error` event, `{"type": "error", "code": "upstream_unreadable", ...}`, audited as `upstream_error` with a `detail`. That covers an event that isn't JSON or repeats a key, an unknown event type, an event outside a message's allowlist, an event after its item's done, a repeated `output_index` or item id, a lifecycle or final event of the wrong shape, a message without its done, an upstream that stops before its final event or fails mid-stream, more than `ACS_GATEWAY_MAX_BODY_BYTES` kept at once, an upstream silent for longer than `ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S` (cause `upstream_idle_timeout`), and a stream running past `ACS_GATEWAY_STREAM_DEADLINE_S` (cause `upstream_deadline`). An upstream that answers a streamed request with a whole JSON answer, or with an error status, gets the same treatment as a request that isn't streamed.

Shadow relays the upstream byte for byte, injects nothing, and applies no idle timeout or limit. After the final event it keeps relaying, whatever the chunking, until the upstream closes or sends nothing for one second, so a trailing `data: [DONE]` still goes out. An upstream that goes silent after the final event releases the session's lock a second later. One that keeps sending after it, keepalives included, holds the session's lock in shadow until it stops or closes, since shadow sets no overall deadline. Enforce sends nothing after the final event. It records a `shadow_decision` for each finished call on a task of its own, at most 256 waiting at once (past that each one is audited as `shadow_decisions_dropped`), and the stream's cleanup waits for those decisions before it releases the session's lock, so the session's steps stay in order. Cleanup stops the recorder on any exit before the lock is released. After an event it can't read, shadow relays the rest ungated.

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

Then point the client at `http://127.0.0.1:8080/v1`. The client's own `Authorization` header goes upstream unchanged, unless `ACS_UPSTREAM_KEY_FILE` names a key file (see [Upstream modes](#upstream-modes)).

Run the tests with `uv run pytest -v`. They start the example Guardian and a fake model upstream on free localhost ports.

## Modes

`ACS_LAB_MODE` picks one of three modes. **Unset means off**, so nothing is governed, or blocked, by accident.

| Mode | Hooks sent | Transcript | What reaches the client and the model |
|---|---|---|---|
| `off` | None | None | Exactly what each side sent, byte for byte, streamed answers included. A pure passthrough with no allowlists and no size limits |
| `shadow` | Every one | Yes | Unchanged. Each decision is recorded as `shadow_decision`, and anything outside the allowlists is recorded, never refused |
| `enforce` | Every one | Yes | Each decision applied, as below |

Shadow mode isn't decision honoring under specification section 6.4. It shows what enforce would have done.

## Upstream modes

`ACS_UPSTREAM` picks where model answers come from. It is separate from `ACS_LAB_MODE`, so any upstream mode runs under off, shadow or enforce. **Unset means live with no key file**, which forwards exactly as the gateway did before upstream modes existed.

| Mode | What answers | Network | Writes |
|---|---|---|---|
| `live` | The model at `ACS_UPSTREAM_URL`. `openai` is accepted as another name for it | Yes | Nothing new |
| `capture` | The same model, as in live | Yes | One recording line per successful exchange in `<ACS_RECORDINGS_DIR>/<ACS_CAPTURE_SCENARIO>.jsonl` |
| `replay` | The recordings in `ACS_RECORDINGS_DIR` | None, and no credentials | Nothing new |

`ACS_CAPTURE=1` turns live into capture, the spelling the lab bundle uses. Each mode sits under the gateway's one upstream client, so gating, the transcript and the audit log work the same whichever mode answered.

**The model key.** In live and capture, `ACS_UPSTREAM_KEY_FILE` names a file holding the real model key. The gateway replaces the client's `Authorization` header with `Bearer <key>` on the upstream request only, so the client (FinBot sends `lab-dummy`) never holds the key. The file must be a regular file, not a symlink, mode 0600 or 0400, owned by the gateway's uid, one key on one line, and outside any git work tree. The key never reaches a recording, the model input log, an audit line or an error message. Replay refuses a key file.

**Recordings.** Each line is one JSON object (A.8):

```json
{"scenario": "s1", "match": "Pay\\ vendor\\ 7", "step": 1, "branch": "a", "stream": false, "response": {"id": "resp_...", "output": ["..."]}}
```

| Field | Meaning |
|---|---|
| `scenario` | The capture's scenario name |
| `match` | A regular expression the request's first user message, with placeholders, must match in full. Capture writes the escaped message, and a curator may loosen it by hand |
| `step` | How many `function_call_output` items the request held. A retry, from FinBot's SDK or its agent runner, lands on the same step |
| `branch` | One token per governed item, comma separated, from the session's own outcome records, never from text in the request: `a` delivered, `d` removed or replaced by the neutral line, `m` rewritten (a MODIFY of a call or an output). Calls and outputs take their tokens in the order the request holds them. A removed call never comes back from the client, so its `d` sits where the request that produced it ended. Off and shadow change nothing, so they give `a` for every call and output |
| `stream` | Whether the request asked for a stream |
| `response` | The Responses API body, or for a stream the list of `{"event", "data"}` server-sent events |

Replay serves the first line, in file name and line order, that fits all of `match`, `step`, `branch` and `stream`. A byte-identical request gets the bytes it got before, from a cache of the last 1,024 requests keyed on the request's SHA-256.

**Placeholders.** FinBot mints a namespace and ids for every visitor, so a recording made in one FinBot would point the replayed model at another FinBot's addresses. Capture swaps each value below for `{{acs:<kind>:<n>}}`, where `n` counts distinct values of that kind in the order they appear in the request, the system text first. Replay fills each placeholder from the live request, so a recording replays into a fresh FinBot with a different namespace.

| Kind | FinBot value at 1450fc4 |
|---|---|
| `ns` | The namespace, `ns_user_` and 16 characters, as in `admin@<namespace>.finbot` |
| `user` | The user id, `user_` and 16 characters |
| `wf` | Workflow ids, `wf_`, `wf_chat_` or `wf_review_` and 16 characters |
| `tr` | Transfer ids, `tr_` and 24 hex digits |
| `uuid` | A UUID |
| `time` | An ISO 8601 date and time, such as the current time in each agent's system prompt |

A value the request never held, one the model made up, stays as the model wrote it.

**A miss.** When no line fits, or a line holds a placeholder the live request can't fill, replay never guesses. It answers with a fixed response, `resp_replay_miss`, holding one assistant message, `msg_replay_miss`, that carries the neutral line (as server-sent events when the request asked for a stream), and audits `replay_miss`.

Capture waits for a whole streamed answer before passing it on, since the line needs all of it. Capture records the body the gateway forwarded, after gating, so the key it writes is the key replay computes for the same run. A failed write is audited as `capture_failed` and the client still gets its answer.

## How enforce applies a decision

| Decision | A `function_call` from the model | A `function_call_output` from the client |
|---|---|---|
| allow | Delivered unchanged | Forwarded unchanged |
| modify | `parameter_overrides` rewrite the arguments | `redactions` (JSON Pointers into the payload, such as `/outputs/0/value/bank_account_number`) or `modified_content` rewrite the output |
| ask on a call, with the approver page on | Held for the approver, as [ASK and the approver page](#ask-and-the-approver-page) describes | Not held. Output replaced by the neutral line |
| deny, defer, and ask with the page off | Removed | Output replaced by the neutral line |
| Any decision failure | Removed | Output replaced by the neutral line |

A decision failure is an error, any non-2xx status (429 included), a timeout, a refusal, or a response that fails verification (D-040, D-046). A MODIFY the gateway can't apply in full, such as a redaction path that doesn't resolve, denies. A redaction that replaces the output item or the outputs array itself (`/outputs/0`, `/outputs`) is honored by withholding the whole output: the model gets the neutral line, and the step is audited as `modify` with cause `output_withheld`. An answer that comes back after the decision deadline is a `decision_timeout`, whatever it says.

When removing calls leaves a response with no message and no call, the gateway adds one assistant message: `I couldn't complete that action.` That line is the one artifact of governance the client or the model ever sees. No session id, request id, reason code, signature or lab header reaches either side.

The gateway's own configuration always denies on a decision failure. A ServerHello that leaves `steps/toolCallRequest` or `steps/toolCallResult` out of `methods_evaluated` doesn't switch gating off: those steps deny, audited as `method_not_evaluated`. A ServerHello that declares `proceed`, or names no posture at all, can't loosen it (D-045).

## ASK and the approver page

An ASK means the Guardian wants a person to answer before a call runs. With `ACS_GATEWAY_APPROVER_PORT` and `ACS_GATEWAY_APPROVER_TOKEN_FILE` set, enforce holds a model's `function_call` that gets an ASK and lists it on a one-page approver UI on that port. The lab sets 8090. The page binds `127.0.0.1` unless `ACS_GATEWAY_APPROVER_HOST` says otherwise. Without the port, every ASK denies, as before. The port without the token file stops startup, on any host.

The page releases held tool calls, so it needs the secret in the token file, which follows the admin token's rules (a regular file, 0600 or 0400, owned by the gateway, at least 32 bytes). A script sends it as `Authorization: Bearer <secret>`. A browser gets a sign-in form. Each sign-in issues a random session id, never the secret, as an `HttpOnly`, `SameSite=Strict` cookie that lasts 15 minutes and is replaced by the next sign-in, since browsers don't separate cookies by port and another loopback listener could capture one. Without the secret there is no page and no answer, whatever `Host` and `Origin` a local process or a sibling container claims.

The page shows each held call's tool name, its arguments, the Guardian's question and its `context`, with an Approve and a Reject button. An approval goes back to the Guardian as the same `steps/toolCallRequest` payload, sent again under a new request_id, with one more field:

```json
{"tool": {"name": "pay_vendor"}, "arguments": {"vendor_id": {"value": 7}},
 "x_acs_lab_ask_answer": {"ask_request_id": "<the ASK step's request_id>", "answer": "approve",
                          "approver": {"type": "human", "id": "lab-approver"}, "assurance": "declared"}}
```

The Guardian's decision on that resend is what the gateway applies after an approval, so an approved call reaches the client only when the Guardian then allows or modifies it. The gateway never turns an ASK into an allow on its own (D-043). A second ASK on the resend denies. `assurance: declared` says the answer is the gateway's word for it, since no approver signature exists yet.

Everything else ends the hold with a deny and no resend:

- A rejection denies at once. Its resend could change nothing, so the Guardian learns of it only from the gateway's audit line until issue #175 defines how an answer reaches it.
- No answer before the deadline.
- The client disconnecting, during the wait or the approved resend. Both paths read one disconnect signal, set the moment the request's receive channel reports the disconnect. After an approval the gateway waits up to 100 ms for a disconnect already on its way, so a click that lands just after the client left sends nothing.
- An epoch bump or a retired session during the wait, since the call's session is gone.

The budget is `ACS_GATEWAY_ASK_MAX_S` (240 seconds, and never higher) from the request's arrival, so the model's own time counts against it. An ASK waits until the earlier of its own `timeout_seconds` and the budget's end, less the time the resend can take, which is the Guardian's negotiated `toolCallRequest` timeout when its ServerHello set one and the decision timeout otherwise, plus a second. The answer then lands inside FinBot's 360-second `LLM_TIMEOUT`. Every ASK in one model response, streamed or not, shares that one budget, so two ASKs never add up past it. A cap no longer than one decision timeout plus a second stops startup.

The gateway honors only what the page can carry out. An ASK whose approver isn't `human`, whose `options` are anything but exactly `approve` and `reject`, or whose `timeout_disposition` isn't `deny` denies at once, audited as `ask_unsupported` naming the field. So does an `ask_details` without a string `question`, a string `approver.id` and an integer `timeout_seconds` of at least 1. The gateway never claims a human answered for a non-human approver.

While a call is held, the session's lock is held too, for up to the 240-second budget, so a second request for the same conversation waits behind it. FinBot runs one agent per conversation, so nothing of its own queues there. A streamed response sends an SSE comment line, `: keepalive`, every 15 seconds while a call is held, so a proxy's idle timeout doesn't cut the stream. Clients skip comment lines.

Shadow records the ASK as a `shadow_decision` and delivers the call, and keeps no approvals, so it never holds anything. Off never sees an ASK. An ASK on a tool's output isn't held, since the tool already ran, and the output is replaced by the neutral line.

Tool arguments come from the model, which an attacker can steer, so the page escapes everything it renders, shows invisible and bidirectional characters, and every default-ignorable code point such as U+3164 and U+FE0F, in every label and argument as `\uXXXX` escapes, runs no script, and refuses to load in a frame. An answer is a POST carrying only the call's id, the choice and a token minted with the page. A token answers only the calls its page showed, once each. Behind the secret, the page also refuses an answer whose `Origin` isn't the page's own, a `Sec-Fetch-Site` of `cross-site` or `same-site`, and any `Host` that isn't a loopback name or the bind host. A click after the deadline, or a second click, changes nothing.

## Sessions and resends

Each agent run is one ACS session, keyed on the SHA-256 of the system text (the `instructions` field, or the first system or developer item) and the first user message. The gateway opens it with the handshake and then `steps/sessionStart`, so the session's chain roots there. One lock per session keeps its steps in order.

A session whose handshake or sessionStart failed denies every step, and the next request for it, at least a second after the failure, retries once under a fresh session_id, audited as `session_retried`.

FinBot's agents resend their whole history every turn. The gateway caches each gated item's outcome on (session_id, call_id) and reapplies it on every resend, so a redacted value never reappears and no item is governed twice.

A call_id that comes back with different content (another tool name, other arguments, or another output) is never served from the cache. Enforce withholds it, removing the call or replacing the output with the neutral line, and every mode audits `call_id_reused`.

An epoch bump forgets every session and every cached outcome, so a call_id seen before is gated afresh under a new session. Send `POST /epoch` with `Authorization: Bearer <token>` to the admin port.

One gap remains by design. When an epoch bump lands between a turn's calls and the client's resend of their outputs, the new session never gated those calls. It gates each output afresh, takes the tool name from the client's resent history, and audits `result_name_from_client`. The bump is a lab operator's action (`lab sign`, `lab mode`, a policy reload), so the lab driver runs it between scenarios, never inside one.

## Records

**Transcript.** In shadow and enforce modes the gateway appends every signed request envelope and every response envelope to `ACS_TRANSCRIPT_DIR/<session_id>.jsonl`, one JSON object per line. Transcript and model input log lines escape every non-ASCII character as `\uXXXX`, so a line can't fail to write, and a JSON reader gets the original text back:

```json
{"dir": "req", "envelope": {"jsonrpc": "2.0", "method": "steps/toolCallRequest", "params": {"...": "..."}}}
{"dir": "resp", "envelope": {"jsonrpc": "2.0", "result": {"decision": "deny", "...": "..."}}}
```

Each request line is written before the request is sent, so the file holds the chain in the order the Guardian built it. When a request gets no usable answer (a timeout, an HTTP error, a refusal, a malformed or tampered answer), its response line is `{"dir": "resp", "envelope": null, "cause": "<cause>"}`. acs.client doesn't hand back the rejected answer itself, so the line can't carry it until LAB-03 (issue #576) adds that hook. An answer that arrived after the deadline keeps its envelope, since the Guardian chained it, and its line adds `"cause": "decision_timeout"`. The handshake isn't in the file, since acs.client sends it internally.

**Audit.** The gateway writes audit lines through acs.client `audit_event`, as `ACS_AUDIT {json}` on stderr and in `ACS_AUDIT_FILE`. The `acs_audit_event` field names the event:

| Event | When |
|---|---|
| `ask_pending` | Enforce held a call for the approver page, with `request_id` (the ASK step's), `tool`, `call_id`, `approver`, `question`, `deadline_s` (the request's budget) and `remaining_s` |
| `ask_resolved` | A held call was settled, exactly one line per held call on every path. `outcome` is `approved`, `rejected`, `timed_out` or `abandoned`, with `ask_request_id`, `resent` (whether the approved resend went out, which a disconnect during it leaves true with outcome `abandoned`), and `request_id` and `guardian_decision` of the resent step (null unless approved), `decision` (what the gateway did), `cause` (`ask_rejected`, `ask_timeout`, `client_disconnected`, `epoch_bumped`, `session_retired`, or the resend's own failure) and `waited_s`. A `decision_applied` line follows for the same call, except after a streamed disconnect, which ends the request |
| `ask_unsupported` | An ASK the page can't carry out denied at once, with `field` (`approver.type`, `options`, `timeout_disposition`, or a required field that isn't usable) |
| `session_opened` | A session finished its handshake and sessionStart. `handshake` says Negotiated, SessionRefused or NoAnswer |
| `decision_applied` | Enforce mode settled a step. `decision` is what the gateway did, `guardian_decision` what the Guardian said, `cause` why a step denied without a Guardian deny (for example `decision_timeout`, `http_429_error`, `response_signature_invalid`, `modify_unsupported`) |
| `shadow_decision` | Shadow mode recorded a step, with the same fields |
| `verification_failed` | A Guardian response failed its signature check |
| `guardian_http_error` | The Guardian answered with a non-2xx status |
| `upstream_error` | An unknown path (`route_not_found`), an unreachable model (`upstream_unreachable`), a non-2xx model answer (`upstream_status`), a 2xx answer the gateway can't read (`upstream_unparseable`), or a body over the size limit (`request_too_large`, `upstream_too_large`). A streamed answer adds `stream: true` and a `detail` naming what it couldn't read, such as `event_not_json`, `output_index_unannounced` or `stream_ended_early` |
| `result_name_from_client` | A tool output arrived for a call the gateway never gated, so the tool name came from the client's resent history |
| `call_id_reused` | A cached call_id came back with different content |
| `call_id_invalid` | A call or output without a non-empty string call_id, with `item_type` and `direction`. On the input side enforce answers 400. On the output side, a call from the model, enforce removes it and gives the neutral line if nothing else is left. Shadow records both |
| `duplicate_json_key` | A request repeated a JSON key, with `key`, `where` (`body`, `function_call.arguments` or `function_call_output.output`), `mode`, and `conversation` or `session_id` when known. A repeated key in an upstream answer is `upstream_rejected` instead |
| `upstream_rejected` | An upstream answer the gateway won't gate, with `cause` (`duplicate_json_key`), `key` (the first repeated key) and `mode` |
| `unsupported_field` | A request field outside the allowlist, with `field` |
| `unsupported_item_type` | An input or output item outside the allowlist, with `item_type` and `direction` |
| `unsupported_content_part` | A part outside the allowlist in a message's content, a reasoning item's summary or content, or a function_call_output's array output, with `part_type`. A value that is neither a string nor a list reports `part_type: non_list_value` |
| `unsupported_tool_choice` | A tool_choice outside the allowlist |
| `unsupported_tool_type` | A tool declaration that isn't a function tool |
| `gateway_step_error` | A fault in the gateway's own gating code. Shadow forwards the traffic unchanged, enforce answers 500 |
| `session_retired` | A claimed step the loop stopped waiting for. The session leaves the map, its remaining steps deny, and the next request for the conversation opens a fresh session. Fields: `session_id`, `method`, `request_id` (the claimed step's), `in_flight` (true when a transcript write or the send had already started and may still land), and `cause`: `step_hung` (the worker passed one more decision timeout) or `request_cancelled` (the request was cancelled while the worker was still landing) |
| `session_retried` | A failed handshake or sessionStart was retried under a new session_id |
| `sessions_full` | Every session was busy, so a new conversation got 503 |
| `session_evicted` | The session cap evicted the least recently used session |
| `epoch_bumped` | The epoch moved |
| `replay_miss` | Replay answered with the miss response. `cause` is `no_recording`, `placeholder_unfilled` or `unreadable_request`, with `step`, `branch` and `stream`, and `scenario` when a line matched but couldn't be filled |
| `capture_skipped` | Capture wrote no line for a successful exchange it couldn't read. `cause` is `unreadable_request` or `unreadable_response` |
| `capture_failed` | Capture couldn't write its line (`cause` `write_error`). The client still got its answer |

**Model input log.** When `ACS_MODEL_INPUT_LOG` is set, every request body forwarded upstream is appended there, one per line, in every mode, off included.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `ACS_LAB_MODE` | `off` | `off`, `shadow` or `enforce` |
| `ACS_UPSTREAM_URL` | `https://api.openai.com/v1` | Model base URL. The gateway posts to `<base>/responses` |
| `ACS_UPSTREAM` | `live` | `live` (or `openai`), `capture` or `replay` |
| `ACS_CAPTURE` | `0` | `1` turns live into capture. Refused with replay |
| `ACS_UPSTREAM_KEY_FILE` | None | The model key, replacing the client's `Authorization` upstream. Live and capture only |
| `ACS_RECORDINGS_DIR` | None | Where capture writes and replay reads recordings. Required by both |
| `ACS_CAPTURE_SCENARIO` | `capture` | The scenario name and recording file name. Letters, digits, `_` and `-`, up to 64 |
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
| `ACS_GATEWAY_MAX_SESSIONS` | `256` | Sessions held at once. The least recently used idle one is evicted and audited as `session_evicted`. A session with a request in progress is never evicted, and a new conversation gets 503 (`sessions_full`) when every session is busy |
| `ACS_GATEWAY_MAX_BODY_BYTES` | `8388608` (8 MiB) | In shadow and enforce, the largest request body (413 above it). Above it, enforce answers 502 to an upstream answer, while shadow relays the answer whole, streaming the rest, and audits `upstream_too_large`. Off is a pure passthrough with no limits |
| `ACS_GATEWAY_WORKERS` | `16` | Worker threads for Guardian calls. Time a step waits for a worker counts against its decision timeout |
| `ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S` | `60` | Enforce only. Seconds a governed stream waits for the upstream's next chunk. Past it the stream ends with the error event and the session's lock is released |
| `ACS_GATEWAY_STREAM_DEADLINE_S` | `600` | Enforce only. Seconds a whole governed stream may run. Past it the stream ends with the error event |
| `ACS_AGENT_ID` | `openai-responses-gateway` | `agent_id` in every envelope |
| `ACS_GATEWAY_HOST`, `ACS_GATEWAY_PORT` | `127.0.0.1`, `8080` | The model port |
| `ACS_GATEWAY_ADMIN_HOST`, `ACS_GATEWAY_ADMIN_PORT` | `127.0.0.1`, unset | The admin port, off unless set |
| `ACS_GATEWAY_ADMIN_TOKEN_FILE` | None | Bearer token for the admin port, 0600, at least 32 bytes. Required with the admin port |
| `ACS_GATEWAY_APPROVER_HOST`, `ACS_GATEWAY_APPROVER_PORT` | `127.0.0.1`, unset | The approver page, enforce only, off unless the port is set. The port is 1 to 65535 and differs from the model and admin ports. The lab sets 8090 |
| `ACS_GATEWAY_APPROVER_TOKEN_FILE` | None | The approver secret, 0600, at least 32 bytes. Required with the approver port |
| `ACS_GATEWAY_ASK_MAX_S` | `240` | One request's ASK budget, from its arrival. Above 240, or no more than one decision timeout plus a second, stops startup |
| `ACS_GUARDIAN_HOST_ALLOWLIST` | None | Read by acs.client: Guardian hosts it may contact |
| `ACS_HANDSHAKE_TIMEOUT_SECONDS` | `5` | Read by acs.client: handshake timeout |
| `NO_PROXY` | None | acs.client honors proxy variables on every call, so list the Guardian here when a proxy is set |

Integer settings (`ACS_GATEWAY_WORKERS`, `ACS_GATEWAY_MAX_SESSIONS`, `ACS_GATEWAY_MAX_BODY_BYTES`) take plain ASCII digits only, at least 1. A fraction, a sign, scientific notation such as `8e6`, or digits from another script stop startup with an error naming the setting.

The gateway ignores `ACS_DEFAULT_DENY`, `ACS_STARTUP_POSTURE` and `ACS_DISABLED`, which the hook adapters read. Its posture is always fail closed, and the mode is its off switch.

## Lab conventions

Each of these is the gateway's own choice where the specification is silent or a later item takes over. None changes the Claude Code, Cursor or NAT adapters.

| Convention | Settled by |
|---|---|
| The three modes and `ACS_LAB_MODE` | Issue #577. Shadow isn't decision honoring under section 6.4 |
| A decision after the timeout is discarded, and the step is audited as `decision_timeout` | Issue #435 |
| The gateway denies on any decision failure whatever the ServerHello says, a missing posture included | D-045 and issue #32 |
| The neutral line stands in for a removed call or a denied output | Issue #577 |
| DEFER denies, and ASK denies unless the approver page is on | Issue #14 for DEFER. Issue #581 adds the page |
| The approver's answer reaches the Guardian as the step resent with `x_acs_lab_ask_answer` in its payload, marked `assurance: declared` | Issue #175 |
| One ASK budget per request, from its arrival, capped at 240 seconds and covering the resend | Issue #581 and PREMORTEM P26 |
| A rejection is not resent, and only a human approver with options approve and reject is held | Issue #175 |
| An SSE comment line every 15 seconds while a streamed call is held | Issue #578. The specification defers streaming semantics |
| In enforce a streamed answer is built by the gateway: message text streams live from an allowlist, every other item is built after the final event from its output, and the gateway owns `sequence_number` and `output_index` | Issue #578. The specification defers streaming semantics, and PREMORTEM P21 allows gateway numbering |
| Responses are verified with acs.client's HMAC-SHA256 check inside its round trip. LAB-03 changes the algorithm dispatch inside acs.client to verify by key_id from the key document | LAB-03, issue #576, and issue #460 |
| An output or argument holding an integer above 2**53 - 1, a non-finite number or a lone surrogate denies its whole step, since RFC 8785 (JCS) can't encode it and the signed bytes would differ from the transcript line | Issue #577 |
| `tool.version` is not sent yet | LAB-07, issue #580, sends the tool digest (issue #38) |
| The request field, input item and output item allowlists. FinBot sends only fields and items on them | Issue #577 |
| The admin port and `POST /epoch` | LAB-15, issue #588, wires the lab CLI to it |
| `ACS_MODEL_INPUT_LOG` names the model input log path | LAB-15, issue #588, sets it in the bundle |
| Live, capture and replay upstreams, the recording format, placeholders for FinBot's generated values, branch tokens from the session's outcome records, and the miss response | Issue #579 |
| Replay runs inside the gateway, so no lab header goes to a separate replay server | Issue #579 |

Spans (LAB-09, issue #582) build on this gateway as a separate module.

## Issues this README names

| Issue | Type | Title |
|---|---|---|
| #14 | Bug | DEFER disposition has no resolution wire method, behavior between DEFER and resolution undefined |
| #175 | Bug | ASK has no way to deliver the approver's answer to the Guardian |
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
