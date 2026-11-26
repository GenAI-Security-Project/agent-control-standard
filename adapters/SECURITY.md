# Adapter security posture

This document is the threat model for everything under `adapters/`: the
three reference adapters (`src/acs/integrations/`), the example Guardian
(`src/acs/guardian/`) with its opt-in OPA backend and ML-DSA-65 decision
signing, the shared helpers in `src/acs/core/` and `src/acs/client/`, the
gateway (`gateway/src/acs_gateway/`), and `acs-verify`
(`src/acs/testing/verify.py`). It says what attacks the code defends
against, how, and what is explicitly out of scope. Each mitigation names
the code that carries it.

ACS is a security project — the whole point of the standard is to
police agent behavior. Adapter code that itself has security holes
undermines the standard. Each threat below names the tests that fail
when its mitigation stops holding, or says why it has none.

## In-scope components

| Component | Trust posture |
|---|---|
| Adapter process (`integrations/claude_code/`, `integrations/cursor/`) | Shell-spawned by the framework per hook event. Runs as the framework's user. Reads framework JSON from stdin. |
| Adapter middleware (`integrations/nat/`) | In-process inside the agent's Python runtime. Same address space as the agent. |
| Guardian process (`src/acs/guardian/`) | HTTP server. Holds the HMAC secret. Computes the rolling audit chain. |
| Wire transport | JSON-RPC over HTTP (deployments wrap with HTTPS / mTLS for production). |
| HMAC shared secret | Loaded from `ACS_HMAC_SECRET_FILE` (preferred) or `ACS_HMAC_SECRET` (env-var fallback), and named by the label in `ACS_HMAC_KEY_ID` (§10). A response signed under any other label fails verification; no other secret is tried. |
| Cache files | `~/.cache/acs-adapter-handshake/` (ServerHello cache), `~/.cache/acs-adapter-session/` (per-session step-id tracking). |
| Audit log | `ACS_AUDIT <json>` lines on adapter stderr. |
| OPA backend (`src/acs/guardian/opa_backend.py`) | Off by default. With `ACS_POLICY_BACKEND=opa`, the Guardian POSTs each `steps/toolCallRequest` and `steps/toolCallResult` to the OPA server at `ACS_OPA_URL` and treats the answer as untrusted input. |
| ML-DSA-65 decision key (`src/acs/guardian/decision_keys.py`) | Off by default. With `ACS_RESPONSE_SIGNING=ML-DSA-65`, the Guardian holds a private seed file (`ACS_GUARDIAN_SIGNING_KEY_FILE`) and publishes a public key document (`ACS_GUARDIAN_KEYS`) at `GET /keys`. Clients and the gateway read the same document to verify answers. |
| Gateway model port (`gateway/src/acs_gateway/app.py`) | Network-facing HTTP server, `127.0.0.1:8080` by default. With `ACS_GATEWAY_CLIENT_TOKEN_FILE` set, every request needs `Authorization: Bearer <token>`, and a key file requires the token. Without a key file or token it takes no client credential. Relays OpenAI Responses API traffic between a client and a model upstream, and in shadow and enforce acts as the client's Observed Agent through `acs.client`. |
| Upstream model key (`ACS_UPSTREAM_KEY_FILE`, `gateway/src/acs_gateway/upstream.py`) | Optional. When set, the gateway holds the real model key and puts it on upstream requests, so the client never sees it. |
| Gateway admin port (`create_admin_app` in `gateway/src/acs_gateway/app.py`) | Off unless `ACS_GATEWAY_ADMIN_PORT` is set. One route, `POST /epoch`, behind a bearer token from `ACS_GATEWAY_ADMIN_TOKEN_FILE`. Binds `127.0.0.1` unless `ACS_GATEWAY_ADMIN_HOST` says otherwise. |
| Gateway approver page (`gateway/src/acs_gateway/approver.py`) | Off unless `ACS_GATEWAY_APPROVER_PORT` is set. Releases tool calls held on an ASK, behind the secret in `ACS_GATEWAY_APPROVER_TOKEN_FILE`. Renders model-chosen tool arguments. Binds `127.0.0.1` unless `ACS_GATEWAY_APPROVER_HOST` says otherwise. |
| Gateway records | Transcripts, recordings, the model input log and the audit file, all written from traffic the gateway relays, so they hold tool arguments and results. Transcripts default to `<ACS_GATEWAY_STATE_DIR>/transcripts`, and `prepare_state_dirs` in `gateway/src/acs_gateway/config.py` sets that state directory to mode 0700. Treat every record as sensitive. |
| `acs-verify` (`src/acs/testing/verify.py`) | Offline command. Reads a transcript it must treat as hostile, since the transcript is the evidence under test, plus a key document and an optional HMAC secret. |

## Threat model

### Defended attacks (with the mitigation that defeats each)

**T1: Envelope tampering on the wire.**
An attacker intercepts the adapter ↔ Guardian connection and modifies
the payload, method, or session_id.
*Mitigation:* HMAC-SHA256 over JCS-canonicalized envelope with the
signature field removed (Specification §10). Both sides verify with
`hmac.compare_digest` (constant-time). Signed input includes
`method`, `metadata.session_id`, `request_id`, and `timestamp` so the
signature is bound to the whole envelope.
*Test:* `test_acs_core_conformance.py::Core07_BaselineIntegrity::test_tampered_request_signature_invalid`

**T2: Cross-session signature lift.**
An attacker captures a signed envelope from session A and replays it
under a different session_id.
*Mitigation:* HMAC key is HKDF-SHA256-derived per-session from
`(input_keying_material, session_id)`. A signature valid under
session A's derived key fails verification under session B's key.
*Test:* `Core07_BaselineIntegrity::{test_per_session_key_derivation,
test_signature_covers_session_id}`

**T3: Replay within a session.**
Same envelope re-sent within the same session_id.
*Mitigation:* Guardian tracks `request_id` per session and rejects
duplicates with `REPLAY_DETECTED` (-32005, §10.3). Per session, persisted
under `ACS_GUARDIAN_STATE_DIR` so a Guardian restart keeps it; setting it
to "" keeps it in memory only, for development.
*Test:* `Core06_ReplayProtection::test_duplicate_request_id_rejected_with_32005`,
`FailureMode2_GuardianRestartReplayWindow::test_replay_protection_survives_guardian_restart`

**T4: Stale or future-dated envelope.**
Captured envelope replayed outside the freshness window.
*Mitigation:* Guardian rejects timestamps outside the negotiated skew
window (default ±5 min) with `TIMESTAMP_OUT_OF_WINDOW` (-32006, §10.3).
*Test:* `Core06_ReplayProtection::test_timestamp_outside_window_rejected_with_32006`
(past and future)

**T5: SSRF via `ACS_GUARDIAN_URL`.**
Attacker controls the env var; sets it to `file:///etc/passwd` to
read arbitrary files, or to `data://` to feed a crafted response.
*Mitigation:* `validate_guardian_url()` rejects any scheme that is
not `http` or `https`. Called from `acs.client.exchange` (every
step's round trip), `open_session` and `ping`. The step and handshake
exchanges do not follow redirects, so a response cannot send the
request to a host the check never saw; a redirect status is a
decision failure under the posture.
*Test:* `GuardianUrlSchemeAllowlist`: `file`, `ftp`, `data` and
`javascript` rejected, `http` and `https` accepted.

**T6: Guardian HTTP DoS via oversized body.**
Attacker POSTs a request with Content-Length > available RAM,
expecting the Guardian to allocate.
*Mitigation:* Guardian refuses Content-Length > `MAX_REQUEST_BODY_BYTES`
(1 MiB, the `max_payload_size_bytes` every adapter's ClientHello declares) before
reading the body. Returns 413 + JSON-RPC error -32600.
*Test:* `GuardianBodySizeCap::test_oversized_request_rejected`

**T7: Leaked HMAC secret via world-readable file.**
Operator (or misconfiguration) leaves `ACS_HMAC_SECRET_FILE` mode
0644 / 0640; any local process can read the key.
*Mitigation:* `load_hmac_secret()` reads the file through
`acs.client.read_trusted_file`, which opens its directory once and the
file inside it without following a symlink. It rejects the file unless
it is a regular file, its mode has no group or other access (0600 or
0400), the file and its directory are owned by the running user or
root, and the directory is not world-writable without the sticky bit.
Ancestors above the directory are not checked. The directory must be
readable by the reader, not only traversable: a 0711 directory fails
with "its directory ... cannot be opened", and the fix is `chmod a+r`
on that directory. A file larger than 64 KiB is refused as unreadable. `SecretFilePermissionsError` (or
`SecretFileUnreadableError` for an unreadable or oversized file)
prevents the adapter from silently using a leaked secret.
*Test:* `HmacSecretFilePermissions::{test_world_readable_rejected,
test_group_readable_rejected, test_symlink_rejected}`

**T8: Cache / session-state poisoning.**
Local attacker writes the handshake cache or session-state file
between adapter invocations. For session-state, this would let them
change the open turn or the decision-failure counts the next hook reads.
*Mitigation:* Both cache directories created mode 0700; cache files
created mode 0600 via `os.open(...O_CREAT, 0o600)`. A local attacker
without same-uid privileges cannot read or write the state. These
modes do not separate the agent from the developer: the agent runs as
the developer, so it can read the HMAC key file, the handshake cache
and the audit file, and write the cache. The record's HMAC stops a
writer that cannot read the key; the agent can, so it can also write a
record that passes, and only a separate user or a sandbox keeps the key
from the agent. Each
session-state update is one read-modify-write under an exclusive lock on
a sidecar file, published through a temp file of its own with
`os.replace`, so parallel hook processes neither lose updates nor read a
partial file. The
handshake record carries an HMAC under the session key over the
decision, the session and the Guardian URL, so a record modified,
damaged or copied from another endpoint by a writer without the key, or
left by an earlier adapter, refuses the session, and so does a decision
that cannot be stored; a deleted record makes the next event handshake again.
*Test:* `CacheDirPermissions::{test_session_state_dir_is_0700,
test_session_state_file_is_0600}`,
`Item22_StoredSessionDecisionIsAuthenticated`

**T9: Regex DoS via oversized command.**
Attacker submits a multi-MB command string crafted to trigger
catastrophic backtracking in the destructive-bash regex set.
*Mitigation:* `scan_destructive_bash_safely()` refuses to scan
commands longer than `DESTRUCTIVE_SCAN_MAX_LEN` (8 KiB). The skip is
audited and the caller MUST treat the return value `"input_too_large"`
as suspicious — NOT as "safe to allow." Real shell commands are tiny;
multi-KB strings are either tunneled data or a DoS attempt.
*Test:* `RegexInputSizeCap::test_oversized_command_is_short_circuited`

**T10: Audit-log injection.**
Field values in audit events (`session_id`, `method`, `error=str(e)`)
could contain newlines or control characters that, if naively written,
would let an attacker forge fake `ACS_AUDIT` lines.
*Mitigation:* `audit_event()` emits a single line of
`json.dumps(payload, sort_keys=True)`. JSON encoding escapes `\n`,
`\r`, and other control characters in string values. The
`ACS_AUDIT ` prefix is the only unescaped text.
*No dedicated test* — the property is enforced by the JSON encoder;
adding a test would be checking stdlib behavior.

**T11: Handshake downgrade.**
Attacker MITMs the handshake response to claim the Guardian doesn't
support signing, hoping the adapter then sends unsigned envelopes.
*Mitigation:* The adapter signs every request with its own secret,
whatever `signature_algorithms_supported` the handshake advertised,
and a hook with no secret refuses its session and sends nothing. The
handshake's advertised algorithm list does not control signing.
*No test* — this is an absence of behavior. Verified by reading the
code: `sign_envelope()` consults `load_signing_material()` only.

**T12: Guardian-side signature stripping.**
Attacker MITMs the Guardian's response and removes the `signature`
field, hoping the adapter's response verification silently accepts.
*Mitigation:* `verify_signature()` returns False for a response with no
signature, and every request is signed. The adapter rejects the response
and denies the step whatever the posture, with an audit event.
*Test:* `ExchangeCauses::test_every_cause` ("unsigned result" and
"unsigned error" are refused) and `Resolve::test_resolution_table` (a
refusal denies under either posture).

The threats below cover the opt-in Guardian modes, the gateway and
`acs-verify`. Their tests live in `tests/guardian/` and
`gateway/tests/`, which `run_conformance.py` does not run. The README's
"Run the checks" section gives the commands.

**T13: Decision forgery by a holder of the shared HMAC secret.**
Every adapter holds the HMAC secret, so under HMAC alone any of them can
sign a decision the Guardian never made.
*Mitigation (opt-in):* With `ACS_RESPONSE_SIGNING=ML-DSA-65`, the example
Guardian signs every answer with its own ML-DSA-65 key
(`src/acs/guardian/decision_keys.py`, `load_decision_signer`). A client
configured with `ACS_RESPONSE_ALGORITHMS=ML-DSA-65` verifies every answer,
the ServerHello included, under the key the key document holds for the
pinned `key_id`, never a key or algorithm the answer names
(`acs.client.response_keys_from_env`). Each answer carries
`x_acs_lab_request_sha256`, the hash of the request it answers, so an
answer can't be moved to another request or session. HMAC-SHA256 stays the
default and requests stay on HMAC. The mode is a lab convention and makes
no ACS-Crypto claim.
*Test:* `tests/guardian/test_decision_signing_e2e.py`,
`tests/client/test_pqc_verification.py`, and
`test_acs_verify.py::test_a_correctly_hmac_signed_allow_inside_an_mldsa_session_fails`.

**T14: Stolen or swapped ML-DSA-65 key material.**
An attacker reads the private seed, or replaces the key document so
clients trust the attacker's key.
*Mitigation:* `decision_keys.write_key_files` writes the seed with mode
0600 through `O_EXCL`, so it never overwrites a key a published document
already names, and creates a missing directory as 0700.
`load_signing_key` reads the seed through `acs.client.read_trusted_file`:
no symlink, no FIFO, owner-only, a 128-byte cap, and exactly 64 lowercase
hex characters. The Guardian refuses to start unless the seed's public key
is a live key in the document under `ACS_GUARDIAN_KEY_ID`
(`load_decision_signer`). A client reads the document through the same
reader, which refuses group or other write, and
`ACS_GUARDIAN_KEY_FINGERPRINT` pins the key so a swapped document fails.
The Guardian prints the fingerprint at startup for an out-of-band check.
The key's validity window and `revoked_at` are checked at every signature
and every verification.
*Test:* `test_decision_keys.py::{test_write_key_files_never_overwrites,
test_load_signing_key_refuses_loose_modes,
test_load_signing_key_refuses_a_symlink}`,
`tests/client/test_key_document.py`.

**T15: A hostile or broken OPA server.**
The OPA answer could be oversized, slow, malformed, or a verdict that
loosens a built-in deny. A proxy variable or a redirect could send the
policy call somewhere the operator never named.
*Mitigation:* `src/acs/guardian/opa_backend.py`. Every failure is a
signed deny with a generic reason code (`FAILURE_REASONING`), and the
detail goes only to the Guardian's stderr log, with the URL's userinfo
removed (`redact_url`). One deadline, at most 4000 ms, bounds the whole
query (`query`), and the response is capped at 1 MiB (`_post`). The opener
has no proxy handler and no redirect handler (`_opener`), so the call goes
only to `ACS_OPA_URL`. `verdict_problem` rejects any verdict outside the
accepted shape. The built-in denies run before OPA, and run again on the
arguments an OPA modify produces, so a policy can't rewrite an allowed call
into one the built-in rules deny.
*Test:* `tests/guardian/test_opa_backend.py`,
`tests/guardian/test_opa_verdict.py`,
`test_opa_process.py::test_the_probe_ignores_proxy_variables`.

**T16: An unauthenticated client spends the operator's model key.**
Without a client credential, anyone who reaches the gateway's model port
with `ACS_UPSTREAM_KEY_FILE` set spends the key.
*Mitigation:* `GatewayConfig.from_env` in
`gateway/src/acs_gateway/config.py` refuses to start with a key file
unless `ACS_GATEWAY_CLIENT_TOKEN_FILE` names a client token file, and
unless `ACS_GATEWAY_HOST` is a loopback address or
`ACS_UPSTREAM_KEY_SHARED=1` records that the operator accepts the reach.
`ClientTokenGate` in `gateway/src/acs_gateway/app.py` compares the bearer
token in constant time before the body is read, answers anything else
with a 401, and refuses a websocket. The model port binds `127.0.0.1` by
default.
*Test:* `test_client_token.py`,
`test_upstream_config.py::test_a_key_file_refuses_a_model_port_off_loopback`.

**T17: Leak of the upstream model key.**
The key could reach the client, a recording, a log, an error message, or a
commit.
*Mitigation:* `read_key_file` in `gateway/src/acs_gateway/upstream.py`
refuses a key file inside a git work tree, and reads it through
`secretfile.load_secret_file`: one descriptor opened with `O_NOFOLLOW` and
`O_NONBLOCK`, a regular file, mode 0600 or 0400, owned by the gateway's
uid. It refuses a key with whitespace or unprintable characters, so the key
can't split the header it goes into. The key replaces the client's
`Authorization` header on the upstream request only, and no error message
carries it. Capture never writes headers. Replay refuses a key file.
*Test:* `test_upstream_config.py::test_a_bad_key_file_is_refused_without_showing_the_key`,
`test_upstream_capture.py::test_the_key_reaches_only_the_upstream_header`,
`test_upstream_shared.py::test_a_fifo_key_file_is_refused`.

**T18: Unauthorized epoch bump on the admin port.**
An epoch bump forgets every session and every cached outcome, so a caller
who can send one makes the gateway gate past calls afresh.
*Mitigation:* `create_admin_app` in `gateway/src/acs_gateway/app.py`
answers 401 unless the `Authorization` header matches `Bearer <token>`,
compared with `hmac.compare_digest`. `cli.main` refuses to open the admin
port without `ACS_GATEWAY_ADMIN_TOKEN_FILE`, and `load_secret_file`
requires a regular file, mode 0600 or 0400, owned by the gateway's uid,
with at least 32 bytes. The admin port is separate from the model port, so
a client can't reach it through `POST /v1/responses`.
*Test:* `test_epoch.py::{test_the_epoch_bump_refuses_a_wrong_token,
test_an_admin_token_file_others_can_read_is_refused,
test_a_short_admin_token_is_refused,
test_a_symlinked_admin_token_file_is_refused}`.

**T19: A forged or injected answer on the approver page.**
The page releases held tool calls, and it renders tool arguments the model
chose, which an attacker can steer. A local process, a sibling container
or a web page could try to answer, and a crafted argument could try to run
script or hide text.
*Mitigation:* `gateway/src/acs_gateway/approver.py`.
`GatewayConfig.from_env` refuses the approver port without
`ACS_GATEWAY_APPROVER_TOKEN_FILE`, on any host. `create_approver_app`
admits a caller only with the secret as a bearer token, or with a sign-in
cookie that holds a random session id, never the secret, marked `HttpOnly`
and `SameSite=Strict`, valid 15 minutes and replaced by the next sign-in.
Behind the secret, an answer also needs a same-origin `Origin`, a
`Sec-Fetch-Site` that isn't cross-site or same-site, a loopback or bind-host
`Host`, and a token minted with the page that answers only the calls that
page showed, once each (`Approvals.submit`, `mint_token`). `visible`
writes every invisible or reordering character as a `\uXXXX` escape before
HTML escaping. `_HEADERS` sends a `Content-Security-Policy` with
`default-src 'none'` and `frame-ancestors 'none'`, and `X-Frame-Options:
DENY`. The gateway never turns an ASK into an allow on its own: an
approval goes back to the Guardian, whose answer decides.
*Test:* `gateway/tests/test_approver.py`, including
`test_without_the_secret_there_is_no_page_and_no_answer`,
`test_a_page_from_a_rebound_host_is_refused`,
`test_a_token_answers_each_call_once` and
`test_the_page_sends_headers_that_keep_it_out_of_frames_and_scripts`.

**T20: A client or model slips a call past the gateway's gate.**
A request field, item type, content part or tool type the gateway doesn't
model could carry a tool call or stored content it never sends to the
Guardian. A repeated JSON key could make the gateway gate one copy while
the model reads another.
*Mitigation:* In enforce, the gateway accepts only what is on its
allowlists, and answers anything else with 501 before it goes upstream
(`gateway/src/acs_gateway/app.py`). `gateway/src/acs_gateway/strict.py`
refuses a repeated JSON key at any depth: a repeated key in the request is
refused with 400, and a repeated key in a tool's arguments denies that step. A streamed answer is rebuilt by the
gateway from an allowlist (`gateway/src/acs_gateway/stream.py`), so no
upstream byte reaches the client in enforce. Every decision failure
denies, and a ServerHello that declares `proceed`, or leaves the tool
methods out of `methods_evaluated`, can't loosen that
(`GuardianClient.posture` in `gateway/src/acs_gateway/guardian.py`). Request bodies
over `ACS_GATEWAY_MAX_BODY_BYTES` get 413.
*Test:* `gateway/tests/test_allowlists.py`,
`gateway/tests/test_duplicate_keys.py`,
`test_enforce_calls.py::test_the_server_hello_never_loosens_the_fail_closed_posture`,
`test_enforce_calls.py::test_a_server_hello_that_skips_tool_calls_denies_them`.

**T21: ACS state leaks to the client or the model.**
A session id, request id, reason code, signature or lab header in the
traffic would tell the model it is governed, or hand a client material to
replay.
*Mitigation:* `forward_headers` in `gateway/src/acs_gateway/app.py` strips
every `x-acs-*` header in both directions, and a removed call or a denied
output becomes one neutral line. Spans never carry a body, a tool's
arguments or output, a key or a signature
(`gateway/src/acs_gateway/telemetry.py`), and an
`OTEL_EXPORTER_OTLP_ENDPOINT` that carries a user name or password stops
startup without echoing it (`_otlp_endpoint` in
`gateway/src/acs_gateway/config.py`).
*Test:* `test_invisibility.py::test_nothing_of_acs_reaches_the_client_or_the_model`,
`test_spans.py::test_no_body_argument_output_or_secret_reaches_a_span`,
`test_telemetry.py::test_a_bad_endpoint_error_never_echoes_the_value`.

**T22: A hostile transcript fools `acs-verify` or the person reading its
report.**
The transcript is the evidence under test, so whoever wrote it may have
forged it. It could switch a check to a weaker algorithm, name its own key,
repeat a JSON key so two readers disagree, exhaust memory, or carry
terminal escape sequences that repaint a failure as a pass.
*Mitigation:* `src/acs/testing/verify.py`. The command-line flags choose
the algorithm, never the transcript, so a rewritten ServerHello can't
switch a check to HMAC. `_verify_mldsa` takes the key from the key
document by `key_id`, honors the pin and the expected fingerprint, and
checks the key was live at the request's timestamp. `_strict_loads`
refuses a repeated key and the constants `NaN` and `Infinity`. The
transcript is capped at 256 MiB by default (`_read_transcript`), and more
than 20 requests waiting on a chain head fail the run (`MAX_UNSETTLED`),
which bounds the chain search. `_printable` escapes every
control, format, surrogate and separator character in report text. The
key document and the HMAC secret go through `acs.client.read_trusted_file`
(`_read_key_document`, `_read_secret`). A pass claims only what a
signature covers, and the report lists every request no signed decision
covers.
*Test:* `tests/guardian/test_acs_verify.py`,
`test_acs_verify_cli.py::{test_a_transcript_over_the_byte_cap_exits_2,
test_every_report_field_that_carries_transcript_text_is_escaped,
test_the_key_document_goes_through_the_trusted_file_reader}`,
`test_acs_verify.py::test_a_line_with_a_repeated_key_fails_at_that_line`.

### Out of scope (deployment / operational concerns)

**O1: Plaintext HTTP exposes payload content.**
Even when HMAC-signed, the body is readable on the wire. An attacker
on the network path can read tool names, arguments, prompts, results.
*Posture:* Use HTTPS for any non-loopback deployment. Set
`ACS_GUARDIAN_URL=https://...` and put the Guardian behind TLS (real
cert, or mTLS for stronger client identity). The adapter's URL
allowlist accepts `https://`. We do not bundle a TLS implementation.
The gateway's model, admin and approver ports serve plain HTTP too, so
the admin and approver secrets cross the wire in the clear off loopback.
Keep those ports on loopback, as their defaults are, or behind a TLS proxy.

**O2: Regex bypass via shell quoting / expansion.**
Shell evaluates `r''m -rf /` as `rm -rf /` after quote removal. The
adapter only sees the literal `r''m -rf /` from the framework, which
does not match our destructive-bash regex. Same for `$(echo rm) -rf /`,
backslash escapes, locale-dependent commands, etc.
*Posture:* The destructive-bash regex is a teaching artifact and a
defense-in-depth heuristic, NOT a security boundary. Production
deployments wire a real policy engine (OPA/Rego, Cedar, or a vendor
policy bundle) into the Guardian. Documented in
`src/acs/guardian/example_guardian.py` and `adapters/README.md`.

**O3: Secret in env-var visible to child processes / `ps eauxw`.**
`ACS_HMAC_SECRET` shows up in `/proc/PID/environ` and is inherited by
any child process the adapter or Guardian spawns.
*Posture:* That's exactly why `ACS_HMAC_SECRET_FILE` exists. The env
var is a development convenience; production deployments use the file
path with mode 0600. Documented in the Guardian README.

**O4: Compromised Guardian.**
A Guardian that holds the symmetric HMAC key can re-sign a rewritten
chain head and present a clean history. The HMAC baseline detects
network tampering and cross-Guardian disagreement but cannot prove
non-repudiation against the Guardian itself.
*Posture:* That's what the ACS-Crypto profile (asymmetric / PQC
signatures) and the ACS-Audit profile (`request_hash` per
ContextEntry) are for. The specification v0.1.0 baseline acknowledges this tradeoff
(`conformance.md`, "What 'ACS-Core conformant' guarantees"); we don't implement those profiles.
The opt-in ML-DSA-65 decision signing (T13) narrows this: a holder of
only the HMAC secret can no longer forge a decision, and `acs-verify`
lets someone other than the Guardian check its chain and signatures.
The Guardian still holds its own private key, so it can still sign a
rewritten history. The mode is off by default and makes no ACS-Crypto
claim.

**O5: Compromised secret-file storage.**
A reader of the storage volume (cloud snapshot, backup, etc.) gets
the HMAC key. File permissions don't help there.
*Posture:* Encrypted storage, sealed secrets (Vault, K8s sealed
secrets, KMS-backed envelopes). Out of scope for the adapter; the
adapter just receives the key bytes from a file path.

**O6: Memory disclosure / core dumps.**
HMAC key in process memory. No explicit zeroize.
*Posture:* Disable core dumps in production (`ulimit -c 0` /
`fs.suid_dumpable=0`). Python doesn't expose secure-erase primitives;
acceptable tradeoff for release 0.1.5. The same holds for the gateway's
admin and approver secrets, the upstream model key and the ML-DSA-65 seed.

**O7: Compromised adapter binary.**
A malicious adapter binary (shipped via supply-chain attack on the
ACS repo, or a tampered local install) does whatever it wants.
*Posture:* Out of scope. Verify the adapter against the published
hash. The ACS-Inspect profile addresses the AgBOM side; binary
integrity of the adapter itself is a deployment-tools concern.

**O8: Compromised framework (Claude Code / Cursor / NAT).**
If Claude Code itself is compromised, all bets are off — it can
choose not to call hooks, ignore deny responses, etc. ACS-Core §6.4
("decision honoring") is a property the framework must implement; an
adapter cannot enforce it on a hostile framework.
*Posture:* Framework integrity is a separate trust boundary outside
ACS's scope.

**O9: Operator-supplied destinations and recordings.**
`ACS_OPA_URL`, `ACS_UPSTREAM_URL`, `ACS_GUARDIAN_URL` and
`OTEL_EXPORTER_OTLP_ENDPOINT` are operator settings, and the code doesn't
restrict which host they name.
`ACS_GUARDIAN_HOST_ALLOWLIST` narrows the Guardian hosts `acs.client`
may contact. A recording's `match` field is a regular expression the
gateway runs as written, with no time limit, so recordings are trusted
input and deserve the review code gets.
*Posture:* Whoever sets the environment controls these. Review a recording
from anywhere else before you replay it.

**O10: The gateway's off and shadow modes.**
Off governs nothing, and shadow records decisions without applying them,
so neither is decision honoring under specification section 6.4.
`ACS_LAB_MODE` unset means off.
*Posture:* Run enforce wherever a decision must hold. The gateway ignores
`ACS_DEFAULT_DENY`, `ACS_STARTUP_POSTURE` and `ACS_DISABLED`, so its mode
is its only switch.

## Mitigation matrix at a glance

| Threat | Mitigation | Test |
|---|---|---|
| T1 envelope tampering | HMAC-SHA256 over JCS canonical input | `Core07_BaselineIntegrity::test_tampered_request_signature_invalid` |
| T2 cross-session lift | per-session HKDF key derivation | `Core07_BaselineIntegrity::test_signature_covers_session_id` |
| T3 in-session replay | per-session `request_id` set + -32005 | `Core06_ReplayProtection::test_duplicate_request_id_rejected_with_32005` |
| T4 timestamp skew | skew-window check + -32006 | `Core06_ReplayProtection::test_timestamp_outside_window_rejected_with_32006` |
| T5 SSRF | URL scheme allowlist (http/https) | `GuardianUrlSchemeAllowlist::*` (6 tests) |
| T6 body-size DoS | Content-Length cap + 413 | `GuardianBodySizeCap::test_oversized_request_rejected` |
| T7 leaky secret file | mode/owner/symlink check on `ACS_HMAC_SECRET_FILE` | `HmacSecretFilePermissions::*` (4 tests) |
| T8 cache poisoning | dir 0700 + file 0600 | `CacheDirPermissions::*` (2 tests) |
| T9 regex DoS | 8 KiB input cap + audit | `RegexInputSizeCap::*` (3 tests) |
| T10 log injection | `json.dumps` escaping | enforced by stdlib |
| T11 handshake downgrade | adapter signs based on own config, not handshake | code-level |
| T12 response sig stripping | `verify_signature` False when the signature is absent | `ExchangeCauses::test_every_cause` |
| T13 decision forgery by an HMAC holder | opt-in ML-DSA-65 answers, key from the pinned key document, request hash | `test_decision_signing_e2e.py`, `test_pqc_verification.py` |
| T14 stolen or swapped ML-DSA-65 key | 0600 seed via `O_EXCL`, trusted-file reader, fingerprint pin | `test_decision_keys.py`, `test_key_document.py` |
| T15 hostile OPA server | deny on every failure, 4000 ms cap, 1 MiB cap, no proxy, no redirect | `test_opa_backend.py`, `test_opa_verdict.py` |
| T16 model key spent by any caller | client bearer token required with a key file, constant-time compare, key file only on a loopback model port unless `ACS_UPSTREAM_KEY_SHARED=1` | `test_client_token.py`, `test_a_key_file_refuses_a_model_port_off_loopback` |
| T17 model key leak | key file rules, no git work tree, upstream header only | `test_the_key_reaches_only_the_upstream_header` |
| T18 unauthorized epoch bump | bearer token, constant-time compare, 0600 token file of 32 bytes or more | `test_epoch.py` |
| T19 forged approver answer | secret, session cookie, Origin and Host checks, one-use page tokens, escaping, CSP | `test_approver.py` |
| T20 call slips past the gate | allowlists, repeated-key refusal, gateway-built streams, fail closed | `test_allowlists.py`, `test_duplicate_keys.py`, `test_enforce_calls.py` |
| T21 ACS state leaks to client or model | `x-acs-*` stripped, neutral line, no bodies or keys in spans | `test_invisibility.py` |
| T22 hostile transcript | flags pick the algorithm, strict JSON, size and chain-search caps, escaped report | `test_acs_verify.py`, `test_acs_verify_cli.py` |

## How to report a finding

**Do not file public issues for security vulnerabilities.** Use
GitHub's [private vulnerability reporting](https://github.com/GenAI-Security-Project/agent-control-standard/security/advisories/new)
to disclose privately — the process and response commitment are in
[`CONTRIBUTING.md` § Reporting Security Issues](../CONTRIBUTING.md#reporting-security-issues).
