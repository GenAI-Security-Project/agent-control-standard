# Rust AGT Guardian (first stage)

This is a Rust Guardian for [issue #88](https://github.com/GenAI-Security-Project/agent-control-standard/issues/88). It runs beside the [TypeScript AGT reference implementation](../agt/README.md), using its current `mapping.yaml`, AGT manifest and policy bundle, and this repository's ACS v0.1.0 schemas. It is a proof of concept. It does not claim ACS-Core conformance.

## What runs

`POST /acs` receives JSON-RPC envelopes. The Guardian validates the envelope and the two supported tool payloads against `specification/v0.1.0/`, assembles an AGT snapshot, calls the pinned `agent_control_specification` Rust SDK (0.3.1-beta.0), and maps its verdict through the shared `mapping.yaml`. A session store keeps source labels and a local hash chain. The server records request and response envelopes in the same JSONL shape as the TypeScript Guardian.

The TypeScript Claude Code and OpenCode shims can point to this server through `ACS_GUARDIAN_URL`. Those shims are the host side of this stage; this directory does not contain Rust replacements for them.

## Prerequisites and run

- Rust 1.89 or newer (the current dependency graph includes Cedar Policy 4.13).
- OPA **0.70.0**, the version used by the pinned AGT policy bundle. Set `ACS_OPA_PATH` to its executable path. Startup checks the reported version and refuses other versions before loading the manifest. CI uses the AGT platform package verified by `../agt/bun.lock`.
- Run from this checkout. The default paths deliberately resolve to the sibling `agt/` tree and the repository schemas.

```sh
cd reference-implementations/agt-rust
export ACS_OPA_PATH=/absolute/path/to/opa
cargo build --locked
cargo run --locked
```

The endpoint is `http://127.0.0.1:8787/acs` by default. To use the existing Claude Code shim, start the Guardian above, then run the hook from `reference-implementations/agt`:

```sh
echo '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo rm -rf /"}}' | bun run hosts/claude-code/acs-hook.ts
```

The shim's `ACS_GUARDIAN_URL` defaults to the same endpoint. The shim does not execute the command.

The Guardian reads `ACS_GUARDIAN_HOST`, `ACS_GUARDIAN_PORT`, `ACS_MANIFEST_PATH`, `ACS_ON_DECISION_FAILURE`, `ACS_ENVELOPE_LOG`, `ACS_SESSION_CONTEXT_LOG`, and `ACS_OPA_PATH`, plus the signing settings described in [Signatures and replay protection](#signatures-and-replay-protection). It binds to loopback and declares `proceed` on decision delivery failure by default. `ACS_ON_DECISION_FAILURE=deny` changes the handshake's declared posture; other values stop startup. The local logs default to `agt/.acs/envelopes-rust.jsonl` and `agt/.acs/session-context-rust.jsonl`. They can contain raw arguments and should be protected as sensitive local data. They are ignored by Git.

The AGT SDK reads `ACS_OPA_TIMEOUT_MS`, defaulting to 5000 milliseconds. The handshake advertises this evaluator timeout plus 1000 milliseconds for request handling and decision delivery. The default host deadline is therefore 6000 milliseconds; setting `ACS_OPA_TIMEOUT_MS=30000` advertises 31000 milliseconds. A timeout too large to represent with the delivery margin stops startup.

## Signatures and replay protection

The Guardian implements the [§10](../../docs/spec/instrument/specification.md#10-cryptographic-signatures) `HMAC-SHA256` baseline and [§10.3](../../docs/spec/instrument/specification.md#103-replay-protection) replay protection.

**Keys.** Each secret is named by a `key_id` the deployment chooses. There is no built-in default. A secret is standard base64 (RFC 4648 §4) with padding, and surrounding whitespace is ignored. It must decode to at least 32 bytes from a cryptographically secure random source, such as `openssl rand -base64 32`. Configure secrets in either or both of these ways:

- `ACS_HMAC_KEYS_FILE` names a JSON file that maps each `key_id` to its secret, for example `{"2026-10": "...", "2026-11": "..."}`. Keep this file readable only by the Guardian.
- `ACS_HMAC_KEY_ID` and `ACS_HMAC_SECRET` give one secret. These are the names the TypeScript host adapter reads. Setting one without the other stops startup.

A malformed, short or duplicated secret stops startup. Error messages name the `key_id` and never the secret. Neither the secret nor a derived key is written to the audit logs or to standard error.

**Rotation.** Several secrets can be configured at once, so a secret is replaced without an outage:

1. Add the new secret under a new `key_id`, such as `"2026-11"`, and restart the Guardian.
2. Move every Observed Agent to the new `key_id`.
3. Remove the old secret and restart again.

**Verification.** With at least one secret configured, every request except `system/ping` must carry `params.signature`. The per-session key is HKDF-SHA256 of the named secret, with no salt and the request's `metadata.session_id` as `info`. The signed input is the RFC 8785 canonical envelope without `params.signature`, and `value` is the standard base64 of the HMAC. A missing signature, another algorithm, an unknown `key_id` or a mismatch is refused with `SIGNATURE_INVALID` (`-32004`). An unknown `key_id` is never checked against another secret.

**Responses.** A response to a verified request carries `result.signature`, or `error.signature` for an error, under the `key_id` and session key of that request. That includes the denial that replaces a decision when an audit record cannot be kept. A response to a request that failed verification is unsigned, because no configured secret matches it. `system/ping` is never signed or checked, so liveness probes keep working during a key-resolution failure.

**Freshness.** A request whose `timestamp` is more than the skew window from the Guardian's clock is refused with `TIMESTAMP_OUT_OF_WINDOW` (`-32006`). The window defaults to 300000 milliseconds, and `ACS_SKEW_WINDOW_MS` changes it. A repeated `request_id` within a session is refused with `REPLAY_DETECTED` (`-32005`). Each id is kept until its timestamp could no longer pass the window. The store holds at most 65536 ids across 4096 sessions. When it is full of ids that are still valid, a new request is refused with `SESSION_REFUSED` (`-32000`, `reason: replay_protection_capacity`) instead of evicting an id that could then be replayed. These checks apply with or without signing. The handshake declares `signature_algorithms_supported` and `skew_window_ms`.

Without any secret, the Guardian prints a warning at startup and neither verifies nor signs. That mode exists for the side-by-side comparison with the TypeScript Guardian and is not ACS-Core.

Not covered yet: the optional `nonce` is not checked, replay state is in memory and lost on restart, hook traffic is not refused before a handshake, and only `HMAC-SHA256` is supported.

## Audit log limits and failures

Both audit logs are required. A missing or unopenable sink stops startup. Each sink
has a maximum segment size of 8 MiB and retains at most five files, including the
active file: 40 MiB per sink and 80 MiB in total. `ACS_LOG_MAX_BYTES` and
`ACS_LOG_MAX_FILES` configure those positive limits. The newline counts towards
the size limit, and a single record larger than a segment is refused.

A full active file moves to `.1`, with older segments moving to `.2` and so on.
Rotation never deletes or overwrites an audit record. When the retained segments
are full, decisions are denied until an operator archives the segments and
restarts the Guardian. Rotation uses same-directory hard links to prevent
overwriting an existing destination; a filesystem that cannot make these links
causes a denial rather than losing history.

Each append is serialized, written, flushed and synchronized to the filesystem.
A write, flush, sync or rotation failure latches the sink unavailable. A valid
step receives a final `deny`, including when logging the response to an otherwise
allowed request fails. It does not receive an error that could trigger the host's
fail-open posture. Subsequent steps remain denied; the Guardian does not silently
disable its audit logs and continue evaluating requests. The unrecordable denial
itself cannot repair an unavailable sink: restore storage and inspect any partial
last record before restarting.

An adjacent `.lock` file holds an exclusive advisory lock for the lifetime of
each sink, including across rotations. Reusing the same configured path in
another sink or Guardian fails startup. The data file remains readable by the
Inspector. Symlink or hard-link aliases and writers that ignore the advisory
lock are not supported: configure distinct physical files for the two sinks and
for separate instances. An incomplete final record prevents restart instead of
appending new records to a partial JSON line.

The session state is still in memory. This does not add crash recovery for that
state or claim full ACS-Core conformance. Parsing and oversized-body errors that
cannot identify a step retain their JSON-RPC error behavior; they cannot be
turned into a step decision.

## Test

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
ACS_OPA_PATH=/absolute/path/to/opa ACS_OPA_TIMEOUT_MS=30000 cargo test --workspace --all-features
```

Unit tests cover verdict mapping, session state, OPA version validation, host deadline calculation, bounded audit logging, replay state, RFC 8785 canonicalization, key handling, and HKDF key derivation against the §10 example key. The HTTP integration test starts a real Guardian and uses the pinned AGT bundle for handshake, allow, deny, request and result redaction, egress denial, WebFetch allowance, malformed payload, unknown method, parse error, oversized body, and log cases. It also checks the advertised deadline. A second integration test signs requests under two configured secrets and checks signed responses, the key_id a response names, replay and timestamp refusals, tampering, an unknown or missing signature, and the `system/ping` exemption. It requires OPA. The test command gives slow test machines a longer OPA subprocess deadline and correspondingly extends the host deadline. The existing TypeScript tests are a separate baseline and can be run from `../agt` with Bun 1.3.11.

For a direct wire comparison, start the Rust Guardian on port 8787 and the TypeScript Guardian on port 8788 with the same AGT policy bundle, then run `node tests/compare-guardians.mjs` from this directory. `RUST_GUARDIAN_URL` and `TS_GUARDIAN_URL` can override the endpoints. CI also runs these nine cases: eight complete response comparisons and one handshake comparison excluding the intentionally different `timeout_config.default_ms` and the signing fields only the Rust Guardian declares. Both Guardians run unsigned for this comparison.

This is evidence for those nine cases, not general parity. The comparison does not cover non-object arguments, handshake validation error details, alternative UUID or timestamp formats, warn or escalate verdicts, or evaluation failures. Those inputs can differ between the Guardians.

## Scope and parity

| Component or behavior | This stage | TypeScript reference |
| --- | --- | --- |
| `POST /acs` JSON-RPC and handshake | Implemented | Implemented |
| `steps/toolCallRequest` and `steps/toolCallResult` | Implemented with AGT Rust SDK and the shared manifest | Implemented with AGT Node binding |
| Repository request and hook schema validation | Implemented | Implemented |
| §10 `HMAC-SHA256` signatures and §10.3 replay protection | Implemented; the optional `nonce` is not checked | Not yet; PR #229 adds them |
| Five AGT verdict mappings from `mapping.yaml` | Implemented; live tests cover allow, deny and transform | Implemented and covered by its mapping tests |
| Egress annotator and IFC source labels | Implemented; the Rust SDK cannot distinguish absent `result_labels` from an explicit empty array | Implemented |
| Session hash chain and envelope JSONL | Implemented locally; no `chain_hash` on the wire | Implemented locally; no `chain_hash` on the wire |
| Claude Code and OpenCode host shims | Use the existing TypeScript shims | Implemented |
| Host adapter, Inspector and conformance runner in Rust | Not yet ported | Implemented |

Both Guardians have these limits of the TypeScript reference: two of nineteen hooks are evaluated; `system/ping` and wrapped MCP are absent; `ask` lacks `ask_details`; and the chain head is not published on responses. The TypeScript Guardian also has no replay checks or signatures, so its wire is unauthenticated. An `ask` response therefore fails the current response schema. This stage must not be used as a claim of full ACS-Core support.

The pinned Rust AGT SDK represents `result_labels` as `Vec<String>` and normalizes both a missing field and an explicit empty array to an empty vector. This Guardian retains the current session labels when the vector is empty. That preserves the prior restriction but can differ from the TypeScript Guardian when a policy explicitly clears labels. Full IFC parity needs an SDK API that preserves this distinction.

The Rust source separates schema loading (`schema.rs`), AGT SDK integration and the egress annotator (`policy.rs`), mapping (`mapping.rs`), session state (`session.rs`), §10 signing (`signing.rs`), §10.3 replay state (`replay.rs`), and HTTP dispatch and logs (`server.rs`). The policy files remain in `../agt/policy/`; none are duplicated here.
