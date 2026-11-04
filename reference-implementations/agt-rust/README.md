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

The Guardian reads `ACS_GUARDIAN_HOST`, `ACS_GUARDIAN_PORT`, `ACS_MANIFEST_PATH`, `ACS_ON_DECISION_FAILURE`, `ACS_ENVELOPE_LOG`, `ACS_SESSION_CONTEXT_LOG`, and `ACS_OPA_PATH`. It binds to loopback and declares `proceed` on decision delivery failure by default. `ACS_ON_DECISION_FAILURE=deny` changes the handshake's declared posture; other values stop startup. The local logs default to `agt/.acs/envelopes-rust.jsonl` and `agt/.acs/session-context-rust.jsonl`. They can contain raw arguments and should be protected as sensitive local data. They are ignored by Git.

The AGT SDK reads `ACS_OPA_TIMEOUT_MS`, defaulting to 5000 milliseconds. The handshake advertises this evaluator timeout plus 1000 milliseconds for request handling and decision delivery. The default host deadline is therefore 6000 milliseconds; setting `ACS_OPA_TIMEOUT_MS=30000` advertises 31000 milliseconds. A timeout too large to represent with the delivery margin stops startup.

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

Unit tests cover verdict mapping, session state, OPA version validation, host deadline calculation, and bounded audit logging. The HTTP integration test starts a real Guardian and uses the pinned AGT bundle for handshake, allow, deny, request and result redaction, egress denial, WebFetch allowance, malformed payload, unknown method, parse error, oversized body, and log cases. It also checks the advertised deadline. It requires OPA. The test command gives slow test machines a longer OPA subprocess deadline and correspondingly extends the host deadline. The existing TypeScript tests are a separate baseline and can be run from `../agt` with Bun 1.3.11.

For a direct wire comparison, start the Rust Guardian on port 8787 and the TypeScript Guardian on port 8788 with the same AGT policy bundle, then run `node tests/compare-guardians.mjs` from this directory. `RUST_GUARDIAN_URL` and `TS_GUARDIAN_URL` can override the endpoints. CI also runs these nine cases: eight complete response comparisons and one handshake comparison excluding the intentionally different `timeout_config.default_ms`.

This is evidence for those nine cases, not general parity. The comparison does not cover non-object arguments, handshake validation error details, alternative UUID or timestamp formats, warn or escalate verdicts, or evaluation failures. Those inputs can differ between the Guardians.

## Scope and parity

| Component or behavior | This stage | TypeScript reference |
| --- | --- | --- |
| `POST /acs` JSON-RPC and handshake | Implemented | Implemented |
| `steps/toolCallRequest` and `steps/toolCallResult` | Implemented with AGT Rust SDK and the shared manifest | Implemented with AGT Node binding |
| Repository request and hook schema validation | Implemented | Implemented |
| Five AGT verdict mappings from `mapping.yaml` | Implemented; live tests cover allow, deny and transform | Implemented and covered by its mapping tests |
| Egress annotator and IFC source labels | Implemented; the Rust SDK cannot distinguish absent `result_labels` from an explicit empty array | Implemented |
| Session hash chain and envelope JSONL | Implemented locally; no `chain_hash` on the wire | Implemented locally; no `chain_hash` on the wire |
| Claude Code and OpenCode host shims | Use the existing TypeScript shims | Implemented |
| Host adapter, Inspector and conformance runner in Rust | Not yet ported | Implemented |

Both Guardians have the TypeScript reference's stated limits: two of nineteen hooks are evaluated; replay checks, signatures, `system/ping`, and wrapped MCP are absent; `ask` lacks `ask_details`; the chain head is not published on responses; and the wire is unauthenticated. An `ask` response therefore fails the current response schema. This stage must not be used as a claim of full ACS-Core support.

The pinned Rust AGT SDK represents `result_labels` as `Vec<String>` and normalizes both a missing field and an explicit empty array to an empty vector. This Guardian retains the current session labels when the vector is empty. That preserves the prior restriction but can differ from the TypeScript Guardian when a policy explicitly clears labels. Full IFC parity needs an SDK API that preserves this distinction.

The Rust source separates schema loading (`schema.rs`), AGT SDK integration and the egress annotator (`policy.rs`), mapping (`mapping.rs`), session state (`session.rs`), and HTTP dispatch and logs (`server.rs`). The policy files remain in `../agt/policy/`; none are duplicated here.
