# Rust AGT Guardian (first stage)

This is a Rust Guardian for [issue #88](https://github.com/GenAI-Security-Project/agent-control-standard/issues/88). It runs beside the [TypeScript AGT reference implementation](../agt/README.md), using its current `mapping.yaml`, AGT manifest and policy bundle, and this repository's ACS v0.1.0 schemas. It is a proof of concept. It does not claim ACS-Core conformance.

## What runs

`POST /acs` receives JSON-RPC envelopes. The Guardian validates the envelope and the two supported tool payloads against `specification/v0.1.0/`, assembles an AGT snapshot, calls the pinned `agent_control_specification` Rust SDK (0.3.1-beta.0), and maps its verdict through the shared `mapping.yaml`. A session store keeps source labels and a local hash chain. The server records request and response envelopes in the same JSONL shape as the TypeScript Guardian.

The TypeScript Claude Code and OpenCode shims can point to this server through `ACS_GUARDIAN_URL`. Those shims are the host side of this stage; this directory does not contain Rust replacements for them.

## Prerequisites and run

- Rust 1.89 or newer (the current dependency graph includes Cedar Policy 4.13).
- An `opa` executable compatible with the pinned AGT policy bundle. Install OPA or set `ACS_OPA_PATH` to its executable path. Construction checks that OPA starts, then loads the AGT manifest. Local tests used the AGT SDK's bundled OPA 0.70.0.
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

## Test

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
ACS_OPA_PATH=/absolute/path/to/opa ACS_OPA_TIMEOUT_MS=30000 cargo test --workspace --all-features
```

The integration test starts a real HTTP Guardian and uses the pinned AGT bundle for handshake, allow, deny, request and result redaction, egress denial, WebFetch allowance, malformed payload, unknown method, parse error, oversized body, and log cases. It requires OPA. The test command gives slow test machines a longer OPA subprocess deadline; the server's default AGT deadline remains five seconds. The existing TypeScript tests are a separate baseline and can be run from `../agt` with Bun 1.3.11.

For a direct wire comparison, start the Rust Guardian on port 8787 and the TypeScript Guardian on port 8788 with the same AGT policy bundle, then run `node tests/compare-guardians.mjs` from this directory. It sends nine identical requests to both servers and fails on any JSON response difference. `RUST_GUARDIAN_URL` and `TS_GUARDIAN_URL` can override the endpoints.

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
