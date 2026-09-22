# ACS Python reference Guardian

An independent Python implementation of the **OWASP Agent Control Standard
(ACS) v0.1.0** wire contract: JSON-RPC 2.0 envelopes, the `handshake/hello`
capability negotiation, the `steps/*` hook taxonomy, the five dispositions, the
SessionContext audit chain with a published `chain_hash`, replay and skew
protection, and the HMAC-SHA256 baseline signature.

It is written against `docs/spec/` and `specification/v0.1.0/`, not against
another implementation. The TypeScript tree in `../agt/` is the original
reference; it is narrower (two gates, no signing yet — see issue #70) and its
audit chain is a projection with its own hash rule, so this tree and that one
do not produce the same `entry_hash`. A full Go port is contributed in the open
PR #169 (`reference-implementations/agt-go/`, not merged at the time of
writing); its documented choices for the wire details ACS leaves undefined are
the ones this tree follows, so the two are intended to interoperate.

## Status

| ACS-Core item (docs/spec/conformance.md) | Status | Where |
| --- | --- | --- |
| Handshake, version/transport/method negotiation, refusals (`-32001`, `-32002`, `-32000`) | Met | `handshake.py`, `tests/test_handshake.py` |
| Request/response envelopes, JSON-RPC error taxonomy | Met | `schemas.py`, `server.py`, `tests/test_server.py` |
| Hook taxonomy: all 19 `steps/*` hooks dispatched through one generic path, each schema pinned to its method | Met | `schemas.py` (`_HOOK_SCHEMAS`), `tests/test_server.py` |
| Dispositions: all five, with required fields, schema-validated | Met | `engine.py`, `server.py`, `tests/test_server.py` |
| SessionContext: append-only chain, §8.2 hash rule, published `chain_hash` | Met | `chain.py`, `tests/test_chain.py` |
| Replay protection: duplicate `request_id`/`nonce`, timestamp skew (`-32005`, `-32006`) | Met | `server.py`, `tests/test_server.py` |
| Baseline integrity: HKDF-SHA256 session key, HMAC-SHA256 signature | Met | `crypto.py`, `tests/test_crypto_vectors.py` |
| Liveness, `system/ping` | Met | `server.py`, `tests/test_server.py` |
| Wrapped MCP, `protocols/MCP/*` and `wrapped:mcp-<version>/*` | Met | `mcp.py`, `methods.py`, `tests/test_wrapped_mcp.py` |
| Dispositions a hook does not permit are substituted, never sent | Met | `methods.py` (`PERMITTED`), `server.py` |
| Decision honoring (§6.4) | Observed Agent responsibility | the host adapter's, not this tree's |
| Trace pillar (OTel/OCSF), AgBOM (`agbom/*`) | Not claimed | v1 roadmap items; `agbom/*` is refused with `-32003` |
| Intent handling (IBAC) | Not claimed | Intent is optional and IBAC-conditional; `ask_details` passes through |

Every ACS-Core item in `docs/spec/conformance.md` is implemented, so the
ServerHello accepts `acs-core`. ACS v0.1.0 has no certification mechanism:
this tree self-declares what it implements and each claimed row names the
tests that cover it. `acs-trace`, `acs-inspect`, `acs-provenance`,
`acs-crypto`, and `acs-audit` are not claimed.

## Run it

```bash
cd reference-implementations/agt-python
uv sync
printf 'change-me-32-bytes-minimum-secret' > /tmp/acs-secret
uv run acs-guardian serve --secret-file /tmp/acs-secret --port 8787
```

Then POST an envelope to `http://127.0.0.1:8787/acs`. Configuration comes from
flags or the environment: `ACS_GUARDIAN_HMAC_SECRET_FILE`,
`ACS_GUARDIAN_KEY_ID`, `ACS_GUARDIAN_HOST`, `ACS_GUARDIAN_PORT`,
`ACS_ON_DECISION_FAILURE`, `ACS_SPEC_ROOT`.

The schemas are read from `specification/v0.1.0/` by relative path, so the
console script works from a source checkout. An out-of-tree install must set
`ACS_SPEC_ROOT`; the Guardian refuses to start when the schemas are missing
rather than failing per request.

## Test it

```bash
uv run pytest -v
```

`tests/test_external_probes.py` ports the ten black-box probes of the
conformance harness's external mode — envelope refusal, pre-session refusal,
transport refusal, handshake, an allowed call, three replay checks, invalid
params, and an unnegotiated method. Nine of the ten are signature-verified;
the first sends a bare envelope with no session, which the harness does not
sign either. `tests/test_wrapped_mcp.py` covers the wrapped MCP contract, and
`tests/test_server.py` the hook dispositions, §6.3 modification composition,
session close, and the session bindings. The external mode itself is
contributed in the open PR #169 (not merged at the time of writing); until it
lands, the probe port is the local gate. Once it lands, the official mode runs
against this Guardian from `reference-implementations/agt`:

```bash
ACS_CONFORMANCE_GUARDIAN_URL=http://127.0.0.1:8787/acs \
ACS_CONFORMANCE_HMAC_SECRET_FILE=/tmp/acs-secret \
bun run conformance
```

## Interoperability choices

ACS v0.1.0 leaves several wire details undefined; two implementations must
make the same choice to interoperate. This tree follows the choices the Go port
documents in its "Behavior that ACS v0.1.0 leaves undefined" table:

- HKDF-SHA256, no salt, UTF-8 `session_id` as the `info` input, 32-byte key.
- An error response to an authenticated request carries its signature at
  `error.signature`; a `ServerHello` at `result.signature`.
- `request_hash` is always written, over the JCS canonicalization of the
  `params` object **as received** — the signature is part of `params` by the
  time the Guardian sees it, so an external verifier must keep the signed
  envelope, not the pre-signature one, to recompute the hash.
- `entry_hash` is `SHA-256(JCS(entry minus entry_hash/previous_hash) ||
  prev_hash_bytes)`; optional members are omitted from the hashed content when
  absent, never written as `null`.
- A ContextEntry's `timestamp` is the originating request's `timestamp`, not
  the Guardian's wall clock at write time: two Guardians cannot agree on each
  other's write time, and the field is inside the hashed content, so a
  deterministic input is what makes cross-implementation `entry_hash`
  comparison possible at all.
- A wrapped MCP message's method must equal the part after `protocols/MCP/`
  for a request (a response carries no method and is wrapped under the method
  it answers). A `parameter_overrides` key names a member of the wrapped
  message's `params.arguments`; a native hook's names a tool argument (a
  `/arguments/<name>` pointer).
- Method routing follows the standard's own distinctions: an undefined method
  is `METHOD_NOT_FOUND` (`-32601`), a defined but never-negotiated method
  (`agbom/*`) and a defined method the handshake did not negotiate are
  `CAPABILITY_NOT_NEGOTIATED` (`-32003`). An empty `methods_evaluated` is a
  valid ServerHello, not a refusal.
- `steps/sessionEnd` closes the session: a later step is answered with a DENY
  `session_closed`, while replay history survives so a replayed step is still
  `REPLAY_DETECTED`. A key_id or agent_id other than the session's is answered
  with a signed DENY (`key_not_bound`, `agent_id_not_bound`), not an error —
  an error would leave the agent to its failure posture.

### A deliberate deviation from an `extend_mcp.md` example

The examples in `docs/spec/instrument/extend_mcp.md` show a wrapped MCP
message placed directly in the ACS envelope's `params`, with no
`acs_version`/`request_id`/`timestamp`/`metadata`/`payload` — a shape
`request-envelope.json` rejects (`params` requires all five). The spec
contradicts itself there, and this tree follows the schema: the MCP message is
carried intact in `params.payload` (as the Go port in open PR #169 does). The
inconsistency is worth an upstream issue; this tree does not silently pick a
side without saying so.

## Non-goals

- **Not a policy engine.** Policy content is a deployment's; the built-in
  engine demonstrates the §12.1 interface and denies a short list of
  unambiguous destructive commands. Nothing more.
- **Not a conformance suite or registry.** The community's suite owns the
  vectors; this tree is an implementation under test.
- **No session eviction.** The default store is in-memory and keeps sessions
  for the process lifetime, so replay history survives `steps/sessionEnd` even
  though a step after it is denied with `session_closed`. A long-lived
  deployment passes its own `SessionStore` (with TTL or capacity limits) as
  `GuardianConfig.session_store`; that is the seam.
- **No host adapters.** Honoring decisions is the Observed Agent's job; the
  TypeScript tree ships the Claude Code and OpenCode adapters.
