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
| MODIFY for an Observed Agent that cannot apply it (§6.5): DENY `modify_unsupported`, ALLOW at `postCompact`, audit event | Met | `server.py`, `engine.py` (`Evaluation.client_cannot_apply_modify`), `tests/test_server.py` |
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
uv run acs-guardian serve --secret-file /tmp/acs-secret --key-id 2026-10 --port 8787
```

Then POST an envelope to `http://127.0.0.1:8787/acs`. Configuration comes from
flags or the environment: `ACS_GUARDIAN_HMAC_SECRET_FILE`,
`ACS_GUARDIAN_KEY_ID` (required; the label this deployment gives its one
configured secret — there is no default, so a request naming a label this
Guardian does not hold is refused `-32004`, never verified with the wrong
secret), `ACS_GUARDIAN_HOST`, `ACS_GUARDIAN_PORT`, `ACS_ON_DECISION_FAILURE`,
`ACS_SPEC_ROOT`. Audit events the standard requires of the Guardian (today,
the §6.5 substitution) go to a deployment-supplied sink; the default writes
one JSON line per event to stderr.

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
- A ContextEntry's `entry_id` is the step's `request_id` and its `turn_id` is
  the envelope's `metadata.turn_id` when the framework set one (turnStart
  requires it propagated onto every per-step entry, and `context-entry.json`
  names no member for it, so the envelope field's name is used). Its
  `timestamp` is the Guardian's write clock, UTC RFC 3339, per
  `context-entry.json` ("when the entry was written"). The
  `request_id`/`turn_id` choices align what the entries commit to across
  implementations for the same step; the two Guardians still disagree on
  `timestamp` — and therefore on `entry_hash` — because write times differ
  by definition.
- The ServerHello names a version the client offered: the Guardian's own when
  it was offered, otherwise the highest offered version sharing its major
  (§3's forward-compat rule, the Go port's selection). A step whose
  `acs_version` does not share the session's negotiated major version is
  `-32001` with the session's version in `data.supported_versions`.
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
  `REPLAY_DETECTED`. An `agent_id` other than the session's is answered with a
  signed DENY (`agent_id_not_bound`), not an error — an error would leave the
  agent to its failure posture. A signature whose `key_id` is not this
  deployment's configured label never resolves a key, so the request is
  refused `-32004`, unsigned: the Guardian does not verify with a secret the
  label does not name.

### Implementation limits (not wire-visible on conformant traffic)

- A request nested past 128 object/array levels takes the normal dispatch
  ladder with a fail-closed bias: if the body's own signature verifies
  against its session, it gets that route's signed answer — the ping's
  ALLOW, a signed refusal (`-32000`, `-32601`, `-32003`, `-32005`,
  `-32602`), or a signed decision (`evaluation_failed`, or the hook's ALLOW
  substitution where no DENY is permitted) with its chain entry; the
  agent-binding and closed checks answer signed denials that write no
  entry. An unverified body gets `-32600`, unsigned, and an internal
  failure on a non-step route is an unsigned `-32603`, like the normal
  path's. The verification and hashing for such bodies run on a single
  serialized thread sized to the parse boundary: at most 10,000 structural
  levels, and raw text past that is refused as a parse error before the
  parser sees it (an interpreter's parser may refuse a body even earlier).
- Duplicate object members are a parse error (`-32700`), like the Go port:
  two parsers must not disagree about one signed body's meaning.
- Once a step's signature has verified, a failure outside the error registry
  (an internal exception on the governed path) is a signed DENY
  (`evaluation_failed`), never an error; the step's chain entry is appended
  when the failure pre-empted it, and `chain_hash` is sent only when this
  step's entry is in the chain. Registry refusals (replay, skew, version,
  schema, capability) keep their own signed error codes, per the spec.

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
