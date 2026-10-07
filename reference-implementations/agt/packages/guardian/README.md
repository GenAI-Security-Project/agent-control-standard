# Guardian

The ACS server. It serves one JSON-RPC 2.0 endpoint, `POST /acs`. For each envelope it validates the request against the schemas in this repository's [`specification/v0.1.0/`](../../../../specification/v0.1.0/), assembles AGT policy input, evaluates it through the [AGT bridge](../agt-bridge/README.md), and maps AGT's verdict to an ACS decision. It keeps one hash chain per session and records every envelope before it validates it.

The Guardian never names a host. It does not know whether Claude Code or OpenCode sent the envelope. That boundary is enforced by [`test/invariants.test.ts`](../../test/invariants.test.ts) at the root of the tree.

## Get started

Run it from `reference-implementations/agt`. Its default paths are relative to that directory.

```bash
export ACS_HMAC_SECRET="$(openssl rand -base64 32)"
bun run guardian
```

```
Guardian listening at http://localhost:8787/acs
Envelope log: .acs/envelopes.jsonl
Session context log: .acs/session-context.jsonl
Failure posture: proceed   (override with ACS_ON_DECISION_FAILURE=deny)
Signature verification: HMAC-SHA256 (required)
```

It constructs the AGT runtime once, at startup, against `policy/manifest.yaml`, then serves until you stop it. Every variable it reads:

| Variable | Default | What it does |
|---|---|---|
| `ACS_ON_DECISION_FAILURE` | `proceed` | The posture the ServerHello declares. `deny` fails closed. Any other value stops the Guardian at startup |
| `ACS_GUARDIAN_PORT` | `8787` | The port for `POST /acs` |
| `ACS_GUARDIAN_HOST` | `127.0.0.1` | The interface to bind. Set `0.0.0.0` only after protecting the transport and provisioning the shared secret to every intended peer |
| `ACS_MANIFEST_PATH` | `policy/manifest.yaml` | The AGT manifest. `policy/manifest.drift.yaml` is the second manifest, used to reach the `warn` verdict |
| `ACS_ENVELOPE_LOG` | `.acs/envelopes.jsonl` | Where every envelope is recorded |
| `ACS_SESSION_CONTEXT_LOG` | `.acs/session-context.jsonl` | Where each session's hash chain is written |
| `ACS_HMAC_SECRET` | required | Base64-encoded input keying material of at least 32 bytes. The Guardian derives per-session keys, verifies requests, and signs addressable non-ping results and errors |

To see a decision without an agent client, pipe a hook payload into the Claude Code shim while the Guardian runs. The [tree README](../../README.md#drive-one-hook-by-hand) shows the command and its output.

## What happens to each request

1. The raw envelope is appended to the envelope log, before anything else.
2. The JSON-RPC and common-envelope shape is validated. Except for the signature-exempt liveness ping, the Guardian then verifies the per-session HMAC, rejects timestamps outside the skew window, and rejects a reused `request_id` from its independent replay store. This includes ClientHello: HMAC key material is provisioned out of band, not negotiated in-band.
3. The authenticated method-specific payload is validated. Invalid `steps/*` payloads receive an honoured `deny`, not a bare error, so the host has a decision to act on without letting malformed unsigned traffic bypass authentication.
4. Registered tool calls are resolved through `mapping.yaml`; unknown tool names receive `tool_unregistered`. Native step hooks and wrapped `protocols/MCP/tools/call` requests use the same registry.
5. The AGT snapshot is assembled and evaluated through the bridge. Its verdict is mapped to an ACS decision; a `transform` becomes the gate-appropriate `modify` operation.
6. One entry is appended to the session's hash chain. Information-flow labels AGT emitted are stored, so the next step of the session sends them back as input.
7. Every addressable non-ping result or error is signed; ping stays signature-exempt in both directions. Every response is checked against the applicable response shape, recorded, and sent. The outbound schema result is diagnostic and never replaces the response.

`handshake/hello` validates the ClientHello, requires support for ACS `0.1.0`, intersects the client's methods with the methods this Guardian actually evaluates, and accepts the `acs-core` profile only when HMAC is configured. The evaluated set is `steps/toolCallRequest`, `steps/toolCallResult`, and `protocols/MCP/tools/call`; lifecycle hooks remain dispatchable audit events but are not advertised as policy-evaluated. The Guardian records each session's `methods_implemented` and refuses, with `-32003`, any step from a session that has not sent `handshake/hello` or for a method that session did not list. `system/ping` needs no handshake. Any other method is answered with a JSON-RPC error carrying `METHOD_NOT_DISPATCHED_CODE`.

Every throw on the request path is caught. Nothing escapes the fetch handler, because an unhandled rejection would produce an HTML error page, the host's client would fail to parse it, and Claude Code would read the failed hook as "never fired" and proceed ungoverned.

## Use it in-process

The tests and the conformance harness start a Guardian in the same process.

```ts
import { startGuardian } from "guardian";

const guardian = await startGuardian({
  port: 0,
  manifestPath: "policy/manifest.yaml",
  hmacSecret: process.env.ACS_HMAC_SECRET,
});
// guardian.url is the full endpoint, on the port the OS assigned.
await guardian.close();
```

`StartGuardianOptions` also accepts `hostname`, `envelopeLogPath`, `sessionContextLog`, `onDecisionFailure`, and `hmacSecret`, which mirror the environment variables above, plus four test overrides: `mappingPath`, `annotator`, `bridge`, and `sessionContextStore`. Omitting `hmacSecret` is an explicit non-conformant compatibility mode for in-process tests; its handshake advertises no `acs-core` profile. Each option is documented where it is declared in `src/server.ts`.

The package has two entry points. `guardian` exports the governance verbs listed in `src/index.ts`. `guardian/deployment` exports `createDeploymentBridge`, the one function that builds the deployment's bridge with the egress annotator wired in. The conformance harness imports the second so it measures the bridge the Guardian ships, not a replica.

## Files

| File | What it holds |
|---|---|
| `src/main.ts` | The `bun run guardian` entry point. Reads the environment, starts the server, prints the banner |
| `src/server.ts` | `startGuardian`, the endpoint, dispatch, the two catches, and the redaction of this machine's paths from error text |
| `src/validate-envelope.ts` | The Ajv registry over the repository's schemas, and `validateEnvelope` |
| `src/check-response.ts` | The outbound check against the response schema. Reports, never throws |
| `src/handshake.ts` | `buildServerHello` |
| `src/verify-signature.ts` | Per-session HKDF derivation plus request verification and response signing |
| `src/map-verdict.ts` | Reads `mapping.yaml`. Resolves intervention points and policy-target arguments. Maps verdicts to decisions |
| `src/assemble-snapshot.ts` | The two snapshot assemblers, one per gate |
| `src/annotate-egress.ts` | Extracts an egress destination from a shell command for AGT's egress gate |
| `src/deployment-bridge.ts` | Builds the bridge with the deployment's annotator |
| `src/deny-on-invalid-envelope.ts` | Turns a schema failure on a `steps/*` method into an honoured `deny` |
| `src/session-context-store.ts`, `src/session-context.ts`, `src/ifc-labels.ts` | The per-session hash chain, provenance, and information-flow labels |
| `src/envelope-log-sink.ts` | The envelope log writer |
| `src/acs-result.ts` | The decision result type |

## Wire security

The standalone Guardian requires HMAC-SHA256 authentication. Hosts sign requests and verify result and error responses with a per-session key derived from `ACS_HMAC_SECRET`; timestamp and replay checks bound reuse. HMAC provides integrity and peer possession of the shared secret, not confidentiality or an origin policy. The endpoint therefore binds loopback by default. Protect the transport and carefully distribute the shared secret before widening the bind.

## Tests

```bash
bun test packages/guardian
```

Twelve files. Most start a real Guardian on port 0 and drive real envelopes through the pinned policy bundle. One test copies `src/` one directory deeper into a fixed scratch directory, so the relative schema path resolves to nothing. It proves that a missing schema directory becomes a recorded JSON-RPC error and never an HTML page. The scratch directories are gitignored and removed in a `finally`.
