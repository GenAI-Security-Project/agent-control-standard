# Guardian

The ACS server. It serves one JSON-RPC 2.0 endpoint, `POST /acs`. For each envelope it validates the request against the schemas in this repository's [`specification/v0.1.0/`](../../../../specification/v0.1.0/), assembles AGT policy input, evaluates it through the [AGT bridge](../agt-bridge/README.md), and maps AGT's verdict to an ACS decision. It keeps one hash chain per session and records every envelope before it validates it.

The Guardian never names a host. It does not know whether Claude Code or OpenCode sent the envelope. That boundary is enforced by [`test/invariants.test.ts`](../../test/invariants.test.ts) at the root of the tree.

## Get started

Run it from `reference-implementations/agt`. Its default paths are relative to that directory.

```bash
bun run guardian
```

```
Guardian listening at http://localhost:8787/acs
Envelope log: .acs/envelopes.jsonl
Session context log: .acs/session-context.jsonl
Failure posture: proceed   (override with ACS_ON_DECISION_FAILURE=deny)
```

It constructs the AGT runtime once, at startup, against `policy/manifest.yaml`, then serves until you stop it. Every variable it reads:

| Variable | Default | What it does |
|---|---|---|
| `ACS_ON_DECISION_FAILURE` | `proceed` | The posture the ServerHello declares. `deny` fails closed. Any other value stops the Guardian at startup |
| `ACS_GUARDIAN_PORT` | `8787` | The port for `POST /acs` |
| `ACS_GUARDIAN_HOST` | `127.0.0.1` | The interface to bind. Set `0.0.0.0` only when you accept an unauthenticated routable endpoint |
| `ACS_MANIFEST_PATH` | `policy/manifest.yaml` | The AGT manifest. `policy/manifest.drift.yaml` is the second manifest, used to reach the `warn` verdict |
| `ACS_ENVELOPE_LOG` | `.acs/envelopes.jsonl` | Where every envelope is recorded |
| `ACS_SESSION_CONTEXT_LOG` | `.acs/session-context.jsonl` | Where each session's hash chain is written |

To see a decision without an agent client, pipe a hook payload into the Claude Code shim while the Guardian runs. The [tree README](../../README.md#drive-one-hook-by-hand) shows the command and its output.

## What happens to each request

1. The raw envelope is serialized and queued for the envelope log, before validation.
2. The envelope is validated against `request-envelope.json`. A `steps/toolCallRequest` or `steps/toolCallResult` is also validated against its own payload schema. An invalid envelope on a `steps/*` method is answered with an honoured `deny`, not a bare error, so the host has a decision to act on.
3. The AGT intervention point for the method is resolved from `mapping.yaml`, and so is the argument the policy target is read from for the tool the payload names.
4. The AGT snapshot is assembled, one shape per gate, and evaluated through the bridge.
5. The verdict is mapped to an ACS decision with the tables in `mapping.yaml`. A `transform` becomes a `modify` whose modification differs by gate: a parameter override at the request gate, a redaction on the result payload at the result gate.
6. One entry is appended to the session's hash chain. Information-flow labels AGT emitted are stored, so the next step of the session sends them back as input.
7. The outgoing response is checked against `response-envelope.json`. The result is logged on stderr and never thrown. The response is then recorded and sent.

`handshake/hello` is answered with a constant ServerHello that names exactly the methods this Guardian dispatches: `steps/toolCallRequest` and `steps/toolCallResult`. The Guardian does not read the ClientHello. Any other method is answered with a JSON-RPC error carrying `METHOD_NOT_DISPATCHED_CODE`, which the conformance harness reads back to confirm the ServerHello tells the truth.

Every throw on the request path is caught. Nothing escapes the fetch handler, because an unhandled rejection would produce an HTML error page, the host's client would fail to parse it, and Claude Code would read the failed hook as "never fired" and proceed ungoverned.

## Use it in-process

The tests and the conformance harness start a Guardian in the same process.

```ts
import { startGuardian } from "guardian";

const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
// guardian.url is the full endpoint, on the port the OS assigned.
await guardian.close();
```

`StartGuardianOptions` also accepts `hostname`, `envelopeLogPath`, `sessionContextLog` and `onDecisionFailure`, which mirror the environment variables above, and four options for tests: `mappingPath`, `annotator`, `bridge` and `sessionContextStore`. Each is documented where it is declared, in `src/server.ts`.

The package has two entry points. `guardian` exports the governance verbs listed in `src/index.ts`. `guardian/deployment` exports `createDeploymentBridge`, the one function that builds the deployment's bridge with the egress annotator wired in. The conformance harness imports the second so it measures the bridge the Guardian ships, not a replica.

## Files

| File | What it holds |
|---|---|
| `src/main.ts` | The `bun run guardian` entry point. Reads the environment, starts the server, prints the banner |
| `src/server.ts` | `startGuardian`, the endpoint, dispatch, the two catches, and the redaction of this machine's paths from error text |
| `src/validate-envelope.ts` | The Ajv registry over the repository's schemas, and `validateEnvelope` |
| `src/check-response.ts` | The outbound check against the response schema. Reports, never throws |
| `src/handshake.ts` | `buildServerHello` |
| `src/map-verdict.ts` | Reads `mapping.yaml`. Resolves intervention points and policy-target arguments. Maps verdicts to decisions |
| `src/assemble-snapshot.ts` | The two snapshot assemblers, one per gate |
| `src/annotate-egress.ts` | Extracts an egress destination from a shell command for AGT's egress gate |
| `src/deployment-bridge.ts` | Builds the bridge with the deployment's annotator |
| `src/deny-on-invalid-envelope.ts` | Turns a schema failure on a `steps/*` method into an honoured `deny` |
| `src/session-context-store.ts`, `src/session-context.ts`, `src/ifc-labels.ts` | The per-session hash chain, provenance, and information-flow labels |
| `src/envelope-log-sink.ts` | The envelope log writer |
| `src/batched-log-writer.ts` | Bounded asynchronous JSONL batching and shutdown drain |
| `src/acs-result.ts` | The decision result type |

## Log batching and shutdown

Envelope and session-context logs keep their existing JSONL formats. Each sink releases
a batch after 64 records or 100 ms from the first queued record, then appends it
asynchronously. The timer schedules a flush; it does not guarantee a disk-completion
deadline. The Inspector can therefore see a decision after the HTTP response arrives.
No file is opened until a record arrives.

Each sink admits at most 4 MiB of serialized UTF-8 data and 4,096 records, counting
writes already in flight. A write error or a record that would exceed either limit
disables that sink and reports once on stderr. Queued records may be lost. Logging
failure does not change the Guardian's policy decision, and the session store remains
authoritative. The host adapter's audit log is a separate writer and is unchanged.

`await guardian.close()` stops accepting connections, waits for active requests, and
drains both logs. Repeated calls wait for the same shutdown. The standalone Guardian
does this on SIGINT and SIGTERM. A stuck request or disk write can delay shutdown;
there is no forced shutdown deadline. SIGKILL, a crash, or power loss can lose buffered
records. Completion means the stream finished appending, not that data was fsynced.

This batches the reference implementation's existing logs. It does not add an
OpenTelemetry exporter or claim ACS-Trace conformance.

## The wire is not secured

The endpoint has no authentication, no origin check and no request signing. It binds loopback by default, so reachability is the only access control. Widen the bind only for a Guardian that runs in its own container, and read the header of `src/server.ts` first.

## Tests

```bash
bun test packages/guardian
```

Most tests start a real Guardian on port 0 and drive real envelopes through the pinned policy bundle. One test copies `src/` one directory deeper into a fixed scratch directory, so the relative schema path resolves to nothing. It proves that a missing schema directory becomes a recorded JSON-RPC error and never an HTML page. The scratch directories are gitignored and removed in a `finally`.
