# Host adapter

The host side of the wire, shared by both host shims. It turns a host's own hook payload into an ACS envelope, negotiates the session with the Guardian, posts the envelope, validates the decision that comes back, applies the failure posture when no decision arrives, renders the decision in the host's own output shape, and writes the audit log.

It contains no policy-runtime vocabulary and names no host output field. Both boundaries are enforced by [`test/invariants.test.ts`](../../test/invariants.test.ts) at the root of the tree. A second host arrives as another thin shim against this package, unchanged.

## Get started

A shim is thin because this package does the work. The two shipped shims are the worked examples. [`hosts/claude-code/acs-hook.ts`](../../hosts/claude-code/README.md) runs as a fresh subprocess per hook. [`hosts/opencode/acs-plugin.ts`](../../hosts/opencode/README.md) runs as one long-lived plugin object. Both call the same sequence, imported from the package root:

1. `loadHookmap` reads the host's hookmap and validates it. A hookmap whose `decisions` block cannot render both `allow` and `deny` is refused at load, so the failure posture always has an output it can express.
2. `resolveSessionConfig` returns the negotiated ServerHello for the session. The first hook of a session sends `handshake/hello` through `negotiateSessionConfig`. Later hooks read the stored answer. The Claude Code shim stores it in a file with `createFileSessionConfigStore`, because each hook is a new process. The OpenCode plugin uses `createMemorySessionConfigStore`.
3. `governStep` builds the envelope, posts it through the client `createGuardianClient` returns, validates the decision, and resolves a missing decision through the negotiated posture. Every fail-open proceed is written to the audit sink before it is returned.
4. `renderDecision` maps the decision onto the host's output shape, as the hookmap's `decisions` block declares it. The shim applies that output: printed to stdout, or written into the live tool call object.

`src/index.ts` is the whole contract a shim relies on. Nothing else in this package is imported from outside it.

## The hookmap

Each host ships one YAML file, and it is the only host-specific data in the tree. It maps host hook names to ACS methods, says where the tool name and the arguments sit in the host payload, and declares how each ACS decision renders in the host's own output.

Paths are JSONPath-lite: `$.tool_input.command`, dotted field access only, with no indexing, filters or wildcards. `src/hookmap-path.ts` is the one parser. A path naming `__proto__` or another reserved segment is refused, because such a path resolves through the prototype chain and would read or write machinery instead of a field the host produced.

A hook may carry a `tools` list. A tool outside that list is not governed, and `auditUngovernedStep` records the skip. A hook with no list governs every tool it fires for.

## Failure handling

| Situation | What the adapter does |
|---|---|
| A decision arrives | It is honoured. The posture never touches it |
| The Guardian answers with a JSON-RPC error, or refuses a schema-invalid envelope | An honoured `deny`, whatever the posture |
| A timeout, a transport failure, or an error with no decision | The negotiated posture applies. `proceed` proceeds and writes an audit entry. `deny` blocks. The three cases write three different audit entries |
| The posture says proceed and the audit entry cannot be written | A block |
| An `ask` or `defer` whose timeout has passed | Its own timeout default |
| Malformed `modifications` | Fails closed |
| A modification the host cannot apply | Refused. At the result gate the refusal withholds the output |

`DEFAULT_POSTURE` and `DEFAULT_TIMEOUT_MS` are exported so both shims agree without one copying the other's number. The stage at which a failure happened, before the request was built, after it went out, or after a decision arrived that the host could not express, is recorded on the audit entry, because the three are different incidents.

## The audit log

The shim tells `createAuditSink` where to write. Both shims default to `.acs/audit.jsonl` and read `ACS_AUDIT_LOG` to override it. One line is written per fail-open proceed, per posture-driven block, and per ungoverned skip. The entry keeps the host's raw session id. The envelope carries a UUID derived from it by `toSessionUuid`, because the ACS schema requires a UUID, so the two logs cannot be joined on that field.

## Files

| File | What it holds |
|---|---|
| `src/build-envelope.ts` | `buildEnvelope`, `loadHookmap`, and the envelope type |
| `src/hookmap-path.ts`, `src/reserved-segments.ts` | The path notation and the segments it refuses |
| `src/handshake.ts`, `src/session-config.ts` | Negotiation, and the file and memory stores for the negotiated ServerHello |
| `src/guardian-client.ts` | The HTTP client and its error types |
| `src/govern-step.ts` | The sequence one governed step runs, with a guarded stage for each failure kind |
| `src/validate-decision.ts`, `src/decision-expiry.ts`, `src/decision-message.ts` | What a decision must look like before it is honoured |
| `src/failure-posture.ts`, `src/failure-kinds.ts` | The posture and the classification of each failure |
| `src/modifications.ts`, `src/decision-modify.ts` | Applying a `modify` decision to a host payload |
| `src/result-output.ts` | Withholding and replacing output at the result gate |
| `src/render-decision.ts` | Rendering a decision through the hookmap's `decisions` block |
| `src/audit-sink.ts` | The audit log writer |

## Tests

```bash
bun test packages/host-adapter
```

Eleven files. They drive each function against fixed payloads and against a real Guardian where the assertion needs one.
