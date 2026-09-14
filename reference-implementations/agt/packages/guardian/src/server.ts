/**
 * startGuardian serves the ACS wire boundary: a single JSON-RPC 2.0 endpoint,
 * POST /acs. The spec mandates no URL path convention -- "/acs" is this
 * project's own choice -- so dispatch inside the handler is by the JSON-RPC
 * `method` field, never by URL path.
 *
 * Composes the full pipeline, in order, for each ACS method it assembles a
 * snapshot for -- `steps/toolCallRequest` and `steps/toolCallResult`:
 *   validateEnvelope -> resolveInterventionPoint(method, mapping) ->
 *   resolvePolicyTargetArgument(mapping, point, tool.name) ->
 *   assemblePreToolCallSnapshot / assemblePostToolCallSnapshot ->
 *   bridge.evaluate(point, snapshot) ->
 *   mapVerdict(verdict, mapping, point, policyTargetArgument) -> response envelope.
 * The resolved point reaches mapVerdict because the ACS modification an AGT
 * transform becomes differs per gate: a tool argument override at the
 * request gate, a redaction on the result payload at the result gate. The
 * resolved argument reaches both the assembler and mapVerdict for the same
 * reason: it is the argument a policy target is read FROM and the argument an
 * override is written TO, and asking twice would let the two answers differ.
 *
 * Every throw on this path is caught, in two places, because nothing may
 * escape the fetch handler. Bun.serve would answer an unhandled rejection with
 * its default error page, which is HTML rather than JSON-RPC. The host's
 * client calls res.json() unconditionally, so an HTML body raises a
 * SyntaxError there instead of surfacing a JSON-RPC error; the hook's
 * catch-all then exits 1 with nothing on stdout, which Claude Code reads as
 * "the hook never fired" and allows the tool call through ungoverned. That is
 * a fail-open in a governance tool.
 *
 * The two catches are:
 *   - Inside `evaluateStep` (reached from `dispatch`, once per assembling
 *     gate), around the assembler / bridge.evaluate / mapVerdict -- the
 *     evaluation itself.
 *   - Around the whole `dispatch` call in `handleAcsRequest` -- the outer
 *     net. `dispatch` rethrows anything that is not an
 *     EnvelopeValidationError, and that rethrow is live: validateEnvelope
 *     builds its Ajv registry lazily, on the first request rather than at
 *     boot, so a checkout whose specification/ directory is missing starts
 *     cleanly and then turns every request into an HTML 500. The outer net puts that
 *     failure response back on the recorded path too, so the envelope log
 *     holds a line for it like any other response.
 *
 * Two distinct catches on the dispatch path -- the evaluation catch above
 * and dispatch's own EnvelopeValidationError catch, around `validateEnvelope`
 * -- turn a steps/* failure into an honoured ACS `deny` decision via
 * denyOnInvalidEnvelope: see the module comment on `dispatch` below. The
 * outer net here is deliberately left untouched: it exists for a `dispatch`
 * rethrow -- a bug in the Guardian itself, such as a missing schema
 * directory, not an invalid envelope -- so it stays a bare JSON-RPC error.
 *
 * The bridge and the mapping table are both built once, when startGuardian is
 * called, rather than per request -- AGT is meant to be constructed at boot
 * and evaluated statelessly.
 *
 * The listening socket defaults to loopback (127.0.0.1). Bun.serve with no
 * `hostname` binds `*` -- every interface, dual-stack -- and this endpoint has
 * no authentication, no origin check and no request signing, so anything that
 * can open the port is both a policy oracle (ask it what would be allowed)
 * and a policy sink (feed it envelopes it evaluates as if a governed host had
 * sent them). Until the wire is authenticated, reachability IS the access
 * control, so the default is the narrowest bind a host shim on the same
 * machine can still reach. A deployment that genuinely needs a routable bind
 * -- a Guardian in its own container, say -- opts in explicitly through the
 * `hostname` option (main.ts reads ACS_GUARDIAN_HOST for it).
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Annotator, PolicyBridge } from "agt-bridge";
import { createDeploymentBridge } from "./deployment-bridge.ts";
import {
  assemblePostToolCallSnapshot,
  assemblePreToolCallSnapshot,
  type AgtPostToolCallSnapshot,
  type AgtPreToolCallSnapshot,
} from "./assemble-snapshot.ts";
import { finalResult, type AcsFinalResult } from "./acs-result.ts";
import { denyOnInvalidEnvelope, type DenyOnInvalidEnvelopeResult } from "./deny-on-invalid-envelope.ts";
import {
  loadMapping,
  mapVerdict,
  resolveInterventionPoint,
  resolvePolicyTargetArgument,
  type Mapping,
} from "./map-verdict.ts";
import {
  EnvelopeValidationError,
  isToolCallRequest,
  isToolCallResult,
  validateEnvelope,
  type AcsRequestEnvelope,
} from "./validate-envelope.ts";
import { checkResponse } from "./check-response.ts";
import { buildServerHello, type ServerHello } from "./handshake.ts";
import { createEnvelopeLogSink, NULL_ENVELOPE_LOG_SINK, type EnvelopeLogSink } from "./envelope-log-sink.ts";
import {
  appendContextEntry,
  createMemorySessionContextStore,
  type IfcLabels,
  type SessionContextStore,
} from "./session-context-store.ts";
import { persistIfcLabels, supplySourceLabels } from "./ifc-labels.ts";

/**
 * Every snapshot message this Guardian can send an intervention point -- one
 * per gate. Each gate this Guardian assembles a snapshot for adds its own
 * point-specific type here.
 *
 * Declared so the bridge seam carries the message rather than erasing it.
 * `PolicyBridge` is parameterised by the snapshot its holder sends, and this
 * is what this holder sends, so the `bridge.evaluate` calls below are checked
 * against the assemblers' own output types instead of against any object at all.
 */
export type GuardianSnapshot = AgtPreToolCallSnapshot | AgtPostToolCallSnapshot;

const MAPPING_PATH = fileURLToPath(new URL("../../../mapping.yaml", import.meta.url));

const HANDSHAKE_METHOD = "handshake/hello";
const ACS_PATH = "/acs";

/** The default bind address -- see the module header for why it is loopback
 * and not `*`. Spelled as the literal address rather than "localhost": the
 * name resolves to both ::1 and 127.0.0.1, and Bun binds only one of them,
 * so the name would make which interfaces are listening a property of the
 * machine's resolver rather than of this line. */
const LOOPBACK_ONLY = "127.0.0.1";
// The repository's absolute root -- `packages/guardian/src` is always five
// directories under it, because this tree sits at
// reference-implementations/agt, the same relationship SCHEMA_ROOT in
// validate-envelope.ts relies on. Used only to redact it out of error text
// before that text leaves the Guardian; see toRepoRelativeMessage below.
const REPO_ROOT = fileURLToPath(new URL("../../../../../", import.meta.url)).replace(/[/\\]+$/, "");
// The lookahead requires the root to be followed by a path separator or the
// end of the string, before the optional `[/\\]?` consumes one such
// separator. Without it, a *sibling* directory whose name merely extends
// the root (`<root>_old`) matched too: the literal
// text of REPO_ROOT is a prefix of that name, so it stripped, leaving a
// misleading `_old/reference-implementations/agt` behind -- not a disclosure of this tree's
// own location, since it's a different directory entirely, but a
// diagnostic that then reads as if it were one. The lookahead makes that
// prefix match fail outright, so a message naming the sibling is left
// alone, in full.
const REPO_ROOT_PATTERN = new RegExp(`${REPO_ROOT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=[/\\\\]|$)[/\\\\]?`, "g");

/**
 * Both catches in this module -- the outer net in handleAcsRequest and the
 * evaluation-failure catch in dispatch -- surface a real error to the ACS
 * client and, through the envelope log, onto disk. A real error's message
 * (an ENOENT out of a missing schema directory, say) carries this machine's
 * absolute filesystem path, e.g.
 * `/Users/you/.../agent-control-standard/specification/v0.1.0/`.
 * That is diagnostic in a way this demo's value depends on, so rather than
 * replace it with something generic, this function removes only the part
 * that discloses where this repository sits on disk, leaving the
 * repository-relative remainder (`specification/v0.1.0/`) intact.
 *
 * Takes the caught value itself, as `unknown`, rather than a pre-extracted
 * string, and calls `String()` on the whole thing. `instanceof Error` does
 * not guarantee `.message` is a string -- nothing stops it from being
 * reassigned to `undefined`, a number, or anything else after construction
 * -- and a throw from this function on the outer-net path has nothing above
 * `handleAcsRequest` to catch it. Staying total for any `unknown`, exactly
 * what a catch clause can hand it, is what keeps that path from becoming an
 * unrecorded HTML 500.
 *
 * Exported -- unlike this module's other internals (`dispatch`, `extractId`,
 * `extractMethod`, `errorResponse`) -- so the redaction above and this
 * function's totality for non-`Error`, non-string-message, and
 * otherwise-shaped `unknown` values can be asserted directly, rather than
 * only through a real Guardian and an HTTP round trip. The same behaviour is
 * also covered end to end, separately -- see server.test.ts's
 * `withFakeValidateEnvelopeGuardian` tests.
 *
 * The whole body is wrapped in its own try/catch, including the
 * `instanceof` check -- belt-and-braces, not a reaction to a live bug.
 * Nothing in this tree currently throws an `Error` whose `.message` is a
 * throwing accessor, a value whose `toString`/`valueOf` throws, or a
 * `Proxy` that throws on `get` or on `getPrototypeOf` (which would defeat
 * `instanceof Error` itself, since it walks the prototype chain through
 * `[[GetPrototypeOf]]`, before `String()` below ever runs). They are guarded
 * anyway because "unreachable today" should not be load-bearing for the one
 * function whose entire job is upholding this module's contract that
 * nothing escapes the outer net. The fallback string names the failure mode
 * rather than guessing at a partial message, since the point is that
 * nothing about the original error could be read at all.
 */
export function toRepoRelativeMessage(error: unknown): string {
  try {
    const message = String(error instanceof Error ? error.message : error);
    return message.replace(REPO_ROOT_PATTERN, "");
  } catch {
    return "<unprintable error>";
  }
}

/**
 * ACS reserves -32000..-32099 for application errors (Specification §17),
 * but only enumerates named codes -32000..-32007 in the §17.1 registry
 * (SESSION_REFUSED, UNSUPPORTED_VERSION, ...) -- none of which names "the
 * envelope failed schema validation", "this method isn't dispatched by this
 * Guardian", or "evaluation itself failed". Rather than reach for the
 * generic JSON-RPC codes that would otherwise fit (-32602 Invalid params,
 * -32601 Method not found), this module mints three codes from the unused
 * part of the reserved band, so every application-level failure stays inside
 * -32000..-32099.
 */
const ENVELOPE_INVALID_CODE = -32010;
/**
 * Exported, unlike its two neighbours, because the conformance harness posts
 * a dispatch probe and has to recognise this Guardian's own answer to it. A
 * copy of the literal over there would be measuring the Guardian against a
 * number the Guardian could also be wrong about.
 */
export const METHOD_NOT_DISPATCHED_CODE = -32011;
/** Any throw the Guardian did not turn into a response itself: mapVerdict's
 * own require_policy_references check, an AGT runtime error, or -- through
 * handleAcsRequest's outer net -- a failure to even build the schema registry.
 * The module header explains why none of this may become dead code. */
const EVALUATION_FAILED_CODE = -32020;

/**
 * The largest request body this Guardian will read, in bytes.
 *
 * Chosen against measured envelopes rather than picked round. An ACS request
 * envelope's fixed part -- jsonrpc, method, id, acs_version, request_id,
 * timestamp, the metadata pair -- measures 355 bytes as
 * packages/host-adapter/src/build-envelope.ts emits it, and a real
 * `steps/toolCallRequest` for a shell command measures 388. The only
 * unbounded member is the argument bag, whose largest realistic occupant is a
 * file body in an edit-a-file tool call: one carrying 64 KiB of content
 * measures 65,951 bytes. 1 MiB is roughly sixteen times that, and roughly
 * 2,700 times the envelope a shell call actually sends, so no legitimate
 * request is anywhere near it -- while a body above it is bounded to
 * something this process can hold per connection rather than to whatever the
 * runtime's own default happens to be.
 *
 * The authoritative check is the count of bytes actually READ, not the
 * declared `Content-Length`. The header is a claim: a chunked body carries
 * none at all, and a client is free to declare one length and send another.
 * It is still consulted first, because a declaration above the cap lets this
 * refuse before reading anything -- but it can only ever refuse early, never
 * admit. See readCappedBody.
 */
const MAX_REQUEST_BODY_BYTES = 1_048_576;

type JsonRpcSuccess = { jsonrpc: "2.0"; id: string | number; result: AcsFinalResult | ServerHello };
type JsonRpcFailure = {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
};

export type StartGuardianOptions = {
  port: number;
  manifestPath: string;
  /** The address to bind. Defaults to loopback; set it only to widen the
   * bind deliberately, and read the module header first -- the endpoint is
   * unauthenticated, so widening it hands the policy decision to whoever can
   * reach the port. main.ts threads ACS_GUARDIAN_HOST into this. */
  hostname?: string;
  /** Overrides the mapping.yaml path this Guardian loads. Defaults to the
   * repo's real mapping.yaml; exists so tests can inject a deliberately
   * misconfigured mapping (e.g. require_policy_references on a decision
   * AGT emits with no reason) to exercise the evaluation-failure catch in
   * handleAcsRequest against a real bridge, without touching the mapping
   * every other consumer reads. Not meant for production use. */
  mappingPath?: string;
  /** Path to the JSONL envelope log. Omitted means no sink: tests construct
   * Guardians freely, and a default-on sink would scatter files through the
   * working tree. `packages/guardian/src/main.ts` -- the demo path --
   * passes it. */
  envelopeLogPath?: string;
  /** Overrides the declared `on_decision_failure` posture this Guardian's
   * ServerHello carries, bypassing `buildServerHello`'s own
   * `process.env.ACS_ON_DECISION_FAILURE` read entirely. Explicit rather
   * than an env-shaped bag on purpose: a test that needs a Guardian
   * declaring `deny` can pass one here instead of mutating `process.env`,
   * which would leak into every other test sharing that process. Omitted
   * means the real deployment path: `buildServerHello()` is called with no
   * argument and reads the actual environment, exactly as
   * `packages/guardian/src/main.ts` needs it to. */
  onDecisionFailure?: "proceed" | "deny";
  /** Overrides the annotator this Guardian dispatches, replacing the built-in
   * one entirely.
   *
   * Omitting this no longer means "no annotator" -- it means the built-in
   * `dispatchGuardianAnnotator` (`./deployment-bridge.ts`).
   * `policy/manifest.yaml` declares an `egress` annotator, and a declared
   * annotator the bridge dispatches nothing for denies EVERY call with
   * runtime_error:annotation_failed, measured, benign calls included. So the
   * dispatcher is never absent, and this option chooses which one rather than
   * whether.
   *
   * The caller that supplies its own is the drift demo: it runs against
   * `policy/manifest.drift.yaml`, whose declared annotator is `drift_score`
   * rather than `egress`, and stands a fixed-score stub in for the
   * behaviour-drift detector AGT's design puts outside the policy engine. Its
   * code block lives in the v3 runbook of the standalone repository
   * (github.com/afogel/ACS_reference_implementation, docs/demos/v3-runbook.md) rather than in this tree --
   * a JS callback cannot cross an environment variable, so the `bun run
   * guardian` CLI cannot take one. `packages/guardian/test/server.test.ts`
   * exercises that manifest through this option. */
  annotator?: Annotator;
  /** Overrides the bridge this Guardian evaluates snapshots against,
   * bypassing `createBridge(manifestPath, ...)` entirely -- and, with it,
   * `manifestPath` and `annotator`: both are silently unused whenever
   * `bridge` is supplied, since `createBridge` is never called. Exists so a
   * test can see exactly which snapshot reached evaluation and choose the
   * `result_labels` that come back. The real bridge supplies neither. It does
   * produce `result_labels` -- `policy/lib/data.json` sets
   * `config.ifc.sink_clearance`, and test/redaction.test.ts measures a real
   * bridge answering `{decision: "allow", result_labels: ["public"]}` -- but
   * AGT propagates the labels it is handed and originates none, so a test
   * driving it could only ever show `public -> public`, and it hands back a
   * verdict rather than the snapshot it was given. Not meant for production
   * use. */
  bridge?: PolicyBridge<GuardianSnapshot>;
  /**
   * Where the session-context chain is appended for the Inspector's
   * session-context view to tail. Defaults to no file: the store is
   * authoritative, and the JSONL is a projection for the Inspector, the same
   * relationship envelopeLogPath has to the envelopes it records. Ignored
   * when `sessionContextStore` is also supplied -- the override store owns
   * its own persistence, and this Guardian does not retrofit a projection
   * onto a store it did not construct; see that option's own doc comment.
   */
  sessionContextLog?: string;
  /**
   * The store itself, for tests and for a deployment that wants to own it.
   * Omitted means a fresh in-memory one per Guardian. Takes precedence over
   * `sessionContextLog` when both are supplied.
   */
  sessionContextStore?: SessionContextStore;
};
export type StartedGuardian = { url: string; close(): Promise<void> };

/**
 * A total-by-construction `appendLine` for the session-context chain's
 * optional JSONL projection -- shaped like `createEnvelopeLogSink`'s own
 * write path (envelope-log-sink.ts: mkdirSync guarded once at construction,
 * every write wrapped, disabled and reported once rather than thrown after
 * the first failure), but not a call into that function.
 * `EnvelopeLogSink.write(direction, envelope, method)` builds its own
 * `EnvelopeLogEntry` (seq, recorded_at, direction, method, rpc_id, envelope)
 * around whatever it is handed; `SessionContextStore`'s `appendLine`
 * contract is one already-serialized JSON line with no wrapping object at
 * all (`session-context-store.ts`: "Called once per appended entry with its
 * JSON line, no trailing newline"). Routing the chain's lines through
 * `createEnvelopeLogSink` would nest every session-context entry inside an
 * unrelated `EnvelopeLogEntry` -- `direction: "request"` on a chain entry is
 * meaningless, and the JSONL shape `test/session-context-roundtrip.test.ts`
 * pins (`{session_id, seq, request_id, ...}` at the line's own top level)
 * would break. The failure behaviour is duplicated because the invariant it
 * upholds is the same one envelope-log-sink.ts states for the envelope log:
 * a projection write must never be able to turn a governed tool call into a
 * denied one.
 */
function createSessionContextLogAppender(path: string): (line: string) => void {
  let disabled = false;

  const fail = (error: unknown): void => {
    disabled = true;
    try {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`session context log disabled after failure (${path}): ${message}`);
    } catch {
      // Silently swallow any error from console.error, matching
      // envelope-log-sink.ts's own guard -- total means total.
    }
  };

  try {
    mkdirSync(dirname(path), { recursive: true });
  } catch (error) {
    fail(error);
  }

  return (line: string): void => {
    if (disabled) {
      return;
    }
    try {
      appendFileSync(path, `${line}\n`);
    } catch (error) {
      fail(error);
    }
  };
}

export async function startGuardian({
  port,
  hostname,
  manifestPath,
  mappingPath,
  envelopeLogPath,
  onDecisionFailure,
  annotator,
  bridge: bridgeOverride,
  sessionContextLog,
  sessionContextStore: sessionContextStoreOverride,
}: StartGuardianOptions): Promise<StartedGuardian> {
  // Construct the bridge once at boot, not per request -- and through the
  // shared recipe rather than assembling one here, so this Guardian and every
  // other caller that evaluates this deployment's manifest get the identical
  // bridge. `createDeploymentBridge` is where "the annotator is never absent"
  // actually lives; see its own module.
  const bridge = bridgeOverride ?? createDeploymentBridge(manifestPath, annotator);
  const mapping = loadMapping(mappingPath ?? MAPPING_PATH);
  const envelopeLog = envelopeLogPath ? createEnvelopeLogSink({ path: envelopeLogPath }) : NULL_ENVELOPE_LOG_SINK;
  // The session-context store is always the in-memory one, or the caller's
  // own override -- sessionContextLog never becomes an alternative backing
  // store, only a JSONL projection of whichever store is in use, the same
  // relationship envelopeLogPath has to the envelope log. The `??` below
  // means the projection is wired up (and its directory created) only in
  // the branch that actually constructs the default store -- an override in
  // sessionContextStore short-circuits past both, per that option's own doc
  // comment.
  const sessionContextStore =
    sessionContextStoreOverride ??
    createMemorySessionContextStore(
      sessionContextLog ? { appendLine: createSessionContextLogAppender(sessionContextLog) } : {},
    );

  const server = Bun.serve({
    hostname: hostname ?? LOOPBACK_ONLY,
    port,
    async fetch(req) {
      const { pathname } = new URL(req.url);
      if (req.method !== "POST" || pathname !== ACS_PATH) {
        return new Response("Not Found", { status: 404 });
      }
      const response = await handleAcsRequest(req, bridge, mapping, envelopeLog, onDecisionFailure, sessionContextStore);
      return Response.json(response);
    },
  });

  return {
    url: `http://localhost:${server.port}${ACS_PATH}`,
    async close() {
      await server.stop(true);
    },
  };
}

/**
 * Four phases, in order: read the body under a cap, parse, record the
 * request, dispatch, record the response. The cap refuses ahead of the parse,
 * so an oversize body is a refusal the host fails closed on rather than a
 * parse failure it would read as a delivery accident. The envelope-log writes
 * live here and only here. `dispatch` below leaves by seven routes: six
 * `return`s and one rethrow. Two of those returns hand off to `evaluateStep`,
 * which itself leaves by three routes (a decision, an honoured deny, or a
 * bare error). Writing to the envelope log inside `dispatch` or
 * `evaluateStep` would make covering every route something a future change
 * has to remember, rather than something this
 * structure guarantees.
 *
 * That guarantee only holds if every route out of `dispatch` is covered,
 * including the one that throws: the try/catch below ensures every route
 * out of `dispatch` produces a response object, and every response object
 * reaches the envelope log.
 *
 * The read comes before the parse because the parse is what an unbounded body
 * is dangerous through: `req.json()` buffers whatever arrives, and the
 * failure it raises past the runtime's own default limit reaches the host as
 * a bare rejection -- which under a `proceed` posture is a fail-open, and one
 * a client picks by choosing how much to send. Refusing above the cap turns
 * that into an answer the host reads as a refusal (see
 * MAX_REQUEST_BODY_BYTES).
 *
 * The sink itself is total (see envelope-log-sink.ts): these two calls cannot
 * throw, so they cannot turn a governed tool call into an ungoverned one.
 */
async function handleAcsRequest(
  req: Request,
  // The role, not `ReturnType<typeof createBridge>`: this handler depends on
  // something it can tell to evaluate a snapshot, not on the shape one
  // factory happens to return.
  bridge: PolicyBridge<GuardianSnapshot>,
  mapping: Mapping,
  envelopeLog: EnvelopeLogSink,
  onDecisionFailure: "proceed" | "deny" | undefined,
  sessionContextStore: SessionContextStore,
): Promise<JsonRpcSuccess | JsonRpcFailure> {
  const body = await readCappedBody(req);
  if (body.withinLimit === false) {
    // Unpaired, for the same reason the parse error below is: nothing was
    // read, so there is no request envelope to record it against.
    //
    // ENVELOPE_INVALID_CODE rather than a code of its own: this IS an invalid
    // envelope -- one whose size alone disqualifies it -- and the host reads
    // that code as the Guardian refusing the envelope, which is exactly what
    // happened. A fresh code would mean a host classifying it as an
    // unrecognised error and falling back on its posture, which for the
    // shipped default is the fail-open this cap exists to close.
    const tooLarge = errorResponse(
      null,
      ENVELOPE_INVALID_CODE,
      `request body exceeds the ${MAX_REQUEST_BODY_BYTES}-byte limit (${body.detail})`,
    );
    envelopeLog.write("response", tooLarge, null);
    return tooLarge;
  }

  let raw: unknown;
  try {
    raw = JSON.parse(body.text) as unknown;
  } catch {
    // Nothing parseable arrived, so there is no request envelope to record
    // -- the response is deliberately recorded unpaired, which is what the
    // Inspector renders when a host sends a malformed body.
    const parseError = errorResponse(null, -32700, "Parse error");
    envelopeLog.write("response", parseError, null);
    return parseError;
  }

  // Recorded before validation, so an envelope that fails the schema is
  // visible to the Inspector rather than invisible.
  const method = extractMethod(raw);
  envelopeLog.write("request", raw, method);

  let response: JsonRpcSuccess | JsonRpcFailure;
  try {
    response = await dispatch(raw, bridge, mapping, onDecisionFailure, sessionContextStore);
  } catch (error) {
    // The outer net. Deliberately a bare JSON-RPC error, not an ACS `deny`:
    // this route is `dispatch` rethrowing entirely past denyOnInvalidEnvelope
    // -- a bug in the Guardian itself (e.g. a missing schema directory), not
    // an invalid envelope, so denyOnInvalidEnvelope never runs. What this
    // buys is that the client can parse the answer at all, and that the
    // envelope log holds a response line paired with the request line above
    // it.
    const message = toRepoRelativeMessage(error);
    response = errorResponse(extractId(raw), EVALUATION_FAILED_CODE, `guardian failed to handle the request: ${message}`);
  }

  const responseCheck = checkResponse(response);
  try {
    // Reported, not thrown, and the response is sent unchanged either way:
    // see check-response.ts. This is the outbound counterpart to
    // validateEnvelope's inbound checking, and it must not be able to turn a
    // governed step into an ungoverned one.
    //
    // One line per status, because they are different findings. Reporting
    // "unchecked" as a schema failure -- which is what the old boolean did --
    // sent an operator hunting a violation that was never observed, when the
    // real fault is a deployment whose schema registry will not build.
    if (responseCheck.status === "checked_invalid") {
      console.error(
        `guardian sent a response that fails response-envelope.json at ${responseCheck.pointer}: ${responseCheck.message}`,
      );
    } else if (responseCheck.status === "unchecked") {
      console.error(
        `guardian sent a response for method ${method} without checking it against response-envelope.json: ${responseCheck.reason}`,
      );
    }
  } catch {
    // A reporting failure (an EPIPE on stderr, say) must not be able to
    // throw out of handleAcsRequest with nothing above it to catch it --
    // matching envelope-log-sink.ts / createSessionContextLogAppender's own
    // guard: total means total, including the reporter that exists only to
    // report a different total component's own finding.
  }

  envelopeLog.write("response", response, method);
  return response;
}

/** What came back from the wire, before anything has tried to read it as an
 * envelope. A union rather than a string plus a flag, so a caller that reads
 * `text` without checking the limit does not compile. */
type CappedBody =
  | { readonly withinLimit: true; readonly text: string }
  | { readonly withinLimit: false; readonly detail: string };

/**
 * Reads the request body, refusing anything past MAX_REQUEST_BODY_BYTES
 * rather than buffering it.
 *
 * Streamed rather than `await req.text()` for the one reason the cap exists:
 * `text()` has already buffered the whole body by the time its length can be
 * measured, so measuring afterwards enforces nothing. Reading chunk by chunk
 * and holding nothing past the cap is what makes the limit a limit.
 *
 * What the cap bounds is what this process HOLDS, not what a client may
 * transmit -- and that distinction is forced, not chosen. The body is drained
 * to its end even once it is refused, because leaving it unread (whether by
 * cancelling the stream or by returning before touching it) leaves the
 * HTTP/1.1 message unfinished: Bun then answers the NEXT request on that
 * keep-alive connection with an empty 400, which a host reads as a delivery
 * failure and resolves with its posture. Refusing one oversize body by
 * breaking the next legitimate request would be a wider fail-open than the
 * one this cap closes. So memory is bounded here, and total transfer stays
 * bounded by the runtime's own per-request ceiling above this.
 *
 * Which check is authoritative, since there are two: the count of bytes
 * actually read. `Content-Length` is a claim -- a chunked body declares none,
 * and a client may declare one length and send another -- so it can refuse a
 * body before anything is held, but it can never admit one. `detail` says
 * which of the two refused, because "you declared 4 MiB" and "you sent 4 MiB
 * having declared nothing" are different client bugs and an operator reading
 * the log needs to know which.
 */
async function readCappedBody(req: Request): Promise<CappedBody> {
  // `Number(null)` is 0, which is the reading wanted for an absent header:
  // nothing was declared, so nothing is refused on this account and the byte
  // count below is the only check. A malformed header is NaN, and `NaN >` is
  // false, so that falls through to the byte count too rather than refusing a
  // request whose body may be perfectly small.
  const declared = Number(req.headers.get("content-length"));
  const declaredTooLarge = declared > MAX_REQUEST_BODY_BYTES;

  // A POST with no body at all: nothing to read, and the parse above is what
  // rejects it -- as an unparseable body, which is what it is.
  if (req.body === null) {
    return declaredTooLarge
      ? { withinLimit: false, detail: `content-length declared ${declared}` }
      : { withinLimit: true, text: "" };
  }

  const reader = req.body.getReader();
  // `{ stream: true }` per chunk: a chunk boundary can land mid-codepoint, and
  // decoding each one in isolation would replace the split character with
  // U+FFFD -- corrupting an envelope that was never too big at all.
  const decoder = new TextDecoder();
  let text = "";
  let read = 0;
  // Nothing is held for a body that already declared itself too large: the
  // decision is made, and the loop below only has to finish the message.
  let holding = !declaredTooLarge;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done === true) {
        break;
      }
      read += value.byteLength;
      if (read > MAX_REQUEST_BODY_BYTES && holding) {
        // Released as soon as the cap is passed, not at the end of the read:
        // a refusal that kept the first megabyte until the body finished
        // arriving would be enforcing the cap on average rather than at all.
        holding = false;
        text = "";
      }
      if (holding) {
        text += decoder.decode(value, { stream: true });
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (declaredTooLarge) {
    return { withinLimit: false, detail: `content-length declared ${declared}` };
  }
  return read > MAX_REQUEST_BODY_BYTES
    ? { withinLimit: false, detail: `${read} bytes read` }
    : { withinLimit: true, text: text + decoder.decode() };
}

async function dispatch(
  raw: unknown,
  bridge: PolicyBridge<GuardianSnapshot>,
  mapping: Mapping,
  onDecisionFailure: "proceed" | "deny" | undefined,
  sessionContextStore: SessionContextStore,
): Promise<JsonRpcSuccess | JsonRpcFailure> {
  const rpcId = extractId(raw);

  let envelope: AcsRequestEnvelope;
  try {
    // validateEnvelope checks the general request-envelope.json shape for
    // every method, plus -- only for steps/toolCallRequest -- the
    // hook-specific payload schema. Failure is a THROWN typed error, never
    // a decision itself -- validateEnvelope stays total to its own contract
    // (see its doc comment) -- but the catch below (denyOnInvalidEnvelope)
    // turns a steps/* failure into an honoured ACS `deny` decision rather
    // than a bare JSON-RPC error, since there is an identifiable step to
    // answer for. A handshake failure and an undispatched method are not
    // steps/*, so they always fall through to the JSON-RPC error unchanged.
    envelope = validateEnvelope(raw);
  } catch (error) {
    if (error instanceof EnvelopeValidationError) {
      if (isStepMethod(raw)) {
        const denial = denyOnInvalidEnvelope(raw, { reasonCode: "envelope_invalid", message: error.message });
        const decisionResponse = asDecisionResponse(rpcId, denial);
        if (decisionResponse) {
          return decisionResponse;
        }
      }
      return errorResponse(rpcId, ENVELOPE_INVALID_CODE, error.message, { pointer: error.pointer });
    }
    throw error;
  }

  if (envelope.method === HANDSHAKE_METHOD) {
    const env = onDecisionFailure === undefined ? undefined : { ACS_ON_DECISION_FAILURE: onDecisionFailure };
    return successResponse(envelope.id, buildServerHello(env));
  }

  // Two gated branches, one per ACS method this Guardian assembles a snapshot
  // for -- and gated by a PREDICATE each, never by `envelope.method` spelled
  // out again here and never by the resolved intervention point. Both halves of
  // that matter:
  //
  //   - Each predicate lives beside the payload check it stands for
  //     (validate-envelope.ts), so a branch cannot come to disagree with the
  //     module that decided whether `params.payload` was validated against that
  //     method's hook schema. Each also narrows the envelope, which is what
  //     lets its assembler take one method's view rather than any request at
  //     all: the two snapshots share no member but `envelope.budgets`, so
  //     there is no one assembler for both and no union type to hand around.
  //
  //   - A branch keyed on the resolved point instead would be a fail-open:
  //     mapping.yaml declares six methods with points and this Guardian
  //     assembles two, so a `steps/sessionStart` envelope would reach whichever
  //     assembler came first and come back as a verdict that looks perfectly
  //     well-formed while having evaluated the wrong policy against the wrong
  //     shape. Anything neither predicate answers falls past both, to
  //     METHOD_NOT_DISPATCHED_CODE below.
  if (isToolCallRequest(envelope)) {
    return await evaluateStep(raw, envelope, assemblePreToolCallSnapshot, bridge, mapping, sessionContextStore);
  }

  // The result gate, beside the request gate rather than merged into it.
  if (isToolCallResult(envelope)) {
    return await evaluateStep(raw, envelope, assemblePostToolCallSnapshot, bridge, mapping, sessionContextStore);
  }

  // A well-formed envelope (it passed validateEnvelope: the method matched
  // the required prefix pattern) naming a method this Guardian has no
  // handler for -- distinct from a malformed envelope, which never reaches
  // here because validateEnvelope already threw above.
  return errorResponse(rpcId, METHOD_NOT_DISPATCHED_CODE, `method not dispatched by this Guardian: ${envelope.method}`, {
    method: envelope.method,
  });
}

/**
 * evaluateStep's own bound: `AcsRequestEnvelope` narrowed just enough to read
 * the one payload member `ToolCallRequestPayload` and `ToolCallResultPayload`
 * both carry, `payload.tool.name` -- so `appendContextEntry`'s chain entry
 * (below) can be built generically over whichever gate called this function,
 * without widening back to a union of the two payload shapes.
 * `ToolCallRequestEnvelope` and `ToolCallResultEnvelope` are each narrower
 * than this and satisfy it, so inference at each call site still lands on
 * the specific envelope type, not on this bound itself.
 */
type SteppedEnvelope = AcsRequestEnvelope & { params: { payload: { tool: { name: string } } } };

/**
 * The half of an assembling branch that is the same whichever gate reached it:
 * assemble, resolve the point, evaluate, map the verdict, answer. One copy,
 * shared by both gates -- not because it is shorter, but because the failure
 * handling below is a project invariant (§6.4) rather than a detail of the
 * request gate, and a second copy of it is a second thing to keep true.
 *
 * Generic in the envelope, and the assembler is a function OF that envelope --
 * `E` and `(envelope: E, sourceLabels: IfcLabels, policyTargetArgument: string
 * | undefined) => GuardianSnapshot` rather than an `AcsRequestEnvelope` and an
 * independent thunk. `E` infers from the narrowed variable each gate passes,
 * both assemblers are assignable as they stand (`assemblePostToolCallSnapshot`
 * takes two parameters and a two-parameter function is assignable to a
 * three-parameter function type), and the one miswiring this function could
 * otherwise permit becomes unrepresentable: `evaluateStep(raw, envelopeA, (_e, s, p) => assemblePreToolCallSnapshot(envelopeB, s, p), ...)`
 * would have resolved the point from A's method and echoed A's ids while
 * evaluating B's snapshot -- the wrong policy against the wrong shape, which
 * this file's own comments call worse than a reported failure. In the inline
 * form that gap did not exist, because the narrowed variable was structurally
 * the one variable; the tie has to be re-stated in the signature once the tail
 * is shared, not left to the call sites to get right.
 *
 * The generic keeps each assembler's parameter type narrow while this function
 * stays method-agnostic about the SNAPSHOT: nothing here reads a snapshot
 * member, so nothing here needs to know which shape it got, and no union of
 * the two snapshot types is needed to say so -- `GuardianSnapshot` is the
 * union of the two messages this Guardian can send, and this function reads
 * no member of either. It does read envelope members now, for the chain
 * entry: `params.metadata.session_id` and `params.request_id`, both already
 * generic over plain `AcsRequestEnvelope` (method-independent, so no
 * narrower bound was needed for them), and one PAYLOAD member,
 * `payload.tool.name` -- the one member `SteppedEnvelope` above exists for,
 * since `payload` is generically `Record<string, unknown>` otherwise. All
 * three reads are shared identically by both payload shapes, so none
 * carries the wrong-shape risk the paragraph above is about. The assembler
 * is called INSIDE the try, so a throw from it -- or from appending to the
 * chain, or from persisting labels -- lands in the same catch as a throw
 * from AGT.
 *
 * The intervention point comes from mapping.yaml's own `intervention_points`
 * table, not from a literal here: that table is what the conformance
 * package's mapping table publishes -- never its coverage matrix, which
 * measures rather than declares -- and a declaration the runtime does not
 * consult is a claim nobody checks. An unresolvable method throws into the
 * catch below rather than defaulting to a point -- evaluating the wrong policy
 * and calling the result a decision is the one outcome worse than a reported
 * failure.
 */
async function evaluateStep<E extends SteppedEnvelope>(
  raw: unknown,
  envelope: E,
  assemble: (envelope: E, sourceLabels: IfcLabels, policyTargetArgument: string | undefined) => GuardianSnapshot,
  bridge: PolicyBridge<GuardianSnapshot>,
  mapping: Mapping,
  sessionContextStore: SessionContextStore,
): Promise<JsonRpcSuccess | JsonRpcFailure> {
  try {
    // The chain entry is appended on arrival, before any verdict exists: a
    // step that is later denied is still a step this session took, and a
    // chain that recorded only permitted steps would be a chain an incident
    // review cannot use.
    appendContextEntry(sessionContextStore, envelope.params.metadata.session_id, {
      method: envelope.method,
      request_id: envelope.params.request_id,
      tool_name: envelope.params.payload.tool.name,
    });

    // Resolved BEFORE the snapshot is assembled, where it used to be resolved
    // after: the assembler needs to know which of this tool's arguments the
    // policy target is read from, and mapVerdict needs the same answer to key
    // any override it has to write back. One resolution, two readers -- asking
    // twice would let them differ.
    const point = resolveInterventionPoint(envelope.method, mapping);
    const policyTargetArgument = resolvePolicyTargetArgument(mapping, point, envelope.params.payload.tool.name);

    const snapshot = assemble(
      envelope,
      supplySourceLabels(sessionContextStore, envelope.params.metadata.session_id),
      policyTargetArgument,
    );
    const verdict = await bridge.evaluate(point, snapshot);
    const decision = mapVerdict(verdict, mapping, point, policyTargetArgument);

    // `verdict.result_labels` is `undefined` when the IFC gate did not run
    // at all and `[]` when it ran and propagated nothing; `persistIfcLabels`
    // keeps those apart deliberately -- see its own doc comment.
    persistIfcLabels(sessionContextStore, envelope.params.metadata.session_id, verdict.result_labels);

    return successResponse(envelope.id, finalResult(envelope.params, decision));
  } catch (error) {
    // This produces a parseable JSON-RPC error rather than an HTML 500.
    // denyOnInvalidEnvelope goes one step further: AGT's evaluation layer
    // fails closed, and this catch is where that failure surfaces, so it is
    // delivered as an honoured `deny` decision rather than a bare error,
    // keeping it inside §6.4's honoured path. An AGT evaluation failure is a
    // deny; a delivery failure is the host's negotiated posture, decided
    // elsewhere and never merged with this.
    const message = toRepoRelativeMessage(error);
    // The same best-effort id `dispatch` reads for its own failure paths, off
    // the same raw body: a response the client cannot correlate is not a
    // decision it can honour (see asDecisionResponse).
    const rpcId = extractId(raw);
    const denial = denyOnInvalidEnvelope(raw, { reasonCode: "evaluation_failed", message });
    const decisionResponse = asDecisionResponse(rpcId, denial);
    if (decisionResponse) {
      return decisionResponse;
    }
    return errorResponse(rpcId, EVALUATION_FAILED_CODE, `evaluation failed: ${message}`);
  }
}

function successResponse(id: string | number, result: AcsFinalResult | ServerHello): JsonRpcSuccess {
  return { jsonrpc: "2.0", id, result };
}

function errorResponse(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcFailure {
  return { jsonrpc: "2.0", id, error: data === undefined ? { code, message } : { code, message, data } };
}

/** Best-effort extraction of the request's JSON-RPC id for error responses,
 * per response-envelope.json: id MUST be null when it cannot be determined,
 * otherwise it matches the request id. Used only on failure paths -- a
 * successful response always uses the schema-validated envelope's id. */
function extractId(raw: unknown): string | number | null {
  if (typeof raw === "object" && raw !== null && "id" in raw) {
    const id = raw.id;
    if (typeof id === "string" || typeof id === "number") {
      return id;
    }
  }
  return null;
}

/** Best-effort method name for envelope-log labelling only. Never used to
 * dispatch -- `dispatch` reads the schema-validated envelope's own `method`. */
function extractMethod(raw: unknown): string | null {
  if (typeof raw === "object" && raw !== null && "method" in raw) {
    const method = raw.method;
    if (typeof method === "string") {
      return method;
    }
  }
  return null;
}

/** Whether the raw envelope names a `steps/*` method -- read before
 * validation, so it is a string test and nothing more. denyOnInvalidEnvelope
 * only turns a schema-validation failure into a deny decision for steps/*:
 * a handshake failure is not a governance decision (there is no step to
 * decide about), and an undispatched method is answered separately, below. */
function isStepMethod(raw: unknown): boolean {
  const method = extractMethod(raw);
  return typeof method === "string" && method.startsWith("steps/");
}

/**
 * Turns a `denyOnInvalidEnvelope` result into a JSON-RPC success response,
 * or `null` when it cannot be delivered as one -- in which case the caller
 * falls back to its own JSON-RPC error response instead.
 *
 * Two distinct reasons produce `null`, not one:
 *   - `denial.kind === "unaddressable"` -- denyOnInvalidEnvelope found no
 *     request_id and no usable JSON-RPC id anywhere on the envelope.
 *   - `denial.kind === "decision"` but `rpcId` is `null` -- the decision
 *     found an id (via `params.request_id`), but that id did not come from
 *     the envelope's own JSON-RPC `id`. `successResponse` requires a
 *     non-null id for the *response*, and a JSON-RPC response with a null
 *     id cannot be correlated by the client either -- so this is not a
 *     cast to paper over (`rpcId as string | number`), it is a real case
 *     the addressability rule exists for, and it is handled the same way
 *     `unaddressable` is: by falling back to the error response.
 */
function asDecisionResponse(rpcId: string | number | null, denial: DenyOnInvalidEnvelopeResult): JsonRpcSuccess | null {
  if (denial.kind === "decision" && (typeof rpcId === "string" || typeof rpcId === "number")) {
    return successResponse(rpcId, denial.result);
  }
  return null;
}
