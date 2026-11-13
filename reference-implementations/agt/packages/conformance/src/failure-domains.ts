/**
 * The last of the four checks that feed the coverage-matrix merge, and the
 * only one that drives a live Guardian over HTTP rather than calling
 * `mapVerdict` or `resolveInterventionPoint` in-process -- a check that
 * constructed its own failure in-process would be measuring its own
 * construction, not the wire boundary that keeps the two failure domains
 * below apart.
 *
 * TWO FAILURE DOMAINS, kept apart here exactly as `deny-on-invalid-envelope.ts`
 * keeps them apart at the point that answers them:
 *
 *   (1) AGT'S EVALUATION LAYER FAILS CLOSED (§6.4). An envelope that fails
 *       schema validation, or whose evaluation throws, arrives as an
 *       honoured ACS `deny` decision -- never a bare JSON-RPC error.
 *       `denyOnInvalidEnvelope` (`packages/guardian/src/deny-on-invalid-
 *       envelope.ts`) is what does it, reached from two different catches in
 *       `server.ts` with two different reason codes: `envelope_invalid`
 *       (`dispatch`'s own catch) and `evaluation_failed` (`evaluateStep`'s
 *       catch). The assertions below that belong to this domain:
 *       `measureDenyColumn` drives one live probe per
 *       mapped point (never one probe generalised to all of them), and
 *       `assertEvaluationFailsClosed` drives one literal probe of its own, a
 *       `steps/toolCallRequest` whose payload fails
 *       `hooks/tool-call-request.json`.
 *
 *   (2) WIRE DELIVERY FAILURE APPLIES THE NEGOTIATED POSTURE. When no
 *       decision arrives at all -- the Guardian is unreachable, times out, or
 *       answers with an error and no `result` -- a `proceed` deployment
 *       proceeds and audits, a `deny` deployment blocks. THIS HALF IS THE
 *       HOST'S, not the Guardian's: the Guardian never applies a posture, it
 *       only ever answers with a decision or fails to answer at all.
 *       `packages/host-adapter/src/failure-posture.ts`'s `applyFailurePosture`
 *       reads `on_decision_failure` off the stored session config and decides
 *       the outcome; `session-config.ts`'s `isSessionConfig` validates that a
 *       stored config carries that field before `applyFailurePosture` can read
 *       it. `hosts/claude-code/acs-hook.ts` calls into this by way of
 *       `governStep` -- it does not apply the posture itself. It is measured
 *       end to end by
 *       `hosts/claude-code/test/posture.test.ts` (which drives a stub
 *       Guardian through every delivery-failure shape it can produce -- dead,
 *       timed out, error-without-decision -- against both postures) and is
 *       referenced here rather than re-driven: constructing a second copy of
 *       that suite inside a Guardian-only check would test the host's own
 *       code from a package that has no host in it.
 *
 * A THIRD BOUNDARY, distinct from both of the above and not a failure domain
 * of its own: DISPATCH. A well-formed envelope naming a method this Guardian
 * has no handler for answers `method_not_dispatched` (server.ts's own
 * `METHOD_NOT_DISPATCHED_CODE`), a plain JSON-RPC error, never a decision --
 * because there is no step here to answer for, which is the same reason
 * `denyOnInvalidEnvelope` is never reached by a handshake failure either. This
 * check posts an envelope naming a method `mapping.yaml` gives no row
 * to at all, and records that it comes back `method_not_dispatched` rather
 * than being swallowed into domain (1)'s deny-on-failure path -- proving the
 * two stay apart, not resolving any cell about it. What this check does not
 * do: `mapping.yaml` gives an `acs_method` to six intervention points, and
 * this Guardian dispatches two (`handshake.ts`'s `METHODS_EVALUATED`); the
 * other four answer `method_not_dispatched` too, live, but that is a
 * different fact -- a mapped-but-undispatched method, not an unmapped one --
 * and this check does not resolve a cell for it or draw a matrix-level
 * conclusion from it; the coverage-matrix merge and the published
 * declaration carry that fact forward instead.
 * `assertHookPayloadFailureIsUndispatchedElsewhere` below measures the same
 * boundary from validation's own side rather than dispatch's: the
 * hook-payload schemas `validateEnvelope` checks a payload against are gated
 * on the identical two method literals `METHODS_EVALUATED` names, in a
 * different file, so an empty payload is invalid only where this Guardian
 * also dispatches -- one seam, seen from validation and from dispatch.
 *
 * ONE LIVE PROBE PER MAPPED POINT, never one probe generalised to all of
 * them, because a single hook-payload probe cannot stand in for the other
 * five points: `checkHookPayload` applies a
 * hook-payload schema only for `steps/toolCallRequest` /
 * `steps/toolCallResult`, so an empty payload never fails validation at all
 * for the other four mapped methods -- they have no hook-payload schema to
 * fail, the envelope passes, and dispatch answers `method_not_dispatched`,
 * not a deny. Measured live: `steps/toolCallRequest` and
 * `steps/toolCallResult` return `decision=deny` for an empty payload;
 * `steps/sessionStart`, `steps/sessionEnd`, `steps/userMessage`,
 * `steps/agentResponse` each return a JSON-RPC error, code -32011.
 * `measureDenyColumn` below is what actually resolves the deny column: one
 * live probe per mapped point, using a generic `request-envelope.json`
 * failure (a missing `params.metadata`) rather than the method-gated
 * hook-payload one -- `validateTopLevel` (validate-envelope.ts's first
 * check) is not method-gated, so this failure mode genuinely does reach
 * `isStepMethod`'s gate identically for all six. Each cell in this file is
 * resolved by a probe naming the point it is a cell about, never by an
 * argument about routing.
 */
import { METHOD_NOT_DISPATCHED_CODE, type Mapping, type StartedGuardian } from "guardian";
import { AGT_POINTS, type CoverageCell } from "./cells.ts";

/** A method no row of mapping.yaml's `intervention_points` table ever
 * assigns to any point (see this module's header: this is the "unmapped
 * method" boundary, distinct from the four mapped-but-undispatched
 * methods). Namespaced under `steps/` so it reaches the same `isStepMethod`
 * branch a real step would, which is the only way this probe can show that
 * an undispatched method does NOT fall into domain (1)'s deny-on-failure
 * path merely for being unrecognised. */
const UNMAPPED_METHOD = "steps/doesNotExist";

/** A method mapping.yaml DOES map (to `agent_startup`) that this Guardian
 * does not dispatch (`handshake.ts`'s `METHODS_EVALUATED` names only
 * `steps/toolCallRequest` / `steps/toolCallResult`). Used only by
 * `assertHookPayloadFailureIsUndispatchedElsewhere` to measure the
 * hook-payload/dispatch coincidence this module's header names -- distinct
 * from `UNMAPPED_METHOD`, which mapping.yaml gives no row to at all. */
const UNDISPATCHED_MAPPED_METHOD = "steps/sessionStart";

type DenyProbeResponse = { result?: { decision?: string; reason_codes?: string[] }; error?: unknown };
type DispatchProbeResponse = { result?: unknown; error?: { code?: number; message?: string } };

/** The reason attached to every `deny` cell `measureDenyColumn` resolves
 * `expressed`. This string is printed into the published coverage matrix, so
 * it has to stand on its own: it states what was measured at this point, not
 * a general claim about the specification and not an inference from a
 * different point's probe. */
const DENY_EXPRESSED_REASON =
  "AGT's evaluation layer fails closed (§6.4): an otherwise well-formed envelope missing a required " +
  "request-envelope.json field (params.metadata) arrives as an honoured ACS deny decision at this point, never " +
  "a bare JSON-RPC error -- denyOnInvalidEnvelope is what does it, measured live against this Guardian at this " +
  "point specifically. What a host does when no decision arrives at all is a different claim, is the host's " +
  "rather than the Guardian's, and is measured separately by hosts/claude-code/test/posture.test.ts.";

/** Builds a schema-valid, generic ACS request envelope naming `method`, so a
 * probe posting it measures exactly one thing at a time -- the hook-payload
 * check, or dispatch -- rather than tripping the generic request-
 * envelope.json checks by accident and reading a different failure than the
 * one intended. `payload` is the caller's own, since the probes that use
 * this need different ones. */
function wellFormedEnvelope(method: string, payload: Record<string, unknown>): Record<string, unknown> {
  const id = crypto.randomUUID();
  return {
    jsonrpc: "2.0",
    id,
    method,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "conformance", session_id: crypto.randomUUID() },
      payload,
    },
  };
}

/**
 * Builds an envelope naming `method` with `params.metadata` OMITTED --
 * request-envelope.json's `AcsParams` requires it, and this is checked by
 * `validateTopLevel` (validate-envelope.ts's FIRST check, against the
 * envelope's general shape), which runs identically before any
 * method-specific branch and before `payload` is ever inspected. Unlike a
 * hook-payload failure (method-gated, in `checkHookPayload`), this
 * failure mode genuinely does not depend on which `steps/*` method is named
 * -- which is what licenses `measureDenyColumn` calling this once per mapped
 * point and expecting the same answer each time, a claim this module trusts
 * only because each call is itself measured, not merely asserted.
 */
function envelopeMissingMetadata(method: string): Record<string, unknown> {
  const id = crypto.randomUUID();
  return {
    jsonrpc: "2.0",
    id,
    method,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      payload: {},
    },
  };
}

/**
 * The domain (1) probe: a `steps/toolCallRequest` whose payload is empty,
 * which fails `hooks/tool-call-request.json` (it requires `tool` and
 * `arguments`) while the envelope around it is otherwise schema-valid -- so
 * the failure this probe measures is the hook-payload check specifically,
 * not some other field validate-envelope.ts would also have rejected.
 *
 * Does not, by itself, license any cell. The hook-payload check this probe
 * trips is method-gated (`checkHookPayload` applies it to only
 * `steps/toolCallRequest` / `steps/toolCallResult` get one), so a deny here
 * says nothing about a mapped point with no hook-payload schema at all.
 * `measureDenyColumn` below is what actually resolves the deny column, from
 * six independent probes using a different, genuinely method-independent
 * failure mode. This function stays because it is the base case
 * `assertHookPayloadFailureIsUndispatchedElsewhere` contrasts against.
 *
 * A throw here, not a resolved `unexpressed` cell: a Guardian that answers
 * this probe with anything but an honoured deny has the fail-closed
 * guarantee broken at the request gate specifically -- not "expressed
 * differently", broken -- and publishing a matrix cell that claims otherwise
 * would be worse than a failed check.
 */
async function assertEvaluationFailsClosed(guardianUrl: string): Promise<void> {
  const response = await fetch(guardianUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(wellFormedEnvelope("steps/toolCallRequest", {})),
  });
  const body = (await response.json()) as DenyProbeResponse;

  if (body.error !== undefined || body.result?.decision !== "deny") {
    throw new Error(
      `a steps/toolCallRequest whose payload fails hooks/tool-call-request.json did not arrive as an ` +
        `honoured ACS deny -- got ${JSON.stringify(body)}. The fail-closed guarantee does not hold against ` +
        `this Guardian.`,
    );
  }
}

/**
 * The hook-payload finding. Posts the same shape as
 * `assertEvaluationFailsClosed` -- an empty payload -- at
 * `UNDISPATCHED_MAPPED_METHOD`, a method mapping.yaml maps to a point
 * (`agent_startup`) but this Guardian does not dispatch, and asserts the
 * answer is `method_not_dispatched`, not a deny.
 *
 * `hooks/session-start.json` (or any schema for a non-tool-call method) is
 * never checked by `validateEnvelope` at all -- `checkHookPayload` is called
 * only for `steps/toolCallRequest` / `steps/toolCallResult`
 * (`checkHookPayload`) -- so an empty payload here is not invalid;
 * the envelope passes validation whole, and dispatch's own predicates answer
 * `method_not_dispatched`. Contrasted directly with
 * `assertEvaluationFailsClosed`'s identical-shaped probe at
 * `steps/toolCallRequest`, this is the hook-payload/dispatch coincidence
 * this module's header names: the two method lists that gate hook-payload
 * checking and dispatch are declared independently, in different files, and
 * today they happen to name the same two methods.
 *
 * A THROW when the answer is anything else -- not because that would be
 * domain (1) or (2) failing, but because it would mean an empty payload has
 * started failing validation for a method with no hook-payload schema this
 * check knows of, which is exactly the kind of drift this probe exists to
 * catch rather than let the module header's claim go unmeasured.
 */
async function assertHookPayloadFailureIsUndispatchedElsewhere(guardianUrl: string): Promise<void> {
  const response = await fetch(guardianUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(wellFormedEnvelope(UNDISPATCHED_MAPPED_METHOD, {})),
  });
  const body = (await response.json()) as DispatchProbeResponse;

  if (body.error?.code !== METHOD_NOT_DISPATCHED_CODE) {
    throw new Error(
      `${JSON.stringify(UNDISPATCHED_MAPPED_METHOD)} with an empty payload -- invalid only at the two ` +
        `hook-payload-checked methods -- answered ${JSON.stringify(body)} instead of method_not_dispatched. The ` +
        `hook-payload/dispatch coincidence this probe measures does not hold against this Guardian.`,
    );
  }
}

/**
 * The third-boundary probe (this module's header): a method no row of
 * mapping.yaml maps to any point at all. A THROW when the answer is anything
 * but `method_not_dispatched` -- not because that would be domain (1) or (2)
 * failing, but because it would mean dispatch itself has started answering
 * for a method it does not recognise, which this check has no cell to
 * record and every reason to refuse to publish silently.
 */
async function assertUnmappedMethodIsUndispatched(guardianUrl: string): Promise<void> {
  const response = await fetch(guardianUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(wellFormedEnvelope(UNMAPPED_METHOD, {})),
  });
  const body = (await response.json()) as DispatchProbeResponse;

  if (body.error?.code !== METHOD_NOT_DISPATCHED_CODE) {
    throw new Error(
      `${JSON.stringify(UNMAPPED_METHOD)}, a method mapping.yaml gives no intervention-point row to, ` +
        `answered ${JSON.stringify(body)} instead of method_not_dispatched -- domain (1)'s deny-on-failure path ` +
        `has started answering for a method this Guardian does not dispatch, which this check exists to catch.`,
    );
  }
}

/**
 * The deny column's real resolution: one live probe per mapped point, none
 * of them standing in for another. For each point mapping.yaml gives an ACS
 * method to, posts `envelopeMissingMetadata` naming that point's own method,
 * asserts the answer is an honoured deny, and resolves that point's `deny`
 * cell `expressed` from that measurement alone. `pre_model_call` /
 * `post_model_call` get no cell here, deliberately, not an `unexpressed`
 * one: no ACS method ever resolves to either, so there is no wire message
 * this check could fail-close in the first place, and a cell about them is
 * `checkInterventionPoints`'s to resolve (it already does, for every verdict
 * including `deny`) -- not this check's to restate.
 *
 * A throw on the first point whose probe does not come back deny, naming
 * which point and method failed -- the same reasoning as
 * `assertEvaluationFailsClosed`: a broken guarantee at one point is not a
 * cell to mark differently, it is a check that must not publish a cell
 * claiming the guarantee holds there.
 */
async function measureDenyColumn(guardianUrl: string, mapping: Mapping): Promise<CoverageCell[]> {
  const cells: CoverageCell[] = [];
  for (const point of AGT_POINTS) {
    const row = mapping.intervention_points[point];
    if (row === undefined || row.acs_method === null) {
      continue;
    }
    const method = row.acs_method;

    const response = await fetch(guardianUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelopeMissingMetadata(method)),
    });
    const body = (await response.json()) as DenyProbeResponse;

    if (body.error !== undefined || body.result?.decision !== "deny") {
      throw new Error(
        `a ${JSON.stringify(method)} envelope (AGT point ${JSON.stringify(point)}) missing params.metadata ` +
          `did not arrive as an honoured ACS deny -- got ${JSON.stringify(body)}. The fail-closed guarantee ` +
          `does not hold at this point against this Guardian.`,
      );
    }
    cells.push({ point, verdict: "deny", status: "expressed", reason: DENY_EXPRESSED_REASON, measuredBy: ["deny fails closed"] });
  }
  return cells;
}

/**
 * Drives `guardian` with four kinds of probe (this module's header), nine
 * wire posts in all, and returns `measureDenyColumn`'s six
 * independently-measured cells -- one post per mapped method, which is the
 * whole point: this column is measured six times, never measured once and
 * generalised. The other three probe kinds assert invariants this check
 * depends on and resolve no cell of their own: `assertEvaluationFailsClosed`
 * is its own literal hook-payload probe,
 * `assertHookPayloadFailureIsUndispatchedElsewhere` measures the
 * hook-payload/dispatch coincidence, and `assertUnmappedMethodIsUndispatched`
 * measures the third boundary against a method mapping.yaml does not map at
 * all.
 *
 * Named for what it returns. `checkFailureDomains` claimed both domains this
 * module's header keeps apart, and domain (2) is the host's -- measured by
 * `hosts/claude-code/test/posture.test.ts`, referenced here and never
 * re-driven. What this function measures is domain (1): that AGT's
 * evaluation layer fails closed at every mapped point.
 *
 * Told a `StartedGuardian` rather than a URL string, and told the `Mapping`
 * its caller already loaded rather than reading `mapping.yaml` a second
 * time: two readers of one file can disagree about it, and the runner is
 * already holding the answer.
 */
export async function checkDenyFailsClosed(
  guardian: StartedGuardian,
  mapping: Mapping,
): Promise<CoverageCell[]> {
  await assertEvaluationFailsClosed(guardian.url);
  await assertHookPayloadFailureIsUndispatchedElsewhere(guardian.url);
  await assertUnmappedMethodIsUndispatched(guardian.url);

  return measureDenyColumn(guardian.url, mapping);
}
