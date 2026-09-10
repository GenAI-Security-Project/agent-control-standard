/**
 * `governStep` -- the exchange that governs one step, for any host.
 *
 * A host shim tells this "resolve this attempt" and is told back what it
 * should write: the output, the decision that output renders, and which stage
 * of the exchange produced that decision. It asks nothing on the way, and it
 * holds no intermediate flags.
 *
 * This lives outside any host shim so the stage-tracking it does is not
 * something every host has to reproduce: each `try`/`catch` below knows its
 * own stage directly, rather than a shim re-deriving which stage failed by
 * inspecting boolean flags after something has already gone wrong.
 *
 * This is the one place the following properties are guaranteed. Each guards
 * against the same shape of fail-open -- something throws, silently no-ops, or
 * emits an output the host does not recognise, so the tool call runs
 * ungoverned and unaudited -- and each has a test that fails if it reopens:
 *
 *   - A decision that arrived always outranks a posture. A response carrying
 *     both an `error` and a `result` that names a decision means a decision
 *     arrived. `GuardianClient.requestDecision` is the one place that
 *     judgement is made, and it is made before any posture is consulted.
 *   - An evaluation failure and a delivery failure never merge. A `deny` the
 *     policy runtime produced -- including one it produced because its own
 *     evaluation failed -- is a decision, and travels the decision path. A
 *     silent Guardian or a dead transport is a delivery failure, and gets
 *     §6.4's negotiated `on_decision_failure`. Conflating them either breaks
 *     the policy layer's fail-closed invariant or halts production on a
 *     network blip.
 *   - An error carrying no decision is one or the other, and which one is not
 *     this function's call. A code meaning the Guardian was alive and refused
 *     the envelope fails closed regardless of posture; any other error is the
 *     wire's business and gets the posture. `applyFailurePosture` makes that
 *     distinction (see failure-kinds.ts), and every path here reaches it,
 *     which is why nothing here has to know the difference.
 *   - Every step that proceeds without a decision is audited (§6.4 MUST), and a
 *     `proceed` that could not be audited is downgraded to `deny`. That is
 *     `applyFailurePosture`'s job, and every path here that has no decision
 *     goes through it -- there is no route to an output that skips it.
 *   - The audit entry names the right incident. "No request was ever built",
 *     "a request went out and nothing came back", and "a decision arrived and
 *     this host could not express it" are three different incidents, filed
 *     under three `FailureStage`s. They are told apart by where in this
 *     function the failure was caught, not by re-reading flags after the fact:
 *     each stage has its own `try`, and each `catch` knows its own stage
 *     because that is the only stage it can be reached from.
 *   - A gate governs only the tools its hookmap entry names, and this module
 *     is where that rule is enacted (see `governsTool` below, and the skip at
 *     the top of `governStep`), not left to each host shim to remember. Each
 *     shim makes the same check itself, one call earlier, to save the cost of
 *     a step it will not govern; this module makes it again, on the tool the
 *     shim tells it (`GovernStepInput.scopedTool`), which is what a shim that
 *     never wrote its own check still gets -- provided it tells this function
 *     which tool the step is. A shim that reaches a `tools`-declaring gate
 *     without telling is refused outright rather than guessed at. What a
 *     skipped tool call costs downstream is not uniform -- see the four-row
 *     table on `GovernedStep`'s `"ungoverned"` member below for what an empty
 *     render actually does at each shipped applier and gate.
 *   - There are exactly three ways out: a `GovernedStep` for a step this gate
 *     governs, a `GovernedStep` for one it does not (`stage: "ungoverned"`, no
 *     decision, nothing asked, and one audit entry saying so), or a throw. A
 *     throw means this hookmap does not map the hook that fired (see the
 *     guard at the top of `governStep`), that it maps a result gate whose
 *     named output no
 *     replacement can be built for (see `assertOutputIsReplaceable`, asked
 *     before any decision is sought), or that the fallback render of a posture
 *     decision itself failed, which `loadHookmap` makes unreachable for a hook
 *     it does map (see `resolveByPosture` below) -- and all three are left as
 *     throws rather than repaired, because half an output is the one thing a
 *     governance hook must never write. The middle one is closed by ordering:
 *     asked any later it arrives with a decision in hand, and the posture
 *     answers a question the decision had already answered.
 *
 * This module knows ACS and hookmaps, and nothing else: no policy-runtime
 * vocabulary, and no host vocabulary -- it never names a field of the output
 * it returns, which is what lets the same function serve a second host with a
 * different wire shape (see render-decision.ts).
 */
import { buildEnvelope, modificationDocumentOf, type AcsRequestEnvelope, type Hookmap } from "./build-envelope.ts";
import type { AuditSink } from "./audit-sink.ts";
import {
  applyFailurePosture,
  DEFAULT_TIMEOUT_MS,
  type FailureResolvedAcsDecision,
  type FailureStage,
} from "./failure-posture.ts";
import type { GuardianClient } from "./guardian-client.ts";
import type { AcsDecision, ValidatedAcsDecision } from "./decision-message.ts";
import { renderDecision, type HostOutput } from "./render-decision.ts";
import type { ResolvedSessionConfig } from "./handshake.ts";
import { assertOutputIsReplaceable, withResultOutput, type HostOutputLocation } from "./result-output.ts";
import { validateDecision } from "./validate-decision.ts";

/**
 * What became of this step's decision -- one axis, not a directory of
 * participants.
 *
 * `"honoured"` means no stage failed: a decision arrived from the Guardian and
 * this host acted on it. `"ungoverned"` means no decision was ever sought.
 * Every other value is a `FailureStage`, the stage whose failure the
 * deployment's posture answered instead, and each is a different audit
 * incident.
 */
export type DecisionStage = "honoured" | "ungoverned" | FailureStage;

export type GovernStepInput = {
  /** The host's own event name, as `buildEnvelope` reads it against the hookmap. */
  hookEventName: string;
  /** The raw host payload for that event. */
  payload: Record<string, unknown>;
  /** The hookmap: the hook -> ACS method table and the decision -> output table. */
  hookmap: Hookmap;
  /** The Guardian this step's decision is sought from. */
  guardian: GuardianClient;
  /**
   * This session's negotiated config and whatever went wrong establishing it,
   * as `resolveSessionConfig` answers. The config decides the timeout and
   * the failure posture; the failure travels onto the audit entry beside the
   * step's own, never merged into it.
   */
  session: ResolvedSessionConfig;
  /** The host's own session identifier, for the audit entry. */
  sessionId: string;
  /** Required, not optional: §6.4 makes auditing a fail-open non-skippable. */
  audit: AuditSink;
  /**
   * The tool this caller has already scoped the step on, in the caller's own
   * vocabulary for that step -- the same value it asked `governsTool` about a
   * call earlier. When a hookmap entry declares a `tools` list, this is what
   * that list is checked against, and no second source is consulted.
   *
   * This module has no independent way to know what a host calls its tools: a
   * name reaches it either from the caller or by resolving the hookmap's own
   * `tool_name` path against the raw payload, and only the caller's is a fact
   * about the running host. Deriving it from the payload instead would give
   * this gate a second source that can disagree with the shim's -- a hookmap
   * whose `tool_name` path resolves to a different string than the one the
   * shim already checked would skip the step silently, with no Guardian
   * request, no decision, and no audit entry. So the caller's word is
   * authoritative and final here, including
   * when a hookmap lists a tool name in a vocabulary the host's own runtime
   * never actually produces: that mismatch is not decidable in this module,
   * and it costs an unaudited, silent skip of every call to that tool. A
   * load-time cross-check against the deployment's own tool registry could
   * catch such a mismatch, but on a host where an over-strict check at load
   * time fails plugin registration outright, that trade replaces a silently
   * skipped gate with a silently ungoverned session for the whole host --
   * worse, not better -- so it stays a known, open gap rather than a fix
   * applied without its own measurement and its own decision about what a
   * hookmap may legitimately name that a registry does not.
   *
   * Optional because a gate can decline to scope at all: host #1 declares no
   * `tools` at either of its gates -- each has its own settings.json matcher
   * already scoping it, and the two are no longer the same matcher: the
   * request gate's matcher names two tools, the result gate's matcher still
   * names one -- so it has nothing to tell and nothing is checked. A caller
   * whose gate does declare a list and does not tell is refused outright,
   * before anything is asked or audited -- see the guard in `governStep`
   * below, which is what makes this structural rather than a convention a
   * third host can skip. An empty string is refused the same way where a list
   * is declared: `governsTool` would answer `false` for it against any list,
   * which would silently skip a step this gate does govern.
   *
   * An unreadable or absent `tool_name` path is now `buildEnvelope`'s own
   * concern alone, and it is answered loudly there: it throws, which the
   * negotiated posture then answers and audits. No payload shape can turn
   * into a silent skip any more.
   */
  scopedTool?: string;
};

/**
 * What a host is told once a step has been governed: the output to write, the
 * decision it renders, and what became of that decision.
 *
 * A discriminated union, so the refinement each path produced survives the
 * seam. The public story these modules tell is one stem with adjectives for
 * stage -- `AcsDecision` off the wire, `ValidatedAcsDecision` after
 * `validateDecision` has applied §6.3 and substituted any expired outcome,
 * `FailureResolvedAcsDecision` after `applyFailurePosture` answered an absent
 * one -- and a caller narrowing on `stage` needs the specific type, not the
 * widened base: a caller holding a `stage: "honoured"` step needs to see that
 * `applied_input` is the field to read; a caller holding a failure-resolved
 * one needs to see that `reasoning` and `reason_codes` are guaranteed
 * present.
 *
 * Discriminating on `stage` rather than declaring a bare union of the members,
 * because the correspondence is exact and is a property of `governStep`'s
 * control flow: the only route that returns `"honoured"` is the one that
 * rendered a validated decision, the only route that returns `"ungoverned"` is
 * the `tools` skip at the top of `governStep` (which returns before any
 * decision is sought), and every remaining route came from `resolveByPosture`.
 * Stating it here is what lets a caller narrow with the field it already reads.
 */
export type GovernedStep =
  | {
      /**
       * The host output to write, rendered from `decision` through the hookmap.
       * Its keys are the hookmap's, never this module's.
       */
      output: HostOutput;
      /** A decision that arrived and was honoured, after `validateDecision`'s last word on it. */
      decision: ValidatedAcsDecision;
      stage: "honoured";
    }
  | {
      output: HostOutput;
      /** The decision `applyFailurePosture` answered an absent one with. */
      decision: FailureResolvedAcsDecision;
      /** The stage whose failure the posture answered -- see DecisionStage. */
      stage: FailureStage;
    }
  | {
      /**
       * Empty, always: this gate does not govern this step's tool, so there is
       * nothing for this module to render. It is a `GovernedStep` rather than a
       * fourth kind of answer so that a shim needs no new branch to receive it.
       *
       * What an empty render means downstream is the host applier's decision,
       * not this module's -- and it is not the same answer everywhere. Handed
       * an empty render, each of the four shipped applier/gate combinations
       * does this:
       *
       *     applier / gate           what an empty render does
       *     -----------------------  ------------------------------------------
       *     host #1 / request gate   exit 2, nothing written to stdout: this
       *                              render carries no wrapper for that host to
       *                              read a decision from, its applier throws
       *                              rather than write half an output, and
       *                              `main().catch` exits 2. The step is stopped.
       *     host #1 / result gate    exit 0, output written, tool result
       *                              delivered as the tool produced it. That
       *                              gate's applier supplies the wrapper itself,
       *                              because an absent one is the honest answer
       *                              for a clean result there.
       *     host #2 / request gate   no throw, nothing applied: the live
       *                              arguments object still carries its
       *                              original content, and the tool call runs.
       *     host #2 / result gate    no throw, nothing applied: the live result
       *                              object and its mirror still carry their
       *                              original content, and it is delivered.
       *
       * One audit entry in all four, and the same one: `auditUngovernedStep`
       * files an `outcome: "ungoverned"` line naming the tool and the list
       * that declined it, before this member is returned. The table above is
       * about what the RENDER does, which is still nothing; the record is
       * what stops those four rows from being indistinguishable from a
       * session in which the hook never fired.
       *
       * So an empty render still guarantees nothing by itself: it does not
       * mean the step was stopped. On three of the four the tool call, or its
       * output, proceeds with no decision; on the fourth it is a blocking
       * stop, itself a side effect of that host's own rule against writing
       * half an output rather than a deliberate policy about skips. What is
       * no longer true is that it proceeds with no trail -- the entry is the
       * trail, and it is the same entry whichever row this is.
       * Whether a skip is silent or loud in the SESSION is decided entirely
       * in the applier -- host #1 answers it differently per gate, on
       * purpose, and host #2's applier simply has no branch for the case.
       * That is host semantics, which is exactly why this module has no
       * opinion about it: it knows ACS and hookmaps, nothing about what a
       * given host does with an empty render.
       *
       * Only the host #2 request-gate row is exercised by a test today
       * (`hosts/opencode/test/apply-opencode-output.test.ts`, which hands
       * `applyOpenCodeOutput` an empty render and asserts the untouched live
       * arguments and a silent console); the other three rows are documented
       * here but not pinned by a test reaching an applier through this
       * function, since no shipped path drives an empty render there today --
       * host #1 never tells a tool, so a `tools` list at its gates is a
       * refusal here rather than a skip, and host #2's own shim returns before
       * this function for a tool its list excludes. Anything that makes an
       * empty render reachable through a new path should add a test pinning
       * these rows too.
       */
      output: Record<string, never>;
      /**
       * `null`, and deliberately not a fabricated `allow`: no decision was
       * sought, and saying "allowed" would put a governance word on a step no
       * policy was ever asked about. A caller that reads this field has to
       * narrow on `stage` first, which is exactly the question it should be
       * asking.
       */
      decision: null;
      stage: "ungoverned";
    };

/**
 * Does this gate govern this tool? -- `hookmap.hooks[hookEventName].tools`,
 * enacted. An entry with no `tools` key governs every tool, which is
 * `HookmapHookEntryCommon.tools`'s own contract (build-envelope.ts) and
 * host #1's own case: its hookmap declares no `tools` at either gate,
 * because each has its own settings.json matcher already scoping it --
 * `^(Bash|WebFetch)$` at the request gate, `^Bash$` at the result gate.
 *
 * `tools` is shared hookmap vocabulary that build-envelope.ts shape-checks at
 * load time (`assertToolsWellFormed`) and normalises (`normalizeTools`), but
 * enforcing what it means -- skipping a tool call it does not name -- has to
 * live somewhere both hosts share, or a new host built from an existing shim
 * would load a `tools` list and govern every tool anyway. This function is
 * that shared enforcement, the same division `outputs.mirrors` has between
 * build-envelope.ts (shape) and result-output.ts (use).
 *
 * What a skip costs: a tool call this gate does not govern at all. Nothing
 * stands between the model and that tool call at this gate -- a real gap, not
 * a formality, and `auditUngovernedStep` (below) is what puts it in the
 * record rather than leaving it to be inferred from an absence.
 *
 * Why it is right anyway: a deployment's own policy configuration (this
 * repo's `policy/manifest.yaml`, outside this package) can bind evaluation to
 * a single fixed target, checked before any of that deployment's own authored
 * rules run, so a tool it never registered is denied there by the shape
 * mismatch alone, never by a rule a policy author wrote. Asking anyway would
 * not govern that tool call; it would deny it and call the denial governance.
 * A gate that declines to ask is the honest answer to "this deployment cannot
 * express a policy question for this tool".
 *
 * A tool this returns `false` for must never reach the rest of `governStep`
 * to be answered by the deployment's negotiated posture -- that would be the
 * same fail-open shape this module exists to prevent elsewhere, one call
 * later. Both callers therefore return before any envelope is built:
 * `governStep`'s own skip below, and each host shim's own check, one call
 * earlier, which additionally returns before it negotiates a session config,
 * so an out-of-scope tool costs no handshake either. The shim's own check
 * saves that work; this module's check is what a shim that never wrote one
 * still gets, provided it tells `governStep` which tool the step is
 * (`GovernStepInput.scopedTool`) -- see that field's own doc comment for why
 * the tool named here is always the caller's word, never re-derived from the
 * hookmap's own paths against the payload.
 *
 * Both callers must also AUDIT the skip, through `auditUngovernedStep`
 * below, and that is a requirement rather than a courtesy: the shim's early
 * return is an optimisation, and an optimisation that changes what the
 * durable record contains is a divergence, not a saving. A shim that skipped
 * without auditing would produce exactly the silent session this entry
 * exists to make visible, on the one host whose gates declare `tools` at all.
 *
 * `entry.tools` needs no further null-handling here: `loadHookmap` returns a
 * normalised hookmap in which a `tools` key written bare in YAML (which
 * parses to `null` -- present and unusable, not absent) comes back omitted,
 * so this function only ever sees it absent or as the non-empty array of
 * non-empty strings `assertToolsWellFormed` already accepted. A `Hookmap`
 * built by hand, bypassing `loadHookmap`, is off contract for this field the
 * same way it is for every other one.
 *
 * `hasOwnProperty`, not a bare index, because `hookEventName` reaches some
 * hosts from their own payloads and `hooks["toString"]` resolves to an
 * inherited `Object.prototype` function rather than `undefined`. Today that
 * changes no answer -- that function carries no `tools` field, so a bare
 * index would report "governs every tool" too, and the caller would go on to
 * the same `governStep` guard that throws on an unmapped hook. This is a
 * hazard kept closed rather than one reopened: the answer stays a property of
 * the hookmap's own entries, not of what `Object.prototype` happens to carry.
 */
export function governsTool(hookmap: Hookmap, hookEventName: string, tool: string): boolean {
  const hooks = hookmap.hooks ?? {};
  const entry = Object.prototype.hasOwnProperty.call(hooks, hookEventName) ? hooks[hookEventName] : undefined;
  const tools = entry?.tools;
  return tools === undefined || tools.includes(tool);
}

/**
 * Records a step this gate declined to govern -- the `tools` skip, in the
 * one log that outlives the process.
 *
 * Called by `governStep`'s own skip and by every host shim that skips one
 * call earlier, so the record does not depend on which of the two got there
 * first. Shared here rather than written twice for the reason `governsTool`
 * itself is shared: a rule only a shim enacts is a rule the next host does
 * not inherit.
 *
 * It does not change the skip. The decision behaviour is exactly what it was
 * -- return, govern nothing, throw nothing -- and the sink's own totality
 * contract means this cannot alter that even when the append fails. The
 * boolean `write` returns is deliberately dropped here, and that is the one
 * place this differs from `applyFailurePosture`, which downgrades an
 * unrecorded proceed to a block: there, the step was about to bypass a
 * decision the deployment wanted made, so an unrecordable bypass is one the
 * spec does not permit. Here the deployment's own hookmap asked for the
 * skip, and blocking a tool the operator deliberately scoped out -- on a host
 * where this fires for every non-listed tool call -- would turn a scoping
 * declaration into an outage.
 *
 * `tools` is read back off the entry rather than taken as an argument: the
 * list that declined the tool is the hookmap's, and a caller passing its own
 * copy could pass one that no longer matches the file this skip was decided
 * against.
 */
export function auditUngovernedStep(input: {
  hookmap: Hookmap;
  hookEventName: string;
  /** The tool the caller scoped on -- the same value `governsTool` answered
   * `false` for, never a name re-derived from the payload. */
  tool: string;
  /** The host's own raw session identifier, as every other entry carries it. */
  sessionId: string;
  audit: AuditSink;
}): void {
  const hooks = input.hookmap.hooks ?? {};
  const entry = Object.prototype.hasOwnProperty.call(hooks, input.hookEventName)
    ? hooks[input.hookEventName]
    : undefined;
  input.audit.write({
    session_id: input.sessionId,
    // The gate's own ACS method, not the host's event name: an ACS-only
    // reader has to be able to tell WHICH gate declined, and this is the
    // only name for it that log's consumers speak.
    method: entry?.acs_method ?? null,
    // No request was built, so there is no id to pair this with in the
    // envelope log -- the same `null` an entry written before a request
    // could be built carries.
    rpc_id: null,
    outcome: "ungoverned",
    ungoverned: { tool: input.tool, tools: entry?.tools ?? [] },
  });
}

/**
 * Governs one step: build the ACS request, ask the Guardian for a decision,
 * honour it, and render it -- answering any failure along the way with the
 * deployment's negotiated posture, audited, at the stage that failed. A step
 * whose tool this gate's own `tools` list does not name is returned as
 * `stage: "ungoverned"` before any of that begins -- scoped on the tool the
 * caller says it already checked (`scopedTool`), and refusing outright when a
 * gate that declares a list is reached by a caller that named none.
 */
export async function governStep({
  hookEventName,
  payload,
  hookmap,
  guardian,
  session,
  sessionId,
  audit,
  scopedTool,
}: GovernStepInput): Promise<GovernedStep> {
  // Every render below -- the arriving decision's and the posture's -- goes
  // through the hook's own decisions block, so a hook this hookmap does not map
  // has nothing to express either answer through. Checked before this step is
  // asked about or audited, because the alternative is worse than a throw:
  // letting it reach the posture would write an audit entry recording a
  // fail-open proceed, and then fail to render it -- a durable record of a
  // bypass that never happened, in the one log an incident review trusts. (The
  // session handshake has already run by the time a host shim calls this; what
  // this ordering protects is the audit log and the step call, not "nothing at
  // all".) A hookmap missing the hook that fired is a broken deployment, the
  // same class as a hookmap that will not load, and a caller answers it the same
  // way.
  //
  // `hasOwnProperty`, not a bare index: `hookEventName` is host-supplied (it
  // arrives on stdin), and `hooks["toString"]` resolves to an inherited
  // Object.prototype function, which is not `undefined`. A bare index therefore
  // passes this guard for a prototype-named event, `buildEnvelope` throws,
  // `resolveByPosture` writes `outcome: "proceeded"`, and only then does
  // `renderDecision` throw -- the exact durable-false-record outcome this guard
  // exists to prevent, reachable without touching the hookmap. Same reasoning as
  // render-decision.ts's RESERVED_SEGMENTS and acs-hook.ts's `expectationFor`.
  if (!Object.prototype.hasOwnProperty.call(hookmap.hooks ?? {}, hookEventName)) {
    throw new Error(
      `governStep: hookmap has no entry for hook "${hookEventName}", so neither an arriving decision nor a ` +
        `posture's answer to an absent one could be expressed for it`,
    );
  }

  // Scoping runs first, and that ordering matters: a step this gate does not
  // govern must cost nothing and record nothing, and every line below this
  // one either costs something (a Guardian round trip, an audit entry) or can
  // refuse the step outright -- `assertOutputIsReplaceable`, a few lines down,
  // throws for a result-gate payload whose named leaf no replacement can be
  // built for, and on host #2 that is precisely what an unlisted tool's
  // payload looks like, since its `outputs`/`exit_status` paths are shaped
  // for the one tool the gate lists. Asked after that check, an out-of-scope
  // tool would stop the deployment instead of being skipped. So this runs
  // before the envelope, before the Guardian, before the audit sink, and
  // before every refusal this function makes on a payload's shape.
  //
  // It runs after the hook guard above, necessarily: `tools` lives on the
  // entry, so a hookmap with no entry for this hook has no list to read and
  // nothing to be out of the scope of. An unmapped hook is a broken
  // deployment whichever tool fired it.
  //
  // A bare index is safe from here on: the guard above has established that
  // `hookEventName` is an own property of `hooks`, so this cannot resolve to
  // an inherited `Object.prototype` member the way the guard's own lookup
  // could have. Read once, into one const, and used for both questions this
  // function asks of the entry -- the `tools` scope here and the gate's kind
  // below.
  const entry = hookmap.hooks[hookEventName];

  // A caller whose gate declares a `tools` list has to say which tool it
  // scoped on, and a missing answer is a throw, not a posture question.
  //
  // The fault is decidable from this hookmap entry and this call's own
  // arguments alone, with no payload consulted: the entry says this gate
  // governs some tools and not others, and the caller has not said which tool
  // this step is. There is no way for this function to answer that correctly
  // -- scoping on a second source is exactly the divergence `scopedTool`
  // exists to remove, and governing everything would ignore a list the
  // deployment wrote down.
  //
  // Thrown outside every `try` block `resolveByPosture` catches, deliberately:
  // a throw caught by a stage-"request" catch would be answered by the
  // negotiated `on_decision_failure`, which under the ACS default `proceed`
  // means an ungoverned step audited as if it were a fail-open the deployment
  // chose. Raised here it reaches the caller instead -- host #1's
  // `main().catch` turns it into exit 2, and on host #2 it leaves the hook
  // the same way `assertUsableTool`'s and `assertUsableSessionId`'s throws
  // do, since nothing between them catches.
  //
  // An empty `scopedTool` is refused here too, not merely a missing one:
  // `governsTool(hookmap, hook, "")` answers `false` against any declared
  // list, so an empty told name would skip a step this gate actually governs
  // -- and now that a skip files an audit entry, it would file one naming
  // `""` as the tool the list declined. A record that describes an in-scope
  // step as out of scope is worse than the silence it replaced, which is the
  // same reason the guard at the top of this function refuses an unmapped
  // hook before the posture can write a bypass that never happened. Refused
  // only where a list is declared, since that is the only place the value
  // decides anything -- with no list, `governsTool` answers `true` for every
  // string including the empty one.
  if (entry?.tools !== undefined && (typeof scopedTool !== "string" || scopedTool.length === 0)) {
    throw new Error(
      `governStep: hookmap entry for hook "${hookEventName}" declares a "tools" list, so this gate governs some ` +
        `tools and not others -- and this call named no scoped tool (scopedTool is ${JSON.stringify(scopedTool)}). ` +
        `Pass the tool the caller already checked as "scopedTool". Deriving a second name from the payload is ` +
        `what let a hookmap pointing "tool_name" at another field skip a governed step as "ungoverned", with no ` +
        `Guardian request and no decision -- and the audit entry that skip now writes would name the wrong tool`,
    );
  }

  // The `tools` skip, on the tool this caller was told to scope on and on no
  // other source. Reached only when the caller told (the guard above refuses
  // every other way to reach a gate that declares a list), so this is the
  // shim's own answer asked a second time about the same value, not a second
  // question about a second value.
  //
  // Both host shims run this same check themselves, one call earlier -- see
  // `governsTool`'s own doc comment for what each of the two call sites saves,
  // and for why both of them audit rather than only this one.
  //
  // The caller's word is final here, including when it is wrong: a told name
  // this list does not contain is skipped even where the payload's own
  // `tool_name` would have resolved to one it does. That is the cost of the
  // vocabulary being the caller's rather than this module's own -- see
  // `GovernStepInput.scopedTool` for why that trade is made anyway. Recording
  // the told name and the list side by side is what makes that cost readable
  // afterwards instead of leaving it to be reconstructed from an absence.
  if (scopedTool !== undefined && !governsTool(hookmap, hookEventName, scopedTool)) {
    auditUngovernedStep({ hookmap, hookEventName, tool: scopedTool, sessionId, audit });
    return { output: {}, decision: null, stage: "ungoverned" };
  }

  const timeoutMs = session.config?.timeout_config.default_ms ?? DEFAULT_TIMEOUT_MS;

  // Which kind of gate this hook is, read off the entry's own shape and never
  // off the event name -- the same rule `buildPayload` states for choosing a
  // payload shape, and for the same reason: an event name is a string a hookmap
  // author types, and branching on one would make a typo in it silently select
  // the wrong behaviour. An entry declaring `outputs` is a gate that sees what a
  // step produced, so a decision there is answered by replacing that output;
  // an entry declaring `arguments` is a gate that decides whether a step runs,
  // and has no output to replace.
  //
  // `?? undefined` because a hookmap is YAML: a key written with nothing after
  // it parses to null, which is a key present and unusable, not a key absent.
  const outputs = entry?.outputs ?? undefined;
  const outputLocation: HostOutputLocation | undefined = outputs === undefined ? undefined : { payload, outputs };

  /**
   * Every render in this function, and the one thing every render at a result
   * gate has to do first: a decision that withholds the output there has to
   * carry a shape-preserving replacement of it (`withResultOutput`, which owns
   * the rule for which dispositions withhold).
   *
   * One function rather than a check at each route, because the withholdings
   * that can reach a render here arrive by different ones -- one the policy
   * runtime sent, one `validateDecision` substituted for a rewrite it could not
   * apply, one a negotiated fail-closed posture produced, and an ask or an
   * unexpired defer that this kind of gate cannot put to anyone -- and every one
   * of them is a withholding. A route that rendered a block without a
   * replacement would report a withholding that never happened while the
   * original output was delivered, and it would be the same defect whichever
   * route reached it.
   */
  function render(decision: AcsDecision): HostOutput {
    return renderDecision(hookEventName, withResultOutput(decision, outputLocation), hookmap);
  }

  /**
   * `applyFailurePosture`'s answer to a failure, rendered. Every stage's catch
   * ends here and nowhere else, which is what makes "no decision without an
   * audit entry" a property of the control flow rather than of remembering to
   * write one.
   *
   * Named for the posture because that is what answers almost every failure
   * that reaches it, and the one exception is deliberately not this function's
   * business: a Guardian that refused the envelope fails closed regardless of
   * posture, decided inside `applyFailurePosture`, so nothing here branches on
   * it and nothing here can forget to.
   *
   * The rendering here cannot fail: `loadHookmap` does not merely check that
   * `allow` and `deny` are present in every hook's `decisions` block, it
   * shape-checks every entry it accepts (`assertRenderableDecisions`), and
   * `applyFailurePosture` never returns any decision but those two -- and the
   * guard at the top of `governStep` has already established that this hook has
   * a block at all. So this cannot recurse into itself, and a throw escaping it
   * means the hookmap bypassed the loader -- which is the caller's problem to
   * fail loudly on, not something to paper over.
   *
   * There is one way this can throw beyond the rendering itself: a negotiated
   * fail-closed `deny` at a result gate has to withhold the output, and building
   * the replacement that withholds it can fail (see `replacingOutput`). Exactly
   * one route reaches that, and it is the one route where a posture is consulted
   * before `assertOutputIsReplaceable` has run: a stage-"request" failure, i.e. a
   * payload that does not carry what this hook's `outputs` block describes at
   * all. That is a posture deny this host cannot carry out, and the honest
   * answers are a loud stop or a block that withholds nothing while claiming to.
   * It throws, and the caller turns that into a blocking stop. Every other route
   * -- a leaf that is present and is not prose above all -- is refused before a
   * decision is sought rather than answered here, because there it would be
   * answering with a posture something a decision had already answered.
   *
   * `method` is the ACS method or null, never the host's own event name: an
   * envelope that could not be built has no ACS method to report, and the audit
   * log is read by consumers that know only ACS. Putting a host event name here
   * made `bun run inspector` -- whose whole claim is that it names no host --
   * print one at runtime.
   */
  function resolveByPosture(
    failure: unknown,
    stage: FailureStage,
    envelope: AcsRequestEnvelope | undefined,
  ): GovernedStep {
    const decision = applyFailurePosture({
      failure,
      session,
      sessionId,
      method: envelope?.method ?? null,
      rpcId: envelope?.id ?? null,
      audit,
      stage,
    });
    return { output: render(decision), decision, stage };
  }

  const startedAt = performance.now();

  // Stage "request": nothing has been asked of anything yet. A payload the
  // hookmap's paths do not resolve against, or an entry naming no single payload
  // shape, is a host-side configuration fault -- so the audit reasoning must not
  // blame a Guardian that was never contacted, which is what this stage records.
  //
  // A hookmap with no entry for this event never reaches this stage: the guard
  // at the top of this function throws on it and audits nothing, because the
  // posture's answer to it could not be rendered either. Every other way
  // `buildEnvelope` can fail still lands here.
  let envelope: AcsRequestEnvelope;
  try {
    envelope = buildEnvelope(hookEventName, payload, hookmap);
  } catch (failure) {
    return resolveByPosture(failure, "request", undefined);
  }

  // Established here, before anything is asked of a Guardian or audited: at a
  // gate that sees what a step produced, a decision has to be able to
  // replace that output, and building the replacement (`withResultOutput`)
  // can fail -- a payload whose named leaf is not prose is a leaf no
  // replacement can be expressed for at all.
  //
  // Asked at render time instead, that failure would arrive with a decision
  // already in hand and land in the render stage's catch, so the
  // deployment's delivery posture would answer it: under `proceed` the full
  // unredacted output would be delivered, the Guardian's `deny` dropped, and
  // the audit entry would say the decision was honoured. Asked here there is
  // no decision yet to drop and no record to falsify: the hookmap either can
  // express a withholding for this payload, or this deployment stops.
  //
  // It is a throw rather than a posture question, for the same reason the
  // guard at the top of this function is one: a hookmap whose declared
  // output this host cannot replace is a broken deployment, the same class
  // as a hookmap that will not load. What stays a posture question is the
  // other failure -- `buildEnvelope` failing above, because the payload not
  // matching the hookmap's `outputs` block can happen legitimately when one
  // hook fires for several tools and only one of them has the mismatch, so
  // it is scoped to that tool's calls rather than to the whole deployment's
  // configuration.
  //
  // A payload with no matching leaf at all leaves the gate with no ACS
  // request built either, so there is a genuine posture question to answer
  // and answering it drops no decision. A leaf that is present but cannot be
  // patched leaves the gate able to ask and unable to act on whatever answer
  // it gets back, and no posture makes it patchable -- the only choices are
  // stopping before asking, or asking and then dropping what comes back. It
  // stops, deliberately over-blocking on the safe side even for a step that
  // would have been allowed, because the alternative is a policy decision
  // arriving and being discarded.
  if (outputLocation !== undefined) {
    try {
      assertOutputIsReplaceable(outputLocation);
    } catch (failure) {
      throw new Error(
        `governStep: hook "${hookEventName}" is a gate whose output an arriving decision has to be able to ` +
          `replace, and no replacement can be built for the output its hookmap entry names: ` +
          `${failure instanceof Error ? failure.message : String(failure)}`,
      );
    }
  }

  // Stage "delivery": a request exists and no decision is in hand yet. §6.4's
  // own case, and everything between those two points belongs to it -- the
  // round trip, and the host's last word on what came back. `requestDecision`
  // never throws, so the `if` below (not a catch) is the delivery failure this
  // stage exists for; the `try` covers the rest, which cannot throw today and
  // would still be a request that produced no decision if it ever did.
  let decision: ValidatedAcsDecision;
  try {
    // The same document that just went out on the wire -- so a `modify`
    // decision's §6.3 pointers apply against exactly the structure the Guardian
    // saw and addressed. At a gate that decides whether a step runs that is the
    // arguments bag, unwrapped from ACS's `{value, provenance?}` shape; at a gate
    // that sees what a step produced it is the result payload, because that is
    // what a result-gate pointer names (`/outputs/0/value` addresses no argument,
    // and there are no arguments at that step). `modificationDocumentOf` reads which
    // from the envelope it just built.
    const modificationDocument = modificationDocumentOf(envelope);

    const answer = await guardian.requestDecision(envelope, { timeoutMs });
    const elapsedMs = performance.now() - startedAt;

    if (answer.decisionArrived === false) {
      return resolveByPosture(answer.failure, "delivery", envelope);
    }

    // A decision arrived, so no posture may touch this step's outcome.
    // `validateDecision` is the host's own last word on it -- §6.3's
    // rewrite, and any expired ask/defer outcome -- and it substitutes only
    // decisions, never failures.
    decision = validateDecision(answer.decision, { elapsedMs, modificationDocument, outputLocation });
  } catch (failure) {
    return resolveByPosture(failure, "delivery", envelope);
  }

  // Stage "render": a decision is in hand and has been honoured in principle;
  // the only thing that can still fail is this host expressing it (a decision
  // string no hookmap entry names, or a gap in the entry that does). That is as
  // undeliverable as a timeout and gets the same posture -- but it is a
  // different incident, and auditing it as "no decision arrived" would send an
  // incident reviewer to a Guardian that answered correctly.
  try {
    return { output: render(decision), decision, stage: "honoured" };
  } catch (failure) {
    return resolveByPosture(failure, "render", envelope);
  }
}
