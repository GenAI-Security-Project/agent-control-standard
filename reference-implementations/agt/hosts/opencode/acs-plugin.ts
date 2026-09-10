/**
 * acs-plugin.ts -- OpenCode's ACS plugin shim against packages/host-adapter,
 * the same package the Claude Code shim uses. Nothing here forks the adapter
 * for this host: whatever this host needed landed in host-adapter/src, which
 * both hosts run, and hosts/claude-code/acs-hook.ts is untouched by this
 * file's existence.
 *
 * This is not hosts/claude-code/acs-hook.ts with a different name. Claude
 * Code's shim is a fresh subprocess per hook: it reads one JSON object on
 * stdin, calls resolveSessionConfig then governStep, and writes the rendered
 * HostOutput to stdout with an exit code. OpenCode is a different shape of
 * host entirely -- one plugin object, loaded once, whose hook methods return
 * void and are handed live, mutable objects (`{args}` at the request gate,
 * `{title, output, metadata, attachments}` at the result gate). There is no
 * document to write and no exit code to set: the only channel back to
 * OpenCode is mutating what it handed us, or throwing. So the same rendered
 * `HostOutput`, from the same `governStep` -> `renderDecision`, is applied
 * here instead of printed, and applying it is the one piece of host semantics
 * this file owns (`applyOpenCodeOutput`, apply-opencode-output.ts).
 *
 * Four things every gate must do at runtime, none of them knowable until a
 * hook actually fires, so none of them is a load-time check. `runExchange`
 * (below) is the single function both hook methods call, so all four happen
 * in one place rather than in two hook bodies kept in step by hand:
 *
 *   - Validate `sessionID` -- present, a non-empty string -- and refuse
 *     before calling `governStep`. `buildEnvelope` already throws on a
 *     missing `session_id`, but that throw lands inside `governStep`'s
 *     stage-"request" catch and is answered by the deployment's negotiated
 *     posture, where a negotiated proceed there would be an ungoverned step.
 *     A missing session id is a broken deployment, not a policy question, so
 *     it is refused here instead. Only the typeof half of the check: the
 *     Claude Code shim's own session id check adds a second, path-safety
 *     half, because its session config store is file-backed and the session
 *     id becomes part of a filesystem path. This host's store (in memory,
 *     see below) is keyed by nothing that ever becomes a filename, so there
 *     is no path-safety hazard here to close.
 *   - Use a throw as the only failure mechanism. OpenCode's hooks return
 *     `void` and have no other channel to report a failure through -- the
 *     same mechanism `applyOpenCodeOutput`'s own `refuse` path uses.
 *   - Know that a throw at the result gate is weaker than one at the request
 *     gate. `opencode.hookmap.yaml`'s own header records the measurement: a
 *     throw at `tool.execute.after` stops the model from ever seeing the
 *     tool's output, but OpenCode discards the plugin's mutations on that
 *     path and rebuilds `metadata` from its own pre-hook copy, so whatever
 *     the tool actually produced survives in OpenCode's own session record
 *     regardless of how early the throw fires. That is why the shipped
 *     hookmap's result-gate `deny`/`modify` withhold by replacing `result`
 *     (`applyOpenCodeOutput`'s merge) rather than by throwing. A sessionID
 *     check that refuses at the result gate is still the right call -- an
 *     ungoverned step is worse than a stop that does not scrub the disk --
 *     but a throw there does not mean the secret is contained the way it
 *     would at the request gate.
 *   - Assemble `session_id: input.sessionID` onto the payload raw, not
 *     pre-converted. `buildEnvelope` reads `payload.session_id` as a
 *     hardcoded top-level field and derives the ACS uuid itself; the uuid
 *     form (`toSessionUuid(input.sessionID)`) is for a different call --
 *     `resolveSessionConfig` takes the uuid, `governStep` takes the raw host
 *     id for the audit log entry. Mixing the two is the bug this note exists
 *     to prevent.
 *
 * A gate also trusts, rather than re-checks, that a decision which must
 * refuse, withhold or rewrite has somewhere to do it: `assertHostAcceptsEveryDecision`
 * (below), called at load time from `AcsPlugin`, refuses a hookmap unless
 * every declared decision at every gate can either land what it arrives
 * carrying or refuse outright -- the silent no-op is the only outcome that is
 * never accepted. See `satisfiesGate` and `CARRIED_AT_REQUEST_GATE`/
 * `CARRIED_AT_RESULT_GATE` (below) for exactly what each decision may do at
 * each gate.
 *
 * And one load-time check is about this file rather than about a hookmap.
 * OpenCode dispatches to a plugin by reading hook names as OBJECT KEYS off
 * whatever this factory returns, skipping any it does not find -- so a key
 * that stops matching the name OpenCode fires disables that gate in total
 * silence, with no throw, no exit code and no audit entry.
 * `assertRegistrationMatchesIntent` (below) refuses at load unless the keys
 * actually registered are exactly the hooks `HOOK_EXPECTATIONS` knows. It
 * cannot see an upstream rename -- nothing inside this repository can, since
 * the plugin API publishes no registry of event names to check against --
 * and that limit is stated at the function rather than left for a reader to
 * discover.
 *
 * And a gate honours `tools` before any of that, except validating `tool`
 * itself: a hookmap entry that declares a `tools` list must return, without
 * building a payload or calling `resolveSessionConfig`/`governStep`, for any
 * tool that list does not name (`governsTool`, imported from the adapter). A
 * gate with no `tools` check would not govern every tool it is asked about;
 * it would deny every tool its deployment's policy target cannot name, and
 * call that governance. `tool` itself is validated first, ahead of the
 * `tools` check, because `Array.prototype.includes` does not throw on a
 * malformed `tool` -- it silently answers `false`, which reads as "out of
 * scope" rather than as the broken deployment it actually is.
 *
 * The store is in memory. The Claude Code shim is a fresh subprocess per
 * hook, so its session config store is file-backed
 * (`createFileSessionConfigStore`). This plugin is one long-lived object for
 * the whole session -- OpenCode calls the plugin factory once, and every hook
 * after that fires against the closure this factory returns -- so the
 * negotiated config survives in a variable and the second hook of a session
 * skips the handshake round trip entirely. One interface
 * (`SessionConfigStore`), two implementations, and `resolveSessionConfig`/
 * `governStep` never learn which host they are running under.
 *
 * This file may name OpenCode freely -- it is host-specific by definition --
 * but it may only reach into host-adapter's public surface, never into
 * agt-bridge or guardian's server-side pieces, and it talks to the Guardian
 * only over HTTP through `createGuardianClient`. `test/invariants.test.ts`'s
 * "every host shim imports the adapter only" gate checks this mechanically,
 * against this file by name.
 */
import { fileURLToPath } from "node:url";
import type { Hooks, Plugin } from "@opencode-ai/plugin";
import {
  // The record a skip leaves. Called from `runExchange`'s own `governsTool`
  // check, because that check returns before `governStep` -- so without this
  // call the one host whose gates declare `tools` would be the one host that
  // never files the entry.
  auditUngovernedStep,
  createAuditSink,
  createGuardianClient,
  createMemorySessionConfigStore,
  DEFAULT_TIMEOUT_MS,
  governStep,
  // The `tools` rule, as the adapter states it. Called from `runExchange`
  // (below), the same call site early enough to skip payload assembly and
  // the handshake for a tool this gate does not govern -- `governStep` also
  // asks this same function, about the value this call site passes it
  // (`scopedTool`), so a shim that forgot to call it here would still skip,
  // and would still audit.
  governsTool,
  loadHookmap,
  resolveSessionConfig,
  toSessionUuid,
  // `AuditSink`/`GuardianClient`/`SessionConfigStore` -- the three
  // collaborators `AcsPlugin`'s factory builds once and hands `runExchange`
  // on every call (`Deployment`, below). Named by the adapter's own published
  // types rather than by `ReturnType<typeof create...>`: what `runExchange`
  // depends on is the interfaces, which is why the in-memory and file-backed
  // session config stores are interchangeable at all.
  type AuditSink,
  type GuardianClient,
  type Hookmap,
  type SessionConfigStore,
} from "host-adapter";
// applyOpenCodeOutput, and every private helper it alone needs, lives in
// apply-opencode-output.ts -- see that file's own header for why exporting it
// from this module would be a hazard rather than a convenience, and
// test/invariants.test.ts for the gate that keeps this file's export surface
// to exactly one symbol.
import { applyOpenCodeOutput, type LiveHookObjects } from "./apply-opencode-output.ts";

// Matches packages/guardian/src/main.ts's own default port, and
// hosts/claude-code/acs-hook.ts's identical constant -- the runbook and both
// shims agree on 8787 without any of the three hardcoding another's value.
const DEFAULT_GUARDIAN_URL = "http://localhost:8787/acs";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
/**
 * The rule this whole gate is about, stated once as a table instead of as a
 * list of accepted shapes: a declared decision must be able to land what it
 * actually arrives carrying at this gate, or to unconditionally refuse. The
 * silent no-op is the only outcome that is never accepted.
 *
 * Which makes the whole gate one question asked twice: what does this
 * decision arrive carrying here? These two tables answer it, and nothing
 * below decides it ad hoc.
 *
 *   - A decision field name means: it arrives carrying that field, so it may
 *     land it (a correctly-declared sink) or refuse.
 *   - `null` means: it arrives carrying nothing this host could land, so
 *     refusing is the only honest shape open to it.
 *   - Absent from the table means: not this check's business. `allow` is the
 *     only such decision, at either gate, and deliberately -- rendering
 *     nothing IS its own meaning ("nothing to change" / "deliver the output
 *     as the tool produced it"), the same distinction `acs-hook.ts`'s
 *     `emptyOutputIsHonest` draws between the Claude Code shim's two gates.
 *
 * A list of accepted shapes, rather than a statement of what each decision
 * carries, is the wrong basis for this rule: a rule widening the result
 * gate to require a sink for `ask`/`defer` reached this gate before anyone
 * asked whether that sink can ever be filled for them. It cannot --
 * `withResultOutput` (result-output.ts) attaches `applied_output` for `deny`
 * alone, throws for a `modify` arriving without one, and returns everything
 * else -- `allow`, `ask`, `defer` -- untouched. So `result: { from:
 * applied_output }` on a result-gate `ask`, the exact declaration such a
 * rule would require, renders no `result` key at all: the applier applies
 * nothing, throws nothing, and the secret is delivered in the leaf and its
 * mirror both (result-gate.test.ts). A table that states what each decision
 * carries makes that unwritable; a list of shapes did not.
 */
type DecisionCarries = ReadonlyMap<string, string | null>;

/**
 * The decisions this gate asks nothing of, and the only ones it may leave
 * unasked -- named as a set rather than left implicit, since an implicit
 * version would silently cover every decision name the tables happened not
 * to list.
 *
 * `allow` is the whole set, at both gates. Rendering nothing IS its own
 * meaning there ("nothing to change" at the request gate, "deliver the
 * output as the tool produced it" at the result gate) -- the same
 * distinction `acs-hook.ts`'s `emptyOutputIsHonest` draws between the Claude
 * Code shim's two gates. Anything else a hookmap declares is either in a
 * `CARRIED_AT_*` table or refused.
 */
const ALWAYS_HONEST_DECISIONS: ReadonlySet<string> = new Set(["allow"]);

/**
 * The request gate (`tool.execute.before`), where the live half is `args`.
 *
 * `deny`/`ask`/`defer` carry nothing to land: the step has not run, there is
 * no output to replace, and none of the three carries an `applied_input`.
 * Refusing is the only honest shape, and a `from:`-only `refuse` block is
 * not one -- a `from:` field renders nothing when its source is absent or
 * the wrong type (render-decision.ts), so an entry built only from `from:`
 * fields can render `{}` on a Guardian's minimal or malformed decision
 * message: this applier sees no keys at all, applies nothing, throws
 * nothing, and the tool proceeds, indistinguishable from a clean allow.
 *
 * `modify` does carry something here -- `applied_input`, guaranteed
 * non-empty by `resolveModify` (decision-modify.ts) or already converted to
 * a `deny` -- so it may land it or refuse. That guarantee is about the
 * decision message and says nothing about the hookmap declaring a path for
 * it: a `modify` declaring only `reason.text` renders `{}`, the tool runs
 * unrewritten, and `governStep` still reports `stage: "honoured"` -- so the
 * audit trail would record the rewrite as honoured rather than as never
 * landed.
 */
const CARRIED_AT_REQUEST_GATE: DecisionCarries = new Map([
  ["deny", null],
  ["ask", null],
  ["defer", null],
  ["modify", "applied_input"],
]);

/**
 * The result gate (`tool.execute.after`), where the live half is `result`.
 *
 * Every decision that withholds here carries `applied_output` -- the whole
 * patched clone of the object at `outputs.within`, leaf and mirror both
 * replaced. `withResultOutput` attaches one for each of them; `modify` must
 * already have its own or that function throws, because a modify's
 * replacement is `resolveModify`'s and never this layer's. Any of them may
 * land it or refuse.
 *
 * `ask` and `defer` are in that set, not exempt from it. At a gate where the
 * step has already run there is no permission left to grant and no pending
 * state to hold, so what survives of both is "this output is not deliverable
 * as it stands" -- a withholding, and the adapter's `withholdsAtResultGate`
 * is the single statement of that rule. They previously carried nothing,
 * which forced them onto the refusal branch and, when a hookmap declared a
 * result sink for them anyway, was measured delivering the secret in the
 * leaf and its mirror both.
 */
const CARRIED_AT_RESULT_GATE: DecisionCarries = new Map([
  ["deny", "applied_output"],
  ["modify", "applied_output"],
  ["ask", "applied_output"],
  ["defer", "applied_output"],
]);

/** One decision's declared `output` block, as this gate reads it off a loaded
 * hookmap, or `undefined` when there is nothing here to check.
 *
 * `undefined` covers two cases this gate deliberately does not report on: a
 * decision the hookmap never declares (`ask`/`defer`/`modify` are optional --
 * `loadHookmap`'s own `assertRenderableDecisions` requires only `allow` and
 * `deny`), and a present-but-malformed entry, which that same function has
 * already refused with a better message than anything here could give. */
function declaredOutputFor(decisions: unknown, decisionName: string): Record<string, unknown> | undefined {
  const rule = isPlainObject(decisions) ? decisions[decisionName] : undefined;
  const output = isPlainObject(rule) ? (rule as { output?: unknown }).output : undefined;
  return isPlainObject(output) ? output : undefined;
}

/**
 * Whether `output` declares the merge sink `sinkKey`, sourced from
 * `sourceField` -- the shared predicate behind both of this file's "can this
 * decision actually land what it arrived carrying" rules (the result gate's
 * `result`/`applied_output`, and the request gate's `modify`
 * `args`/`applied_input`).
 *
 * All four conditions below are load-bearing:
 *
 *   - The exact key, not a path leading with it. `applyOpenCodeOutput`
 *     merges the rendered value at this key onto the live object; a path
 *     naming something under it (`result.output`, `args.command`) renders a
 *     nested object, which the applier merges one level too deep -- landing
 *     the whole container in a field that holds a leaf, and leaving the
 *     mirror unwritten.
 *   - The source field, not merely that some source is named. A `from:`
 *     field renders nothing when the arriving decision does not carry that
 *     source (render-decision.ts), so `result: { from: applied_input }`
 *     declares the right key against a field a result-gate decision never
 *     carries: it renders no `result` key at all, the applier applies
 *     nothing and throws nothing, and the tool's output is delivered in the
 *     leaf and its mirror both.
 *   - No `type:`, or `type: "object"`. `type` is a `typeof` filter, and
 *     `renderDecision` drops a `from:` field whose carried value fails it --
 *     the same skip an absent source takes. `applied_output` and
 *     `applied_input` are both objects, so `type: string` never matches and
 *     the field never renders.
 *   - No `value:` key, even beside a correct `from:`. `renderDecision`
 *     checks for an own `value` property first and stops there -- it never
 *     reads `from` at all, so `result: { value: {}, from: applied_output }`
 *     renders `{"result":{}}`, which the applier merges, merging nothing.
 *
 * A literal at the sink is refused for a reason worth keeping: a hookmap
 * could land something that way, but not the decision's own withholding or
 * rewrite -- it would be a fixed value the Guardian never chose, applied
 * identically to every decision, which is a hardcoded answer wearing
 * governance's clothes. The only thing that honours an arriving decision
 * here is that decision's own field, rendered.
 */
function declaresSinkFrom(output: Record<string, unknown>, sinkKey: string, sourceField: string): boolean {
  if (!Object.prototype.hasOwnProperty.call(output, sinkKey)) {
    return false;
  }
  const sink = output[sinkKey];
  if (!isPlainObject(sink)) {
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(sink, "value")) {
    return false;
  }
  if (sink.type !== undefined && sink.type !== "object") {
    return false;
  }
  return sink.from === sourceField;
}

/**
 * Whether `output` declares an unconditional refusal -- at least one path
 * whose leading segment is `refuse` carrying a literal `{value: ...}`.
 *
 * The leading segment, not the exact key: the marker legitimately sits
 * beside `refuse.reason` under a shared `refuse` container, and it is the
 * container the applier reads and throws on, so anything unconditional
 * inside it is enough to guarantee the container exists. See
 * `satisfiesGate` (below) for how this combines with `declaresSinkFrom` to
 * decide whether a decision may honestly do nothing here.
 */
function declaresUnconditionalRefusal(output: Record<string, unknown>): boolean {
  return Object.entries(output).some(([outputPath, field]) => {
    const leadingSegment = outputPath.split(".")[0];
    return leadingSegment === "refuse" && isPlainObject(field) && Object.prototype.hasOwnProperty.call(field, "value");
  });
}

/**
 * The rule this whole gate is about: a decision passes if it can land what
 * it arrived carrying, or if it can unconditionally refuse. The silent
 * no-op is the only outcome that is never accepted.
 *
 * Both alternatives are honest. Landing is what the shipped hookmap does.
 * Refusing is a deliberately more conservative choice an author may prefer,
 * and it is this file's own idiom -- `opencode.hookmap.yaml` maps `ask` and
 * `defer` to `refuse.denied` at the request gate precisely because this host
 * has no native "ask". A gate that refused an author for applying that same
 * idiom one gate over would be contradicting the file it ships beside.
 *
 * The alternative matters more on this host than it would on the Claude
 * Code shim. Over-refusal is not a free direction to err in here: a throw
 * out of `AcsPlugin`'s factory does not stop the session the way the Claude
 * Code shim's exit 2 stops a tool call. OpenCode catches it, logs it, and
 * continues the session with the plugin unloaded, so every tool call for
 * the rest of that session runs completely ungoverned. Between "an author's
 * conservative mapping this gate did not anticipate" and "no governance at
 * all", the first is strictly better, and the gate has to be written
 * knowing that.
 *
 * What a refusal costs at the result gate, said plainly. It is a weaker
 * withholding than replacing: `applyOpenCodeOutput` throws and the model
 * never sees the tool's output, but OpenCode discards this plugin's
 * mutations on that path and rebuilds `metadata` from its own pre-hook
 * copy, so the plaintext survives in OpenCode's own session record. Weaker,
 * and still honest, and still far better than the alternative this gate
 * would otherwise force -- a hookmap that never registers and a session
 * that governs nothing.
 *
 * `allow` is asked neither question, at either gate: rendering nothing IS
 * its own meaning there.
 */
function satisfiesGate(output: Record<string, unknown>, sinkKey: string, sourceField: string): boolean {
  return declaresSinkFrom(output, sinkKey, sourceField) || declaresUnconditionalRefusal(output);
}

/**
 * How `declaresSinkFrom` just failed, in words, for the two messages below --
 * the two failures need different fixes, so a single "declares no X" would
 * misdescribe one of them.
 *
 * Absent lists the paths the decision does declare, which is what makes the
 * near-miss legible: a `deny` whose output block reads `["result.output",
 * "reason.text"]` looks, to the author who wrote it, exactly like it
 * declares the sink. Wrong source prints the declared field object
 * verbatim, so `{"from":"applied_input"}` is visible beside the
 * `applied_output` it should have named rather than being described in
 * prose.
 */
function sinkFaultPhrase(output: Record<string, unknown>, sinkKey: string, sourceField: string): string {
  if (!Object.prototype.hasOwnProperty.call(output, sinkKey)) {
    return (
      `declares no ${JSON.stringify(sinkKey)} output field at all (its output block declares ` +
      `${JSON.stringify(Object.keys(output))}), and no unconditional "value:" field under "refuse" either`
    );
  }
  const sink = output[sinkKey];
  const declared = `declares ${JSON.stringify(sinkKey)} as ${JSON.stringify(sink)}, which `;
  // Which of the three render faults it is -- they need three different
  // one-character fixes, and "does not source it from X" would misdescribe
  // two of them.
  if (isPlainObject(sink) && Object.prototype.hasOwnProperty.call(sink, "value")) {
    return (
      `${declared}renders that LITERAL and never reads "from" at all -- renderDecision checks for a "value" key ` +
      `first and stops there (render-decision.ts), so the decision's own ${JSON.stringify(sourceField)} is never ` +
      `read`
    );
  }
  if (isPlainObject(sink) && sink.type !== undefined && sink.type !== "object") {
    return (
      `${declared}declares a "type" of ${JSON.stringify(sink.type)} -- "type" is a typeof filter and ` +
      `${JSON.stringify(sourceField)} is an OBJECT, so renderDecision drops this field every time ` +
      `(render-decision.ts). Only an absent "type", or "object", can match`
    );
  }
  return `${declared}does not source it from ${JSON.stringify(sourceField)}`;
}

/**
 * What this shim expects of ONE hook -- the same role `HOOK_EXPECTATIONS`
 * plays in hosts/claude-code/acs-hook.ts, for host #2's own two gates.
 *
 * A table rather than one rule, for the same reason host #1 needs one: this
 * host's two gates are not symmetric, and neither gate's rule is the other's.
 * A request-gate decision that cannot refuse lets a step RUN; a result-gate
 * decision that cannot withhold DELIVERS what a step produced. Different key,
 * different failure, same class.
 */
type HookExpectation = {
  /**
   * Throws unless this hook's entry can honour every decision it declares --
   * each of them either landing what it arrives carrying here or refusing
   * outright, per this gate's own `CARRIED_AT_*` table.
   *
   * Takes the whole entry, not just its `decisions` block: whether a
   * decision can land anything depends on the entry too, not only on the
   * decision's own output block. A `tool.execute.after` entry declaring no
   * `outputs:` makes `governStep` build no output location, which makes
   * `withResultOutput` a no-op for every decision -- so the sink this gate
   * demands is unfillable no matter how correctly it is declared. A
   * signature that saw only `decisions` could not ask that question.
   */
  assertEntry: (entry: unknown, path: string, hookEventName: string) => void;
};

/**
 * Applies this gate's own `CARRIED_AT_*` table to one entry's decisions --
 * the single place the invariant is enforced, for both gates.
 *
 * One loop, one question per decision: what does it arrive carrying here?
 *
 *   - `null` -- nothing this host could land, so an unconditional refusal is
 *     the only honest shape and the only one accepted.
 *   - a field name -- it may land that field through `sinkKey`, or refuse.
 *
 * A decision the hookmap does not declare is skipped (`declaredOutputFor`
 * returns `undefined`). A decision the table does not name is refused, not
 * skipped -- see the loop's own comment below: `allow` is the only decision
 * the tables omit deliberately, and `ALWAYS_HONEST_DECISIONS` names that
 * set, so everything outside it throws rather than passing unchecked.
 *
 * The two messages are built by the caller, because what a silent no-op
 * costs differs by gate: at the request gate the tool runs ungoverned; at
 * the result gate the tool's output, secret included, is delivered in the
 * leaf and its mirror both.
 */
function assertDecisionsCanAct(
  decisions: unknown,
  carried: DecisionCarries,
  sinkKey: string,
  path: string,
  hookEventName: string,
  onCannotRefuse: (decisionName: string, output: Record<string, unknown>) => Error,
  onCannotLand: (decisionName: string, output: Record<string, unknown>, sourceField: string) => Error,
): void {
  // A declared decision this gate has no answer for is a throw, not a skip
  // -- the same rule `expectationFor` states for an unknown hook, applied
  // one level down. The loop below iterates the table, so a hookmap
  // declaring `decisions.block` (or `Deny`, or `warn`) is never asked
  // anything by it: without this check it would load clean, and a Guardian
  // answering with that string would render whatever the entry declares
  // while the applier applies nothing and throws nothing.
  //
  // That is worse than not declaring it at all: the same hookmap without
  // the entry makes `renderDecision` throw `no decisions entry for ACS
  // decision "block"`, which `governStep` catches and the deployment's
  // posture answers -- audited either way. Declaring an inert entry would
  // convert an audited failure into a silent one.
  //
  // Reaching it needs a non-conformant Guardian, so this ranks below the
  // faults a conformant one reaches. It is still the same class, and the
  // throw costs nothing a correct hookmap would ever pay.
  const answerable = new Set([...carried.keys(), ...ALWAYS_HONEST_DECISIONS]);
  for (const declaredName of Object.keys(isPlainObject(decisions) ? decisions : {})) {
    if (!answerable.has(declaredName)) {
      throw new Error(
        `acs-plugin: ${path}'s "hooks.${hookEventName}.decisions" declares ${JSON.stringify(declaredName)}, ` +
          `which this shim has no expectation for at this gate -- it knows ${JSON.stringify([...answerable])} ` +
          `here and nothing else. A decision name nothing checks is a decision nothing governs: if a Guardian ` +
          `ever answered with it, this entry would render whatever it declares and this host's applier would ` +
          `apply nothing and throw nothing, silently. Declaring it is strictly WORSE than leaving it out -- ` +
          `without the entry renderDecision throws, governStep catches that, and the deployment's posture ` +
          `answers it, audited either way. Remove it, or teach this shim the decision (CARRIED_AT_REQUEST_GATE ` +
          `/ CARRIED_AT_RESULT_GATE, this file) so it can say what the decision may honestly do here.`,
      );
    }
  }
  for (const [decisionName, sourceField] of carried) {
    const output = declaredOutputFor(decisions, decisionName);
    if (output === undefined) {
      continue;
    }
    if (sourceField === null) {
      if (!declaresUnconditionalRefusal(output)) {
        throw onCannotRefuse(decisionName, output);
      }
      continue;
    }
    if (!satisfiesGate(output, sinkKey, sourceField)) {
      throw onCannotLand(decisionName, output, sourceField);
    }
  }
}

/**
 * What this shim's own payload assembly fixes about an entry, per gate -- the
 * second half of "what does this decision arrive carrying here", the half
 * that is a property of the entry rather than of any decision.
 *
 * `AcsPlugin`'s two hook methods assemble the payload themselves and
 * construct a hardcoded live half for the applier (handed to `runExchange`,
 * below, which makes the one `applyOpenCodeOutput` call). That makes two
 * things facts about the shim rather than choices left to a hookmap -- and a
 * hookmap disagreeing with either produces an entry that satisfies every
 * other check here while governing nothing:
 *
 *   - Which payload shape this hook builds. `governStep` and `buildEnvelope`
 *     read that off the entry's shape (`arguments` vs `outputs`) and never
 *     off the event name, deliberately, so a typo in an event name cannot
 *     silently select the wrong behaviour. This shim decides the same
 *     question by hook name, because its two hook methods hardcode
 *     `{gate: "request", args}` and `{gate: "result", result}`. When the two
 *     disagree, the decision that arrives is shaped for the other gate -- a
 *     request hook declaring `outputs:` gets an output location it should
 *     not have, so `resolveModify` (decision-modify.ts) fills
 *     `applied_output` instead of `applied_input`, and the
 *     `args: { from: applied_input }` this gate requires becomes correct,
 *     declared, and unfillable: the rewrite lands nowhere while `governStep`
 *     still reports `stage: "honoured"`.
 *   - Which paths resolve against what this shim assembled. `tool_name` must
 *     name `$.tool`, because that is the field this shim's own payload
 *     assembly puts `input.tool` in, and `tool_name` is what `buildEnvelope`
 *     reads to name the tool on the wire -- pointing it elsewhere asks the
 *     policy runtime about a value it never governed (measured: a `deny`
 *     rule went unconsulted because the field actually evaluated was the
 *     tool's title, not its command, so the step was audited as a clean
 *     allow). `outputs.within` must name `$.result`, because that is where
 *     this shim puts the live object it hands the applier: an
 *     `applied_output` is a patched clone of that container, so naming
 *     another one lands the clone at a depth the applier then merges
 *     wrongly, leaving the mirror unwritten or merging junk keys onto
 *     OpenCode's own live object.
 *
 * `outputs.mirrors` is deliberately not fixed here, and the asymmetry with
 * `outputs.from`/`within` is the point rather than an oversight. Which
 * container the live object is, and which leaf inside it is the tool's
 * output, are both facts about the shape this shim assembles -- fixed, so
 * checked. Where that leaf is mirrored is not: `metadata` is per-tool on
 * this host (`bash`'s carries `exit`/`output`, `read`'s carries `preview`,
 * `grep`'s carries `matches` -- opencode.hookmap.yaml's own measurement
 * table), so a second deployment scoping this gate to a different tool
 * would name a different mirror, or none. Nothing here could say which is
 * right.
 *
 * That leaves two things genuinely open, worth stating rather than leaving
 * implicit. First, a hookmap that omits `mirrors` entirely is not refused,
 * and it leaks: a real `deny` withholds the leaf and leaves the secret
 * standing in the unmirrored field. This is not closed here, because the
 * same freedom that makes it possible is what lets a second deployment
 * declare the right mirror at all. Second, the bound on that leak rests on
 * this entry's own `tools: [bash]` scope, which `fixedPaths` above does not
 * pin: without it, a `read`-shaped result whose `metadata` carries no
 * `exit` makes `buildEnvelope` throw, which the deployment's negotiated
 * posture can answer with a proceed -- a delivered secret through a
 * hookmap this gate loaded cleanly, with the step never asked about at
 * all. Neither gap weakens `declaresSinkFrom`'s own checks; both are
 * properties of a differently-shaped hookmap this check does not, and
 * structurally cannot, rule out.
 *
 * `mirrors` is not what holds either of those shut, which matters before
 * touching either line: `replacingOutput` (result-output.ts) already
 * refuses to build a withholding when a declared mirror resolves to no
 * value in the payload, which is the guard that actually protects a
 * `mirrors`-scoped deployment. That guard runs over whatever mirrors a
 * hookmap declares, so a deployment that declares none simply never arms
 * it -- correctly, by its own design, since it was told there is no mirror
 * to check.
 *
 * The adapter cannot make any of these checks itself, and that is
 * deliberate on its side rather than an omission: every one rests on
 * knowing which hook name is which gate, and on what this shim's own
 * payload assembly named. Only a host shim has both.
 */
type GateEntryShape = {
  /** The payload-shape key this gate's entry must declare. */
  readonly declares: "arguments" | "outputs";
  /** The other one, which it must not declare -- see `declares`. */
  readonly notDeclares: "arguments" | "outputs";
  /** What a mis-shaped entry costs at this gate, for the message. */
  readonly mismatchCosts: string;
  /**
   * Dotted paths into the ENTRY whose value this shim's own payload assembly
   * fixes, and the value it fixes them to.
   */
  readonly fixedPaths: ReadonlyArray<readonly [string, string]>;
};

const REQUEST_GATE_ENTRY: GateEntryShape = {
  declares: "arguments",
  notDeclares: "outputs",
  mismatchCosts:
    "governStep would build this gate an output location off that shape, so resolveModify (decision-modify.ts) " +
    'fills "applied_output" instead of "applied_input" -- and the "args: { from: applied_input }" this gate ' +
    'requires would then be correct, declared and unfillable: the rewrite lands nowhere while governStep still ' +
    'reports stage "honoured"',
  fixedPaths: [
    ["tool_name", "$.tool"],
    ["arguments", "$.args"],
  ],
};

const RESULT_GATE_ENTRY: GateEntryShape = {
  declares: "outputs",
  notDeclares: "arguments",
  mismatchCosts:
    "governStep would build NO output location, so withResultOutput (result-output.ts) returns every decision " +
    'untouched -- "deny" included -- and a perfectly-declared "result: { from: applied_output }" renders ' +
    "nothing: the tool's own output, leaf and metadata.output mirror both, is delivered. It would also make " +
    "buildEnvelope ask the Guardian a tool-call-REQUEST question about a step that already ran",
  fixedPaths: [
    ["tool_name", "$.tool"],
    ["outputs.from", "$.result.output"],
    ["outputs.within", "$.result"],
  ],
};

/** Reads a dotted path out of a loaded hookmap entry, for `fixedPaths` above. */
function entryValueAt(entry: unknown, path: string): unknown {
  let cursor: unknown = entry;
  for (const segment of path.split(".")) {
    if (!isPlainObject(cursor)) {
      return undefined;
    }
    cursor = cursor[segment];
  }
  return cursor;
}

/**
 * Refuses an entry whose payload shape, or whose `$.` paths, disagree with what
 * this shim's own hook of that name actually does -- see `GateEntryShape`
 * above for each fault, what it was measured to cost, and why only a host shim
 * can make the check.
 */
function assertEntryMatchesGate(entry: unknown, path: string, hookEventName: string, shape: GateEntryShape): void {
  const declared = isPlainObject(entry) ? (entry as Record<string, unknown>)[shape.declares] : undefined;
  const wellDeclared =
    shape.declares === "outputs" ? isPlainObject(declared) : typeof declared === "string" && declared.length > 0;
  if (!wellDeclared) {
    throw new Error(
      `acs-plugin: ${path}'s "hooks.${hookEventName}" declares no usable "${shape.declares}" (it declares ` +
        `${JSON.stringify(declared)}). This shim's "${hookEventName}" hook is fixed: it assembles the payload ` +
        `itself and hands applyOpenCodeOutput a hardcoded live half, so an entry at this hook has to be the ` +
        `matching payload shape. Without it, ${shape.mismatchCosts}. Declare "${shape.declares}" on this hook.`,
    );
  }
  const forbidden = isPlainObject(entry) ? (entry as Record<string, unknown>)[shape.notDeclares] : undefined;
  if (forbidden !== undefined && forbidden !== null) {
    throw new Error(
      `acs-plugin: ${path}'s "hooks.${hookEventName}" declares "${shape.notDeclares}" ` +
        `(${JSON.stringify(forbidden)}) at a hook this shim treats as the "${shape.declares}" gate. governStep ` +
        `and buildEnvelope read a gate's KIND off the entry's shape and never off the event name -- ` +
        `deliberately, so an event-name typo cannot silently select the wrong behaviour -- while this shim ` +
        `decides it by hook NAME, because its two hook methods hardcode which live half the applier gets. When ` +
        `the two disagree, ${shape.mismatchCosts}. Remove "${shape.notDeclares}" from this hook.`,
    );
  }
  for (const [fixedPath, required] of shape.fixedPaths) {
    const actual = entryValueAt(entry, fixedPath);
    if (actual !== required) {
      throw new Error(
        `acs-plugin: ${path}'s "hooks.${hookEventName}.${fixedPath}" is ${JSON.stringify(actual)}, and this ` +
          `shim's own payload assembly fixes it at ${JSON.stringify(required)}. That payload is built in this ` +
          `file, not by the hookmap. "$.tool" is where "tool_name" has to look, because that is the field this ` +
          `shim puts input.tool in and "tool_name" is what buildEnvelope reads to NAME THE TOOL ON THE WIRE: ` +
          `measured with "tool_name: $.args.command", the step was governed and audited normally while the ` +
          `envelope carried payload.tool.name "rm -rf /" -- the command, not the tool -- so the policy runtime ` +
          `was asked about a tool this deployment never registered. "$.args"/"$.result" are where ` +
          `this shim puts the live objects it hands applyOpenCodeOutput -- an "applied_output" is a patched ` +
          `clone OF the container "outputs.within" names, so naming another container lands that clone at the ` +
          `wrong depth: measured with "within: $", the leaf AND its metadata.output mirror both kept the ` +
          `plaintext while the payload's own top-level fields were merged onto OpenCode's live result object. ` +
          `And "outputs.from" is the leaf that goes ON THE WIRE as this step's outputs[0].value -- the value ` +
          `the policy runtime is asked ABOUT -- so pointing it elsewhere does not withhold the wrong field, it ` +
          `asks the wrong question: measured with "from: $.result.title", the Guardian was handed the tool's ` +
          `own title, answered "allow", and "rm -rf /" was audited as a clean allow and delivered. ` +
          `Point this at ${JSON.stringify(required)}.`,
      );
    }
  }
}

/**
 * Keyed by hook event name, not by the entry's own shape -- the correct
 * basis rather than a convenience. Hook name is what actually decides which
 * live half the applier gets: `AcsPlugin`'s returned object has exactly two
 * hooks, and each constructs a hardcoded tag -- `"tool.execute.before"`
 * builds `{ gate: "request", args }` and `"tool.execute.after"` builds
 * `{ gate: "result", result }` (both at the bottom of this file; each hands
 * its own to `runExchange`, which makes the one `applyOpenCodeOutput` call
 * with whichever it was given). So "which key withholds here" is a fact
 * about the hook method, which is per hook name, regardless of what payload
 * shape the hookmap entry declares. A hookmap declaring `tool.execute.before`
 * with `outputs:` instead of `arguments:` would still be handed
 * `{gate: "request", args}` at runtime, and still needs the refusal rule
 * this table states for that hook name -- a check keyed on the entry's own
 * declared shape would apply the wrong rule to it, or none.
 */
const HOOK_EXPECTATIONS: Record<string, HookExpectation> = {
  /**
   * Checks by structure, not by trusting the shipped field name -- but the
   * structure that matters is which key the unconditional field sits under,
   * not merely that some field somewhere in the block carries
   * `{value: ...}`. `applyOpenCodeOutput` (apply-opencode-output.ts) refuses
   * on exactly one output key: `refuse`. `reason` is declared-inert, and
   * `args`/`result` are merges that leave a governed decision looking like a
   * successful, unremarkable rewrite: an unconditional `{value: ...}`
   * planted at `reason.text` or `args.something` renders a non-empty output
   * block, but a non-empty render at the wrong key is not a refusal --
   * `applyOpenCodeOutput` never reads `refuse` from it, so the applier
   * proceeds all the same. That is a hole a hookmap author (or a
   * compromised config) could use to satisfy this gate's letter while
   * rendering nothing a reader would call a refusal: an entry naming only
   * `from:` fields under `refuse`, plus one unconditional field under any
   * other key, would pass a check that only asked "does some field carry a
   * literal" while still applying nothing and throwing nothing.
   *
   * So: an entry passes only when at least one output path whose leading
   * segment is `refuse` carries `{value: ...}` -- `refuse.denied` (this
   * hookmap's own marker) is one instance of that shape, not a stand-in for
   * "any field, anywhere". Leading segment, not the exact key, because the
   * marker legitimately sits beside `refuse.reason` under a shared `refuse`
   * container: it is the container the applier reads and throws on, so
   * anything unconditional inside it is enough to guarantee the container
   * exists. (The result gate's rule below is the exact key for the opposite
   * reason -- there the sink IS the key.)
   */
  "tool.execute.before": {
    assertEntry(entry, path, hookEventName) {
      assertEntryMatchesGate(entry, path, hookEventName, REQUEST_GATE_ENTRY);
      const decisions = isPlainObject(entry) ? (entry as { decisions?: unknown }).decisions : undefined;
      assertDecisionsCanAct(
        decisions,
        CARRIED_AT_REQUEST_GATE,
        "args",
        path,
        hookEventName,
        (decisionName) =>
          new Error(
            `acs-plugin: ${path}'s "hooks.${hookEventName}.decisions.${decisionName}" declares no unconditional ` +
              `"value:" output field under "refuse" -- applyOpenCodeOutput (apply-opencode-output.ts) refuses only on ` +
              `the "refuse" key; an unconditional field declared under any other key (e.g. "reason.text" or ` +
              `"args...") renders a non-empty output block without making this a refusal, and "refuse.reason" ` +
              `alone is a "from:" field that renders NOTHING when the arriving decision does not carry that ` +
              `source field, or carries it as the wrong type (render-decision.ts). This host's applier would then ` +
              `apply nothing and throw nothing, and the tool would proceed -- a ${decisionName} indistinguishable ` +
              `from a clean allow. Add a literal sibling under "refuse", e.g. "refuse.denied: { value: true }", ` +
              `so this decision always renders a refusal.`,
          ),
        (decisionName, output, sourceField) =>
          new Error(
            `acs-plugin: ${path}'s "hooks.${hookEventName}.decisions.${decisionName}" ` +
              `${sinkFaultPhrase(output, "args", sourceField)} -- at this ` +
              `host's request gate "args" is the ONLY key a rewrite can land in, because applyOpenCodeOutput ` +
              `(apply-opencode-output.ts) merges it onto the live args object OpenCode handed the hook and nothing ` +
              `else it renders reaches that object at all ("reason" is declared-inert, "refuse" throws, "result" ` +
              `has no live half at this gate). THE EXACT KEY: a path under it ("args.command") renders a nested ` +
              `object the applier merges one level too deep, so the whole rewrite bag lands in a single argument. ` +
              `AND THE EXACT SOURCE: "applied_input" is the field a request-gate modify carries its rewrite on, ` +
              `and a "from:" field naming anything else renders NOTHING (render-decision.ts). Without both, this ` +
              `host's applier would apply nothing and throw nothing while the tool ran with its ORIGINAL ` +
              `arguments -- and governStep would still return stage "honoured", so the audit trail would record ` +
              `the rewrite as honoured rather than recording that it never landed. EITHER declare ` +
              `'args: { from: applied_input }' so the rewrite lands, OR declare an unconditional refusal ` +
              `('refuse.denied: { value: true }') so this decision blocks the tool instead -- both are honest ` +
              `outcomes and this gate accepts either; only the silent no-op is refused.`,
          ),
      );
    },
  },
  /**
   * The gate that holds the secret.
   *
   * `result` is the only key that withholds anything at this event, and the
   * requirement is `result: { from: applied_output }` exactly -- that key,
   * that source. `declaresSinkFrom` (above) carries why both halves are
   * load-bearing; in short, the exact key because a path under it
   * (`result.output`) merges one level too deep and leaves the mirror
   * unwritten, and the exact source because a `from:` naming a field the
   * arriving decision does not carry renders nothing at all.
   *
   * Declaring `refuse` instead is allowed, too. A throw out of
   * `tool.execute.after` makes OpenCode discard this plugin's mutations and
   * rebuild `metadata` from its own pre-hook copy, so the tool's output
   * survives in OpenCode's own session record however early the throw
   * fires. That makes replacing the stronger of the two, which is why the
   * shipped hookmap replaces and why this rule's error message says which
   * one an author is choosing. It does not make refusing a silent no-op:
   * the model never sees the output, so it is an honest outcome and
   * `satisfiesGate` accepts it. The cost of the alternative -- refusing
   * such a hookmap at load, on a host where that leaves the plugin
   * unloaded and the session ungoverned -- is stated in `satisfiesGate`'s
   * own doc comment.
   */
  "tool.execute.after": {
    assertEntry(entry, path, hookEventName) {
      // Before any decision is looked at: an entry whose payload shape or
      // whose `$.` paths disagree with what this shim's own hook does makes
      // every sink below unfillable, or fillable with the wrong thing,
      // however correctly it is declared. Checked first so the message
      // names the real fault rather than blaming a correctly-declared
      // decision.
      assertEntryMatchesGate(entry, path, hookEventName, RESULT_GATE_ENTRY);
      const decisions = isPlainObject(entry) ? (entry as { decisions?: unknown }).decisions : undefined;
      assertDecisionsCanAct(
        decisions,
        CARRIED_AT_RESULT_GATE,
        "result",
        path,
        hookEventName,
        // Unreachable at this gate, and kept honest rather than deleted: the
        // parameter exists for the REQUEST gate, whose deny/ask/defer carry
        // nothing and are held to a refusal. Every decision in
        // CARRIED_AT_RESULT_GATE now carries "applied_output", so no decision
        // here can route to this arm -- and if one ever does, that table and
        // this factory have disagreed, which is worth saying outright instead
        // of raising a message about a shape that is no longer the only one
        // open to an author.
        (decisionName) =>
          new Error(
            `acs-plugin: ${path}'s "hooks.${hookEventName}.decisions.${decisionName}" was routed to the ` +
              `carries-nothing branch, but CARRIED_AT_RESULT_GATE declares every decision at this gate to carry ` +
              `"applied_output". The table and this branch disagree; one of them is wrong.`,
          ),
        (decisionName, output, sourceField) =>
          new Error(
            `acs-plugin: ${path}'s "hooks.${hookEventName}.decisions.${decisionName}" ` +
              `${sinkFaultPhrase(output, "result", sourceField)} -- at ` +
              `this host's result gate "result" is the ONLY key that withholds anything, because ` +
              `applyOpenCodeOutput (apply-opencode-output.ts) merges it onto the live object OpenCode handed the hook ` +
              `and nothing else it renders reaches that object at all ("reason" is declared-inert, "args" has no ` +
              `live half at this gate). withResultOutput (result-output.ts) guarantees the arriving decision ` +
              `CARRIES a withholding on "applied_output" for THIS decision; it cannot make this hookmap declare ` +
              `anywhere to land it. THE EXACT KEY, NOT a leaf under it: "result.output" renders the whole patched ` +
              `container into a field that is a string on this host, and leaves the metadata.output mirror ` +
              `unwritten. AND THE EXACT SOURCE, RENDERABLY DECLARED: a "from:" naming another field, a "type:" an ` +
              `object can never satisfy, or a "value:" beside the "from:" all render nothing (render-decision.ts). ` +
              `Without all of it, the applier would apply nothing and throw nothing, and the tool's own output -- ` +
              `the leaf AND its mirror -- would be delivered: a ${decisionName} indistinguishable from a clean ` +
              `allow. EITHER declare 'result: { from: applied_output }' so the withholding lands, OR declare an ` +
              `unconditional refusal ('refuse.denied: { value: true }') so this decision throws instead -- this ` +
              `gate accepts either, because only the silent no-op is unacceptable. Be aware which you are ` +
              `choosing, though: a throw out of "${hookEventName}" stops the model seeing the output, but ` +
              `OpenCode discards this plugin's mutations on that path and rebuilds metadata from its own ` +
              `pre-hook copy, so the plaintext survives in OpenCode's own session record. Replacing is the ` +
              `stronger of the two.`,
          ),
      );
    },
  },
};

/**
 * This shim's expectation of `hookEventName`, or a throw -- the same rule
 * `expectationFor` states in hosts/claude-code/acs-hook.ts, for two reasons
 * here rather than one.
 *
 * A hook this table has no entry for is a hook whose declared decisions
 * nothing checks: an unchecked hook is an unchecked fail-open, which is the
 * whole reason this gate exists. And on THIS host there is a second, sharper
 * reason -- `AcsPlugin` returns exactly two hooks, `"tool.execute.before"` and
 * `"tool.execute.after"`, so a hookmap entry for any other event is never
 * registered with OpenCode at all. It would sit in the hookmap looking like
 * governance and govern nothing, silently, for the life of the deployment.
 * Refused rather than skipped, on both counts.
 *
 * "Returns exactly two hooks" is now checked rather than asserted in prose:
 * `assertRegistrationMatchesIntent` (below) compares this table's own keys
 * against the object the factory actually returns, so this comment cannot go
 * stale against the registration it describes. The two functions are the two
 * directions of one rule -- this one refuses a hookmap entry with no
 * registered hook behind it, that one refuses a registered hook with no
 * expectation in front of it.
 */
function expectationFor(hookEventName: string, path: string): HookExpectation {
  // `hasOwnProperty`, not a bare index: a hookmap naming a hook `toString` or
  // `constructor` would otherwise read an inherited function off
  // Object.prototype, pass the `undefined` check, and then fail on a missing
  // `assertDecisions` -- an unrelated TypeError in place of the message that
  // says which hook is unknown. Same reasoning as acs-hook.ts's own
  // `expectationFor`, and as `isReservedSegment` (reserved-segments.ts).
  const expectation = Object.prototype.hasOwnProperty.call(HOOK_EXPECTATIONS, hookEventName)
    ? HOOK_EXPECTATIONS[hookEventName]
    : undefined;
  if (expectation === undefined) {
    throw new Error(
      `acs-plugin: ${path} maps hook "${hookEventName}", which this shim has no expectation for -- nothing here ` +
        `can say which of this host's output keys withholds at that event, or which live object OpenCode hands a ` +
        `hook there. It is also a hook this plugin never registers: AcsPlugin returns "tool.execute.before" and ` +
        `"tool.execute.after" and nothing else, so this entry would sit in the hookmap looking like governance ` +
        `and govern nothing. A hook nothing checks is a hook nothing governs, so it is refused rather than ` +
        `passed through. Teach this shim the event (HOOK_EXPECTATIONS, this file) before mapping it here.`,
    );
  }
  return expectation;
}

/**
 * Refuses to register a hookmap in which any decision that must refuse (at
 * the request gate) or must withhold (at the result gate) declares no
 * output field this host's applier would honour that way -- called from
 * `AcsPlugin`, beside `loadHookmap`, so this is a load-time stop rather than
 * a fault this shim could only discover from a live decision.
 *
 * Load time, not posture time, and that is the whole point. This fault is
 * decidable from the hookmap file alone, with no invocation payload,
 * rather than left to surface downstream, where a throw is caught by
 * `governStep` and answered by the deployment's negotiated delivery
 * posture instead of refused outright. A negotiated proceed there is an
 * ungoverned step -- and at the result gate an ungoverned step is the
 * tool's output, secret included, delivered.
 *
 * This cannot live in `loadHookmap`, host-agnostically: it is this host's
 * own rule about what its applier needs -- which decisions exist, which
 * output key refuses, which one withholds -- not a claim
 * packages/host-adapter/src may make about any host's field names. For
 * `refuse` that is enforced mechanically: test/invariants.test.ts's
 * host-vocabulary gate fails on the word appearing anywhere in the
 * adapter's own source. Not for `result`: `result-output.ts` uses "result"
 * for ACS's own replacing-output concept, so listing it there would fail
 * on day one for a word the adapter is supposed to speak. What keeps
 * `result`-as-an-OpenCode-output-key out of the adapter is this function
 * living here, not a gate -- the same reason `assertHostAcceptsEveryDecision`
 * lives in hosts/claude-code/acs-hook.ts rather than in the adapter.
 *
 * What this still does not do, stated so a reader does not read more into
 * it. It is a check on the hookmap, not on a rendered output: a hookmap
 * that declares the right key and source, and a decision that reaches the
 * render carrying nothing to put in it, are different faults, and only the
 * first is decidable here -- the same split `acs-hook.ts` draws between its
 * own load-time check and `asClaudeCodeOutput`'s runtime one. It also asks
 * nothing of `allow` at either gate (rendering nothing is that decision's
 * own meaning at both) and nothing about a decision the hookmap never
 * declares. And it does not rank the two honest outcomes: a hookmap that
 * refuses where it could have replaced passes, with the trade-off spelled
 * out in the error message an author sees on the way to choosing.
 */
function assertHostAcceptsEveryDecision(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    expectationFor(hookEventName, path).assertEntry(entry, path, hookEventName);
  }
}

/**
 * Refuses at load unless the hooks this plugin actually registers are exactly
 * the hooks it has expectations for -- the missing direction of
 * `expectationFor`'s own rule, which refuses a hookmap entry for a hook this
 * plugin never registers and had nothing to say about the converse.
 *
 * The fault this exists for. `AcsPlugin` returns its hooks as OBJECT KEYS,
 * and OpenCode dispatches by reading them: for each loaded plugin it does the
 * equivalent of `const hook = plugin[eventName]; if (!hook) continue;` --
 * read out of OpenCode 1.18.18's own compiled `Plugin.trigger`, not inferred
 * from its published types. A key that does not match the name OpenCode fires
 * is simply never called. No throw, no exit code, no audit entry, no
 * diagnostic: an entirely ungoverned session that looks like a quiet one. The
 * Claude Code shim fails CLOSED in the same situation -- an event its own
 * table has no expectation for reaches `govern-step`'s throw and exits 2 --
 * so this host was the weaker of the two and nothing said so.
 *
 * WHAT IT CATCHES, and what it does not, stated precisely because the gap it
 * leaves is bigger than the one it closes:
 *
 *   - It DOES catch this file disagreeing with itself: a hook key added to,
 *     removed from, or renamed in the returned object without
 *     `HOOK_EXPECTATIONS` moving with it. Either half is a real fault -- a
 *     registered hook the table does not know is a gate whose decisions
 *     nothing checks, and a known hook the plugin does not register is an
 *     expectation that governs nothing. Both are conditions the rest of this
 *     file's reasoning silently assumes and nothing verified.
 *   - It DOES NOT catch an upstream rename, and cannot, until the hookmap or
 *     this file is updated toward the new name. If OpenCode renames
 *     `tool.execute.after`, this plugin's key and this table's key still
 *     agree with each other -- and are now both wrong. The agreement is
 *     internal, and internal agreement cannot observe a fourth party
 *     changing. What it does buy is that a rename can no longer be
 *     half-applied: the first edit toward the new name stops the deployment
 *     at load instead of leaving one key stale and the session ungoverned.
 *
 * Why there is nothing stronger available here. The OpenCode plugin API hands
 * a factory `{client, project, directory, $}` and takes back a bag of hook
 * keys. It publishes no registry of valid event names, and the dispatcher
 * asks the plugin for names rather than offering its own, so a plugin has
 * nothing to interrogate: an assertion against the published types would only
 * restate what this file's own keys already say. Closing the rest is
 * OpenCode's to do -- a host that reported an unrecognised hook key instead
 * of skipping it would turn the residual gap into a startup failure the way
 * this gate turns the internal half into one.
 *
 * WHAT IS DELIBERATELY NOT CHECKED: that every hook this plugin registers is
 * one the hookmap declares. It is a real gap -- a registered hook with no
 * entry reaches `governStep` and finds none -- and refusing it here would be
 * the wrong answer anyway, for the reason `satisfiesGate` (above) already
 * gives about over-refusal on this host: a throw from this factory leaves the
 * plugin unloaded and the WHOLE session ungoverned, so refusing a hookmap
 * that declares one gate and not the other would trade "one gate governed,
 * the other stopping loudly" for "nothing governed at all". And it stops
 * loudly on its own: measured, `governsTool` answers `true` for an unmapped
 * hook (no entry, so no `tools` list to be outside of) and `governStep`'s
 * first guard then throws `hookmap has no entry for hook ...`, at the first
 * call of that gate, before anything is asked or audited. Fail-closed
 * already, at the cost of being per-call rather than at load -- which is the
 * cheaper of the two costs on a host where load-time refusal means no
 * governance at all.
 *
 * `HOOK_EXPECTATIONS`'s own key set is what "the set it intends" means, and
 * deliberately not a third list beside it: that table already IS this shim's
 * statement of which hooks it knows, and a separate constant would be one
 * more thing to keep in step by hand -- the class of fault this function
 * exists to make impossible.
 */
function assertRegistrationMatchesIntent(registered: readonly string[]): void {
  const known = Object.keys(HOOK_EXPECTATIONS);
  const unknownToThisShim = registered.filter((hook) => !known.includes(hook));
  const knownButUnregistered = known.filter((hook) => !registered.includes(hook));
  if (unknownToThisShim.length === 0 && knownButUnregistered.length === 0) {
    return;
  }
  throw new Error(
    `acs-plugin: the hooks this plugin registers and the hooks it has expectations for are not the same set -- ` +
      `registered ${JSON.stringify(registered)}, expected ${JSON.stringify(known)}` +
      `${unknownToThisShim.length === 0 ? "" : `; registered and unknown here: ${JSON.stringify(unknownToThisShim)}`}` +
      `${knownButUnregistered.length === 0 ? "" : `; known here and never registered: ${JSON.stringify(knownButUnregistered)}`}` +
      `. OpenCode dispatches by reading these keys off the object this factory returns, so a key it does not ` +
      `fire is never called: no throw, no exit code, no audit entry, and every tool call for the rest of the ` +
      `session runs ungoverned while the session looks quiet. Register exactly the hooks HOOK_EXPECTATIONS ` +
      `names, or teach that table the hook before registering it -- a gate nothing checks is a gate nothing ` +
      `governs. NOTE what this does NOT prove: that these names are the ones OpenCode still fires. They agree ` +
      `with each other, and could be stale together -- see this function's own doc comment.`,
  );
}

/**
 * Refuses before `resolveSessionConfig`/`governStep` are ever asked, when
 * `sessionID` is missing or not a non-empty string. `buildEnvelope` already
 * throws on a missing `session_id`, but that throw lands inside
 * `governStep`'s stage-"request" catch and is answered by the deployment's
 * negotiated posture, where a negotiated proceed there is an ungoverned
 * step. A missing session id is a broken deployment, not a policy question,
 * so both gates refuse it here, before either call is made.
 *
 * The mechanism is a throw, not an exit code: OpenCode's hooks return
 * `void` and have no other channel to report a failure through -- the same
 * mechanism `applyOpenCodeOutput`'s own `refuse` path (apply-opencode-output.ts)
 * uses to stop a tool call.
 *
 * One call site, not one per gate: both gates reach this through
 * `runExchange` (below), which is where the whole exchange they share
 * lives. The `hookEventName` parameter names the gate that actually fired,
 * for the error message.
 */
function assertUsableSessionId(sessionID: unknown, hookEventName: string): asserts sessionID is string {
  if (typeof sessionID !== "string" || sessionID.length === 0) {
    throw new Error(
      `acs-plugin: "${hookEventName}" fired with no usable sessionID (got ${JSON.stringify(sessionID)}) -- a ` +
        `missing or empty session id is a broken deployment, not a policy question, so this refuses before ` +
        `resolveSessionConfig/governStep are ever asked rather than letting buildEnvelope's throw be answered ` +
        `by the negotiated posture, where a negotiated "proceed" would be an ungoverned step`,
    );
  }
}

/**
 * Refuses before `governsTool` is ever asked, when `tool` is not a
 * non-empty string.
 *
 * Without this, the `tools` check itself would silently absorb the fault.
 * `Array.prototype.includes` never throws on a non-string needle -- a
 * malformed `tool` (this host's own contract types `input.tool: string`,
 * but nothing enforces that at the boundary a hook actually fires across)
 * simply reads as "not in this gate's `tools` list", and the caller returns
 * the identical no-op path a genuinely out-of-scope tool takes: silently
 * and unaudited. That is the same asymmetry this file otherwise refuses --
 * a missing `sessionID` is a hard throw a few lines later. This closes the
 * same gap for `tool`, so a broken host contract for either value is
 * refused the same way: a throw, this host's only blocking mechanism,
 * never a fault routed through a posture.
 *
 * `governStep` also scopes on the value this function has just vouched
 * for, handed to it as `scopedTool` (`runExchange`, below) -- so at a gate
 * that declares a `tools` list, `governStep`'s own guard is a backstop for
 * a caller that skipped this shim's own early return, not what would catch
 * a malformed value reaching it directly.
 *
 * The empty string is the case worth naming specifically, because it is
 * the one that reaches a live Guardian rather than throwing or silently
 * skipping. `buildEnvelope` checks a resolved `tool_name` for type, not
 * length, so `""` builds an envelope carrying `tool: {"name": ""}` and the
 * step is genuinely asked about, unaudited by any check upstream. Against
 * this repo's own shipped policy, a Guardian answers that envelope under a
 * registry-miss rule rather than under the deployment's own authored rule
 * for the tool that actually ran -- a governed step judged under a name
 * the deployment does not have, rather than under the one it does. Nothing
 * downstream refuses an empty tool name: not `governsTool` (no list to be
 * outside of, when none is declared), not `governStep`'s own guard
 * (reached only where a list is declared), not `buildEnvelope` (checks
 * type, not length). This function does, at the boundary that has the
 * value in its host's own type, before either call site has to be correct
 * about a value that should never have arrived at all.
 *
 * Generic over `hookEventName`, exactly like `assertUsableSessionId`, and
 * called from the same one place: `runExchange` (below), which runs the
 * exchange both gates share. The parameter puts the firing gate's own name
 * in the message.
 */
function assertUsableTool(tool: unknown, hookEventName: string): asserts tool is string {
  if (typeof tool !== "string" || tool.length === 0) {
    throw new Error(
      `acs-plugin: "${hookEventName}" fired with no usable tool name (got ${JSON.stringify(tool)}) -- a missing ` +
        `or empty tool name is a broken deployment, not a policy question, so this refuses before governsTool ` +
        `or governStep are ever asked rather than letting a malformed value read as "not in this gate's tools ` +
        `list" and silently proceed ungoverned and unaudited`,
    );
  }
}

/**
 * The long-lived collaborators `AcsPlugin`'s factory builds once and every
 * hook call then shares for the rest of the session -- passed to
 * `runExchange` (below) as an argument rather than closed over, so the one
 * exchange both gates run is a module-level function whose dependencies are
 * named in its signature.
 *
 * The Claude Code shim needs no equivalent, and the difference is this
 * host's own shape rather than a disagreement: hosts/claude-code/acs-hook.ts
 * is a fresh subprocess per hook, so its `main()` takes no arguments and
 * builds its own collaborators on the way through. What the two shims share
 * is one function carrying the whole exchange, not how that function is
 * handed what it needs.
 *
 * Interfaces, not implementations: `SessionConfigStore` is what lets the
 * in-memory and file-backed session config stores be interchangeable at all
 * (this host binds the in-memory implementation, the Claude Code shim the
 * file-backed one, and neither `resolveSessionConfig` nor `governStep`
 * learns which).
 */
type Deployment = {
  readonly hookmap: Hookmap;
  readonly guardian: GuardianClient;
  readonly audit: AuditSink;
  readonly store: SessionConfigStore;
};

/**
 * What ONE gate's own payload assembly produces: the single object
 * `opencode.hookmap.yaml`'s `$.` paths resolve against, and the live object
 * that gate's rendered decision is applied to.
 *
 * The two halves are assembled together, at the edge, because they share a
 * reference: the live object the applier mutates is the same one the payload
 * carries, which is what makes a rendered `args`/`result` land on the object
 * OpenCode is actually holding.
 */
type AssembledStep = {
  readonly payload: Record<string, unknown>;
  readonly live: LiveHookObjects;
};

/**
 * The one exchange both gates run.
 *
 * `"tool.execute.before"` and `"tool.execute.after"` make the same seven
 * moves in the same order -- validate `tool`, honour `tools`, validate
 * `sessionID`, assemble the payload, negotiate the session, govern the
 * step, apply what comes back. They are this function; the two hook
 * methods below are edges: each names its own event, assembles its own
 * payload, and constructs its own live half.
 *
 * The order is load-bearing, every step of it:
 *
 *   - `assertUsableTool` first, ahead of the `tools` check, because
 *     `Array.prototype.includes` does not throw on a malformed `tool` -- it
 *     answers a silent `false`, which reads as "out of scope" and turns an
 *     audited, posture-answered fault into a silent unaudited proceed.
 *   - `assertUsableSessionId` next, ahead of the `tools` check rather than
 *     after it. It used to sit after, so a tool this gate does not govern
 *     cost no session validation either -- and that stopped being right
 *     when the skip started leaving a record: `auditUngovernedStep` files
 *     the entry against a session, and a record filed under a missing or
 *     empty session id is one an incident review cannot join to anything.
 *     Nothing expensive moved. What the old ordering actually saved is the
 *     handshake round trip (`resolveSessionConfig`, below), which still
 *     happens only for a tool this gate governs; this check is a typeof and
 *     a length. The behaviour it adds is that a broken `sessionID` now
 *     refuses even for an out-of-scope tool, which is the same
 *     "broken deployment, not a policy question" rule `assertUsableTool`
 *     already applies unconditionally one line above.
 *   - `assertUsableSessionId` before `governStep` for its original reason
 *     too, which the move does not disturb: `buildEnvelope`'s own throw on
 *     a missing `session_id` lands in `governStep`'s stage-"request" catch
 *     and is answered by the negotiated posture, where a proceed is an
 *     ungoverned step.
 *   - `governsTool`'s early return before `assemble`/`resolveSessionConfig`,
 *     so a tool this gate does not govern costs no payload assembly and no
 *     handshake. `governStep` asks the same function itself, about the very
 *     value this function hands it (`scopedTool`), so a shim that forgot
 *     would still skip; this call site is the only one early enough to skip
 *     the rest as well. It is NOT early enough to skip the record, though,
 *     and must not be: see `auditUngovernedStep` (govern-step.ts) for why
 *     an optimisation that changes the durable record is a divergence
 *     rather than a saving.
 *
 * Payload assembly stays at the edge, called from here rather than done
 * here, because the two gates genuinely differ: the request gate reads
 * `args` off the mutable `output` object OpenCode hands it (the only place
 * OpenCode puts them at that gate), while the result gate reads `args` off
 * `input` directly and passes the whole live `{title, output, metadata,
 * attachments}` object as `result`. Called in the ordered position -- after
 * both validations, not before -- and handed the two values this function
 * has just checked, so a gate cannot put an unvalidated `tool` or
 * `sessionID` on its payload.
 *
 * Both `sessionId` forms are here, which is why this is where the note
 * belongs: `resolveSessionConfig` takes the derived ACS uuid
 * (`toSessionUuid`), `governStep` takes the raw host id for the audit log
 * entry, and the payload carries the raw one too because `buildEnvelope`
 * reads `payload.session_id` as a hardcoded top-level field and derives
 * the uuid itself. Mixing the two is the exact bug this note exists to
 * prevent -- see acs-hook.ts's own step 4 and step 5 for the Claude Code
 * shim's two calls side by side.
 */
async function runExchange(
  deployment: Deployment,
  hookEventName: string,
  input: { tool: string; sessionID: string; callID: string },
  assemble: (tool: string, sessionID: string) => AssembledStep,
): Promise<void> {
  // `tool` first, ahead of the `tools` check below: a list membership test
  // cannot tell a malformed `tool` from a genuinely out-of-scope one, so a
  // broken host contract for `tool` has to be refused here, the same
  // "broken deployment" shape `assertUsableSessionId` gives `sessionID` --
  // see `assertUsableTool`'s own doc comment for the asymmetry this closes.
  assertUsableTool(input.tool, hookEventName);

  // Before the `tools` check below, not after it: the skip files an audit
  // entry, and that entry is filed against a session. See this function's
  // own doc comment for what moving this cost and what it did not.
  assertUsableSessionId(input.sessionID, hookEventName);

  // A tool this gate's own `tools` list does not name is not governed here
  // -- return before assembling a payload, before negotiating a session
  // config, before building an envelope, and without asking the Guardian
  // anything. See `governsTool`'s own doc comment (govern-step.ts) for what
  // this costs and why it is right anyway.
  //
  // Recorded on the way out, through the adapter's own `auditUngovernedStep`
  // rather than through anything written here. `governStep`'s own copy of
  // this check files the identical entry, and this call site exists only to
  // save the work below it -- so a skip has to leave the same record
  // whichever of the two got there first, or this shim's optimisation is
  // quietly deciding what the durable log contains. On THIS host that is not
  // a hypothetical: both gates declare `tools`, OpenCode fires the result
  // gate for every tool, and this early return is the one that actually
  // runs. Every non-`bash` tool call therefore writes one of these, which is
  // a lot of lines -- and is the honest count of the steps this deployment
  // does not govern.
  if (!governsTool(deployment.hookmap, hookEventName, input.tool)) {
    auditUngovernedStep({
      hookmap: deployment.hookmap,
      hookEventName,
      tool: input.tool,
      sessionId: input.sessionID,
      audit: deployment.audit,
    });
    return;
  }

  // One payload object, so `opencode.hookmap.yaml`'s `$.` paths have a
  // single thing to resolve against -- OpenCode hands a hook two
  // arguments, not one blob, so this assembly is a shim job the same way
  // reading stdin is the Claude Code shim's. Handed the checked `tool` and
  // the raw, un-converted `sessionID`; see this function's own doc comment
  // above for why the raw host id and the derived uuid must never be
  // mixed.
  const { payload, live } = assemble(input.tool, input.sessionID);

  const session = await resolveSessionConfig(
    {
      guardian: deployment.guardian,
      agentId: deployment.hookmap.host,
      sessionId: toSessionUuid(input.sessionID),
      timeoutMs: DEFAULT_TIMEOUT_MS,
    },
    deployment.store,
  );

  const governed = await governStep({
    hookEventName,
    payload,
    hookmap: deployment.hookmap,
    guardian: deployment.guardian,
    session,
    // Raw, the other of the two `sessionId` forms -- this one is for the
    // audit log entry, never the uuid `resolveSessionConfig` above was
    // given.
    sessionId: input.sessionID,
    audit: deployment.audit,
    // The tool this exchange already scoped on, told rather than left to
    // be asked a second time. It is the very value `governsTool` was asked
    // about a few lines up, and passing it is what makes the two checks
    // two askings of one question: if `governStep` instead re-derived a
    // name by resolving the entry's `tool_name` path against the payload,
    // a hookmap pointing that path elsewhere could have this file
    // proceeding on `input.tool` while the adapter scoped on something
    // else -- a governed step that returns "ungoverned", unaudited, with
    // the actual command through. Both of this shim's gates pass through
    // here, so this one line is both of its call sites.
    scopedTool: input.tool,
  });

  applyOpenCodeOutput(governed.output, live);
}

/**
 * OpenCode's plugin entry point: loads the hookmap and this deployment's
 * long-lived collaborators once, and returns the hooks OpenCode calls for
 * the rest of the session's lifetime.
 *
 * A throw here -- an unreadable or invalid hookmap (`loadHookmap` shape-checks
 * everything statically decidable from the hookmap file alone,
 * `assertHostAcceptsEveryDecision` adds this host's own such check for both
 * of its gates, and `assertRegistrationMatchesIntent` checks the hooks this
 * factory is about to hand back against the ones this shim has expectations
 * for) -- names the same "broken deployment, not a policy question"
 * fault the Claude Code shim's `BlockingConfigurationError`/exit 2 stops its
 * session for. This host does not stop, though: OpenCode's plugin loader
 * catches whatever a plugin module's factory throws during registration,
 * logs a `level=ERROR message="failed to load plugin"` line, and continues
 * the session without this plugin -- every subsequent hook call for the
 * rest of that session is simply never registered, so every tool call runs
 * completely ungoverned, silently, with no further indication anything is
 * wrong. So a throw here is a log line the Claude Code shim has no
 * counterpart for, not a stop its exit 2 is equivalent to -- it names the
 * fault correctly without being able to halt the session the way exit 2
 * does. That gap is OpenCode's to close, not this file's.
 */
export const AcsPlugin: Plugin = async () => {
  // Override with ACS_HOOKMAP_PATH to point this shim at a different
  // hookmap -- same convention as hosts/claude-code/acs-hook.ts. Read here,
  // inside the factory, rather than at module scope (unlike acs-hook.ts's
  // own HOOKMAP_PATH): this plugin factory is a plain function a test can
  // call directly, with no subprocess boundary forcing a fresh module
  // evaluation per test the way spawning acs-hook.ts does for its own
  // suite, so a module-scope constant would freeze whatever
  // ACS_HOOKMAP_PATH was at import time and ignore anything a test set
  // afterwards.
  const hookmapPath = process.env.ACS_HOOKMAP_PATH ?? fileURLToPath(new URL("./opencode.hookmap.yaml", import.meta.url));
  const hookmap = loadHookmap(hookmapPath);
  assertHostAcceptsEveryDecision(hookmap, hookmapPath);

  // Built once, here, and handed to `runExchange` on every call -- the four
  // this deployment runs on, in one object so the exchange both gates
  // share can take them as one argument.
  const deployment: Deployment = {
    hookmap,
    guardian: createGuardianClient(process.env.ACS_GUARDIAN_URL ?? DEFAULT_GUARDIAN_URL),
    audit: createAuditSink({ path: process.env.ACS_AUDIT_LOG ?? ".acs/audit.jsonl" }),
    // In memory: one plugin object per session, so the negotiated config
    // survives in a variable and the second hook of a session skips the
    // handshake round trip. One interface, two implementations, and the
    // adapter never learns which host is running.
    store: createMemorySessionConfigStore(),
  };

  // Named as a const rather than returned inline, so `Object.keys` below
  // reads the registration OpenCode will actually dispatch against, and
  // annotated because the object literal otherwise loses the contextual
  // typing the inline return gave it and both hook methods' parameters go
  // implicitly `any`. `Hooks` is the package's own name for exactly this
  // value -- the thing `Plugin` resolves to.
  const hooks: Hooks = {
    // Both hooks are edges on one exchange: the seven moves they share --
    // validate `tool`, honour `tools`, validate `sessionID`, assemble the
    // payload, negotiate the session, govern the step, apply what comes
    // back -- are `runExchange` (above), which is also where the order
    // they must happen in is stated and defended. What is left here is the
    // half the two gates genuinely differ on: which event name this is,
    // and where OpenCode puts the live objects it hands this hook. And for
    // why a throw at the result gate specifically does not mean what it
    // means at the request gate, see "tool.execute.after"'s own doc
    // comment, below.

    /**
     * The request gate. `args` off the mutable `output` object OpenCode
     * hands this hook -- the only place it puts them at this gate, which is
     * why the payload's `args` and the applier's live half are both read
     * from there: they are the same object, so a rendered rewrite lands on
     * the arguments OpenCode is actually about to run (`applyOpenCodeOutput`'s
     * in-place merge, apply-opencode-output.ts).
     */
    "tool.execute.before": async (input, output) =>
      runExchange(deployment, "tool.execute.before", input, (tool, sessionID) => ({
        payload: { tool, session_id: sessionID, callID: input.callID, args: output.args },
        live: { gate: "request", args: output.args },
      })),

    /**
     * The result gate. The seven moves `runExchange` makes are shared with
     * the request gate; what differs here is the seam -- `{result}` in
     * place of `{args}`, one step later.
     *
     * `tools: [bash]` on this hookmap entry: `metadata` is per-tool on this
     * host -- only `bash`'s carries `exit`/`output`, which is what this
     * entry's `outputs`/`exit_status` are shaped for; `read`'s carries
     * `preview`, `grep`'s carries `matches`. An unlisted tool takes the
     * same documented no-op `governsTool` already gives the request gate.
     *
     * A result missing `metadata.exit` posture-proceeds, and that is
     * correct rather than a gap this gate should close: `exitStatusOf`
     * (build-envelope.ts) throws when `$.result.metadata.exit` resolves to
     * no value, and `governStep`'s stage-"request" catch answers that with
     * this deployment's negotiated posture, which can proceed and deliver
     * the tool's own output, secret included, audited with
     * `failure.kind: "host_configuration"`. That is the same
     * payload-dependent class of fault this file otherwise routes to the
     * negotiated posture rather than closing directly. It is not reachable
     * through `bash`, the only tool this gate governs today -- a failing
     * `bash` command still carries `metadata.exit`/`metadata.output`, and
     * an invalid tool call reports itself as `tool: "invalid"`, which the
     * `tools` check skips before any payload is built at all -- but it is
     * one load-clean hookmap edit away: nothing refuses a hookmap that
     * drops this entry's `tools` line, and a `read` call against that
     * hookmap would take exactly this route. See `GateEntryShape`'s own
     * doc comment (above) for what `mirrors` does and does not backstop
     * about it.
     *
     * `args: input.args`, raw -- unlike the request gate, where `args` sits
     * on the mutable `output` object because that is the only place
     * OpenCode puts it there, OpenCode hands this hook `input.args`
     * directly, so no second read is needed to put it on the payload.
     *
     * `result: output`, the whole live object, not one of its fields --
     * OpenCode hands this hook `{title, output, metadata, attachments}`.
     * `governed.output.result`, when a `deny`/`modify` renders one, is
     * `applied_output`, the whole patched clone of that same object,
     * mirror included, so `applyOpenCodeOutput`'s merge lands `output` and
     * `metadata.output` together and leaves everything a render does not
     * name exactly as OpenCode handed it in.
     *
     * A throw here does not mean what it means at the request gate:
     * OpenCode discards this plugin's mutations on a throw out of
     * `tool.execute.after` and rebuilds `metadata` from its own pre-hook
     * copy, so a secret scrubbed by a throw does not stay scrubbed on
     * disk. That is why this entry's `deny`/`modify` decisions render
     * `result` (a replacing merge) instead of `refuse` (a throw) -- the
     * `refuse` key never appears in either decision here.
     * `assertUsableTool`/`assertUsableSessionId` still refuse a broken
     * `tool`/`sessionID` by throwing, same as the request gate: an
     * ungoverned step is worse than a stop that does not scrub the disk,
     * and neither of those two faults is a governed decision this gate
     * could instead withhold by replacing.
     */
    "tool.execute.after": async (input, output) =>
      runExchange(deployment, "tool.execute.after", input, (tool, sessionID) => ({
        payload: { tool, session_id: sessionID, callID: input.callID, args: input.args, result: output },
        // The cast is on the field, never on `live` itself: OpenCode's
        // published type for this object (`{title, output, metadata}`) has
        // no index signature, and the applier takes what it may merge as a
        // `Record<string, unknown>`. `live` stays a typed object literal
        // owning its own `gate` -- which is the fact `LiveHookObjects`' own
        // doc comment (apply-opencode-output.ts) rests part of its
        // reasoning on.
        live: { gate: "result", result: output as unknown as Record<string, unknown> },
      })),
  };

  // Checked against the object that was actually built, not against a list
  // of names typed out beside it: `Object.keys(hooks)` is what OpenCode will
  // read, so this is the registration itself being asserted rather than a
  // second description of it. Last, because it is a check ON the returned
  // value; still load time, since nothing has fired yet and a throw here
  // reaches OpenCode's plugin loader exactly as `loadHookmap`'s would.
  // See `assertRegistrationMatchesIntent` for exactly which drift this
  // catches, which it cannot, and which direction it deliberately leaves to
  // `governStep`'s own unmapped-hook throw.
  assertRegistrationMatchesIntent(Object.keys(hooks));
  return hooks;
};
