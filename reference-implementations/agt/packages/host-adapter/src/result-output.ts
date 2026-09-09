/**
 * The result gate's replacing output: how a decision about what a step
 * produced reaches a host in a shape the host will actually accept.
 *
 * The hazard this module exists for: a host that lets a hook replace a
 * tool's output validates the replacement against that tool's own output
 * schema, and a replacement that does not match it is discarded silently,
 * with the original delivered. Verified by hand against the first host wired
 * to this gate -- a hook answering with the redacted text alone, as a bare
 * string, produced a warning line on stderr while the model received the
 * real secret. So a redaction is only a redaction if every sibling field
 * survives.
 *
 * The way that is achieved, and there is deliberately only one: patch a
 * clone of the object the host handed us, at the path the hookmap named.
 * Never construct a new output object. That symmetry is the whole answer --
 * the shape is preserved because it was never rebuilt, so a field this
 * adapter has never heard of survives exactly as well as one it has.
 *
 * The ACS document is not simply handed back, because the ACS result
 * payload carries one leaf -- `outputs[0].value`, the leaf the hookmap's
 * `outputs.from` names -- where the host's own output object carries that
 * leaf and its siblings. §6.3's pointers address the ACS payload
 * (`/outputs/0/value`), and that is what they are applied to; this module
 * then projects the applied leaf back through `outputs.from` into a clone of
 * `outputs.within`. The two notations stay deliberately separate: nothing
 * here reinterprets an ACS pointer as a host-side path, because the
 * agreement that keeps them aligned is a declaration the policy side owns,
 * not a translation this side could check.
 *
 * This module knows ACS's decision vocabulary, ACS's result payload shape,
 * and a hookmap's `outputs` block. It names no host field and no policy
 * runtime -- the field names in the object it clones are the host's own,
 * copied without being read, which is exactly what lets a second host reuse
 * it.
 */
import type { HookmapOutputs } from "./build-envelope.ts";
import { pathSegments, resolvePath, resolveSegments } from "./hookmap-path.ts";
import type { AcsDecision, ValidatedAcsDecision } from "./decision-message.ts";

/**
 * Where a host's own output object lives for one invocation of one result-gate
 * hook: the raw host payload, and that hook's declared `outputs` paths into it.
 *
 * Both members together, because neither is usable alone -- the paths say where
 * to look and the payload is what they are resolved against, and a caller
 * holding one without the other could not build a replacement at all.
 *
 * Named `HostOutputLocation` rather than `HostOutputTarget`: "target" is
 * reserved for what §6.3's own pointers address, and `modificationDocumentOf`
 * already names the ACS side. This is a location -- where the host keeps the
 * output, and how to address it -- not a target.
 */
export type HostOutputLocation = {
  /** The raw host payload the hook was invoked with. */
  payload: Record<string, unknown>;
  /** The hookmap's `outputs` block for the hook that asked. */
  outputs: HookmapOutputs;
};

/**
 * What a withholding at a result gate puts in place of the output it
 * withholds.
 *
 * A withholding at this gate has to replace the output, not merely report a
 * block: the tool has already run and its result has already formed, so a
 * block on its own injects a reason and suppresses nothing (verified directly
 * -- the model received the real stdout and the block reason). The replacing
 * output is the half that actually withholds.
 *
 * Prose rather than an empty string, and prose that names policy rather than
 * an error: what lands here is read by a model that will otherwise conclude
 * the tool produced nothing and try again. Why it was withheld travels
 * separately, in whatever field the hookmap points at the decision's own
 * `reasoning` -- one string per job, so a marker a reader might match on
 * never carries text a policy author wrote.
 */
export const WITHHELD_OUTPUT = "[OUTPUT WITHHELD BY POLICY]";

/** The two ACS dispositions that hand a host something to deliver at a gate
 * where the step has already run. Not host values: ACS's own dispositions,
 * the same strings every other module here reads. Named as the delivering
 * pair rather than as a list of withholdings because that is the direction
 * the rule below runs in. */
const DELIVERS_AS_PRODUCED = "allow";
const DELIVERS_A_REPLACEMENT = "modify";

/**
 * Whether `decision` withholds the output at a gate where the step has already
 * run -- the rule, stated once, that both the producer below and a host's own
 * declaration gate read, so the two ends cannot come apart.
 *
 * A RULE AND NOT A LIST, so the next disposition ACS adds inherits it instead
 * of needing an edit here: a disposition delivers at this gate only if it says
 * what to deliver. `allow` says "what the tool produced" and `modify` carries a
 * replacement of its own; everything else withholds. The default is the
 * withholding one, which is also the fail-closed one -- a disposition this
 * module has never heard of does not become a delivery by going unlisted.
 *
 * `ask` and `defer` are the two worth stating, because at the OTHER kind of
 * gate neither withholds and both are answerable: a gate deciding whether a
 * step RUNS can hold the call while a human is asked, or leave it pending.
 * Here there is nothing left to hold. The step has run, its result exists, and
 * there is no permission left to seek -- whatever an approver would say
 * afterwards, the output is not deliverable now, and "not deliverable now" is
 * what withholding means. So both collapse onto `deny`'s shape at this gate
 * and only at this gate: a request gate keeps its three-valued ask, and that
 * asymmetry is the honest part rather than an oversight.
 *
 * WHAT IT COSTS, stated because it is a real loss and not a technicality: the
 * question stops being asked. An `ask` here becomes a withholding no human is
 * invited to lift, so an output an approver would have released stays withheld
 * and the step's own answer is gone -- nothing re-delivers it once the model
 * has read the substitute. A `defer` resolves as though its window had already
 * closed, which is the least-wrong reading available to a host with no pending
 * state, and the same one `resolveDefer` reaches for a defer whose window did.
 * The alternative is delivering the output while reporting that it was held,
 * which is the failure this module exists to prevent.
 */
export function withholdsAtResultGate(decision: string): boolean {
  return decision !== DELIVERS_AS_PRODUCED && decision !== DELIVERS_A_REPLACEMENT;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * True when some leaf of `container` is `value`, walking plain objects and
 * arrays and comparing every leaf it bottoms out at. Used by `replacingOutput`
 * to ask, of the fully-patched replacement, whether the value it just withheld
 * still survives somewhere the leaf patch never touched -- a sibling that
 * mirrors the leaf rather than one that merely sits beside it.
 *
 * This compares whole values, never a substring: serialising the replacement
 * and asking whether it contains the original's serialisation would be wrong
 * in both directions, and one of them is catastrophic -- an empty-string leaf
 * serialises to `""`, whose interior is the empty string, and every
 * replacement contains that, so a tool that produced no output would have
 * had every result withheld. Comparing whole values by `===` at each leaf has
 * no such degenerate case, and it is the same equality `projectAppliedOutput`'s
 * own landing check already uses for a prose leaf.
 */
function holdsValue(container: unknown, value: unknown): boolean {
  if (isPlainObject(container)) {
    return Object.values(container).some((leaf) => holdsValue(leaf, value));
  }
  if (Array.isArray(container)) {
    return container.some((leaf) => holdsValue(leaf, value));
  }
  return container === value;
}

/**
 * True when two already-split paths are NOT disjoint -- equal, or one an
 * ancestor of the other. The same test `modifications.ts`'s own
 * `segmentsOverlap` makes for two redaction paths, duplicated here rather
 * than imported: this module names no host-field vocabulary and no §6.3
 * vocabulary, and importing from `modifications.ts` would pull that module's
 * own redaction/override types across a boundary that has none today. Three
 * lines is cheaper than a new cross-module dependency for this module to own.
 *
 * Used to refuse an overlapping leaf/mirror pair before any patch is
 * applied, so the refusal is the same regardless of which path a hookmap
 * author happened to list first: patching a descendant then an ancestor
 * would silently collapse the descendant's edit, while the reverse order
 * would throw a confusing, unrelated "no object to descend through" error
 * from `patchedClone`. Neither is this check's job to rely on; this asks
 * the question directly, before either can happen.
 */
function pathsOverlap(a: string[], b: string[]): boolean {
  const shorter = a.length <= b.length ? a : b;
  const longer = a.length <= b.length ? b : a;
  return shorter.every((segment, index) => segment === longer[index]);
}

/**
 * `document` with its ACS-side projected leaf (`outputs[0].value`, the same
 * one `projectAppliedOutput` reads back) replaced by a constant, so two
 * documents differing only at that leaf serialise identically. Used to ask
 * "did anything besides the leaf change" without naming what changed --
 * `JSON.stringify` on the result does that.
 *
 * Falls back to `document` untouched when `outputs[0]` is not an object --
 * the shape the leaf lives in is itself either present or a real
 * difference, and comparing the untouched fallback still reports that
 * difference rather than masking it by pretending a leaf was found.
 */
function withoutProjectedLeaf(document: Record<string, unknown>): unknown {
  const outputs = document.outputs;
  if (!Array.isArray(outputs) || !isPlainObject(outputs[0])) {
    return document;
  }
  const [first, ...rest] = outputs;
  return { ...document, outputs: [{ ...(first as Record<string, unknown>), value: null }, ...rest] };
}

/**
 * Returns a clone of `container` with `segments` set to `replacement`, cloning
 * every level the path descends through.
 *
 * Cloning each level, not only the outermost object, is what keeps a nested
 * replacement from reaching back into the payload the host handed us -- which a
 * later step, the audit sink and the envelope log all still read.
 *
 * Every level must already be there: unlike §6.3's own apply step this never
 * creates one. A path that has to invent a level is describing a field the tool
 * did not produce, and adding one is precisely the shape change that gets a
 * replacement declined and the original delivered. So it throws, and the caller
 * turns that into a decision.
 */
function patchedClone(
  container: Record<string, unknown>,
  segments: string[],
  replacement: unknown,
  path: string,
): Record<string, unknown> {
  const [head, ...rest] = segments as [string, ...string[]];
  const clone: Record<string, unknown> = { ...container };
  if (rest.length === 0) {
    clone[head] = replacement;
    return clone;
  }
  const child = container[head];
  if (!isPlainObject(child)) {
    throw new Error(
      `result-output: the host payload has no object at ${JSON.stringify(head)} for output path ` +
        `${JSON.stringify(path)} to descend through, so there is no object to clone and patch there`,
    );
  }
  clone[head] = patchedClone(child, rest, replacement, path);
  return clone;
}

/**
 * The one way a replacing output is ever built: a clone of the object at
 * `outputs.within`, with the leaf at `outputs.from` replaced, and every
 * declared `outputs.mirrors` path replaced alongside it.
 *
 * Every failure mode is a throw, because each means the replacement would be a
 * shape the host may decline, and a declined replacement delivers the original.
 * A redaction that does not land is a failure, not a partial success:
 *
 *   - the two paths not describing one leaf inside one object -- `within`'s
 *     segments not being the leading segments of `from`'s. The leaf's path inside
 *     the container is `from` minus `within`, so a pair that does not stand in
 *     that relation has no leaf to take.
 *   - `within` resolving to something that is not an object, or the leaf being
 *     absent from it. There is nothing to clone, or nothing to patch.
 *   - a replacement of a different `typeof` than the value it replaces. Prose
 *     in place of prose preserves the shape; prose in place of a number,
 *     an object or a list does not, and writing it would produce exactly the
 *     silently-discarded replacement this module exists to prevent.
 *
 *     Both directions of that mismatch are reachable, and the one reachable
 *     here is the replacement's, not the leaf's. `Redaction.replacement?:
 *     string` is a TypeScript type on a value that arrives over the wire, and
 *     nothing checks it at runtime. A Guardian sending `{path:
 *     "/outputs/0/value", replacement: 42}` reaches this comparison with a
 *     number for a string leaf and gets `deny(modifications_invalid)` -- an
 *     arriving decision this gate cannot carry out, answered as a decision,
 *     which is what this comparison is for. The other direction, a leaf that
 *     is not prose, no longer reaches a decision at all:
 *     `assertOutputIsReplaceable` refuses the deployment for it before one is
 *     sought, because a leaf no replacement can be expressed for is not a
 *     decision to answer, it is a hookmap that could not carry one out.
 *
 * None of this is assumed away: the path relation is checked here rather
 * than inherited from `buildEnvelope`'s check on the raw strings. This
 * function is handed a payload and two paths; "some caller checked" is not a
 * property of a function, and on one live route it is not even true --
 * `resolveByPosture` calls this on the stage-"request" path, where
 * `buildEnvelope` failed and may have failed on exactly that check. What the
 * caller contributes is order, not trust: `assertOutputIsReplaceable` runs
 * every check below before a decision is sought, so no failure here can
 * reach a gate that is already holding one.
 */
export function replacingOutput(location: HostOutputLocation, replacement: unknown): Record<string, unknown> {
  const { payload, outputs } = location;

  // The two paths first, the payload after -- `buildEnvelope`'s own ordering, for
  // its own reason: a malformed pair of paths is a hookmap fault and an
  // unresolvable one is a payload fault, and which of them throws is what tells
  // an incident reviewer them apart.
  const fromSegments = pathSegments(outputs.from);
  const withinSegments = pathSegments(outputs.within);

  // `within`'s segments must be the leading segments of `from`'s, checked
  // segment-wise on the arrays the patch is actually applied through -- not
  // inferred from a count, and not borrowed from `buildEnvelope`'s check on the
  // raw strings. Those two are equivalent for every path pair this deployment
  // has, which is exactly why the derivation must not depend on it: the leaf's
  // path is `from` minus `within`, and taking it by length alone is sound only
  // while the prefix relation happens to hold. `resolveByPosture` calls this
  // function on the stage-"request" path, where `buildEnvelope` failed --
  // possibly on that very check -- so "the caller established it" is untrue on
  // the one route that most needs it to be true.
  if (!withinSegments.every((segment, index) => fromSegments[index] === segment)) {
    throw new Error(
      `result-output: hookmap paths ${JSON.stringify(outputs.from)} and ${JSON.stringify(outputs.within)} do ` +
        `not describe one leaf inside one object -- "within" names the object a replacement is patched into a ` +
        `clone of, so its segments have to be the leading segments of "from"`,
    );
  }

  const container = resolvePath(payload, outputs.within);
  if (!isPlainObject(container)) {
    throw new Error(
      `result-output: hookmap path ${JSON.stringify(outputs.within)} does not resolve to an object in this ` +
        `payload, so there is no output object to clone and patch a replacement into`,
    );
  }

  const segments = fromSegments.slice(withinSegments.length);
  if (segments.length === 0) {
    throw new Error(
      `result-output: hookmap path ${JSON.stringify(outputs.from)} names no leaf inside ` +
        `${JSON.stringify(outputs.within)}, so a replacement would replace the whole output object`,
    );
  }

  const original = resolveSegments(container, segments);
  if (original === undefined) {
    throw new Error(
      `result-output: hookmap path ${JSON.stringify(outputs.from)} resolves to no value in this payload, so ` +
        `patching it would ADD a field this tool never produced -- a shape the host may decline, and a ` +
        `declined replacement delivers the original output`,
    );
  }
  if (typeof original !== typeof replacement) {
    throw new Error(
      `result-output: the replacement for hookmap path ${JSON.stringify(outputs.from)} is a ` +
        `${typeof replacement} where this tool produced a ${typeof original} -- the host validates a ` +
        `replacement against the tool's own output shape and delivers the ORIGINAL when it does not match, ` +
        `so a replacement of the wrong type withholds nothing and redacts nothing`,
    );
  }

  // Every declared mirror, validated in full before any patch is applied --
  // inside `within`, a real field inside it (not `within` itself), disjoint
  // from the leaf and from every other declared mirror, present in the
  // payload, and the same `typeof` as `replacement`. See this function's own
  // doc comment for why each of these mirrors one of the leaf's own guards,
  // and why the overlap check has to run before any write happens rather
  // than after.
  const mirrors: { mirror: string; relative: string[] }[] = [];
  for (const mirror of outputs.mirrors ?? []) {
    const mirrorSegments = pathSegments(mirror);
    if (!withinSegments.every((segment, index) => mirrorSegments[index] === segment)) {
      throw new Error(
        `result-output: hookmap mirror ${JSON.stringify(mirror)} is not inside ` +
          `${JSON.stringify(outputs.within)}, so it names no field of the object a replacement is patched into`,
      );
    }
    const relative = mirrorSegments.slice(withinSegments.length);
    if (relative.length === 0) {
      throw new Error(
        `result-output: hookmap mirror ${JSON.stringify(mirror)} names the same object as "outputs.within" ` +
          `${JSON.stringify(outputs.within)} itself, not a field inside it -- a mirror stands in the same ` +
          `relation to "within" that "outputs.from" does`,
      );
    }
    mirrors.push({ mirror, relative });
  }

  for (const { mirror, relative } of mirrors) {
    if (pathsOverlap(segments, relative)) {
      throw new Error(
        `result-output: hookmap mirror ${JSON.stringify(mirror)} and leaf path ${JSON.stringify(outputs.from)} ` +
          `are not disjoint (equal, ancestor, or descendant) -- a mirror names a field DIFFERENT from the leaf, ` +
          `not the leaf itself or a container it sits inside`,
      );
    }
  }
  for (let i = 0; i < mirrors.length; i += 1) {
    for (let j = i + 1; j < mirrors.length; j += 1) {
      const first = mirrors[i] as { mirror: string; relative: string[] };
      const second = mirrors[j] as { mirror: string; relative: string[] };
      if (pathsOverlap(first.relative, second.relative)) {
        throw new Error(
          `result-output: hookmap mirrors ${JSON.stringify(first.mirror)} and ${JSON.stringify(second.mirror)} ` +
            `are not disjoint (equal, ancestor, or descendant) -- patching one after the other would silently ` +
            `overwrite whichever was patched first`,
        );
      }
    }
  }

  // Existence and type, checked and discarded -- neither value is threaded
  // any further. What each mirror actually holds after patching is asked
  // again, directly, by the first post-condition below (the "did it land"
  // check); the only thing this loop's own result needs to leave behind is
  // that every mirror passed, which the loop itself already enforces by
  // throwing.
  for (const { mirror, relative } of mirrors) {
    const mirrorOriginal = resolveSegments(container, relative);
    if (mirrorOriginal === undefined) {
      throw new Error(
        `result-output: hookmap mirror ${JSON.stringify(mirror)} resolves to no value in this payload, so ` +
          `patching it would ADD a field this tool never produced -- a shape the host may decline, and a ` +
          `declined replacement delivers the original output`,
      );
    }
    if (typeof mirrorOriginal !== typeof replacement) {
      throw new Error(
        `result-output: the replacement for hookmap mirror ${JSON.stringify(mirror)} is a ` +
          `${typeof replacement} where this tool produced a ${typeof mirrorOriginal} -- the host validates a ` +
          `replacement against the tool's own output shape and delivers the ORIGINAL when it does not match, ` +
          `so a replacement of the wrong type withholds nothing and redacts nothing`,
      );
    }
  }

  // The writes: the leaf first, then every declared mirror into the same
  // clone -- so a container with two copies of the leaf ends the loop with
  // neither copy left standing. Every pair above is already known disjoint,
  // so the order among the mirrors themselves cannot change the result.
  let patched = patchedClone(container, segments, replacement, outputs.from);
  for (const entry of mirrors) {
    patched = patchedClone(patched, entry.relative, replacement, entry.mirror);
  }

  // The first post-condition: every declared mirror actually holds
  // `replacement` now -- see this function's own doc comment for why this is
  // asked directly rather than trusted from the write above.
  for (const entry of mirrors) {
    const landed = resolveSegments(patched, entry.relative);
    if (landed !== replacement) {
      throw new Error(
        `result-output: hookmap mirror ${JSON.stringify(entry.mirror)} does not hold the replacement after ` +
          `being patched -- the replacement this function is about to return would not actually withhold what ` +
          `it claims to at that field`,
      );
    }
  }

  // The second post-condition, run only when at least one mirror is
  // declared: see this function's own doc comment for why the scan is gated
  // this way, and why the leaf and every declared mirror -- not the leaf
  // alone -- are excluded from it by a sentinel no real value can equal.
  if (mirrors.length > 0) {
    const EXCLUDED = Symbol("result-output: leaf or declared mirror, not an undeclared duplicate");
    let masked = patchedClone(patched, segments, EXCLUDED, outputs.from);
    for (const entry of mirrors) {
      masked = patchedClone(masked, entry.relative, EXCLUDED, entry.mirror);
    }
    if (holdsValue(masked, original)) {
      throw new Error(
        `result-output: the replacement still holds the value being replaced -- some field beside ` +
          `${JSON.stringify(outputs.from)} and its declared mirrors carries its own copy, and withholding a ` +
          `leaf while an undeclared sibling keeps it withholds nothing. Declare that field in this hook's ` +
          `"mirrors" so it is replaced too`,
      );
    }
  }

  return patched;
}

/**
 * Throws unless a replacing output can be built for this payload at all --
 * asked, deliberately, by building one.
 *
 * This is asked before a decision is sought, rather than where the
 * replacement is needed, because every precondition `replacingOutput`
 * reports is a property of the payload and the hookmap alone -- an object to
 * clone, a leaf to patch, and a leaf whose own type prose can stand in for --
 * and not one of them depends on which decision arrives. Asked once a
 * decision is in hand, a hookmap that fails any of them leaves the caller
 * holding a `deny` it cannot carry out, at the one point where the caller's
 * only remaining answer is a delivery-failure posture: `proceed` there
 * delivers the unredacted output and drops the decision, `deny` there blocks
 * with nothing withheld. Both are the shape this module exists to prevent,
 * arrived at from the other side.
 *
 * So the question is asked first, where the only answer needed is a loud
 * stop. A hookmap that cannot express a withholding for the payload in hand
 * is a broken deployment, not a policy question -- the same class as a
 * hookmap that will not load -- and nothing has been asked of a policy
 * runtime and nothing has been audited at that point, so there is no
 * decision to drop and no record to falsify.
 *
 * It asks by building one, rather than by re-stating what building one
 * requires. "A replacement can be built" and "here is what building a
 * replacement needs" are two sentences that can drift, and this check's
 * whole value is that the projection and its precondition cannot come apart.
 * `WITHHELD_OUTPUT` is not a stand-in either: it is the exact value the
 * fail-closed path would have to patch, so what is checked is the very
 * projection that would be performed. The clone is discarded -- the answer
 * is in whether it could be made.
 */
export function assertOutputIsReplaceable(location: HostOutputLocation): void {
  replacingOutput(location, WITHHELD_OUTPUT);
}

/**
 * The applied ACS result payload, projected onto the host's own output object:
 * §6.3's rewrite, landed where the host reads it.
 *
 * Named `projectAppliedOutput` rather than `appliedOutput`: the old name was
 * the field it fills -- `ValidatedAcsDecision.applied_output` -- while the
 * function projects the applied document onto the host's shape and then asks
 * whether the rewrite reached the leaf at all. Its sibling `applyModifications`
 * already means "apply §6.3", so two functions sharing a stem would do
 * different jobs without either name saying which. The verb here is the
 * projection; the landing check is the question the projection has to answer
 * before it can claim to have landed, which is why it stays inside rather
 * than beside.
 *
 * The leaf is read back from `outputs[0].value` -- the one place `buildEnvelope`
 * put it, from the same `outputs.from` path this projects it back through. The
 * two halves are symmetric on purpose: one path in the hookmap, one leaf on the
 * wire, one leaf patched back.
 *
 * Called from inside `resolveModify`'s apply step, so a throw here becomes
 * `deny(modifications_invalid)` -- the same answer as a rewrite that could
 * not be applied at all, for the same reason: a rewrite the host cannot land
 * is a rewrite that did not happen, and reporting it as applied is the one
 * outcome that is worse than denying.
 *
 * The last way a rewrite can fail to land is by landing somewhere else,
 * which is the one failure the projection cannot report by failing, because
 * it does not fail. §6.3's pointers address the whole ACS result payload,
 * and that payload has fields beside the one leaf this gate carries: a
 * redaction of `/exit_status` or `/tool/name`, or an override of
 * `exit_status` or of `tool` wholesale, is honourable, has a real target,
 * and applies exactly as written. (`parameter_overrides` keys are single
 * top-level names, never pointers, so `/tool/name` itself cannot be
 * overridden -- only `tool` as a whole.) `outputs[0].value` then comes back
 * untouched, the projection patches the leaf with the value already there,
 * and the replacement is the object the host is already holding. Measured:
 * the host was handed the tool's own output, secret and all, beside a
 * decision reporting a redaction and an explanation saying so.
 *
 * So the question asked here is whether the rewrite reached the leaf, not
 * whether its pointer looked like the leaf's. Comparing pointers would have
 * to decide what an ancestor pointer means -- an override replacing the
 * whole `outputs` array does reach the leaf, and does land (measured) --
 * and even then it could only say the pointer covers the leaf, never that
 * the value under it changed, which is the half that catches an ancestor
 * override carrying the value already there (also measured). The comparison
 * below asks the projection's own inputs, so it cannot drift from the
 * projection, which is `assertOutputIsReplaceable`'s argument for probing by
 * building rather than by re-stating.
 *
 * What it therefore does not ask is whether every modification landed, and
 * the difference is reachable. It asks about one leaf, so a `modifications`
 * object bundling a leaf edit with a non-leaf one passes: the leaf changed,
 * the non-leaf edit was silently dropped, and the whole `modify` is reported
 * applied. Measured, all four -- a leaf redaction beside a `/exit_status`
 * redaction, beside an `exit_status` override, beside a `/tool/name`
 * redaction, and an `outputs` override carrying a second element that
 * nothing projects. Each of those non-leaf edits alone is correctly denied.
 * No secret reaches the model, since the leaf redaction did land, so what
 * this leaves is a false audit and transcript record, not an unredacted
 * delivery -- but it is a best-effort partial apply reported as a full one,
 * which modifications.ts's own header forbids, reached one seam later than
 * that header can see. Recorded rather than closed: the check that would
 * close it is per-modification and belongs in the apply step, where both
 * documents and every target are in hand, and it would close the request
 * gate's identical hole at the same time (see validate-decision.ts's own
 * note). `mapVerdict` emits exactly one redaction, so this bundle cannot
 * produce it -- the same reachability class as the case this function does
 * refuse, which is exactly why neither is left to the bundle's good
 * behaviour.
 *
 * `===` is exact equality for a prose leaf, and that is a call-site
 * invariant rather than a property of this function. Every route through
 * `governStep` passes `assertOutputIsReplaceable` -- which refuses a leaf
 * `WITHHELD_OUTPUT` is not the same `typeof` as -- before a decision is
 * sought, so the leaf reaching here is a string and `===` is value equality.
 * Stated as the invariant it is because this module insists elsewhere that
 * "some caller checked" is not a property of a function, and because of what
 * breaking it would cost: for an object leaf `===` becomes reference
 * equality, so a structurally identical replacement would read as a change
 * and be reported applied -- a fail-open, not merely a weak comparison. Left
 * stated rather than closed, the way `withResultOutput`'s modify-throw is: a
 * host with such a leaf needs this comparison taught about its shape, the
 * same way the projection would need teaching about arrays, and neither is
 * machinery for a case the preflight refuses first.
 *
 * What this refuses that a policy author might not expect: a redaction
 * whose `replacement` is the value the leaf already held. Nothing about it
 * is malformed and its pointer is the right one -- and it is refused
 * anyway, because what this gate can observe is the object the host will be
 * handed, and that object is the one the tool produced. A Guardian that
 * wants the output delivered as produced has `allow` for exactly that; a
 * `modify` this host cannot tell apart from one is not a rewrite it can
 * report as applied. An over-refusal on the safe side, deliberately, and
 * the same side as the preflight's.
 */
export function projectAppliedOutput(
  appliedDocument: Record<string, unknown>,
  originalDocument: Record<string, unknown>,
  location: HostOutputLocation,
): Record<string, unknown> {
  const outputs = appliedDocument.outputs;
  const first = Array.isArray(outputs) ? (outputs[0] as unknown) : undefined;
  if (!isPlainObject(first) || !Object.prototype.hasOwnProperty.call(first, "value")) {
    throw new Error(
      `result-output: the applied result payload carries no "outputs[0].value" to project back onto this ` +
        `host's output object -- the modifications were applied to a document that no longer describes what ` +
        `the step produced`,
    );
  }

  // The projection first, the landing question after. Every check
  // `replacingOutput` makes is about the hookmap and the payload, and one of
  // those failing is a different incident from a rewrite that went somewhere
  // this gate cannot carry -- so it gets to speak first, on the same reasoning
  // this module already orders its own checks by.
  const replacement = replacingOutput(location, first.value);
  if (first.value === resolvePath(location.payload, location.outputs.from)) {
    throw new Error(
      `result-output: applying these modifications left "outputs[0].value" -- the one leaf of the ACS result ` +
        `payload this gate can carry back to the host -- exactly as the step produced it, so the replacement ` +
        `projected from it is the output the host is already holding. Either the modifications addressed some ` +
        `other part of the result payload, which this gate has no second leaf to project, or they replaced ` +
        `that leaf with the value already there. Both deliver the ORIGINAL output, so a rewrite reported here ` +
        `is one that nothing carried out`,
    );
  }

  // The bundle check: the leaf landed -- the check above would already have
  // refused otherwise -- so ask whether anything else about the document
  // changed too, by comparing both documents with that one projected leaf
  // subtracted out. Anything left over is a modification that changed its own
  // target (`applyModifications`'s own post-condition already refused the
  // no-op form of this) in a document nothing downstream ever reads: applied,
  // honourable, and unobservable, reported as part of an applied `modify`
  // with no record of whether it reached anything.
  const appliedElsewhere = JSON.stringify(withoutProjectedLeaf(appliedDocument));
  const originalElsewhere = JSON.stringify(withoutProjectedLeaf(originalDocument));
  if (appliedElsewhere !== originalElsewhere) {
    throw new Error(
      `result-output: applying these modifications changed more of the ACS result payload than the one leaf ` +
        `this gate projects onto the host's output object -- "outputs[0].value" landed, but the document ` +
        `differs from what the step produced somewhere else too, and nothing besides that one leaf is ever ` +
        `projected there. Each such edit is honourable on its own and none of them is malformed; bundled here, ` +
        `the ones beside the leaf are applied to a document nothing downstream reads, and reporting the whole ` +
        `"modify" applied claims a rewrite for a part of it that never reached anything`,
    );
  }

  return replacement;
}

/**
 * A decision's last word before it is rendered, at a gate where the step has
 * already run: whatever withholds the output here carries the output it
 * withholds.
 *
 * Applied to every decision on its way to a render. Which ones it changes is
 * `withholdsAtResultGate`'s rule and not a list kept here:
 *
 *   - anything that withholds gains a replacing output. Without it the rendered
 *     answer is a block with an empty wrapper -- a reported withholding that did
 *     not happen, while the secret is delivered. That covers a deny the policy
 *     runtime sent, a deny `resolveModify` substituted for a rewrite it could
 *     not apply, a deny a negotiated fail-closed posture produced, and an `ask`
 *     or an unexpired `defer`, neither of which anything at this gate can carry
 *     out: all of them are withholdings, and one arriving unable to withhold
 *     would be the same defect by a different route.
 *
 *     The ask/defer route reached this function last and did not look like the
 *     others: they were not undeliverable-yet-unwithholding, they were
 *     UNDECLARED. The first host wired to this gate named `allow`, `deny` and
 *     `modify` in its mapping and no more, so an ask arriving threw at the
 *     render, the render stage's catch answered it with the deployment's
 *     negotiated posture, and the shipped default (`proceed`) delivered the very
 *     output it should have withheld -- audited as a decision that could not be
 *     rendered, which reads like a mapping gap rather than a bypass. Fixed here
 *     and not only in that mapping, because a declaration alone cannot withhold:
 *     the replacement is the half that withholds, only a decision can carry one,
 *     and this is the one function that attaches one.
 *   - `modify` is checked, not changed. Its replacement was built by
 *     `resolveModify`'s apply step, and a `modify` reaching a render without
 *     one would render an empty wrapper too -- a rewrite reported and never
 *     applied. Unreachable while `validateDecision` is given this gate's
 *     location, which is why it is a throw and not a repair.
 *
 *     The two halves are not guarded the same way, and the asymmetry is worth
 *     knowing. A withholding cannot fail to build its replacement, structurally:
 *     `assertOutputIsReplaceable` establishes that before any decision is sought.
 *     This one rests on a call-site invariant instead -- that whoever hands this
 *     function a location handed `validateDecision` the same one -- and if that ever
 *     broke, this throw would land in the render stage's catch and a delivery
 *     posture would answer a rewrite, which is exactly the shape the withholding
 *     half no longer has. Left stated rather than closed: telling it apart from a
 *     legitimate hookmap gap, which the posture should answer, needs an error
 *     class, and that is machinery for a case one call site and one type already
 *     prevent.
 *   - `allow` is returned untouched, and deliberately emits no replacement at
 *     all: the output is delivered as the tool produced it, and an unnecessary
 *     replacement is a chance to get the shape wrong for no benefit.
 *
 * `location` is `undefined` at a gate that decides whether a step runs. Nothing is
 * withheld there -- the step's own output does not exist yet -- so every decision
 * passes through, including the `ask` that gate can genuinely put to a human.
 */
export function withResultOutput(decision: AcsDecision, location: HostOutputLocation | undefined): AcsDecision {
  if (location === undefined) {
    return decision;
  }
  if (withholdsAtResultGate(decision.decision)) {
    return { ...decision, applied_output: replacingOutput(location, WITHHELD_OUTPUT) } satisfies ValidatedAcsDecision;
  }
  if (decision.decision === DELIVERS_A_REPLACEMENT && (decision as ValidatedAcsDecision).applied_output === undefined) {
    throw new Error(
      `result-output: a "modify" reached this gate's render carrying no applied output, so the rewrite it ` +
        `reports has nowhere to land -- the host would deliver the original output unchanged`,
    );
  }
  return decision;
}
