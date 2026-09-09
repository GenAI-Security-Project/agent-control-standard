/**
 * buildEnvelope turns a host's own hook invocation into an ACS v0.1.0 request
 * envelope (a `steps/*` method), driven entirely by a hookmap -- never by
 * host-specific literals baked into this function.
 *
 * This package knows ACS and hookmaps, nothing else. No file under
 * packages/host-adapter/ may name a policy runtime, its rule language, or its
 * decision vocabulary, and a grep gate in the test suite checks that. This
 * module has no runtime dependency on the Guardian package or the policy
 * bridge behind it: it talks to the Guardian over the wire, never in-process.
 */
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolvePath } from "./hookmap-path.ts";

/**
 * A hookmap value the host sent no field for: the constant this hook always
 * means. `{ literal: success }` on a hook a host fires only for the successful
 * case says that in data, rather than a path being invented to derive it from a
 * neighbouring field the host never meant that way.
 */
export type HookmapLiteral = { literal: string };

/**
 * An exit status read from the payload rather than fixed by the hookmap.
 *
 * Claude Code's PostToolUse hook fires only for the success case, so
 * `HookmapLiteral` is the whole truth there. OpenCode's result gate instead
 * reports a real `metadata.exit` number, so `exit_status` needs a path here,
 * resolved the same way `outputs.from` is -- against the raw hook payload, at
 * the same seam.
 */
export type HookmapFieldRead = { from: string };

/** Where a result-gate hook's output lives in the raw hook payload. */
export type HookmapOutputs = {
  /** JSONPath-lite (`$.foo.bar`) to the leaf that becomes `outputs[0].value`. */
  from: string;
  /**
   * JSONPath-lite (`$.foo.bar`) to the object that leaf sits inside -- so
   * `from` must be `within` plus at least one further segment, which
   * `buildPayload` checks. Declared here and read by the projection side
   * (result-output.ts), not by this module: a decision replacing the output is
   * patched into a clone of that object, so every sibling field the host put
   * beside the leaf survives the round trip. A replacement missing one of them
   * is a shape the host may decline, and a declined replacement delivers the
   * original -- which is why the whole object is named, not just the leaf that
   * goes on the wire.
   */
  within: string;
  /**
   * Further paths inside `within` that hold their own copy of the leaf, and
   * must receive the same replacement.
   *
   * Patching a clone preserves every sibling field, which is right when the
   * siblings are unrelated fields -- but on OpenCode one sibling mirrors the
   * leaf, so preserving it unchanged would preserve the secret too: a
   * redaction that is clean, warns about nothing, is invisible to the model,
   * and leaves the plaintext in the host's own session record. The property
   * that makes the clone safe is the property that leaks, so the hookmap has
   * to say where the copies are; nothing here could infer it.
   */
  mirrors?: string[];
};

/** The members every hook entry carries, whichever payload it builds. */
type HookmapHookEntryCommon = {
  /** The ACS `steps/*` method this hook fires. Never hardcoded here. */
  acs_method: string;
  /** JSONPath-lite (`$.foo.bar`) into the raw hook payload for the tool/step name. */
  tool_name: string;
  /**
   * This hook's own decision -> host-output mapping, consumed by
   * `renderDecision` and never by this module.
   *
   * Per hook, not per hookmap. One host can expose several gates, and a
   * gate's output shape is a property of the gate: a request gate answers with
   * a permission-style field, a result gate answers by replacing what a step
   * produced, and neither field exists on the other. One block shared by every
   * hook could only describe one of them, so a second gate would have had to
   * borrow the first's rule and render a field the host does not read there.
   * `assertRenderableDecisions` applies the same minimum to each block
   * separately, for the same reason it applies it at all.
   */
  decisions?: Record<string, unknown>;
  /**
   * The tool names this gate governs. Undeclared (`undefined`) means "every
   * tool" -- matching Claude Code's own hookmap, which needs no scoping at
   * all because its settings.json matcher already provides it, for both of
   * its gates: `^(Bash|WebFetch)$` at the request gate, `^Bash$` at the
   * result gate.
   *
   * Common to both entry kinds, not just the result-gate shape: scoping
   * which tools a gate governs is orthogonal to which payload shape that
   * gate builds, and OpenCode needs it at both gates, for two different
   * reasons.
   *
   *   - The result gate (`tool.execute.after`) needs it because its own
   *     `outputs`/`exit_status` paths are shaped per tool: OpenCode's hooks
   *     fire for every tool with no matcher, and the raw payload field those
   *     paths read is a different shape per tool (only `bash` carries the
   *     fields `outputs`/`exit_status` below are written for; other tools
   *     carry an unrelated shape those paths were never meant to read). A
   *     path that does not resolve for the arriving tool is a hookmap fault
   *     this gate must not try to govern with.
   *   - The request gate (`tool.execute.before`) needs it for a different
   *     reason: resolving this module's own `$.` paths for every tool a host
   *     fires the hook for is not the same question as whether a
   *     deployment's own policy configuration can evaluate one. A
   *     deployment's policy configuration (policy/manifest.yaml, outside
   *     this package) can bind its evaluation to a single fixed target,
   *     checked before any of that deployment's own authored rules run; a
   *     tool call this deployment never registered, or whose arguments that
   *     fixed target does not resolve against, is refused there by the shape
   *     mismatch alone, never by an authored rule. Against this repo's own
   *     shipped configuration, every tool but the names it registers denies,
   *     unconditionally, before a rule is ever consulted -- it registers
   *     three (`run_shell`, AGT's own stock example name; `Bash`, Claude
   *     Code's; `bash`, OpenCode's). Asking a deployment configured that way
   *     is not wrong, but the answer it gives is a configuration mismatch
   *     reported as if it were governance. `tools` here lets a host shim
   *     decline to ask at all for a tool its own deployment cannot express a
   *     target for.
   *
   * Whether a given invocation's tool is actually in this list is
   * `governsTool`'s question (govern-step.ts), never this module's --
   * `assertToolsWellFormed` (below) checks only the shape. That division is
   * the same one `outputs.mirrors` has: declared and shape-checked here,
   * acted on in the module whose job the acting is.
   */
  tools?: string[];
};

/** A hook asking before a step runs: builds a tool-call-request payload. */
export type HookmapRequestHookEntry = HookmapHookEntryCommon & {
  /** JSONPath-lite (`$.foo.bar`) into the raw hook payload for the argument bag. */
  arguments: string;
  /**
   * JSONPath-lite into the raw hook payload for the command line this step is,
   * verbatim -- ACS's own `raw_command`, optional in
   * hooks/tool-call-request.json and optional here.
   *
   * Declared per host because the field it lives in is the host's: Claude Code
   * puts it at `$.tool_input.command`, OpenCode at `$.args.command`. A tool
   * that is not a shell command resolves it to nothing, and that is an
   * ordinary outcome, not a fault -- see buildPayload.
   */
  raw_command?: string;
  outputs?: never;
  exit_status?: never;
};

/** A hook asking after a step ran: builds a tool-call-result payload. */
export type HookmapResultHookEntry = HookmapHookEntryCommon & {
  arguments?: never;
  /** A result payload carries no command. Spelled `never` beside the request
   * entry's own member, the same way `arguments` and `outputs` are, so the
   * broken entry is not a legal type. */
  raw_command?: never;
  outputs: HookmapOutputs;
  /**
   * The exit status this hook means. A literal for a host whose gate genuinely
   * cannot fail (Claude Code's PostToolUse -- see HookmapLiteral); a field
   * read for a host that reports one (see HookmapFieldRead).
   */
  exit_status: HookmapLiteral | HookmapFieldRead;
};

/**
 * One hook's mapping onto an ACS method: the hookmap's `hooks.<hookName>` entry.
 *
 * Exactly one of `arguments` and `outputs`, spelled as an exclusive union --
 * each member declaring the other's keys as `?: never` -- rather than as one
 * type with both keys optional. The optional-key form types the two broken
 * entries as legal: one declaring both names two payload shapes at once, one
 * declaring neither names none, and both would only be complained about at the
 * far end, as a rejected envelope, by which point the fault reads as a policy
 * failure rather than as the hookmap typo it is. `buildEnvelope` makes the same
 * check at runtime, where a hookmap parsed out of YAML actually lands.
 */
export type HookmapHookEntry = HookmapRequestHookEntry | HookmapResultHookEntry;

/**
 * The hookmap in full: one entry per hook, each mapping that hook onto an ACS method
 * (consumed here) and onto the output its host reads back (consumed by
 * `renderDecision`, not by this module -- present on the entry type only so a
 * hookmap loaded whole, as `loadHookmap` does, round-trips without loss).
 */
export type Hookmap = {
  host: string;
  hooks: Record<string, HookmapHookEntry>;
};

/** An ACS argument wrapper: every hook argument is `{value, provenance?}`. */
type AcsArgument = { value: unknown };

/** An ACS output wrapper: every step output is `{value, provenance?}` too. */
type AcsOutput = { value: unknown };

/** hooks/tool-call-request.json's payload: what a step was asked to do. */
export type AcsToolCallRequestPayload = {
  tool: { name: string };
  arguments: Record<string, AcsArgument>;
  /** ACS's optional `raw_command`. Present only when the hookmap declared a
   * path for it AND that path resolved to a string. */
  raw_command?: string;
  exit_status?: never;
  outputs?: never;
};

/**
 * hooks/tool-call-result.json's payload: what a step produced. That schema
 * requires exactly `tool`, `exit_status` and `outputs` -- a different member set
 * from the request payload, not the request payload plus extras.
 */
export type AcsToolCallResultPayload = {
  tool: { name: string };
  arguments?: never;
  /** A result payload carries no command line, the same way it carries no
   * arguments -- declared `never` here for the identical reason, so the
   * exclusive union stays exclusive and `raw_command` reads as `string |
   * undefined` on either payload shape without a cast. */
  raw_command?: never;
  exit_status: string;
  outputs: AcsOutput[];
};

/**
 * The payload an envelope carries, as an exclusive union of the two shapes --
 * for the same reason `HookmapHookEntry` is one. A single type with every member
 * optional would let a caller build an envelope carrying neither shape, and the
 * type would have said nothing: a payload that names no step is then rejected at
 * the far end, where the rejection reads as governance declining a step rather
 * than as this module having built nothing coherent to govern.
 */
export type AcsRequestPayload = AcsToolCallRequestPayload | AcsToolCallResultPayload;

/** The ACS v0.1.0 request envelope this module produces. */
export type AcsRequestEnvelope = {
  jsonrpc: "2.0";
  method: string;
  id: string;
  params: {
    acs_version: string;
    request_id: string;
    timestamp: string;
    metadata: {
      agent_id: string;
      session_id: string;
    };
    payload: AcsRequestPayload;
  };
};

const ACS_VERSION = "0.1.0";

/**
 * Every hook's `decisions` block must declare at least `allow` and `deny` --
 * the only two decisions a delivery-failure posture (`applyFailurePosture`)
 * ever produces -- and every entry it declares must actually be renderable,
 * not merely present. "Renderable" means shaped like render-decision.ts's own
 * `DecisionRenderRule`: a non-null object carrying a non-empty `output` block,
 * every field of which names its own source. Presence alone does not
 * guarantee that: `allow: null` still satisfies `"allow" in decisions`, and
 * then `renderDecision` throws on the non-object entry; `allow: {}` also
 * satisfies it and renders an output whose one field is `undefined`, which
 * `JSON.stringify` drops entirely -- stdout ends up with no decision in it at
 * all, defeating "always a decision on stdout" exactly as surely as a missing
 * entry does, just more quietly.
 *
 * The minimum is applied per hook, because the posture answers a delivery
 * failure at whichever gate suffered it: a hook missing `allow` or `deny` is
 * a hook whose posture answer cannot be rendered, and one gate having both
 * says nothing about the other.
 *
 * Every declared entry is checked here, not only `allow` and `deny`: a
 * malformed `modify` (or `ask`, or `defer`) entry would otherwise only
 * surface when a Guardian actually returns that decision, and by then the
 * throw lands inside the caller's own catch, gets treated as a delivery
 * failure, and the posture answers it as a fail-open proceed -- an arriving
 * policy decision silently degraded into the exact bypass this project
 * exists to remove. Checking every entry at load time closes that for the
 * cost of one loop.
 *
 * What this guarantees, once it passes, is that every entry `loadHookmap`
 * accepted is renderable -- so a caller's fallback render of
 * `applyFailurePosture`'s "allow"/"deny" output can be trusted never to
 * throw, because existing here means shape-checked here. "Shape-checked"
 * means the hookmap's own declarative output shape: a non-empty `output`
 * block whose every field names either a literal `value` or a non-empty
 * `from`. It is deliberately not a check for any particular host field --
 * this module names none, and test/invariants.test.ts gates that -- so the
 * check is that the rule is renderable, not that it renders anything in
 * particular.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertRenderableDecisions(hookmap: Hookmap, path: string): void {
  const hooks = hookmap.hooks;
  // A hookmap mapping no hook at all would make every check below iterate
  // nothing and pass -- and a gate that cannot fail reads as enforcement while
  // enforcing nothing (the same reasoning test/invariants.test.ts's own
  // emptiness check states). It is also not a hookmap: a host with no hook
  // mapped is a host nothing governs.
  if (!isPlainObject(hooks) || Object.keys(hooks).length === 0) {
    throw new Error(`loadHookmap: ${path} maps no hooks, so it declares nothing this host could govern`);
  }

  for (const [hookEventName, entry] of Object.entries(hooks)) {
    const decisions = isPlainObject(entry) ? entry.decisions : undefined;
    if (!isPlainObject(decisions)) {
      throw new Error(`loadHookmap: ${path}'s hook "${hookEventName}" has no "decisions" block`);
    }
    for (const required of ["allow", "deny"] as const) {
      if (!(required in decisions)) {
        throw new Error(
          `loadHookmap: ${path}'s "hooks.${hookEventName}.decisions" block has no "${required}" entry`,
        );
      }
    }
    for (const [decision, rule] of Object.entries(decisions)) {
      const named = `"hooks.${hookEventName}.decisions.${decision}"`;
      if (!isPlainObject(rule)) {
        throw new Error(
          `loadHookmap: ${path}'s ${named} entry must be an object carrying an "output" block, got ${JSON.stringify(rule)}`,
        );
      }
      const output = rule.output;
      if (!isPlainObject(output) || Object.keys(output).length === 0) {
        throw new Error(
          `loadHookmap: ${path}'s ${named} entry needs a non-empty "output" block, got ${JSON.stringify(output)}`,
        );
      }
      // The same rule renderDecision enforces per field, checked here so that
      // "loadHookmap accepted it" and "renderDecision can render it" cannot come
      // apart. A field naming neither source is a hookmap typo; the decision it
      // belongs to would render an output missing a field its author believes is
      // there, and for `modify` or `ask` that is a policy decision arriving and
      // being silently degraded.
      for (const [field, source] of Object.entries(output)) {
        if (!isPlainObject(source)) {
          throw new Error(
            `loadHookmap: ${path}'s ${named} output field "${field}" must be an object naming ` +
              `"value" or "from", got ${JSON.stringify(source)}`,
          );
        }
        const hasValue = Object.prototype.hasOwnProperty.call(source, "value");
        const hasFrom = typeof source.from === "string" && source.from.length > 0;
        if (!hasValue && !hasFrom) {
          throw new Error(
            `loadHookmap: ${path}'s ${named} output field "${field}" must name a literal "value" ` +
              `or a non-empty string "from", got ${JSON.stringify(source)}`,
          );
        }
      }
    }
  }
}

function assertMirrorsWellFormed(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    const outputs = isPlainObject(entry) ? (entry as { outputs?: unknown }).outputs : undefined;
    if (!isPlainObject(outputs)) {
      continue;
    }
    const rawMirrors = outputs.mirrors ?? undefined;
    if (rawMirrors === undefined) {
      continue;
    }
    if (!Array.isArray(rawMirrors) || rawMirrors.some((mirror) => typeof mirror !== "string" || mirror.length === 0)) {
      throw new Error(
        `loadHookmap: ${path}'s "hooks.${hookEventName}.outputs.mirrors" is ${JSON.stringify(rawMirrors)} -- ` +
          `when present, "mirrors" must be a list of non-empty JSONPath-lite strings, each a further path ` +
          `inside "outputs.within"`,
      );
    }
    const within = typeof outputs.within === "string" ? outputs.within : "";
    if (within.length === 0) {
      continue;
    }
    for (const mirror of rawMirrors as string[]) {
      if (!mirror.startsWith(`${within}.`) || mirror.length <= within.length + 1) {
        throw new Error(
          `loadHookmap: ${path}'s "hooks.${hookEventName}.outputs.mirrors" entry ${JSON.stringify(mirror)} is ` +
            `not a field inside "outputs.within" ${JSON.stringify(within)} -- a mirror is a further path into ` +
            `the same object the leaf lives in, the same relation "outputs.from" has to it`,
        );
      }
    }
  }
}

/**
 * Rejects a hookmap entry whose `tools` is malformed, at load time -- the
 * same seam `assertMirrorsWellFormed` uses, and for the identical reason: a
 * throw reached only from `buildEnvelope`/`buildPayload` is caught by
 * `governStep` and answered with the deployment's negotiated delivery
 * posture, which can be `proceed`. A hookmap that provably cannot scope its
 * own result gate must not get to govern a step anyway; it has to be a hard
 * stop here, before `governStep` is ever reached.
 *
 * This check is the shape check only -- `tools`, when present, is a
 * non-empty list of non-empty strings. Whether a given invocation's tool is
 * actually in that list is `governsTool`'s question (govern-step.ts), and
 * each host shim asks the same function one call earlier: nothing in this
 * module reads `tools` for either purpose, the same division `outputs.mirrors`
 * has between this file (shape) and result-output.ts (use).
 */
function assertToolsWellFormed(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    if (!isPlainObject(entry)) {
      continue;
    }
    // `?? undefined` for the same YAML reason every other check in this file
    // uses it: a key written with nothing after it parses to `null`, present
    // and unusable, not absent.
    const rawTools = (entry as { tools?: unknown }).tools ?? undefined;
    if (rawTools === undefined) {
      continue;
    }
    if (
      !Array.isArray(rawTools) ||
      rawTools.length === 0 ||
      rawTools.some((tool) => typeof tool !== "string" || tool.length === 0)
    ) {
      throw new Error(
        `loadHookmap: ${path}'s "hooks.${hookEventName}.tools" is ${JSON.stringify(rawTools)} -- when present, ` +
          `"tools" must be a non-empty list of non-empty tool-name strings`,
      );
    }
  }
}

/**
 * Rejects a hookmap entry whose `exit_status` declares both `literal` and
 * `from`, at load time -- the same seam `assertMirrorsWellFormed` and
 * `assertToolsWellFormed` use, and for the identical reason: a throw reached
 * only from `exitStatusOf` (via `buildPayload`/`buildEnvelope`) is caught by
 * `governStep` and answered with the deployment's negotiated delivery
 * posture, which can be `proceed` -- so a hookmap declaring both forms could
 * otherwise reach a step ungoverned rather than refused. A both-forms entry
 * needs no payload to detect; it is visible from the hookmap alone, exactly
 * like `mirrors` and `tools`, so it belongs at this load-time seam.
 *
 * `exitStatusOf` keeps its own runtime throw for the one case that genuinely
 * cannot move here: an unresolvable `from` path, which needs a specific
 * invocation's payload to even ask the question.
 */
function assertExitStatusNotBothForms(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    const exitStatus = isPlainObject(entry) ? (entry as { exit_status?: unknown }).exit_status : undefined;
    if (!isPlainObject(exitStatus)) {
      continue;
    }
    const hasLiteral = typeof exitStatus.literal === "string" && exitStatus.literal.length > 0;
    const hasFrom = typeof exitStatus.from === "string" && exitStatus.from.length > 0;
    if (hasLiteral && hasFrom) {
      throw new Error(
        `loadHookmap: ${path}'s "hooks.${hookEventName}.exit_status" declares both "literal" and "from" -- ` +
          `an entry names exactly one form`,
      );
    }
  }
}

/**
 * Rejects a hookmap entry that declares `arguments` (a request-gate shape)
 * and also declares `outputs` (a result gate's own output/mirror
 * declaration), at load time.
 *
 * A request gate may also declare `tools`, for the same reason a result
 * gate can: to decline asking at all for a tool its own deployment cannot
 * express a policy target for, rather than asking and reporting a
 * configuration mismatch as if it were governance (see
 * `HookmapHookEntryCommon.tools`'s own doc comment).
 *
 * `outputs` is refused here for an unrelated reason: `HookmapRequestHookEntry`
 * types it `?: never`, but a hookmap arrives as `Bun.YAML.parse(...) as
 * Hookmap`, a cast TypeScript never checks against the parsed YAML, so that
 * type promise binds nothing at runtime -- an entry declaring `arguments`
 * alongside `outputs` loads clean and round-trips the extra field untouched
 * unless something checks for it. A request gate builds no result payload,
 * so it has nothing an output/mirror declaration could describe; refused
 * here, at the same load-time seam as `assertToolsWellFormed` and
 * `assertExitStatusNotBothForms`, rather than left to `buildPayload`'s own
 * "declares both" check, which only catches it through the posture-answered
 * seam every check above this one closes.
 *
 * `exit_status` is deliberately not covered here: an entry declaring
 * `arguments` alongside `exit_status` alone (no `outputs`) is inert --
 * `buildPayload`'s `arguments` branch never looks at `exit_status`.
 */
function assertRequestGateDeclaresNoOutputs(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    if (!isPlainObject(entry)) {
      continue;
    }
    const raw = entry as { arguments?: unknown; outputs?: unknown };
    const hasArguments = typeof raw.arguments === "string" && raw.arguments.length > 0;
    if (!hasArguments) {
      continue;
    }
    if (raw.outputs !== undefined && raw.outputs !== null) {
      throw new Error(
        `loadHookmap: ${path}'s "hooks.${hookEventName}" declares "arguments" (a request-gate shape) and ` +
          `also declares "outputs" -- an entry names exactly one payload shape, and a request gate builds no ` +
          `result payload for a result gate's own output/mirror declaration to describe`,
      );
    }
  }
}

/**
 * Rewrites every entry whose `tools` key is present-but-`null` to omit the
 * key instead, and returns the result as a fresh `Hookmap` -- never a
 * mutation of the object `Bun.YAML.parse` produced.
 *
 * A bare `tools:` line parses to `null` in YAML: a key present and unusable,
 * not a key absent. `tools: null` and no `tools` key mean the same thing,
 * "every tool" (see `HookmapHookEntryCommon.tools`), so normalising one into
 * the other is a representation change, not a semantic one -- it does not
 * touch what `assertToolsWellFormed` already decided is well-formed. What it
 * buys is that every consumer of the returned `Hookmap` can read `tools`
 * with a plain `=== undefined` check rather than each having to repeat a `??
 * undefined` dance to treat `null` the same way; a consumer that checks
 * `tools !== undefined` instead reads a bare `tools:` as a declared list and
 * throws a raw `TypeError` calling `.includes()` on `null`.
 *
 * Called last, after every load-time check above it -- `assertToolsWellFormed`
 * included -- so nothing upstream of this function loses sight of the
 * hookmap exactly as `Bun.YAML.parse` produced it. Rewriting the entry
 * before those checks ran would have hidden the very shape
 * `assertToolsWellFormed` exists to inspect from the one function that
 * inspects it.
 */
function normalizeTools(hookmap: Hookmap): Hookmap {
  const hooks: Record<string, HookmapHookEntry> = {};
  // `?? {}` for the same reason every sibling check above uses it, even
  // though `assertRenderableDecisions` already throws before this function
  // is ever reached if `hookmap.hooks` is not a non-empty plain object: this
  // keeps the guard a property of every function that walks `hooks`, not of
  // the one check that happens to run first today, so a reordering of
  // `loadHookmap`'s own call sequence cannot turn a named
  // `loadHookmap: … maps no hooks` throw into a bare `TypeError` here.
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    if (isPlainObject(entry) && (entry as { tools?: unknown }).tools === null) {
      const { tools: _tools, ...rest } = entry as Record<string, unknown>;
      hooks[hookEventName] = rest as HookmapHookEntry;
    } else {
      hooks[hookEventName] = entry;
    }
  }
  return { ...hookmap, hooks };
}

/** Loads and parses a hookmap YAML file (e.g. claude-code.hookmap.yaml).
 * Throws if any hook's `decisions` block is absent or missing `allow` or
 * `deny`, or if any declared entry is not a renderable rule -- see
 * assertRenderableDecisions. Also throws if any entry's `outputs.mirrors` is
 * malformed or names a field outside `outputs.within` -- see
 * assertMirrorsWellFormed. Also throws if any entry's `tools` is malformed --
 * see assertToolsWellFormed. Also throws if any entry's `exit_status`
 * declares both `literal` and `from` -- see assertExitStatusNotBothForms.
 * Also throws if a request-gate entry (one declaring `arguments`) also
 * declares `outputs` -- see assertRequestGateDeclaresNoOutputs.
 *
 * Returns a normalised `Hookmap`, not the raw parse tree `Bun.YAML.parse`
 * produced: an entry whose `tools` key is present-but-`null` comes back with
 * the key omitted instead -- see normalizeTools, run last, once every check
 * above has passed. */
export function loadHookmap(path: string): Hookmap {
  const hookmap = Bun.YAML.parse(readFileSync(path, "utf8")) as Hookmap;
  assertRenderableDecisions(hookmap, path);
  assertMirrorsWellFormed(hookmap, path);
  assertToolsWellFormed(hookmap, path);
  assertExitStatusNotBothForms(hookmap, path);
  assertRequestGateDeclaresNoOutputs(hookmap, path);
  return normalizeTools(hookmap);
}

/**
 * Unwraps ACS's `{value, provenance?}` argument shape back into a plain
 * `{argName: value}` bag -- the same values `buildEnvelope` just put on the
 * wire. Knowledge of the ACS argument wrapper belongs here, next to the type
 * that defines it, not duplicated in every host shim that needs the unwrapped
 * form.
 *
 * Takes a request payload, and only a request payload. A result payload has
 * no arguments, and answering an empty bag for one instead of refusing it
 * would be a silent hazard: handed to the apply step, an empty bag is a
 * perfectly good value, so every result-gate `modify` would fail closed as
 * `deny(modifications_invalid)` -- a deny where a redaction was asked for,
 * which is the one thing the result gate exists to do. `modificationDocumentOf`
 * below is the safe collaborator and the only one apply work goes through.
 *
 * That shape is unrepresentable rather than merely discouraged: the
 * parameter is the request payload, `AcsToolCallResultPayload` declares
 * `arguments?: never`, and a caller reaching here with the wrong one does
 * not compile. It is not exported from the package barrel either -- leaving
 * this verb on the public surface beside a safe one is how the next caller
 * picks the wrong one.
 */
function unwrapArguments(payload: AcsToolCallRequestPayload): Record<string, unknown> {
  const unwrapped: Record<string, unknown> = {};
  for (const [key, argument] of Object.entries(payload.arguments)) {
    unwrapped[key] = argument.value;
  }
  return unwrapped;
}

/**
 * The ACS-side document a decision's §6.3 `modifications` pointers address --
 * for whichever of the two payload shapes this envelope carries.
 *
 * Named `modificationDocumentOf` rather than `modificationTarget`: "target"
 * is reserved for §6.3's own pointer targets and for the host-side output
 * location, so a reader would meet the word three times meaning three
 * things. What this answers with is a document: the JSON the pointers are
 * resolved against.
 *
 * A request payload's pointers address its arguments: `/env/TOKEN` names an
 * argument field, so the document is the unwrapped bag above and the applied
 * result is a tool input the host can run.
 *
 * A result payload's pointers address the payload itself: the pointer for
 * the leaf that went out is `/outputs/0/value`, which names nothing inside
 * an arguments bag -- there isn't one at this step, and inventing one was
 * never an option (see `unwrapArguments`'s own note). So the document is the
 * payload, and the pointer resolves against exactly the structure the far
 * end evaluated and named.
 *
 * A shallow copy, never the payload object itself: the apply step returns a
 * new object but reads this one, and an envelope is also what the audit and
 * envelope logs record. Nothing downstream of a decision may reach back
 * into the message that asked for it.
 *
 * The applied result is not what a result-gate host delivers -- the ACS
 * payload carries one leaf where the host's own output object carries that
 * leaf and its siblings. Projecting the applied document back onto the
 * host's shape is result-output.ts's job, and the reason
 * `HookmapOutputs.within` is declared.
 */
export function modificationDocumentOf(envelope: AcsRequestEnvelope): Record<string, unknown> {
  const { payload } = envelope.params;
  if (payload.arguments !== undefined) {
    return unwrapArguments(payload);
  }
  return { ...(payload as Record<string, unknown>) };
}

/**
 * `success` / `failure`, per ACS's own enum -- from whichever form this
 * hook's `exit_status` declares.
 *
 * A host that reports a numeric exit code is mapped here, in the adapter,
 * rather than in the hookmap: the hookmap is data, and "0 means success" is a
 * fact about process exit codes, not a per-host choice. A host whose gate
 * genuinely cannot fail (Claude Code's PostToolUse) uses the literal form
 * instead, handled by the same function so `buildPayload` has one call site
 * for either.
 *
 * An entry naming both a non-empty `literal` and a non-empty `from` is
 * refused before this function ever runs -- see `assertExitStatusNotBothForms`,
 * run from `loadHookmap` -- rather than here, so this function only ever sees
 * one legal form or neither.
 *
 * The malformed/absent case -- neither a non-empty `literal` nor a non-empty
 * `from` -- throws naming both legal forms, so a `from`-shaped typo (`fromm:`,
 * say) is not told to add a literal instead, which would not be the fix for it.
 */
function exitStatusOf(event: string, rawExitStatus: unknown, payload: Record<string, unknown>): string {
  const hasLiteral =
    isPlainObject(rawExitStatus) && typeof rawExitStatus.literal === "string" && rawExitStatus.literal.length > 0;
  const hasFrom =
    isPlainObject(rawExitStatus) && typeof rawExitStatus.from === "string" && rawExitStatus.from.length > 0;

  // The both-forms case is refused earlier, at load time -- see
  // `assertExitStatusNotBothForms`'s own doc comment for why it belongs
  // there rather than here.
  if (hasLiteral) {
    return (rawExitStatus as { literal: string }).literal;
  }

  if (hasFrom) {
    const from = (rawExitStatus as { from: string }).from;
    const raw = resolvePath(payload, from);
    if (raw === undefined) {
      throw new Error(
        `buildEnvelope: hookmap path ${JSON.stringify(from)} for hook "${event}"'s "exit_status" resolves to ` +
          `no value in this payload, so this gate cannot say whether the step succeeded`,
      );
    }
    return raw === 0 || raw === "0" || raw === "success" ? "success" : "failure";
  }

  throw new Error(
    `buildEnvelope: hookmap entry for hook "${event}" declares "outputs" without a non-empty ` +
      `"exit_status.literal" or "exit_status.from"`,
  );
}

/**
 * The payload half of an envelope, built from whichever of the two shapes the
 * hookmap entry declares.
 *
 * Branches on the entry's shape, never on `acs_method`. The method is a string a
 * hookmap author types; branching on it would make a typo in it silently select
 * a payload shape, and the shape that actually matters is the one the entry's
 * own paths can build. `acs_method` is carried onto the envelope verbatim,
 * never read here.
 *
 * An entry declaring both keys, or neither, names no single payload shape and
 * throws with the hook named. There is deliberately no default and no partial
 * payload: falling back to one shape would put a payload on the wire the hook's
 * own paths were never written to fill, and the far end would then be governing
 * a step it had been described wrongly, rather than the hookmap being reported
 * broken here where it can be fixed.
 */
function buildPayload(
  event: string,
  payload: Record<string, unknown>,
  entry: HookmapHookEntry,
  toolName: string,
): AcsRequestPayload {
  // `?? undefined` because a hookmap is YAML: a key written with nothing after
  // it parses to null, which is a key present and unusable, not a key absent.
  const argumentsPath = entry.arguments ?? undefined;
  const outputs = entry.outputs ?? undefined;

  if (argumentsPath !== undefined && outputs !== undefined) {
    throw new Error(
      `buildEnvelope: hookmap entry for hook "${event}" declares both "arguments" and "outputs" -- ` +
        `an entry names exactly one payload shape`,
    );
  }

  if (argumentsPath !== undefined) {
    // `arguments` is a scalar path, while its sibling `outputs:` is a map of
    // paths (`from` / `within`), which makes an author writing `arguments:
    // {from: $.tool_input}` by analogy a realistic hookmap typo. Unchecked it
    // dies inside `resolvePath` as a bare `TypeError: path.replace is not a
    // function` -- fail-closed, so never a fail-open, but naming neither the
    // hook nor the member at fault, which every other check in this function
    // does. The `outputs` branch below is type-checked member by member with
    // hook-naming throws; this is the one branch that is not.
    if (typeof argumentsPath !== "string") {
      throw new Error(
        `buildEnvelope: hookmap entry for hook "${event}" declares "arguments" as ` +
          `${JSON.stringify(argumentsPath)} -- "arguments" names the argument bag with a single ` +
          `JSONPath-lite string, unlike "outputs", whose own paths are members of a map`,
      );
    }

    const rawArguments = resolvePath(payload, argumentsPath);
    const args: Record<string, AcsArgument> = {};
    if (rawArguments !== null && typeof rawArguments === "object") {
      for (const [key, value] of Object.entries(rawArguments as Record<string, unknown>)) {
        args[key] = { value };
      }
    }

    const payloadOut: AcsToolCallRequestPayload = { tool: { name: toolName }, arguments: args };

    // `?? undefined` for the same reason its siblings use it: a bare
    // `raw_command:` line parses to null in YAML, which is a key present and
    // unusable rather than a key absent.
    const rawCommandPath = entry.raw_command ?? undefined;
    if (rawCommandPath !== undefined) {
      if (typeof rawCommandPath !== "string") {
        throw new Error(
          `buildEnvelope: hookmap entry for hook "${event}" declares "raw_command" as ` +
            `${JSON.stringify(rawCommandPath)} -- "raw_command" names the verbatim command line with a ` +
            `single JSONPath-lite string, the same notation as "arguments" beside it`,
        );
      }
      const rawCommand = resolvePath(payload, rawCommandPath);
      // Omitted, never a throw, and the asymmetry with outputs.from below is
      // deliberate. An unresolvable outputs.from throws because a result
      // payload with no output would ask the far end to govern a step whose
      // output it cannot see. raw_command is different in kind: it is optional
      // in hooks/tool-call-request.json, a request payload without one is
      // complete and fully governable, and a tool that is not a shell command
      // resolves this path to nothing on EVERY call. Throwing there would send
      // every one of those steps to governStep's posture path, which under the
      // shipped `proceed` runs the step ungoverned.
      if (typeof rawCommand === "string") {
        payloadOut.raw_command = rawCommand;
      }
    }

    return payloadOut;
  }

  if (outputs !== undefined) {
    // A result gate declaring a command path is a hookmap fault, not a payload
    // one: the result payload this branch builds has no member for it, so the
    // declaration could only ever be silently dropped.
    if (entry.raw_command !== undefined && entry.raw_command !== null) {
      throw new Error(
        `buildEnvelope: hookmap entry for hook "${event}" declares "raw_command" beside "outputs" -- a ` +
          `result payload carries no command line, and this declaration could only be dropped`,
      );
    }

    // The entry's own three members are checked first and the payload after. A
    // malformed entry is a hookmap fault and an unresolvable path is a payload
    // fault; which of these throws is what tells an incident reviewer apart,
    // and validating the entry as a whole first stops a broken entry being
    // reported as a payload that was missing something.
    const from = isPlainObject(outputs) && typeof outputs.from === "string" ? outputs.from : "";
    if (from.length === 0) {
      throw new Error(
        `buildEnvelope: hookmap entry for hook "${event}" declares "outputs" without a non-empty "outputs.from" path`,
      );
    }

    // `within` is validated here even though this module never reads it, for
    // exactly the reason assertRenderableDecisions validates a decision entry it
    // never renders: so that "buildEnvelope accepted this entry" and "the render
    // side can apply a replacement through it" cannot come apart. An entry
    // naming `from` and no `within` builds a clean envelope and a correct
    // decision comes back, and the gap surfaces only at render -- where a
    // replacement carrying the named leaf alone is a shape a host may decline,
    // and a declined replacement means the original output is delivered. A
    // redaction that does not land is a failure, not a partial success, so an
    // entry missing `within` is malformed and says so here, where a hookmap
    // author can still fix it, rather than at the one moment it matters.
    const within = isPlainObject(outputs) && typeof outputs.within === "string" ? outputs.within : "";
    if (within.length === 0) {
      throw new Error(
        `buildEnvelope: hookmap entry for hook "${event}" declares "outputs" without a non-empty ` +
          `"outputs.within" path -- a replacement applied to the named leaf alone loses every sibling ` +
          `field beside it, and a replacement a host declines delivers the original`,
      );
    }

    // And the two paths have to describe one leaf inside one object, which is
    // the whole premise of patching a clone: `from` must name a field under
    // `within`. Checked here, beside the check above and for the same stated
    // reason -- so that "buildEnvelope accepted this entry" and "the projection
    // side can patch a replacement through it" cannot come apart. An entry
    // whose two paths point into different objects (or at the same one) builds a
    // clean envelope and gets a correct decision back, and the gap surfaces only
    // at the one moment it matters, as a replacement the host declines and an
    // original delivered with a log line.
    if (!from.startsWith(`${within}.`) || from.length <= within.length + 1) {
      throw new Error(
        `buildEnvelope: hookmap entry for hook "${event}" declares "outputs.from" ${JSON.stringify(from)}, ` +
          `which is not a field inside "outputs.within" ${JSON.stringify(within)} -- the leaf that goes on ` +
          `the wire is the one a replacement is patched into a clone of that object at, so one path must ` +
          `extend the other`,
      );
    }

    // `outputs.mirrors`, if this entry declares any, is deliberately not
    // validated here. A throw from this function is caught by `governStep`
    // and answered with the deployment's negotiated delivery posture, which
    // can be `proceed` -- so a hookmap fault refused only here could still
    // govern the step it describes, which is precisely the class of hookmap
    // fault this whole file exists to stop before it becomes possible.
    // `assertMirrorsWellFormed`, run from `loadHookmap` before this function
    // is ever reached in the real deployment path, is where that refusal
    // lives instead. `from` and `within`, immediately above, carry the
    // identical hazard and are still only checked here, not at load time.
    const exitStatus = exitStatusOf(event, entry.exit_status, payload);

    const value = resolvePath(payload, from);
    if (value === undefined) {
      throw new Error(
        `buildEnvelope: hookmap path "${from}" for hook "${event}" did not resolve -- a result payload ` +
          `carrying no output would ask the far end to govern a step whose output it cannot see`,
      );
    }

    return { tool: { name: toolName }, exit_status: exitStatus, outputs: [{ value }] };
  }

  throw new Error(
    `buildEnvelope: hookmap entry for hook "${event}" declares neither "arguments" nor "outputs" -- ` +
      `an entry names exactly one payload shape`,
  );
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Fixed, arbitrary namespace UUID used only to derive a stable v5 UUID from
// a host session id that is not itself a UUID -- Claude Code's session_id
// is host-assigned free-form text with no uuid guarantee, but ACS's
// metadata.session_id schema field requires format "uuid". Never
// regenerate this constant: doing so changes every derived session_id.
const SESSION_ID_NAMESPACE = "11c79ebd-8469-4b4e-8de0-72674add484c";

/**
 * Maps a host's raw session id onto a schema-valid uuid. If the host
 * already hands us a uuid, it is carried through unchanged (lowercased).
 * Otherwise a RFC 4122 version-5 (namespace + SHA-1) uuid is derived
 * deterministically -- the same raw session id always derives the same
 * uuid, so per-session correlation on the Guardian side survives the
 * translation honestly, rather than a random uuid being minted and
 * silently discarding the host's real session identity.
 */
export function toSessionUuid(rawSessionId: string): string {
  if (UUID_RE.test(rawSessionId)) {
    return rawSessionId.toLowerCase();
  }

  const namespaceBytes = Buffer.from(SESSION_ID_NAMESPACE.replace(/-/g, ""), "hex");
  const hash = createHash("sha1")
    .update(Buffer.concat([namespaceBytes, Buffer.from(rawSessionId, "utf8")]))
    .digest();

  hash[6] = (hash[6]! & 0x0f) | 0x50; // version 5
  hash[8] = (hash[8]! & 0x3f) | 0x80; // RFC 4122 variant

  const hex = hash.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Builds an ACS v0.1.0 request envelope from a raw hook invocation.
 * `hookmap` drives every host-shape decision: the ACS method, which of the two
 * payload shapes this hook carries, and where the tool/step name and that
 * shape's own content live in the raw payload. An event name absent from
 * `hookmap.hooks` throws, and so does an entry naming no single payload shape --
 * there is no default method, no default shape, and no partial envelope.
 */
export function buildEnvelope(event: string, payload: Record<string, unknown>, hookmap: Hookmap): AcsRequestEnvelope {
  const entry = hookmap.hooks[event];
  if (!entry) {
    throw new Error(`buildEnvelope: hookmap has no entry for hook "${event}"`);
  }

  const toolName = resolvePath(payload, entry.tool_name);
  if (typeof toolName !== "string") {
    throw new Error(
      `buildEnvelope: hookmap path "${entry.tool_name}" for hook "${event}" did not resolve to a string`,
    );
  }

  const acsPayload = buildPayload(event, payload, entry, toolName);

  const rawSessionId = payload.session_id;
  if (typeof rawSessionId !== "string" || rawSessionId.length === 0) {
    throw new Error(`buildEnvelope: hook payload for "${event}" is missing a "session_id" string field`);
  }

  const requestId = randomUUID();

  return {
    jsonrpc: "2.0",
    method: entry.acs_method,
    id: requestId,
    params: {
      acs_version: ACS_VERSION,
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: {
        agent_id: hookmap.host,
        session_id: toSessionUuid(rawSessionId),
      },
      payload: acsPayload,
    },
  };
}
