import { readFileSync } from "node:fs";
import type { AgtVerdict } from "agt-bridge";

export type AcsModifications = {
  modified_content?: string;
  redactions?: { path: string; replacement?: string }[];
  parameter_overrides?: Record<string, unknown>;
};

export type AcsDecision = {
  decision: "allow" | "deny" | "modify" | "ask" | "defer";
  reasoning?: string;
  reason_codes?: string[];
  policy_references?: { policy_id: string; policy_version?: string; rule_id: string }[];
  modifications?: AcsModifications;
};

type VerdictRule = {
  decision: AcsDecision["decision"];
  require_policy_references?: boolean;
};

/** A leaf of field_synthesis that copies a verdict field verbatim. */
type FieldSource = { source: string };
/** A leaf of field_synthesis that wraps a scalar verdict field into a
 * single-element array -- the only shape `verdict.reason` can take to satisfy
 * ACS's `string[]`. `wrap` is required, not optional, so a string source is
 * always wrapped and never cast. */
type WrappedFieldSource = { source: string; wrap: WrapMode };
type FieldLiteral = { literal: string };

/** One rule's summary sentence: a single string, or one per intervention
 * point where the same rule means different things at different gates. */
type ReasoningSummary = string | Record<string, string>;

/** How AGT's own message is rendered into the composed sentence's last
 * clause. */
type ReasoningDetail = { when_matches: string; render: string; otherwise: string };

/**
 * How `reasoning` is composed.
 *
 * `source` still names the verdict field AGT's own message arrives in.
 * Everything beside it is wording THIS side supplies, and it has to be:
 * AGT writes that message in `policy/lib/patterns.rego`, which is vendored
 * byte-identical from upstream and proven so by `scripts/verify-pin.sh`, so
 * rewording it upstream would fork the bundle this deployment's whole claim
 * rests on. Composing here is what leaves that bundle untouched.
 */
type ReasoningRule = {
  source: string;
  /** Absent means this mapping asks for `source` copied, not composed. */
  template?: string;
  summaries?: Record<string, ReasoningSummary>;
  detail?: ReasoningDetail;
};

/** The wrap modes this mapping can express. Named as a set so `applyWrap`
 * can refuse everything outside it. */
type WrapMode = "array";

/** The mapping's declaration of how an AGT transform becomes ACS
 * modifications, for ONE intervention point. `when_path` is the only transform
 * path this mapping can express; anything else is a mapping gap and must fail
 * loudly rather than silently drop a rewrite. Same for `into`: the union is the
 * whole truth about what this mapping can build -- one modification shape per
 * gate, and each member carries only the fields its own shape needs, so a
 * value the code cannot honour is a typecheck failure when written into code,
 * not a runtime surprise. That guarantee doesn't reach mapping.yaml itself,
 * though: loadMapping casts the parsed YAML with `as Mapping` and validates
 * nothing, so `into` is still read from the mapping (not hardcoded) and
 * checked at synthesis time against the values this mapping can express.
 *
 * `into` is the discriminant. The result gate's own field beside it,
 * `into_path`, names which leaf of the result payload the rewrite lands in;
 * the request gate's equivalent question -- which argument -- is answered by
 * `policy_target_argument` on the same row rather than a field here, because
 * that is the same argument `resolvePolicyTargetArgument` reads the policy
 * target FROM, and one fact declared twice is two things that can disagree.
 *
 * This type expresses exactly two rewrite shapes, each added only together
 * with a checked value for its `into`, never by casting an arbitrary `into`
 * into the output key. `modified_content`, §6.3's third and exclusive shape,
 * is legal ACS and remains inexpressible here, which is the gap the check
 * keeps loud. */
type ModificationsRule =
  | {
      from: string;
      when_path: string;
      /** The request gate rewrites a tool ARGUMENT. WHICH argument is not
       * declared here: it is `policy_target_argument` on the same row, because
       * the argument an override lands on is the argument the policy target was
       * read from, and one fact declared twice is two things that can
       * disagree. */
      into: "parameter_overrides";
    }
  | {
      from: string;
      when_path: string;
      /** The result gate rewrites the result payload's own leaf, addressed by
       * an ACS JSON pointer the mapping supplies. */
      into: "redactions";
      into_path: string;
    };

/** Which argument a tool's policy target lives in, for one intervention
 * point. `default` covers every tool `by_tool` does not name. */
type PolicyTargetArgument = { default: string; by_tool?: Record<string, string> };

type InterventionPoint = {
  acs_method: string | null;
  note?: string;
  policy_target_argument?: PolicyTargetArgument;
  modifications?: ModificationsRule;
};

export type Mapping = {
  acs_version: string;
  agt_version: string;
  intervention_points: Record<string, InterventionPoint>;
  verdicts: Record<string, VerdictRule>;
  field_synthesis: {
    reasoning: ReasoningRule;
    reason_codes: WrappedFieldSource;
    policy_references: {
      rule_id: FieldSource;
      policy_id: FieldLiteral;
    };
  };
};

export function loadMapping(path: string): Mapping {
  return Bun.YAML.parse(readFileSync(path, "utf8")) as Mapping;
}

/**
 * Resolves an ACS method to the AGT intervention point that answers it.
 *
 * mapping.yaml lists these the other way round: each entry is keyed by the AGT
 * intervention point and names the ACS method it answers. This searches that
 * table backwards, because a request arriving off the wire tells us its ACS
 * method, and what we need in order to evaluate it is the AGT point.
 *
 * If the table names no point for the method, or names more than one, this
 * throws rather than picking one. Falling back to a default would mean
 * evaluating the wrong policy and then returning that answer as this step's
 * decision.
 */
export function resolveInterventionPoint(acsMethod: string, mapping: Mapping): string {
  const table = mapping.intervention_points;
  if (typeof table !== "object" || table === null) {
    throw new Error(
      `mapping.yaml declares no intervention_points table, so ACS method "${acsMethod}" ` +
        `cannot be resolved to an AGT intervention point`,
    );
  }

  const points = Object.entries(table)
    .filter(([, entry]) => typeof entry === "object" && entry !== null && entry.acs_method === acsMethod)
    .map(([point]) => point);

  const [point, ...ambiguous] = points;
  if (point === undefined) {
    throw new Error(
      `mapping.yaml's intervention_points table maps no AGT intervention point to ACS method "${acsMethod}"`,
    );
  }
  if (ambiguous.length > 0) {
    // A table that answers one method with two points has no single right
    // answer, and picking the first would make the choice depend on YAML key
    // order. Loud beats arbitrary.
    throw new Error(
      `mapping.yaml's intervention_points table maps ACS method "${acsMethod}" to more than one ` +
        `AGT intervention point: ${[point, ...ambiguous].join(", ")}`,
    );
  }
  return point;
}

/**
 * Which argument this tool's policy target is read from, at this point.
 *
 * Told the tool NAME, never an envelope. Its callers already hold the name --
 * the Guardian reads `payload.tool.name` for the session chain entry two
 * statements earlier -- and a resolver that took an envelope would couple this
 * module to the wire shape it currently knows nothing about.
 *
 * Answers `undefined` for a point that declares no table, which is the honest
 * answer for the result gate: that gate rewrites a leaf of the result payload
 * addressed by JSON pointer, and no tool argument is involved. A point the
 * table has no row for at all is a different thing and throws, for the same
 * reason `resolveInterventionPoint` throws rather than defaulting -- a mapping
 * that cannot answer must say so rather than guess.
 */
export function resolvePolicyTargetArgument(
  mapping: Mapping,
  point: string,
  toolName: string,
): string | undefined {
  const row = mapping.intervention_points?.[point];
  if (row === undefined) {
    throw new Error(
      `mapping.yaml's intervention_points table has no row for AGT intervention point "${point}", so the ` +
        `argument its policy target is read from cannot be resolved`,
    );
  }

  const table = row.policy_target_argument;
  if (table === undefined) {
    return undefined;
  }

  const named = table.by_tool?.[toolName];
  if (typeof named === "string") {
    return named;
  }

  if (typeof table.default !== "string") {
    throw new Error(
      `mapping.yaml's intervention_points.${point}.policy_target_argument names no argument for tool ` +
        `${JSON.stringify(toolName)} and declares no usable "default"`,
    );
  }
  return table.default;
}

/** Resolves a field_synthesis `source: "verdict.<field>"` path against a verdict. */
function readVerdictField(verdict: AgtVerdict, source: { source: string }): unknown {
  const field = source.source.slice("verdict.".length) as keyof AgtVerdict;
  return verdict[field];
}

/**
 * Applies a field_synthesis leaf's declared `wrap` to the string it read.
 *
 * An unrecognised mode throws rather than falling back to array-wrapping.
 * `loadMapping` parses the YAML without validating it, so `wrap` can be
 * anything the file happens to say; wrapping it anyway would build a
 * `reason_codes` list the mapping never asked for and hand it to the host as
 * the machine-readable half of the decision. The Guardian catches the throw
 * and denies the step instead, which is the honest answer when it cannot carry
 * out the mapping it was given.
 */
function applyWrap(value: string, wrap: WrapMode, leaf: string): string[] {
  if (wrap !== "array") {
    throw new Error(
      `mapping.yaml declares field_synthesis.${leaf}.wrap as ${JSON.stringify(wrap)}, but this mapping can ` +
        `only express "array"`,
    );
  }
  return [value];
}

/**
 * The $policy_target bound survives as ACS modifications.
 *
 * AGT's transform names the leaf it rewrote by the literal "$policy_target",
 * resolved against the manifest's intervention point for that point. The same
 * verdict therefore means two different ACS edits depending on which gate
 * asked: at the request gate $policy_target is a tool argument, which ACS
 * expresses as parameter_overrides keyed by argument name; at the result gate
 * it is a leaf of the result payload, which ACS expresses as a redaction
 * addressed by JSON pointer. So the rule is read from `point`'s own row of
 * mapping.yaml's intervention_points table -- the same table
 * resolveInterventionPoint reads -- and the point is a parameter rather than
 * something inferred here.
 *
 * The output key comes from rule.into, not a hardcoded literal, so this
 * stays genuinely declaration-driven: mapping.yaml and this function can
 * never quietly disagree about which modifications.json field the rewrite
 * lands in. rule.into is still checked against the values this mapping
 * can express before use, because loadMapping validates nothing at runtime
 * -- the same reason transform.path is checked against rule.when_path
 * above rather than trusted.
 *
 * Every failure here is a THROW, and the alternative in each case is worse
 * than a reported failure: a point with no rule, a transform of a path the
 * mapping cannot name, or an `into` the code cannot build would all otherwise
 * become a `modify` the host has nothing to apply -- a rewrite reported as
 * applied while the original is delivered. The Guardian's evaluation catch
 * turns these into an honoured `deny` instead (§6.4).
 *
 * Note what is NOT here: re-applying the substitution. `verdict.transform.value`
 * is already the finished string -- AGT's own rule applies the substitution
 * before the verdict is formed, confirmed against the pinned bundle by the
 * SDK also reporting it as `transformedPolicyTarget` beside the verdict -- so
 * this moves a value rather than recomputing one. The bridge does not forward
 * that second field: it is the SDK's evidence for the claim, not the channel
 * the value travels by, and `PolicyBridge.evaluate` answers with the verdict
 * alone.
 */
function synthesizeModifications(
  verdict: AgtVerdict,
  mapping: Mapping,
  point: string,
  policyTargetArgument: string | undefined,
): AcsModifications {
  const rule = mapping.intervention_points[point]?.modifications;
  if (!rule) {
    throw new Error(
      `mapping.yaml maps AGT decision ${JSON.stringify(verdict.decision)} to ACS "modify", but its ` +
        `intervention_points row for "${point}" declares no modifications rule, so this mapping cannot ` +
        `express the rewrite`,
    );
  }

  const transform = verdict.transform;
  if (!transform || typeof transform !== "object") {
    throw new Error(
      `mapping.yaml maps this verdict to ACS "modify", which requires modifications, ` +
        // `rule.from` is a fully-qualified path ("verdict.transform"), so the
        // sentence has to read around it rather than append it to "carries no".
        `but ${rule.from} is absent`,
    );
  }
  if (transform.path !== rule.when_path) {
    throw new Error(
      `mapping.yaml can express a transform of ${JSON.stringify(rule.when_path)} only, ` +
        `but the verdict rewrote ${JSON.stringify(transform.path)}`,
    );
  }

  // Read before the narrowing below, so the final throw can name what the
  // mapping actually declared without casting a checked value back out.
  const declaredInto: string = rule.into;
  if (rule.into === "parameter_overrides") {
    // A rewrite with no argument to land on is the one thing this function
    // exists not to produce: a modification reported applied while the
    // original ships. The Guardian's evaluation catch turns this throw into an
    // honoured deny.
    if (policyTargetArgument === undefined) {
      throw new Error(
        `mapping.yaml maps this verdict into an ACS parameter override, but its intervention_points row ` +
          `for "${point}" declares no policy_target_argument, so there is no argument for the rewrite to ` +
          `land on`,
      );
    }
    return { [rule.into]: { [policyTargetArgument]: transform.value } };
  }
  if (rule.into === "redactions") {
    // ACS's redaction `replacement` is a string (modifications.json), and
    // AGT's redact rule returns the finished substituted text. A non-string
    // is a rewrite this mapping cannot express as a redaction, so it throws
    // rather than being coerced: String(value) would deliver a replacement
    // nobody chose, which is the one thing this function exists not to do.
    if (typeof transform.value !== "string") {
      throw new Error(
        `mapping.yaml maps this verdict into an ACS redaction, whose replacement is a string, but ` +
          `${rule.from}.value is ${typeof transform.value}`,
      );
    }
    return { [rule.into]: [{ path: rule.into_path, replacement: transform.value }] };
  }
  throw new Error(
    `mapping.yaml declares intervention_points.${point}.modifications.into as ` +
      `${JSON.stringify(declaredInto)}, but this mapping can only express "parameter_overrides" ` +
      `or "redactions"`,
  );
}

/**
 * The summary sentence for the rule that decided, at the gate it decided at.
 *
 * A rule with no entry takes `default` rather than throwing. Every other
 * failure in this module is a throw because the alternative is a decision the
 * host cannot honour; this one is different in kind. An incomplete wording
 * table is a gap in prose, and the Guardian's evaluation catch turns a throw
 * into a deny -- so throwing here would convert a step AGT allowed into a
 * blocked one because nobody had written its sentence yet.
 *
 * The same reasoning covers a per-gate rule reached at a gate it has no
 * sentence for: fall back rather than refuse the step.
 */
function resolveSummary(summaries: Record<string, ReasoningSummary>, ruleId: string, point: string): string {
  const entry = summaries[ruleId];
  if (typeof entry === "string") return entry;
  if (entry !== undefined) {
    const perPoint = entry[point];
    if (typeof perPoint === "string") return perPoint;
  }
  const fallback = summaries.default;
  return typeof fallback === "string" ? fallback : "";
}

/**
 * AGT's own message, rendered for the reader the composed sentence is for.
 *
 * The recognised shape is `patterns.rego`'s sprintf, whose regex is the one
 * part of the raw message a human gains nothing from -- the offset is kept
 * and the regex dropped. Anything else is passed through whole and
 * attributed to AGT, so a message shape this does not know is never lost.
 * That fallback is what keeps the recognition safe: it couples to an upstream
 * sprintf format that no schema pins and the upstream watch does not cover,
 * and the cost of that format changing is a longer sentence, not a missing one.
 *
 * Replacements are functions, never strings: AGT's messages carry regexes
 * containing `$`, and a string replacement would have `$&` and `$1` inside
 * one interpreted as replacement patterns.
 */
function renderDetail(rule: ReasoningDetail, message: string | undefined): string {
  if (message === undefined || message.length === 0) return "";
  const hit = new RegExp(rule.when_matches).exec(message);
  if (hit) return rule.render.replaceAll("{1}", () => hit[1] ?? "");
  return rule.otherwise.replaceAll("{message}", () => message);
}

/**
 * Composes the sentence a host shows a human or hands a model.
 *
 * Answers `undefined` when no rule decided -- a clean allow carries no reason
 * and has nothing to explain, and composing a sentence for it would put
 * reasoning on the one decision whose entire signature is the absence of it.
 */
function composeReasoning(
  rule: ReasoningRule,
  ruleId: string | undefined,
  message: string | undefined,
  policyId: string,
  point: string,
): string | undefined {
  // A mapping that declares no template is asking for its source copied
  // rather than composed, and copying it is implementing that table exactly.
  // This is the shape every mapping had before a wording table existed, so a
  // fixture pinning some other part of the translation stays a two-line
  // declaration instead of carrying a table it does not test.
  if (rule.template === undefined) return message;
  if (ruleId === undefined || ruleId.length === 0) return undefined;
  const summary = resolveSummary(rule.summaries ?? {}, ruleId, point);
  const detail = rule.detail === undefined ? "" : renderDetail(rule.detail, message);
  return rule.template
    .replaceAll("{summary}", () => summary)
    .replaceAll("{rule_id}", () => ruleId)
    .replaceAll("{policy_id}", () => policyId)
    .replaceAll("{detail}", () => detail);
}

export function mapVerdict(
  verdict: AgtVerdict,
  mapping: Mapping,
  point: string,
  policyTargetArgument: string | undefined,
): AcsDecision {
  const rule = mapping.verdicts[verdict.decision];
  if (!rule) {
    throw new Error(`mapping.yaml has no verdict rule for AGT decision "${verdict.decision}"`);
  }

  const fs = mapping.field_synthesis;
  const out: AcsDecision = { decision: rule.decision };

  // Read before `reasoning` is composed, because the composed sentence names
  // the rule; assigned to `out` below, in the order the wire has always
  // carried these fields.
  const ruleId = readVerdictField(verdict, fs.policy_references.rule_id);

  // Composed, not copied. AGT's verdict.message is written for an operator
  // reading a log, and the bundle that writes it is vendored byte-identical
  // from upstream -- so the sentence a host shows a human, or hands a model,
  // is assembled here from the table mapping.yaml declares.
  const agtMessage = readVerdictField(verdict, fs.reasoning);
  const reasoning = composeReasoning(
    fs.reasoning,
    typeof ruleId === "string" ? ruleId : undefined,
    typeof agtMessage === "string" ? agtMessage : undefined,
    fs.policy_references.policy_id.literal,
    point,
  );
  if (reasoning !== undefined) {
    out.reasoning = reasoning;
  }

  const reasonForCodes = readVerdictField(verdict, fs.reason_codes);
  if (typeof reasonForCodes === "string") {
    out.reason_codes = applyWrap(reasonForCodes, fs.reason_codes.wrap, "reason_codes");
  }

  if (typeof ruleId === "string") {
    out.policy_references = [{ policy_id: fs.policy_references.policy_id.literal, rule_id: ruleId }];
  }

  if (rule.require_policy_references && !(out.policy_references && out.policy_references.length > 0)) {
    throw new Error(
      `mapping.yaml declares require_policy_references for AGT decision "${verdict.decision}", ` +
        `but no policy_references could be synthesized (verdict.reason was empty)`,
    );
  }

  if (rule.decision === "modify") {
    out.modifications = synthesizeModifications(verdict, mapping, point, policyTargetArgument);
  }

  return out;
}
