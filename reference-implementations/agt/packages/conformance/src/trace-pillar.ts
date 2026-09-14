/**
 * Whether a downstream consumer of the ACS v0.1.0 wire -- reading nothing
 * this Guardian keeps process-local -- could emit each required Trace-pillar
 * attribute `trace/otel-mapping.json` names. This is a check, not an
 * exporter: nothing here is named `exportTrace`, `traceExporter` or
 * `emitSpan`. Its render half, `renderTraceRows`, lives in `render.ts` --
 * that file's own module header is why: `render.ts`'s only imports are
 * `import type`, so it structurally cannot read a file, and this module is
 * where the reading happens instead.
 *
 * `otel-mapping.json` is a JSON **Schema**, not a data file -- its data
 * lives inside `default` keys, three places:
 *   - `properties.step_to_span.default` -- an object keyed by ACS method,
 *     18 entries, each `{span_name, required_attributes, optional_attributes?}`.
 *   - `properties.decision_event.properties.{required_attributes,
 *     conditional_attributes}.default` -- two string arrays.
 *   - `properties.provenance_attributes.properties.required.default` -- one
 *     string array.
 * A reader who expects the mapping to BE the data, rather than to declare a
 * schema whose `default` happens to carry it, looks at the top level and
 * finds nothing -- this module reads the three paths above, not the schema
 * shape around them.
 *
 * SCOPE: the six ACS methods `mapping.yaml`'s `intervention_points` table
 * gives an `acs_method` (`steps/toolCallRequest`, `steps/toolCallResult`,
 * `steps/sessionStart`, `steps/sessionEnd`, `steps/userMessage`,
 * `steps/agentResponse`). This implementation can only claim or decline the
 * Trace pillar for the methods it evaluates. `otel-mapping.json` declares
 * eighteen; the other twelve (`steps/agentTrigger`,
 * `steps/knowledgeRetrieval`, `steps/memoryStore`,
 * `steps/memoryContextRetrieval`, `steps/turnStart`, `steps/turnEnd`,
 * `steps/preCompact`, `steps/postCompact`, `steps/subagentStart`,
 * `steps/subagentStop`, `agbom/snapshot`, `agbom/changed`) are out of scope
 * for the same reason `mapping.yaml` never reaches them. The six are frozen
 * here rather than re-read from `mapping.yaml`: this module's interface
 * consumes nothing else, so the scope is a stated design fact (which methods
 * this Guardian evaluates), not something re-derived from a file this check
 * would otherwise have to import.
 *
 * THE RULE: a row is emittable only when its field is PRESENT and REQUIRED
 * in the v0.1.0 schema that would carry it. An optional field means a
 * conformant envelope may omit it, so a wire consumer cannot be relied on to
 * emit the attribute -- present-but-optional and absent-entirely are both
 * "not emittable", but they are different findings, and each row's `reason`
 * says which. Both are resolved by `resolveField` below, at runtime, against
 * the actual parsed schema files: nothing here hardcodes a row's verdict,
 * only which file and field path a given attribute WOULD resolve against
 * (the "wire site"), which is domain knowledge no schema states directly --
 * `otel-mapping.json` names `acs.capability`, not
 * `hooks/tool-call-request.json`'s `capability` field.
 *
 * Decision facts (`acs.decision`, `acs.evaluator`, and the four conditional
 * attributes) are recorded as a span EVENT named `acs.decision` on the
 * parent step span -- not a span of their own -- so every row built from
 * `decision_event` carries that literal string as its `span`, matching
 * `otel-mapping.json`'s own `event_name` const. Provenance attributes are
 * plainer still: `provenance_attributes`'s own description says they land
 * as ordinary attributes "on the resulting span" whichever step that is, so
 * that row's `span` is a parenthesised description rather than a literal
 * OTel name -- there is no single step span to point at. This is why
 * `TraceRow.span` (below) is typed as a bare `string`: a caller reading it
 * off a `TraceRow` this module returns cannot assume it is always a literal
 * OTel span or event name -- one of the seventeen rows' `span` value (the
 * provenance row) is not.
 *
 * WHAT `resolveField` DOES NOT MODEL: JSON Schema's conditional-requirement
 * keywords (`allOf`/`if`/`then`), which `response-envelope.json`'s
 * `$defs.AcsResult` uses to require `reasoning` when `decision` is `deny`,
 * `modify`, `ask` or `defer`. `resolveField` only ever reads a node's own
 * unconditional `required` array, so `acs.reasoning`'s row reads "exists but
 * is optional" -- true of `AcsResult` generally (its top-level `required`
 * omits `reasoning`), but only because `allow` is the one decision that
 * carries no such conditional obligation; a `deny`/`modify`/`ask`/`defer`
 * result DOES require it. The verdict this rule produces is still correct
 * under this module's own stated definition ("required" means "in the
 * schema's own unconditional `required` list"), and none of the other six
 * files this module reads uses `allOf`/`if`/`then` on a path any site here
 * walks -- `AcsResult` is the only one.
 *
 * `acs.provenance.origin` is measured under a narrower rule than every other
 * row, and that is deliberate, not an inconsistency left unstated. Every
 * other row asks "starting from a construct guaranteed to exist once per
 * step (a hook payload, the envelope's own metadata, the one `acs.decision`
 * event) is this field present and unconditionally required", walking the
 * FULL path including whatever optional container sits in between --
 * `acs.evaluator`'s path walks through `AcsResult.metadata`, itself optional
 * on `AcsResult`, and that optionality is exactly what makes the row red.
 * Provenance has no such always-present parent in scope: nothing in the six
 * in-scope spans' `required_attributes` names a `provenance` field, and
 * whether a `Provenance` object is attached at all is a per-argument,
 * per-output, per-content-item choice (`provenance.json`'s own consumers
 * describe it as "OPTIONAL in the base schema") that this module's sites
 * never walk into. `otel-mapping.json`'s own text scopes
 * `provenance_attributes.required` the same way -- "When Provenance is
 * attached to a hook payload, the resulting span MUST carry provenance
 * facts as attributes" -- so this row measures exactly that conditional
 * claim: GIVEN a `Provenance` object, is `origin` guaranteed within it. It
 * does not, and could not from the sites this module reads, additionally
 * ask whether a `Provenance` object is ever attached in the first place.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export type TraceRow = {
  attribute: string;
  /** The OTel span or span-event name this attribute is recorded on --
   * EXCEPT for the provenance row, whose `span` is a parenthesised
   * description rather than a literal OTel name (module header): nothing in
   * `otel-mapping.json` names a span or event for provenance facts the way
   * `decision_event`'s `event_name` const names one for decision facts. A
   * caller reading `.span` off a row this module returns cannot assume it
   * is always one of the wire's own names. */
  span: string;
  wireSource: string | null;
  emittableByWireConsumer: boolean;
  reason?: string;
};

// The repository's own schemas, five directories up from this file; see
// packages/guardian/src/validate-envelope.ts for the same relationship.
const SPEC_ROOT = fileURLToPath(new URL("../../../../../specification/v0.1.0/", import.meta.url));

function readSpecJson<T>(relativePath: string): T {
  return JSON.parse(readFileSync(`${SPEC_ROOT}${relativePath}`, "utf8")) as T;
}

/** The six methods in scope (module header). Order is this module's own
 * publication order, not `mapping.yaml`'s -- rows are built method by
 * method, in this order, so a diff of two runs is stable. Exported so
 * `test/trace-pillar.test.ts` can assert this frozen list is exactly
 * `mapping.yaml`'s non-null `acs_method` values, rather than a copy that
 * could drift from it silently. */
export const METHODS_IN_SCOPE = [
  "steps/toolCallRequest",
  "steps/toolCallResult",
  "steps/sessionStart",
  "steps/sessionEnd",
  "steps/userMessage",
  "steps/agentResponse",
] as const;

/** A minimal JSON-Schema node -- just enough structure for `resolveField`
 * to walk `properties`/`required`/`items`/`minItems` and follow a LOCAL
 * `$ref` (`#/$defs/...`), which is every `$ref` shape this module's sites
 * use. Every field is optional because a node this module's `deref` reaches
 * (a bare `{ "$ref": "..." }` property value, say) may carry only one of
 * them.
 *
 * Deliberately NOT modeled: `allOf`, `if`/`then`, and every other
 * conditional-requirement keyword. `resolveField` below only ever consults a
 * node's own unconditional `required` array (module header, "WHAT
 * resolveField DOES NOT MODEL") -- a field `AcsResult`'s `allOf` requires
 * only when `decision` takes a particular value reads as plain "optional"
 * here, which is this module's stated rule working as designed, not a gap
 * in this type. */
type SchemaNode = {
  type?: string;
  properties?: Record<string, SchemaNode>;
  required?: string[];
  items?: SchemaNode;
  minItems?: number;
  $ref?: string;
  $defs?: Record<string, SchemaNode>;
};

type StepSpanEntry = { span_name: string; required_attributes: string[]; optional_attributes?: string[] };

type OtelMappingSchema = {
  properties: {
    step_to_span: { default: Record<string, StepSpanEntry> };
    decision_event: {
      properties: {
        required_attributes: { default: string[] };
        conditional_attributes: { default: string[] };
      };
    };
    provenance_attributes: {
      properties: {
        required: { default: string[] };
      };
    };
  };
};

/** Follows a LOCAL `$ref` (`#/$defs/...`) against `fileRoot`, the parsed
 * file `node` came from. Every `$ref` this module's sites cross is local --
 * `request-envelope.json`'s `AcsParams.metadata` to its own `$defs.Metadata`,
 * `response-envelope.json`'s top level to its own `$defs.AcsResult` (read
 * directly, not through a `$ref`, so this function is never asked to cross
 * one for it). A `$ref` reaching into ANOTHER file (`hooks/*.json`'s
 * `argument.provenance` to `"../provenance.json"`, say) throws rather than
 * resolving into the wrong schema silently -- no site below needs one, so
 * hitting this means a site's `path` was written wrong. */
function deref(fileRoot: SchemaNode, node: SchemaNode | undefined): SchemaNode | undefined {
  if (node === undefined || node.$ref === undefined) {
    return node;
  }
  if (!node.$ref.startsWith("#/")) {
    throw new Error(
      `trace-pillar: cannot follow cross-file $ref "${node.$ref}" -- resolve it against its own file instead`,
    );
  }
  let target: unknown = fileRoot;
  for (const key of node.$ref.slice(2).split("/")) {
    target = (target as Record<string, unknown> | undefined)?.[key];
  }
  return target as SchemaNode | undefined;
}

/**
 * Walks `path` from `startNode`, resolved against `fileRoot` for `$ref`
 * indirection. `"[]"` descends into an array's `items` and additionally
 * demands `minItems >= 1`: a field only every ITEM of an array is required
 * to carry is not reliably present on the wire unless the array itself is
 * guaranteed non-empty (`hooks/user-message.json`'s `content`, the one site
 * that takes this branch, declares `minItems: 1`).
 *
 * `present` and `required` are computed independently at every call -- this
 * is the one function every row below is resolved through, so a wrong
 * per-site `path` shows up as a wrong runtime answer, not as a silently
 * transcribed one.
 */
function resolveField(
  fileRoot: SchemaNode,
  startNode: SchemaNode | undefined,
  path: string[],
): { present: boolean; required: boolean } {
  let node = deref(fileRoot, startNode);
  let required = true;

  for (const segment of path) {
    if (node === undefined) {
      return { present: false, required: false };
    }
    if (segment === "[]") {
      if (node.type !== "array") {
        return { present: false, required: false };
      }
      if ((node.minItems ?? 0) < 1) {
        required = false;
      }
      node = deref(fileRoot, node.items);
      continue;
    }
    const child = node.properties?.[segment];
    if (child === undefined) {
      return { present: false, required: false };
    }
    if (!(node.required ?? []).includes(segment)) {
      required = false;
    }
    node = deref(fileRoot, child);
  }

  return { present: true, required };
}

/** Where one attribute would live on the wire: which file, which node that
 * file's own root resolves to, and the path from there. `label` is the
 * human-readable form of `path`, used to build `wireSource` and `reason` --
 * kept as a separate field rather than derived from `path` mechanically, so
 * `[]` renders as `[]` beside the field it qualifies (`content[].type`)
 * rather than as a path segment of its own. */
type FieldSite = {
  file: string;
  fileRoot: SchemaNode;
  startNode: SchemaNode | undefined;
  path: string[];
  label: string;
};

function buildRow(attribute: string, span: string, site: FieldSite): TraceRow {
  const { present, required } = resolveField(site.fileRoot, site.startNode, site.path);

  if (!present) {
    return {
      attribute,
      span,
      wireSource: null,
      emittableByWireConsumer: false,
      reason: `${site.file} has no "${site.label}" property -- no wire source for ${attribute}`,
    };
  }

  const wireSource = `${site.file}#${site.label}`;
  if (!required) {
    return {
      attribute,
      span,
      wireSource,
      emittableByWireConsumer: false,
      reason:
        `${site.file}'s "${site.label}" exists but is optional there, so a conformant envelope may omit it -- ` +
        `a wire consumer cannot rely on ${attribute} being emitted`,
    };
  }

  return { attribute, span, wireSource, emittableByWireConsumer: true };
}

export function checkTracePillar(): TraceRow[] {
  const otelMapping = readSpecJson<OtelMappingSchema>("trace/otel-mapping.json");
  const toolCallRequest = readSpecJson<SchemaNode>("hooks/tool-call-request.json");
  const toolCallResult = readSpecJson<SchemaNode>("hooks/tool-call-result.json");
  const sessionEnd = readSpecJson<SchemaNode>("hooks/session-end.json");
  const userMessage = readSpecJson<SchemaNode>("hooks/user-message.json");
  const requestEnvelope = readSpecJson<SchemaNode>("request-envelope.json");
  const responseEnvelope = readSpecJson<SchemaNode>("response-envelope.json");
  const provenance = readSpecJson<SchemaNode>("provenance.json");

  // request-envelope.json's AcsParams.metadata is REQUIRED on every step
  // request (`Metadata` itself requires `agent_id` and `session_id`) --
  // it is the wire source for `acs.session.id` and `acs.agent.id` on every
  // span that needs them, not any hook's own payload schema.
  // `hooks/session-start.json` and `hooks/agent-response.json` declare no
  // `session_id`/`agent_id`-shaped field at all (verified by reading both),
  // which is why neither is read here.
  const acsParams = requestEnvelope.$defs?.AcsParams;
  // response-envelope.json's $defs.AcsResult is read directly, not through
  // a $ref -- there is exactly one place in this file it could come from.
  const acsResult = responseEnvelope.$defs?.AcsResult;

  /** Resolves the wire site for each of the ten (span, attribute) pairs the
   * six in-scope spans' `required_attributes` name. Domain knowledge --
   * which file and field an OTel attribute NAME resolves to -- not
   * something any schema states directly, so it is written here once, by
   * hand, and checked by `resolveField` above rather than trusted. */
  function stepAttributeSite(spanName: string, attribute: string): FieldSite {
    switch (`${spanName}::${attribute}`) {
      case "gen_ai.tool.call::gen_ai.tool.name":
        return { file: "hooks/tool-call-request.json", fileRoot: toolCallRequest, startNode: toolCallRequest, path: ["tool", "name"], label: "tool.name" };
      case "gen_ai.tool.call::acs.capability":
        return { file: "hooks/tool-call-request.json", fileRoot: toolCallRequest, startNode: toolCallRequest, path: ["capability"], label: "capability" };
      case "gen_ai.tool.result::gen_ai.tool.name":
        return { file: "hooks/tool-call-result.json", fileRoot: toolCallResult, startNode: toolCallResult, path: ["tool", "name"], label: "tool.name" };
      case "gen_ai.tool.result::acs.exit_status":
        return { file: "hooks/tool-call-result.json", fileRoot: toolCallResult, startNode: toolCallResult, path: ["exit_status"], label: "exit_status" };
      case "acs.session::acs.session.id":
      case "acs.message.user::acs.session.id":
      case "acs.message.agent::acs.session.id":
        return {
          file: "request-envelope.json",
          fileRoot: requestEnvelope,
          startNode: acsParams,
          path: ["metadata", "session_id"],
          label: "AcsParams.metadata.session_id",
        };
      case "acs.session.end::acs.session.reason":
        return { file: "hooks/session-end.json", fileRoot: sessionEnd, startNode: sessionEnd, path: ["reason"], label: "reason" };
      case "acs.message.user::acs.content.types":
        return {
          file: "hooks/user-message.json",
          fileRoot: userMessage,
          startNode: userMessage,
          path: ["content", "[]", "type"],
          label: "content[].type",
        };
      case "acs.message.agent::acs.agent.id":
        return {
          file: "request-envelope.json",
          fileRoot: requestEnvelope,
          startNode: acsParams,
          path: ["metadata", "agent_id"],
          label: "AcsParams.metadata.agent_id",
        };
      default:
        throw new Error(
          `checkTracePillar: no known wire site for attribute "${attribute}" on span "${spanName}" -- add one to stepAttributeSite`,
        );
    }
  }

  const rows: TraceRow[] = [];

  const stepDefaults = otelMapping.properties.step_to_span.default;
  for (const method of METHODS_IN_SCOPE) {
    const entry = stepDefaults[method];
    if (entry === undefined) {
      throw new Error(`checkTracePillar: trace/otel-mapping.json's step_to_span.default has no entry for "${method}"`);
    }
    for (const attribute of entry.required_attributes) {
      rows.push(buildRow(attribute, entry.span_name, stepAttributeSite(entry.span_name, attribute)));
    }
  }

  // Decision facts ride the "acs.decision" span EVENT, not a step span of
  // their own (module header).
  const DECISION_SPAN = "acs.decision";

  /** Where each `decision_event` attribute lives on `AcsResult`. Explicit,
   * not derived from the attribute name: a mechanical `"acs.".length` slice
   * would be wrong for four of these six, because `acs.evaluator`,
   * `acs.confidence`, `acs.evaluator_version` and `acs.model_id` are not
   * siblings of `AcsResult.decision` -- they live one level deeper, at
   * `AcsResult.metadata.<name>` (verified by reading
   * `response-envelope.json`: `AcsResult.properties.metadata.properties`
   * lists all four; `AcsResult.required` and `metadata`'s own `required`
   * are both silent on them, which is exactly what makes the row red under
   * this module's rule -- metadata itself is optional on `AcsResult`, and
   * none of its own fields is required either). `acs.decision` and
   * `acs.reasoning` remain direct `AcsResult` siblings. A `decision_event`
   * attribute this table does not name throws, rather than silently
   * degrading to "no wire source" the way the mechanical derivation did. */
  function decisionAttributeSite(attribute: string): FieldSite {
    switch (attribute) {
      case "acs.decision":
        return { file: "response-envelope.json", fileRoot: responseEnvelope, startNode: acsResult, path: ["decision"], label: "AcsResult.decision" };
      case "acs.evaluator":
        return {
          file: "response-envelope.json",
          fileRoot: responseEnvelope,
          startNode: acsResult,
          path: ["metadata", "evaluator"],
          label: "AcsResult.metadata.evaluator",
        };
      case "acs.reasoning":
        return { file: "response-envelope.json", fileRoot: responseEnvelope, startNode: acsResult, path: ["reasoning"], label: "AcsResult.reasoning" };
      case "acs.confidence":
        return {
          file: "response-envelope.json",
          fileRoot: responseEnvelope,
          startNode: acsResult,
          path: ["metadata", "confidence"],
          label: "AcsResult.metadata.confidence",
        };
      case "acs.evaluator_version":
        return {
          file: "response-envelope.json",
          fileRoot: responseEnvelope,
          startNode: acsResult,
          path: ["metadata", "evaluator_version"],
          label: "AcsResult.metadata.evaluator_version",
        };
      case "acs.model_id":
        return {
          file: "response-envelope.json",
          fileRoot: responseEnvelope,
          startNode: acsResult,
          path: ["metadata", "model_id"],
          label: "AcsResult.metadata.model_id",
        };
      default:
        throw new Error(
          `checkTracePillar: no known wire site for decision_event attribute "${attribute}" -- add one to decisionAttributeSite`,
        );
    }
  }

  const decisionEvent = otelMapping.properties.decision_event.properties;
  const decisionAttributes = [...decisionEvent.required_attributes.default, ...decisionEvent.conditional_attributes.default];
  for (const attribute of decisionAttributes) {
    rows.push(buildRow(attribute, DECISION_SPAN, decisionAttributeSite(attribute)));
  }

  // Provenance attributes land as ordinary attributes on whichever step
  // span the payload they describe belongs to -- not a span or event of
  // their own (module header), hence the parenthesised, non-literal span.
  // Measured under a narrower, deliberately different rule from every row
  // above -- module header, "acs.provenance.origin is measured under a
  // narrower rule".
  const PROVENANCE_SPAN = "(every step span, when Provenance is attached)";
  for (const attribute of otelMapping.properties.provenance_attributes.properties.required.default) {
    const field = attribute.slice("acs.provenance.".length);
    rows.push(
      buildRow(attribute, PROVENANCE_SPAN, {
        file: "provenance.json",
        fileRoot: provenance,
        startNode: provenance,
        path: [field],
        label: field,
      }),
    );
  }

  return rows;
}
