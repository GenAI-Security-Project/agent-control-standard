/**
 * The trace's vocabulary: what `specification/v0.1.0/trace/otel-mapping.json`
 * says, and the source tables that say where each attribute's value comes from.
 * Shared by the two writers of the same file shape: the Guardian's exporter
 * (otel-trace-exporter.ts) and the audit-log converter (audit-to-otlp.ts).
 *
 * What the mapping does not say is which envelope field feeds which
 * attribute. That is the one piece of knowledge this module adds, in the
 * four source tables below, written once by hand. An attribute the mapping
 * names and no table knows is not emitted, and nothing is invented to fill a
 * slot the wire did not carry. A required attribute the envelope lacks is
 * simply absent, which is itself a fact worth seeing.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Attributes, AttributeValue } from "@opentelemetry/api";

/** The most Provenance objects one step span describes. The attribute
 * length limit in otel-trace-exporter.ts bounds each string, not how many a
 * column holds. Both columns are cut at the same index, so the i-th element
 * of each still describes the same object. */
const PROVENANCE_COLUMN_LIMIT = 64;

/** JSON-RPC REPLAY_DETECTED. The pair on a replayed request belongs to the
 * earlier request, so #228 forbids a failure event for it: one would mark
 * that earlier, legitimate decision as not enforced. */
export const REPLAY_DETECTED_CODE = -32005;
/** JSON-RPC SIGNATURE_INVALID and TIMESTAMP_OUT_OF_WINDOW (Specification
 * §17.1). Defined here beside REPLAY_DETECTED_CODE so the Guardian's checks
 * and the trace's rejection mapping read one number for each. */
export const SIGNATURE_INVALID_CODE = -32004;
export const TIMESTAMP_OUT_OF_WINDOW_CODE = -32006;

// The repository's own mapping, five directories up from this file, the
// same relationship SCHEMA_ROOT in validate-envelope.ts relies on.
const OTEL_MAPPING_PATH = fileURLToPath(
  new URL("../../../../../specification/v0.1.0/trace/otel-mapping.json", import.meta.url),
);

/** The span status for a step answered with an error instead of a decision.
 * One sentence for both writers, the Guardian here and the audit converter,
 * so a query on status text finds both sides of the same failure. */
export const GUARDIAN_ERROR_STATUS = "The Guardian returned an error instead of a decision.";

/**
 * A request this Guardian cannot vouch for, recorded apart from the steps it
 * governed. Trace Events forbids an acs.decision or acs.decision.failure
 * under the pair of a request rejected before it was trusted, because such a
 * request can carry any pair, a genuine request's included. Issue #283 ruled
 * that it is still recorded, under names outside `step_to_span`, so a forged
 * or replayed request stays visible without being attributed to the request
 * whose ids it carries. These names belong to this reference Guardian, not
 * to the ACS mapping.
 */
export const REJECTED_SPAN_NAME = "guardian.rejected_request";
export const REJECTED_CLAIMED_SESSION_ID = "guardian.rejected.claimed_session_id";
export const REJECTED_CLAIMED_REQUEST_ID = "guardian.rejected.claimed_request_id";
export const REJECTED_REASON = "guardian.rejected.reason";
export const REJECTED_ERROR_CODE = "guardian.rejected.error_code";
export const REJECTED_STATUS = "The Guardian could not vouch for this request, so it carries no ACS ids or events.";

/** The longest id an unverified source puts on a span. A real one is a UUID. */
const UNVERIFIED_ID_LIMIT = 128;

/** An id nothing has verified, safe to print: bounded, with control, format
 * and line-separator characters written as `\\uXXXX`, because a reader may
 * decode the attribute into a terminal or a line-based log. A UUID is unchanged. */
export function printableId(value: string): string {
  return value
    .slice(0, UNVERIFIED_ID_LIMIT)
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** Why a request was rejected before it was trusted. `guardian_fault` is the
 * Guardian failing to check the request at all (a missing schema directory,
 * say): its ids are just as unverified, so it is recorded the same way. */
export type RejectionReason =
  | "envelope_invalid"
  | "guardian_fault"
  | "signature_invalid"
  | "replay_detected"
  | "timestamp_out_of_window";

/**
 * The §17.1 codes that mean the Guardian rejected a request before trusting
 * it. dispatch reports its own rejections to the exporter directly. This is
 * the backstop: a step answered with one of these codes is recorded as a
 * rejected request even if the check that produced it forgot to report, so
 * a rejected request's ids never land on a step span.
 */
export const PRE_TRUST_REJECTION_CODES: ReadonlyMap<number, RejectionReason> = new Map([
  [SIGNATURE_INVALID_CODE, "signature_invalid"],
  [REPLAY_DETECTED_CODE, "replay_detected"],
  [TIMESTAMP_OUT_OF_WINDOW_CODE, "timestamp_out_of_window"],
]);

/** The event's attribute keys: the three required ones first, then the
 * ones carried when known. */
export const FAILURE_ATTRIBUTES = {
  class: "acs.failure.class",
  posture: "acs.failure.posture",
  reportedBy: "acs.failure.reported_by",
  detail: "acs.failure.detail",
  errorCode: "acs.failure.error_code",
  timeoutMs: "acs.failure.timeout_ms",
  elapsedMs: "acs.failure.elapsed_ms",
  payloadBytes: "acs.failure.payload_bytes",
} as const;

export const FAILURE_CLASSES = [
  "timeout",
  "unreachable",
  "malformed_response",
  "guardian_error",
  "observed_agent_error",
  "signature_invalid",
  "handshake_failure",
  "other",
] as const;
export type FailureClass = (typeof FAILURE_CLASSES)[number];

export const FAILURE_STATUS: Readonly<Record<FailureClass, string>> = {
  timeout: "No decision arrived before the host's timeout.",
  unreachable: "The host could not reach the Guardian.",
  malformed_response: "An answer arrived that could not be used.",
  guardian_error: GUARDIAN_ERROR_STATUS,
  observed_agent_error: "The host could not build a request for this hook.",
  signature_invalid: "A reply arrived that failed verification.",
  handshake_failure: "The handshake did not complete.",
  other: "The step ended without a usable decision.",
};
export type FailurePosture = "fail_open" | "fail_closed";
export type FailureReporter = "guardian" | "observed_agent";

/** One decision failure, as the event records it. `detail` is required
 * when the class is `other`; the rest travel when known. */
export type DecisionFailure = {
  class: FailureClass;
  posture: FailurePosture;
  reportedBy: FailureReporter;
  detail?: string;
  errorCode?: number;
  timeoutMs?: number;
  elapsedMs?: number;
  payloadBytes?: number;
};

/** The event's attributes: the required three always, the others when
 * present. One function for both reporters, so the Guardian's exporter and the
 * audit-log converter (audit-to-otlp.ts) build the same event. */
export function decisionFailureAttributes(failure: DecisionFailure): Attributes {
  const attributes: Attributes = {
    [FAILURE_ATTRIBUTES.class]: failure.class,
    [FAILURE_ATTRIBUTES.posture]: failure.posture,
    [FAILURE_ATTRIBUTES.reportedBy]: failure.reportedBy,
  };
  if (failure.detail !== undefined) attributes[FAILURE_ATTRIBUTES.detail] = failure.detail;
  if (failure.errorCode !== undefined) attributes[FAILURE_ATTRIBUTES.errorCode] = failure.errorCode;
  if (failure.timeoutMs !== undefined) attributes[FAILURE_ATTRIBUTES.timeoutMs] = failure.timeoutMs;
  if (failure.elapsedMs !== undefined) attributes[FAILURE_ATTRIBUTES.elapsedMs] = failure.elapsedMs;
  if (failure.payloadBytes !== undefined) attributes[FAILURE_ATTRIBUTES.payloadBytes] = failure.payloadBytes;
  return attributes;
}

/** One `step_to_span` entry. `conditional_attributes` is the list #227
 * adds, for attributes the wire carries only sometimes (`acs.capability`
 * among them); read the same way as the other two. */
type StepSpanEntry = {
  span_name: string;
  required_attributes: string[];
  conditional_attributes?: string[];
  optional_attributes?: string[];
};

/**
 * Methods this Guardian evaluates that have no `step_to_span` entry in
 * otel-mapping.json yet, and why. A method here gets no span. The test
 * fails for an evaluated method that is neither mapped nor listed here, so
 * a new method cannot quietly go untraced: it is either mapped or named
 * with its reason.
 */
export const METHODS_WITHOUT_SPAN: Readonly<Record<string, string>> = {};

/** otel-mapping.json is a JSON Schema whose data lives inside `default` and
 * `const` keys. This type names only the ones the loader below reads. */
type OtelMappingSchema = {
  properties: {
    step_to_span: { default: Record<string, StepSpanEntry> };
    step_span_attributes: {
      properties: {
        required_attributes: { default: string[] };
      };
    };
    decision_event: {
      properties: {
        event_name: { const: string };
        required_attributes: { default: string[] };
        conditional_attributes: { default: string[] };
      };
    };
    decision_failure_event: {
      properties: {
        event_name: { const: string };
      };
    };
    provenance_attributes: {
      properties: {
        required: { default: string[] };
        optional: { default: string[] };
      };
    };
  };
};

export type OtelMapping = {
  stepToSpan: Record<string, StepSpanEntry>;
  stepSpanAttributes: string[];
  decisionEventName: string;
  /** The event's required attributes first, then its conditional ones. Both
   * are read the same way (emitted when a value is present), so one list
   * serves. */
  decisionAttributes: string[];
  failureEventName: string;
  /** Required first, then optional. Carried on a step span whose payload
   * has a Provenance object attached, as the mapping's own text says. */
  provenanceAttributes: string[];
};

export function loadOtelMapping(path: string = OTEL_MAPPING_PATH): OtelMapping {
  const schema = JSON.parse(readFileSync(path, "utf8")) as OtelMappingSchema;
  const stepSpan = schema.properties.step_span_attributes.properties;
  const decision = schema.properties.decision_event.properties;
  const failure = schema.properties.decision_failure_event.properties;
  const provenance = schema.properties.provenance_attributes.properties;
  const stepSpanAttributes = stepSpan.required_attributes.default;
  const decisionEventName = decision.event_name.const;
  const failureEventName = failure.event_name.const;
  // Checked here because these are otherwise first read per step. A bad value
  // would load, then cost the exporter on its first step or the converter
  // halfway through a run, after it created its output. One name for both
  // events would let a failure read as a verdict. A listed name with no source
  // would drop the join ids from every span and report nothing.
  if (typeof decisionEventName !== "string" || decisionEventName === "") {
    throw new Error(`${path}: decision_event.event_name has no const string`);
  }
  if (typeof failureEventName !== "string" || failureEventName === "") {
    throw new Error(`${path}: decision_failure_event.event_name has no const string`);
  }
  if (decisionEventName === failureEventName) {
    throw new Error(`${path}: decision_event and decision_failure_event share one event_name`);
  }
  if (!Array.isArray(stepSpanAttributes) || stepSpanAttributes.some((name) => !Object.hasOwn(CORRELATION_ATTRIBUTE_SOURCES, name))) {
    throw new Error(`${path}: step_span_attributes must list only ${Object.keys(CORRELATION_ATTRIBUTE_SOURCES).join(" and ")}`);
  }
  return {
    stepToSpan: schema.properties.step_to_span.default,
    stepSpanAttributes,
    decisionEventName,
    decisionAttributes: [...decision.required_attributes.default, ...decision.conditional_attributes.default],
    failureEventName,
    provenanceAttributes: [...provenance.required.default, ...provenance.optional.default],
  };
}

export type JsonObject = Record<string, unknown>;

export function asObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as JsonObject) : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** A non-empty array of strings, or nothing. An empty array is carried by
 * the wire (`policy_references: []` on an envelope-invalid deny) but says
 * nothing a reader can use, so it is not emitted. */
function asStrings(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  return value.every((item) => typeof item === "string") ? (value as string[]) : undefined;
}

/**
 * One column of `policy_references`, in the wire's own order: the same
 * length as `policy_references`, with `""` where a reference lacks the
 * field. That is the rule agreed on #228, so a reader lines the three
 * columns up by position and never loses the values the other references
 * did carry. Absent only when there are no references at all.
 */
function policyColumn(references: unknown, field: string): string[] | undefined {
  if (!Array.isArray(references) || references.length === 0) return undefined;
  return references.map((reference) => asString(asObject(reference)?.[field]) ?? "");
}

/** The parts of a request envelope the source tables read. Read off the
 * parsed JSON rather than the validated envelope, because the span starts
 * before validation runs and an envelope that fails the schema is still a
 * step this session took. */
export type RequestParts = { params: JsonObject; metadata: JsonObject; payload: JsonObject; tool: JsonObject };

export function requestParts(envelope: unknown): RequestParts {
  const params = asObject(asObject(envelope)?.params) ?? {};
  const metadata = asObject(params.metadata) ?? {};
  const payload = asObject(params.payload) ?? {};
  const tool = asObject(payload.tool) ?? {};
  return { params, metadata, payload, tool };
}

/** The decision half of a success response: the `result` and its optional
 * `metadata`. `undefined` for a JSON-RPC error response, which carries no
 * decision. */
export type ResultParts = { result: JsonObject; metadata: JsonObject };

export function resultParts(response: unknown): ResultParts | undefined {
  const result = asObject(asObject(response)?.result);
  if (result === undefined) return undefined;
  return { result, metadata: asObject(result.metadata) ?? {} };
}

export type Source<Parts> = (parts: Parts) => AttributeValue | undefined;

/**
 * Attribute name -> where it is read from on the request envelope, for every
 * attribute `step_to_span` can name on a span this Guardian emits. The
 * mapping decides WHICH of these a span carries; this table only says HOW
 * each one is read. Paths follow the hook payload schemas
 * (`hooks/tool-call-request.json`, `hooks/tool-call-result.json`) and
 * `request-envelope.json`'s `AcsParams.metadata`.
 */
export const STEP_ATTRIBUTE_SOURCES: Readonly<Record<string, Source<RequestParts>>> = {
  "acs.session.id": (r) => asString(r.metadata.session_id),
  "acs.agent.id": (r) => asString(r.metadata.agent_id),
  "gen_ai.tool.name": (r) => asString(r.tool.name),
  "acs.tool.provider": (r) => asString(r.tool.provider),
  "acs.tool.version": (r) => asString(r.tool.version),
  "acs.capability": (r) => asString(r.payload.capability),
  "acs.operation": (r) => asString(r.payload.operation),
  "acs.exit_status": (r) => asString(r.payload.exit_status),
  "acs.duration_ms": (r) => asNumber(r.payload.duration_ms),
  "acs.request_id_ref": (r) => asString(r.payload.request_id_ref),
};

/** The ids that join a step across the Guardian's spans and the converter's.
 * Each writer reads them from its own input: the envelope, or the audit entry. */
export type CorrelationIds = { sessionId: string | undefined; requestId: string | undefined };

export function requestCorrelationIds(parts: RequestParts): CorrelationIds {
  return { sessionId: asString(parts.metadata.session_id), requestId: asString(parts.params.request_id) };
}

/**
 * Attribute name -> which id fills it, for every name `step_span_attributes`
 * can list. Both writers read this through `correlationAttributes`, so the
 * mapping alone decides which ids a span carries. loadOtelMapping refuses a listed name with
 * no row here, the check `packages/conformance/src/trace-pillar.ts` makes on
 * its own table, so a renamed attribute stops the run instead of dropping the
 * join ids.
 */
export const CORRELATION_ATTRIBUTE_SOURCES: Readonly<Record<string, Source<CorrelationIds>>> = {
  "acs.session.id": (ids) => ids.sessionId,
  "acs.request_id": (ids) => ids.requestId,
};

/** The join attributes for one span: the names the mapping lists, in this
 * table's order, so the order of the mapping's list cannot reorder every span
 * and every example copied from one. */
export function correlationAttributes(ids: CorrelationIds, listed: readonly string[]): Attributes {
  const attributes: Attributes = {};
  const names = Object.keys(CORRELATION_ATTRIBUTE_SOURCES).filter((name) => listed.includes(name));
  collect(attributes, names, CORRELATION_ATTRIBUTE_SOURCES, ids);
  return attributes;
}

/**
 * The `acs.decision` event's attributes, for every name the mapping's
 * `decision_event` lists. Paths follow `response-envelope.json`'s
 * `AcsResult`: `decision` and `reasoning` are direct members; the other four
 * sit under `metadata`. `acs.evaluator` is read off the wire like the rest
 * and never filled in here: the value this Guardian would send is
 * `deterministic`, but it has to come from the Guardian's response (#229
 * puts it there), or the trace says something the wire never said and a
 * reader cannot tell the two apart.
 */
export const DECISION_ATTRIBUTE_SOURCES: Readonly<Record<string, Source<ResultParts>>> = {
  "acs.decision": (d) => asString(d.result.decision),
  "acs.evaluator": (d) => asString(d.metadata.evaluator),
  "acs.reasoning": (d) => asString(d.result.reasoning),
  "acs.confidence": (d) => asNumber(d.metadata.confidence),
  "acs.evaluator_version": (d) => asString(d.metadata.evaluator_version),
  "acs.model_id": (d) => asString(d.metadata.model_id),
  // The decision facts #228 adds to the mapping. Each is emitted only when
  // the response carries it; `acs.chain_hash` in particular appears only once
  // a Guardian puts the chain head on the wire.
  "acs.reason_codes": (d) => asStrings(d.result.reason_codes),
  "acs.policy.ids": (d) => policyColumn(d.result.policy_references, "policy_id"),
  "acs.policy.versions": (d) => policyColumn(d.result.policy_references, "policy_version"),
  "acs.policy.rule_ids": (d) => policyColumn(d.result.policy_references, "rule_id"),
  "acs.cited_provenance_ids": (d) => asStrings(d.result.cited_provenance_ids),
  "acs.chain_hash": (d) => asString(d.result.chain_hash),
};

export function asClampedErrorCode(value: unknown): number | undefined {
  if (typeof value !== "number" || Number.isNaN(value)) return undefined;
  return Math.max(Number.MIN_SAFE_INTEGER, Math.min(Number.MAX_SAFE_INTEGER, value));
}

/**
 * Attribute name -> which field of a Provenance object (`provenance.json`)
 * it reads. Unlike the tables above, each of these becomes a COLUMN: one
 * array per attribute, one element per Provenance object the payload
 * carries, in wire order. A span has one value per attribute key, and a
 * payload can carry several Provenance objects (one per argument), so an
 * array is the only shape that keeps every object visible; the i-th element
 * of each column describes the i-th object, and `acs.provenance.origin` is
 * always complete because provenance.json requires `origin`.
 *
 * `acs.provenance.lineage_depth` is in the mapping's optional list and has
 * no entry here. provenance.json defines no lineage_depth field, so there is
 * nothing on the wire to read it from, and deriving one (from the length of
 * `derived_from`, say) would be a value nobody sent.
 */
export const PROVENANCE_ATTRIBUTE_SOURCES: Record<string, (provenance: JsonObject) => string | undefined> = {
  "acs.provenance.origin": (p) => asString(p.origin),
  "acs.provenance.source_id": (p) => asString(p.source_id),
};

/** The Provenance objects a payload carries, in wire order: one per
 * argument that has one, in the order the parsed object holds them, then one
 * per output that has one, in array order. "Parsed" order rather than the
 * bytes' order because `JSON.parse` has already hoisted integer-like
 * argument names ahead of the rest (envelope-log-sink.ts notes `{"0": ...}`
 * is a real shape), so this is the order every reader of the envelope log
 * sees too. The two never meet on one payload (the request gate carries
 * `arguments`, the result gate `outputs`), and an argument or output
 * without one contributes nothing. */
export function provenanceObjects(payload: JsonObject): JsonObject[] {
  const carriers: unknown[] = [
    ...Object.values(asObject(payload.arguments) ?? {}),
    ...(Array.isArray(payload.outputs) ? payload.outputs : []),
  ];
  const found: JsonObject[] = [];
  for (const carrier of carriers) {
    if (found.length === PROVENANCE_COLUMN_LIMIT) {
      break;
    }
    const provenance = asObject(asObject(carrier)?.provenance);
    if (provenance !== undefined) {
      found.push(provenance);
    }
  }
  return found;
}

/** One column over every Provenance object, in order, padded with `""`
 * where an object lacks the field, which is the same rule policyColumn applies, for
 * the same reason: every column is the length of `acs.provenance.origin`, so
 * the i-th element of each describes the i-th object, and a `source_id` one
 * argument carries is never hidden by another argument that has none. */
export function provenanceColumn(objects: JsonObject[], read: (provenance: JsonObject) => string | undefined): string[] {
  return objects.map((object) => read(object) ?? "");
}

export function collect<Parts>(into: Attributes, names: Iterable<string>, sources: Record<string, Source<Parts>>, parts: Parts): void {
  for (const name of names) {
    const value = Object.hasOwn(sources, name) ? sources[name]?.(parts) : undefined;
    if (value !== undefined) {
      into[name] = value;
    }
  }
}
