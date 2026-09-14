/**
 * validateEnvelope checks an incoming ACS request envelope against the
 * v0.1.0 JSON Schemas at the root of this repository
 * (specification/v0.1.0/request-envelope.json), and -- for
 * `steps/toolCallRequest` and `steps/toolCallResult` -- additionally against
 * that method's own hook payload schema (hooks/tool-call-request.json,
 * hooks/tool-call-result.json).
 *
 * It returns an `AcsRequestEnvelope`: a request of ANY method, named the
 * same thing the host's own builder names it
 * (packages/host-adapter/src/build-envelope.ts). Narrowing to a hook-specific
 * view is a separate, explicit step (`isToolCallRequest`,
 * `isToolCallResult`), so a method this module validated only generically can
 * never be read as one whose hook-specific payload was checked.
 *
 * Failure is a thrown, typed EnvelopeValidationError -- never a returned
 * decision. The Guardian server is the caller, and it is responsible for
 * turning a thrown error into a JSON-RPC error response.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { ErrorObject, ValidateFunction } from "ajv";

/** An ACS argument wrapper: `{value, provenance?}`. */
export type AcsArgument = { value: unknown; provenance?: unknown };

/**
 * An ACS output wrapper: `{value, provenance?}` too, per
 * hooks/tool-call-result.json's `outputs` items. Structurally identical to
 * `AcsArgument` and deliberately a separate name, the same choice the host's
 * builder makes (packages/host-adapter/src/build-envelope.ts): what a step was
 * asked to do and what it produced are different things, and one alias for
 * both would read as if the request and result payloads shared a member.
 */
export type AcsOutput = { value: unknown; provenance?: unknown };

/** request-envelope.json's Metadata $def -- method-independent. */
export type AcsRequestMetadata = {
  agent_id: string;
  agent_name?: string;
  session_id: string;
  turn_id?: string;
  parent_turn_id?: string;
  session_state?: { chain_hash?: string };
  environment?: "development" | "staging" | "production";
  platform?: string;
  platform_version?: string;
  user_context?: { user_id?: string; roles?: string[]; authentication_method?: string };
};

/**
 * request-envelope.json's AcsParams $def. `payload` is deliberately as open
 * here as the schema itself leaves it -- "Hook-specific payload. Schema
 * depends on method." -- because that is the honest shape of a request whose
 * method has not been discriminated yet.
 */
export type AcsRequestParams = {
  acs_version: string;
  request_id: string;
  timestamp: string;
  nonce?: string;
  tenant_id?: string;
  metadata: AcsRequestMetadata;
  payload: Record<string, unknown>;
  signature?: { algorithm: string; value: string; key_id: string };
};

/**
 * A validated ACS request of ANY method -- `handshake/hello`,
 * `steps/toolCallRequest`, or anything else request-envelope.json's method
 * pattern admits. This is what `validateEnvelope` returns, and it is the
 * consumer half of the host's `AcsRequestEnvelope`
 * (packages/host-adapter/src/build-envelope.ts): one wire message, one noun,
 * on both sides of the seam.
 *
 * The narrower tool-call shape lives in `ToolCallRequestEnvelope` below, and
 * is reachable only once the method has been checked -- so handshake traffic
 * can never arrive under a name that claims it is a tool call.
 */
export type AcsRequestEnvelope = {
  jsonrpc: "2.0";
  method: string;
  id: string | number;
  params: AcsRequestParams;
};

/**
 * hooks/tool-call-request.json's payload shape -- the payload this module
 * additionally validates when, and only when, the method is
 * `steps/toolCallRequest`.
 */
export type ToolCallRequestPayload = {
  tool: { name: string; version?: string; provider?: string };
  operation?: string;
  capability?: string;
  arguments: Record<string, AcsArgument>;
  raw_command?: string;
  intent?: { description?: string; goal?: string };
};

/**
 * The method-narrowed view of an `AcsRequestEnvelope`: same envelope, with
 * `method` pinned to the one method whose payload has actually been validated
 * against hooks/tool-call-request.json, and `payload` narrowed to that
 * schema's shape.
 *
 * Reachable only through `isToolCallRequest` below, never returned by
 * `validateEnvelope` directly: the narrow type is the conclusion of a method
 * check, not the type every request is handed back as.
 *
 * Spelled with `Omit` rather than an intersection so that `params.payload` is
 * exactly `ToolCallRequestPayload`. An intersection would type-check, but it
 * would leave `Record<string, unknown>`'s index signature in play, so a
 * mistyped property name would quietly resolve to `unknown` instead of
 * becoming an error.
 */
export type ToolCallRequestEnvelope = Omit<AcsRequestEnvelope, "method" | "params"> & {
  method: typeof TOOL_CALL_REQUEST_METHOD;
  params: Omit<AcsRequestParams, "payload"> & { payload: ToolCallRequestPayload };
};

/**
 * hooks/tool-call-result.json's payload shape -- the result gate's own ACS
 * method. That schema requires exactly `tool`, `exit_status` and `outputs`: a
 * different member set from the request payload, not the request payload
 * plus extras. There is no `arguments` here and none is invented -- the wire
 * cannot supply them at this step, and correlation back to the originating
 * request runs through the optional `request_id_ref`, not through carrying
 * state forward.
 */
export type ToolCallResultPayload = {
  tool: { name: string; version?: string; provider?: string };
  operation?: string;
  request_id_ref?: string;
  exit_status: "success" | "failure" | "timeout" | "blocked";
  outputs: AcsOutput[];
  duration_ms?: number;
};

/**
 * The result-gate view of an `AcsRequestEnvelope`, and the sibling of
 * `ToolCallRequestEnvelope` above rather than a widening of it: same envelope,
 * with `method` pinned to the one method whose payload has actually been
 * validated against hooks/tool-call-result.json, and `payload` narrowed to
 * that schema's shape.
 *
 * Reachable only through `isToolCallResult`, for the same reason its twin is
 * reachable only through `isToolCallRequest`, and spelled with the same `Omit`
 * rather than an intersection so `params.payload` is exactly
 * `ToolCallResultPayload` and a typo is an error rather than `unknown`.
 */
export type ToolCallResultEnvelope = Omit<AcsRequestEnvelope, "method" | "params"> & {
  method: typeof TOOL_CALL_RESULT_METHOD;
  params: Omit<AcsRequestParams, "payload"> & { payload: ToolCallResultPayload };
};

/**
 * Thrown when an envelope fails schema validation. `pointer` is the JSON
 * pointer, relative to the envelope root, of the first failing location, so
 * that a human -- or the server's JSON-RPC error mapping -- can find the
 * offending field without re-deriving it from `errors`. For `required`
 * failures it is synthesized from Ajv's instancePath plus missingProperty,
 * because Ajv reports those against the parent object rather than the missing
 * child.
 */
export class EnvelopeValidationError extends Error {
  readonly pointer: string;
  readonly errors: ErrorObject[];

  constructor(pointer: string, errors: ErrorObject[]) {
    const detail = errors[0]?.message ?? "invalid";
    super(`ACS envelope failed schema validation at ${pointer}: ${detail}`);
    this.name = "EnvelopeValidationError";
    this.pointer = pointer;
    this.errors = errors;
  }
}

// Five directories up: this tree sits at reference-implementations/agt
// inside the specification repository, and the schemas it validates
// against are that repository's own, so the two cannot drift apart.
const SCHEMA_ROOT = fileURLToPath(new URL("../../../../../specification/v0.1.0/", import.meta.url));
/** The `$id` base every v0.1.0 schema declares. Exported so check-response.ts
 * derives its id from the same string, and a namespace move is one edit. */
export const SCHEMA_BASE = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/";
const REQUEST_ENVELOPE_SCHEMA_ID = `${SCHEMA_BASE}request-envelope.json`;
const TOOL_CALL_REQUEST_SCHEMA_ID = `${SCHEMA_BASE}hooks/tool-call-request.json`;
const TOOL_CALL_REQUEST_METHOD = "steps/toolCallRequest";
const TOOL_CALL_RESULT_SCHEMA_ID = `${SCHEMA_BASE}hooks/tool-call-result.json`;
const TOOL_CALL_RESULT_METHOD = "steps/toolCallResult";

function listSchemaFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listSchemaFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Builds one Ajv instance with every v0.1.0 schema registered under its own
 * $id -- agbom/, hooks/, inspect/ and trace/ included -- so that the modular
 * $refs between them resolve against $id rather than file path, the way the
 * spec authors intended. One such ref is hooks/tool-call-request.json's
 * argument.provenance pointing at "../provenance.json". Ajv resolves a
 * relative $ref against the referencing schema's own $id as base URI, so
 * registering everything up front is enough; nothing needs inlining or
 * rewriting.
 *
 * strict:true stays on. Every v0.1.0 schema compiles cleanly under it once
 * ajv-formats supplies the "uuid" and "date-time" format validators the
 * schemas declare -- Ajv core recognizes no formats on its own, and strict
 * mode would otherwise reject them as unknown. Nothing else needed disabling.
 */
function buildAjv() {
  const ajv = new Ajv2020({ strict: true, allErrors: true, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv);
  for (const file of listSchemaFiles(SCHEMA_ROOT)) {
    const schema = JSON.parse(readFileSync(file, "utf8")) as { $id?: string };
    if (schema.$id && !ajv.getSchema(schema.$id)) {
      ajv.addSchema(schema);
    }
  }
  return ajv;
}

let ajv: ReturnType<typeof buildAjv> | undefined;

/**
 * Exported so validate-response.ts, this module's outbound twin, can look up
 * response-envelope.json's validator through the same lazily-built Ajv
 * instance this module builds for the inbound side, rather than
 * constructing a second registry that loads the same 44 schema files from
 * the same SCHEMA_ROOT a second time. Sharing the instance, not just the
 * construction code, is what makes "the two validators cannot come to
 * disagree about which spec they check against" true by construction
 * instead of by two call sites happening to stay in sync.
 */
export function getValidator(schemaId: string): ValidateFunction {
  if (!ajv) {
    ajv = buildAjv();
  }
  const validate = ajv.getSchema(schemaId);
  if (!validate) {
    throw new Error(`validate-envelope: schema not registered: ${schemaId}`);
  }
  return validate;
}

/** The JSON pointer an Ajv error names, honoring `required`'s
 * missingProperty (Ajv reports the parent's instancePath there, not the
 * missing child's). */
function pointerOf(error: ErrorObject): string {
  if (error.keyword === "required") {
    const missingProperty = (error.params as { missingProperty: string }).missingProperty;
    return `${error.instancePath}/${missingProperty}`;
  }
  return error.instancePath || "/";
}

function toValidationError(errors: ErrorObject[] | null | undefined, prefix: string): EnvelopeValidationError {
  const list = errors ?? [];
  const firstPointer = list[0] ? pointerOf(list[0]) : "/";
  return new EnvelopeValidationError(`${prefix}${firstPointer}`, list);
}

/** Validates `params.payload` against one hook payload schema, reporting a
 * failure against the payload's own JSON pointer. One helper, so the two
 * methods below cannot come to check their payloads differently. */
function checkHookPayload(envelope: AcsRequestEnvelope, schemaId: string): void {
  const validatePayload = getValidator(schemaId);
  if (!validatePayload(envelope.params.payload)) {
    throw toValidationError(validatePayload.errors, "/params/payload");
  }
}

/**
 * Validates an incoming envelope against request-envelope.json, and -- only
 * when `method` is `steps/toolCallRequest` or `steps/toolCallResult` --
 * additionally validates `params.payload` against that method's own hook
 * schema. Returns the envelope, typed, on success. Throws
 * EnvelopeValidationError on any failure; never returns a decision.
 *
 * Two explicit method checks rather than one table lookup, and each paired
 * with the predicate below that stands for it: what makes the narrow types
 * trustworthy is that the condition under which a payload gets checked and the
 * condition under which it may be read are the same condition, written once
 * per method, in this file.
 */
export function validateEnvelope(input: unknown): AcsRequestEnvelope {
  const validateTopLevel = getValidator(REQUEST_ENVELOPE_SCHEMA_ID);
  if (!validateTopLevel(input)) {
    throw toValidationError(validateTopLevel.errors, "");
  }

  const envelope = input as AcsRequestEnvelope;

  if (envelope.method === TOOL_CALL_REQUEST_METHOD) {
    checkHookPayload(envelope, TOOL_CALL_REQUEST_SCHEMA_ID);
  } else if (envelope.method === TOOL_CALL_RESULT_METHOD) {
    checkHookPayload(envelope, TOOL_CALL_RESULT_SCHEMA_ID);
  }

  return envelope;
}

/**
 * The one way to get from a validated ACS request to the tool-call view of
 * it. Narrows on `method`, which is exactly the condition under which
 * `validateEnvelope` above validated `params.payload` against
 * hooks/tool-call-request.json -- so the narrowing is not a convenient cast,
 * it is a claim the same module already checked.
 *
 * Kept next to that check on purpose: the two must agree about which method
 * carries a tool-call payload, and they can only be trusted to agree while
 * they read the same constant in the same file. A second ACS method adds its
 * own predicate and its own narrow type beside these, rather than widening
 * either.
 */
export function isToolCallRequest(envelope: AcsRequestEnvelope): envelope is ToolCallRequestEnvelope {
  return envelope.method === TOOL_CALL_REQUEST_METHOD;
}

/**
 * The second ACS method's own predicate, and the sibling of
 * `isToolCallRequest` above: same shape, its own method, its own narrow type.
 *
 * One predicate per hook payload, never one predicate answering for two
 * methods. Each of these two stands for a different payload schema and admits
 * a different narrow type, and the caller that dispatches on them
 * (packages/guardian/src/server.ts) turns each answer into a different
 * assembler. A single predicate covering both would make the wrong assembler
 * reachable for a payload whose members it does not have -- read as a
 * governance failure at the far end rather than as the merge it was.
 */
export function isToolCallResult(envelope: AcsRequestEnvelope): envelope is ToolCallResultEnvelope {
  return envelope.method === TOOL_CALL_RESULT_METHOD;
}
