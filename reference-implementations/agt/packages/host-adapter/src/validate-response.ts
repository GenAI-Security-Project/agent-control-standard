/**
 * Validates a Guardian response before the host accepts its result as an ACS
 * decision. The schema is the repository's response-envelope.json. Every
 * v0.1.0 schema is registered first so its relative references resolve from
 * the canonical `$id` graph.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { ErrorObject } from "ajv";

const SCHEMA_ROOT = fileURLToPath(new URL("../../../../../specification/v0.1.0/", import.meta.url));
const SCHEMA_BASE = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/";
const RESPONSE_ENVELOPE_SCHEMA_ID = `${SCHEMA_BASE}response-envelope.json`;
const ACS_RESULT_SCHEMA_ID = `${RESPONSE_ENVELOPE_SCHEMA_ID}#/$defs/AcsResult`;

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

function buildValidators() {
  const ajv = new Ajv2020({ strict: true, allErrors: false, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv);
  const schemaIds = new Set<string>();
  for (const file of listSchemaFiles(SCHEMA_ROOT)) {
    const schema = JSON.parse(readFileSync(file, "utf8")) as { $id?: string };
    if (schema.$id) {
      if (schemaIds.has(schema.$id)) {
        throw new Error(`duplicate schema id: ${schema.$id}`);
      }
      schemaIds.add(schema.$id);
      ajv.addSchema(schema);
    }
  }
  const responseEnvelope = ajv.getSchema(RESPONSE_ENVELOPE_SCHEMA_ID);
  if (!responseEnvelope) {
    throw new Error(`response schema is not registered: ${RESPONSE_ENVELOPE_SCHEMA_ID}`);
  }
  const acsResult = ajv.getSchema(ACS_RESULT_SCHEMA_ID);
  if (!acsResult) {
    throw new Error(`decision result schema is not registered: ${ACS_RESULT_SCHEMA_ID}`);
  }
  return { responseEnvelope, acsResult };
}

let validators: ReturnType<typeof buildValidators> | undefined;

function pointerOf(error: ErrorObject | undefined): string {
  if (!error) return "/";
  if (error.keyword === "required") {
    const missing = (error.params as { missingProperty: string }).missingProperty;
    return `${error.instancePath}/${missing}`;
  }
  return error.instancePath || "/";
}

/** A Guardian answered, but its response does not satisfy the ACS contract. */
export class GuardianResponseValidationError extends Error {
  readonly pointer: string;

  constructor(pointer: string, detail: string) {
    super(`Guardian response failed response-envelope.json at ${pointer}: ${detail}`);
    this.name = "GuardianResponseValidationError";
    this.pointer = pointer;
  }
}

/** The host could not run its local canonical-schema validator. */
export class GuardianResponseValidatorError extends Error {
  constructor(detail: string) {
    super(`Host could not validate the Guardian response: ${detail}`);
    this.name = "GuardianResponseValidatorError";
  }
}

/** The envelope is canonical, but its result is not valid for a decision method. */
export class GuardianDecisionResponseError extends Error {
  readonly pointer: string;

  constructor(pointer: string, detail: string) {
    super(`Guardian response to a decision method failed the AcsResult contract at ${pointer}: ${detail}`);
    this.name = "GuardianDecisionResponseError";
    this.pointer = pointer;
  }
}

function getValidators(): ReturnType<typeof buildValidators> {
  try {
    return validators ?? (validators = buildValidators());
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new GuardianResponseValidatorError(detail);
  }
}

function runValidator(validate: ReturnType<typeof buildValidators>["responseEnvelope"], value: unknown): boolean {
  let valid: boolean;
  try {
    valid = validate(value) as boolean;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new GuardianResponseValidatorError(detail);
  }
  return valid;
}

/** Throws when `response` is not a canonical ACS response envelope. */
export function validateGuardianResponse(response: unknown): void {
  const validate = getValidators().responseEnvelope;
  if (runValidator(validate, response)) return;

  const first = validate.errors?.[0];
  throw new GuardianResponseValidationError(pointerOf(first), first?.message ?? "invalid response");
}

/** Throws when a canonical response's result is not an AcsResult for a decision method. */
export function validateGuardianDecisionResult(result: unknown): void {
  const validate = getValidators().acsResult;
  if (runValidator(validate, result)) return;

  const first = validate.errors?.[0];
  throw new GuardianDecisionResponseError(pointerOf(first), first?.message ?? "invalid decision result");
}
