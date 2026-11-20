/**
 * Validates Guardian responses against the specification schemas. OpenClaw
 * bundles plugins before load, so the adapter imports schemas instead of
 * reading them from disk. Guardian responses arrive only over the wire.
 * A malformed response provides no usable answer (§6.4).
 */
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { ValidateFunction } from "ajv";
import askDetails from "../../specification/v0.1.0/ask-details.json" with { type: "json" };
import deferDetails from "../../specification/v0.1.0/defer-details.json" with { type: "json" };
import handshake from "../../specification/v0.1.0/handshake.json" with { type: "json" };
import modifications from "../../specification/v0.1.0/modifications.json" with { type: "json" };
import provenance from "../../specification/v0.1.0/provenance.json" with { type: "json" };
import requestEnvelope from "../../specification/v0.1.0/request-envelope.json" with { type: "json" };
import responseEnvelope from "../../specification/v0.1.0/response-envelope.json" with { type: "json" };

/** `response-envelope.json` and its referenced schemas. The test asserts this list. */
export const RESPONSE_SCHEMAS: ReadonlyArray<{ $id: string }> = [
  responseEnvelope, askDetails, deferDetails, handshake, modifications, provenance, requestEnvelope,
];

let ajv: Ajv2020 | undefined;

/** Returns validation errors for `value`, or `undefined` when it passes. */
function schemaFailure(ref: string, value: unknown): string | undefined {
  if (ajv === undefined) {
    ajv = new Ajv2020({ strict: true, allErrors: true, strictRequired: false, allowUnionTypes: true });
    addFormats(ajv);
    for (const schema of RESPONSE_SCHEMAS) {
      ajv.addSchema(schema);
    }
  }
  const validate: ValidateFunction | undefined = ajv.getSchema(ref);
  if (validate === undefined) {
    throw new Error(`the specification has no ${ref}`);
  }
  return validate(value) ? undefined : (validate.errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
}

/** Returns why the full JSON-RPC response fails `response-envelope.json`, or `undefined`. */
export function responseEnvelopeFailure(response: unknown): string | undefined {
  return schemaFailure(responseEnvelope.$id, response);
}

/** Returns why a step decision fails the response schema, or `undefined`. */
export function decisionSchemaFailure(decision: unknown): string | undefined {
  return schemaFailure(`${responseEnvelope.$id}#/$defs/AcsResult`, decision);
}

/** Returns why `serverHello` fails `handshake.json`, or `undefined`. */
export function serverHelloSchemaFailure(serverHello: unknown): string | undefined {
  return schemaFailure(`${handshake.$id}#/$defs/ServerHello`, serverHello);
}
