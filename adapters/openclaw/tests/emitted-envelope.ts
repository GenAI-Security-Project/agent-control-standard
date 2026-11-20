/**
 * Checks each emitted envelope against `specification/v0.1.0/`, loaded by
 * relative path as the Guardian loads it. It also checks every `steps/*`
 * payload against its hook schema, even when the Guardian skips that check.
 */
import {
  getValidator,
  SCHEMA_BASE,
  validateEnvelope,
} from "../../../reference-implementations/agt/packages/guardian/src/validate-envelope.ts";

/** Returns why `envelope` fails the specification, or `undefined`. */
export function specificationFailure(envelope: Record<string, unknown>): string | undefined {
  try {
    validateEnvelope(envelope);
  } catch (error) {
    return (error as Error).message;
  }
  const method = envelope.method;
  if (typeof method !== "string" || !method.startsWith("steps/")) {
    return undefined;
  }
  const hook = method.slice("steps/".length).replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
  const validate = getValidator(`${SCHEMA_BASE}hooks/${hook}.json`);
  return validate((envelope.params as { payload?: unknown }).payload)
    ? undefined
    : `${method} payload fails hooks/${hook}.json: ${JSON.stringify(validate.errors)}`;
}
