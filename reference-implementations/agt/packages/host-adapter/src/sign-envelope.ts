/**
 * Request signing for the host side: HKDF key derivation, JCS
 * canonicalization, and HMAC-SHA256 — the mirror of the Guardian's
 * verify-signature.ts. Duplicated here because the host adapter must not
 * import from the Guardian package (test/invariants.test.ts enforces
 * that boundary).
 */
import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import type { AcsRequestEnvelope } from "./build-envelope.ts";

function jcsCanonicalise(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalise).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalise(obj[k])).join(",") + "}";
}

function deriveSessionKey(masterSecret: Buffer, sessionId: string): Buffer {
  return Buffer.from(hkdfSync("sha256", masterSecret, Buffer.alloc(0), sessionId, 32));
}

type SignableRequest = {
  params: { metadata: { session_id: string } };
};

export type SignedRequestEnvelope<T extends SignableRequest> = T & {
  params: T["params"] & {
    signature: { algorithm: string; value: string; key_id: string };
  };
};

export type SignedAcsRequestEnvelope = SignedRequestEnvelope<AcsRequestEnvelope>;

export type ResponseSignatureVerificationResult =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Signs an ACS request envelope with HMAC-SHA256 using an HKDF-derived
 * per-session key (§10). Returns a new envelope with params.signature
 * populated. The original is not mutated.
 */
export function signEnvelope<T extends SignableRequest>(
  envelope: T,
  masterSecret: Buffer,
): SignedRequestEnvelope<T> {
  const sessionId = envelope.params.metadata.session_id;
  const sessionKey = deriveSessionKey(masterSecret, sessionId);

  const { signature: _, ...paramsWithoutSig } = envelope.params as T["params"] & {
    signature?: unknown;
  };
  const signingInput = jcsCanonicalise({ ...envelope, params: paramsWithoutSig });
  const value = createHmac("sha256", sessionKey).update(signingInput).digest("base64");

  return {
    ...envelope,
    params: {
      ...envelope.params,
      signature: { algorithm: "HMAC-SHA256", value, key_id: sessionId },
    },
  };
}

/** Verifies the Guardian's HMAC over a JSON-RPC result or error response. */
export function verifyResponseSignature(
  response: Record<string, unknown>,
  masterSecret: Buffer,
  sessionId: string,
): ResponseSignatureVerificationResult {
  const result = response.result;
  const error = response.error;
  const carrier = typeof result === "object" && result !== null
    ? result as Record<string, unknown>
    : typeof error === "object" && error !== null
      ? error as Record<string, unknown>
      : undefined;
  if (!carrier) {
    return { valid: false, reason: "response carries no result or error to verify" };
  }
  const signature = carrier.signature;
  if (typeof signature !== "object" || signature === null) {
    return { valid: false, reason: "response signature is missing" };
  }
  const fields = signature as Record<string, unknown>;
  if (fields.algorithm !== "HMAC-SHA256") {
    return { valid: false, reason: `unsupported response signature algorithm: ${String(fields.algorithm)}` };
  }
  if (fields.key_id !== sessionId) {
    return { valid: false, reason: "response signature key_id does not match the session" };
  }
  if (typeof fields.value !== "string") {
    return { valid: false, reason: "response signature value is not a string" };
  }

  const { signature: _, ...carrierWithoutSignature } = carrier;
  const input = result === carrier
    ? jcsCanonicalise({ ...response, result: carrierWithoutSignature })
    : jcsCanonicalise({ ...response, error: carrierWithoutSignature });
  const sessionKey = deriveSessionKey(masterSecret, sessionId);
  const computed = createHmac("sha256", sessionKey).update(input).digest();
  const supplied = Buffer.from(fields.value, "base64");
  if (supplied.length !== computed.length || !timingSafeEqual(supplied, computed)) {
    return { valid: false, reason: "response signature mismatch" };
  }
  return { valid: true };
}
