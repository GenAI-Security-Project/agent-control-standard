import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

/**
 * RFC 8785 JSON Canonicalization Scheme. Deterministic serialization:
 * object keys sorted lexicographically at every depth, no whitespace,
 * numbers via ES2015 Number::toString (which JSON.stringify already uses).
 */
export function jcsCanonicalise(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalise).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalise(obj[k])).join(",") + "}";
}

/**
 * §10: per-session HMAC key is HKDF-derived from deployment-provided IKM
 * together with the session_id.
 */
export function deriveSessionKey(masterSecret: Buffer, sessionId: string): Buffer {
  return Buffer.from(hkdfSync("sha256", masterSecret, Buffer.alloc(0), sessionId, 32));
}

/**
 * Builds the canonical signing input for an ACS request envelope: the full
 * JSON-RPC envelope with params.signature removed, then JCS-canonicalised.
 */
export function signingInput(envelope: Record<string, unknown>): string {
  const params = envelope.params as Record<string, unknown> | undefined;
  if (!params) return jcsCanonicalise(envelope);
  const { signature: _, ...paramsWithoutSig } = params;
  return jcsCanonicalise({ ...envelope, params: paramsWithoutSig });
}

/**
 * Builds the canonical signing input for an ACS response envelope: the full
 * JSON-RPC response with result.signature removed, then JCS-canonicalised.
 */
export function responseSigningInput(response: Record<string, unknown>): string {
  const result = response.result as Record<string, unknown> | undefined;
  if (result) {
    const { signature: _, ...resultWithoutSig } = result;
    return jcsCanonicalise({ ...response, result: resultWithoutSig });
  }
  const error = response.error as Record<string, unknown> | undefined;
  if (error) {
    const { signature: _, ...errorWithoutSig } = error;
    return jcsCanonicalise({ ...response, error: errorWithoutSig });
  }
  return jcsCanonicalise(response);
}

export type SignatureVerificationResult =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verifies an HMAC-SHA256 signature on an ACS request envelope.
 */
export function verifyHmacSha256(
  envelope: Record<string, unknown>,
  signatureValue: string,
  secret: Buffer,
): SignatureVerificationResult {
  const input = signingInput(envelope);
  const computed = createHmac("sha256", secret).update(input).digest();

  let expected: Buffer;
  try {
    expected = Buffer.from(signatureValue, "base64");
  } catch {
    return { valid: false, reason: "signature value is not valid base64" };
  }

  if (computed.length !== expected.length) {
    return { valid: false, reason: "signature length mismatch" };
  }

  if (!timingSafeEqual(computed, expected)) {
    return { valid: false, reason: "signature mismatch" };
  }

  return { valid: true };
}

/**
 * Computes an HMAC-SHA256 signature over a response envelope, returning
 * the base64-encoded value.
 */
export function signResponseHmacSha256(response: Record<string, unknown>, secret: Buffer): string {
  const input = responseSigningInput(response);
  return createHmac("sha256", secret).update(input).digest("base64");
}
