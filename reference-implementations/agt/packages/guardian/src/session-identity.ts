import { createHash } from "node:crypto";
import type { AcsRequestParams } from "./validate-envelope.ts";

/** Consistency of declared identity is not authentication. The deployment must
 * authenticate peers before trusting their first declaration. */
export function sessionIdentityDigest(params: AcsRequestParams): string {
  const user = params.metadata.user_context;
  // Ignore unknown extension fields and treat role ordering as insignificant.
  // Absence differs from an explicit identity or authentication method.
  return createHash("sha256").update(JSON.stringify([
    params.tenant_id ?? null,
    params.metadata.agent_id,
    user?.user_id ?? null,
    user?.authentication_method ?? null,
    [...new Set(user?.roles ?? [])].sort(),
  ])).digest("hex");
}

export class SessionIdentityError extends Error {
  constructor(public readonly reasonCode: string, message: string) { super(message); }
}
