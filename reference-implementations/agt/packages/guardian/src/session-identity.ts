import { createHash } from "node:crypto";
import type { AcsRequestParams } from "./validate-envelope.ts";

/** Consistency of declared identity is not authentication. The deployment must
 * authenticate peers before trusting their first declaration. */
export function sessionIdentityDigest(params: AcsRequestParams): string {
  // A shared session may contain requests from several users. User context
  // remains request-scoped for policy evaluation; only agent and tenant bind.
  // An absent tenant differs from an explicit tenant.
  return createHash("sha256").update(JSON.stringify([
    params.tenant_id ?? null,
    params.metadata.agent_id,
  ])).digest("hex");
}

export class SessionIdentityError extends Error {
  constructor(public readonly reasonCode: string, message: string) { super(message); }
}
