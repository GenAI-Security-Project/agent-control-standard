// Package guardian implements an ACS Guardian. It validates and authenticates
// requests, maintains each session's SessionContext, obtains policy decisions
// and signs every response to an authenticated request. An unsigned
// system/ping response and errors produced before authentication remain
// unsigned.
//
// Everything the standard defines is fixed inside the package. What the
// standard leaves to the deployment is behind four interfaces:
// PolicyEngine decides (§12.1), Signer holds the keys (§10),
// SessionContextStore keeps session state (§8) and AuditLog receives the
// envelopes and the audit events the standard requires.
package guardian
