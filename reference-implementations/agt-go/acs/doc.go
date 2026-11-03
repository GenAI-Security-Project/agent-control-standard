// Package acs declares the wire shapes of the Agent Control Standard v0.1.0:
// the request and response envelopes, the handshake, the decision and its
// disposition-specific details, the SessionContext objects, the hook payloads
// the Guardian reads, the method names and the error codes.
//
// Types follow the v0.1.0 schemas and use their field names. Where another
// normative requirement needs a member that a schema omits, the documented
// extension is called out on the field and in docs/conformance.md. Optional
// fields follow one rule: an optional scalar is a pointer or a string whose
// empty value carries no meaning, a slice or map is nil when absent and
// non-nil when present, and raw JSON is nil when absent. This package defines
// wire shapes; schema validation is performed by guardian.
package acs
