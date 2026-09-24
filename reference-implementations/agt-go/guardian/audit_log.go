package guardian

import (
	"context"
	"encoding/json"
	"time"
)

// AuditLog receives every envelope the Guardian reads or sends and every
// audit event the standard requires of it (§6.5, §8.4, §8.5, §9.2), which
// the standard leaves to "the deployment's own audit log".
//
// Its methods return nothing and must not block or panic: logging must never
// be able to turn a governed step into an ungoverned one. An implementation
// that cannot write reports its own failure. Calls may be concurrent. An
// implementation that retains a record must copy it before returning.
type AuditLog interface {
	Envelope(ctx context.Context, r EnvelopeRecord)
	Event(ctx context.Context, e AuditEvent)
}

// Direction says which way an envelope crossed the wire.
type Direction string

// The two directions of an envelope.
const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// EnvelopeRecord is one envelope as it crossed the wire.
type EnvelopeRecord struct {
	Direction Direction
	// Method is the request's method, empty when the request never parsed
	// far enough to name one.
	Method string
	// Body is the envelope. An inbound body that is not JSON is never
	// recorded; only the response to it is.
	Body       json.RawMessage
	RecordedAt time.Time
}

// AuditEventKind names an audit event the standard requires.
type AuditEventKind string

// The audit events the Guardian records.
const (
	// EventModifyUnsupported: a Modify was substituted for a client that
	// cannot apply it (§6.5).
	EventModifyUnsupported AuditEventKind = "modify_unsupported"
	// EventAskSubstituted: an Ask was substituted for a client that cannot
	// resolve it (§9.2).
	EventAskSubstituted AuditEventKind = "ask_substituted"
	// EventIntentMutationRejected: a step tried to change an established
	// Intent other than through an approver's extension (§8.4).
	EventIntentMutationRejected AuditEventKind = "intent_mutation_rejected"
	// EventChainMismatch: the Observed Agent's chain_hash disagreed with the
	// Guardian's head (§8.6).
	EventChainMismatch AuditEventKind = "chain_mismatch"
	// EventDispositionNotPermitted: a decision the hook does not permit
	// (hooks.md) was replaced, DENY where the hook permits it and ALLOW
	// where it permits only ALLOW. The standard names no event for this;
	// the Guardian records it so no decision is changed silently.
	EventDispositionNotPermitted AuditEventKind = "disposition_not_permitted"
	// EventLineageMismatch: a postCompact summary's derived_from is not the
	// union of the provenance_ids of the entries it compacted, or its origin
	// is not agent_generated (post-compact.json). The hook permits no DENY,
	// so the step is answered ALLOW and the mismatch is recorded.
	EventLineageMismatch AuditEventKind = "lineage_mismatch"
	// EventFailure: a store, signer or engine failed, or the Guardian did.
	// The Message carries the detail the wire does not.
	EventFailure AuditEventKind = "failure"
)

// AuditEvent is one audit event, tied to the step that caused it.
type AuditEvent struct {
	Kind      AuditEventKind
	SessionID string
	RequestID string
	Method    string
	// Message names what happened in words, for example the modification
	// that could not be delivered.
	Message    string
	RecordedAt time.Time
}
