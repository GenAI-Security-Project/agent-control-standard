package guardian

import (
	"context"
	"encoding/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// PolicyEngine decides every step (§12.1). The standard defines its
// interface and leaves the engine to the deployment: the Guardian gives it
// the request envelope, the SessionContext and the Intent, and receives a
// decision.
//
// Decide is called after the step's ContextEntry is appended and before the
// response is signed, under the negotiated decision timeout and the session
// store's lock context. An implementation must be safe for concurrent calls,
// must not mutate its input and must stop promptly when ctx ends. The Guardian
// may stop waiting after cancellation. An error, a timeout or a decision
// without the fields its disposition requires is answered DENY: the step is
// already in the chain, and a transport error would let an Observed Agent on
// the default posture proceed.
type PolicyEngine interface {
	// Policy describes what the engine's policy requires of every session;
	// the ServerHello declares it.
	Policy() PolicyDescription

	// Decide returns the decision for one step.
	Decide(ctx context.Context, in PolicyInput) (PolicyDecision, error)
}

// PolicyDescription is what a policy declares to every Observed Agent in the
// handshake (§4).
type PolicyDescription struct {
	// RequiresProvenance refuses an Observed Agent that declares
	// provenance_producer "none" with PROVENANCE_REQUIRED.
	RequiresProvenance bool
	// ApproverTypes lists the approver types the deployment routes Ask
	// decisions to (approver_types_supported).
	ApproverTypes []acs.ApproverType
}

// PolicyInput is §12.1's input: the request envelope, the SessionContext and
// the Intent. Provenance travels inside the envelope's payload.
type PolicyInput struct {
	// Request is the validated request envelope; its payload is raw JSON
	// that has passed the method's payload schema.
	Request acs.Request
	// Session is the SessionContext after this step's ContextEntry was
	// appended.
	Session SessionContext
}

// SessionContext is the standard's SessionContext (§8) as the engine sees it.
type SessionContext struct {
	SessionID string
	// ChainHash is the head after this step's entry.
	ChainHash string
	Entries   []acs.ContextEntry
	// Intent is nil until the session establishes one (§8.4).
	Intent *acs.Intent
	// Handshake is what the session negotiated.
	Handshake Handshake
	// PolicyState is what the engine returned as State for an earlier step
	// of the session, nil until it returned any.
	PolicyState json.RawMessage
}

// PolicyDecision is §12.1's output: a decision, and what the deployment's
// policy knows that the wire does not carry.
type PolicyDecision struct {
	acs.Decision

	// DelegateToAgent is delegate_to "agent": the deterministic layer asks
	// the agent layer (§12.2) to decide. This Guardian has no agent layer,
	// so it answers DENY with reason code agent_layer_unavailable.
	DelegateToAgent bool

	// Client is what the Observed Agent can apply, which v0.1 leaves to
	// deployment-defined means (§6.5, §9.2). The zero value is an Observed Agent
	// that applies every disposition.
	Client ClientCapability

	// Grant is an approver's intent extension that arrived for this step
	// (§9.1), nil when none did. The engine authenticates the approver and
	// applies the session's scope_mode before returning it, since both are
	// policy.
	Grant *IntentGrant

	// State, when not nil, is valid JSON kept with the session and given back
	// as SessionContext.PolicyState on its later steps, so an engine whose
	// policy carries state across steps keeps it where the chain is kept.
	State json.RawMessage
}

// ClientCapability records what an Observed Agent cannot apply, as the
// deployment determines it.
type ClientCapability struct {
	// CannotApplyModify substitutes DENY with reason code
	// modify_unsupported for a Modify decision, or ALLOW at
	// steps/postCompact (§6.5).
	CannotApplyModify bool
	// CannotResolveAsk substitutes AskSubstitute for an Ask decision
	// (§9.2).
	CannotResolveAsk bool
	// AskSubstitute is Defer or Deny; the policy chooses (§9.2).
	AskSubstitute acs.Disposition
}

// IntentGrant is an approved intent extension and who approved it (§9.1).
type IntentGrant struct {
	Approver  acs.Approver
	Extension acs.IntentExtension
	// AskStepID is the step_id of the step whose Ask the approver answered.
	AskStepID string
}
