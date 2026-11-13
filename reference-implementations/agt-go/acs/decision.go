package acs

import "encoding/json"

// Disposition is one of the five decisions of §6.
type Disposition string

// The five dispositions, lowercase as they appear on the wire.
const (
	Allow  Disposition = "allow"
	Deny   Disposition = "deny"
	Modify Disposition = "modify"
	Ask    Disposition = "ask"
	Defer  Disposition = "defer"
)

// Decision is a disposition with the fields of §6.1 that explain and
// qualify it. Reasoning is required for every disposition except Allow;
// Modifications, AskDetails and DeferDetails are required for Modify, Ask
// and Defer respectively.
type Decision struct {
	Disposition Disposition `json:"decision"`
	Reasoning   string      `json:"reasoning,omitzero"`
	ReasonCodes []string    `json:"reason_codes,omitzero"`
	// PolicyReferences is nil when no rule is cited and empty when the
	// decision states that no rule fired.
	PolicyReferences   []PolicyReference   `json:"policy_references,omitzero"`
	PolicyData         json.RawMessage     `json:"policy_data,omitzero"`
	CitedProvenanceIDs []string            `json:"cited_provenance_ids,omitzero"`
	Modifications      *Modifications      `json:"modifications,omitzero"`
	AskDetails         *AskDetails         `json:"ask_details,omitzero"`
	DeferDetails       *DeferDetails       `json:"defer_details,omitzero"`
	Metadata           *EvaluationMetadata `json:"metadata,omitzero"`
}

// PolicyReference names a policy or rule that contributed to a decision.
type PolicyReference struct {
	PolicyID      string `json:"policy_id,omitzero"`
	PolicyVersion string `json:"policy_version,omitzero"`
	PolicyName    string `json:"policy_name,omitzero"`
	RuleID        string `json:"rule_id,omitzero"`
}

// EvaluationMetadata describes how a decision was reached (§6.1).
type EvaluationMetadata struct {
	Evaluator            string   `json:"evaluator,omitzero"`
	EvaluatorVersion     string   `json:"evaluator_version,omitzero"`
	EvaluationDurationMS *int64   `json:"evaluation_duration_ms,omitzero"`
	ModelID              string   `json:"model_id,omitzero"`
	Confidence           *float64 `json:"confidence,omitzero"`
}

// Modifications is the payload of a Modify decision (modifications.json):
// either ModifiedContent alone, or Redactions and ParameterOverrides on
// disjoint targets (§6.3).
type Modifications struct {
	ModifiedContent    *string                    `json:"modified_content,omitzero"`
	Redactions         []Redaction                `json:"redactions,omitzero"`
	ParameterOverrides map[string]json.RawMessage `json:"parameter_overrides,omitzero"`
}

// Redaction replaces the field a JSON pointer addresses.
type Redaction struct {
	Path        string  `json:"path"`
	Replacement *string `json:"replacement,omitzero"`
}

// ApproverType is the kind of approver an Ask decision routes to (§9).
type ApproverType string

// The approver types of §9.
const (
	ApproverHuman   ApproverType = "human"
	ApproverAgent   ApproverType = "agent"
	ApproverService ApproverType = "service"
)

// AskDetails is the payload of an Ask decision (ask-details.json).
type AskDetails struct {
	Approver       Approver `json:"approver"`
	Question       string   `json:"question"`
	Context        *string  `json:"context,omitzero"`
	Options        []string `json:"options,omitzero"`
	TimeoutSeconds int64    `json:"timeout_seconds"`
	// TimeoutDisposition is allow or deny; absent means deny.
	TimeoutDisposition Disposition      `json:"timeout_disposition,omitzero"`
	IntentExtension    *IntentExtension `json:"intent_extension,omitzero"`
}

// Approver identifies who resolves an Ask decision.
type Approver struct {
	Type     ApproverType  `json:"type"`
	ID       string        `json:"id"`
	Endpoint *string       `json:"endpoint,omitzero"`
	Auth     *ApproverAuth `json:"auth,omitzero"`
}

// ApproverAuth describes how a non-human approver authenticates.
type ApproverAuth struct {
	Method *string `json:"method,omitzero"`
}

// IntentExtensionScope says how long an approved intent extension lasts
// (§9.1).
type IntentExtensionScope string

// The two intent extension scopes of §9.1.
const (
	ScopeThisRequest IntentExtensionScope = "this_request"
	ScopeSession     IntentExtensionScope = "session"
)

// IntentExtension carries the capabilities an approver's grant adds to
// Intent.parsed (§9.1).
type IntentExtension struct {
	Capabilities []Capability         `json:"capabilities"`
	Scope        IntentExtensionScope `json:"scope"`
	Provenance   *Provenance          `json:"provenance,omitzero"`
}

// DeferReason is why a Defer decision could not reach a verdict.
type DeferReason string

// The Defer reasons of §6.
const (
	DeferInsufficientContext DeferReason = "insufficient_context"
	DeferConflictingPolicies DeferReason = "conflicting_policies"
	DeferLowConfidence       DeferReason = "low_confidence"
	DeferPendingDependency   DeferReason = "pending_dependency"
)

// ResolutionMethod is how a Defer decision is expected to resolve.
type ResolutionMethod string

// The resolution methods of defer-details.json.
const (
	ResolveAdditionalContext ResolutionMethod = "additional_context"
	ResolveHumanApproval     ResolutionMethod = "human_approval"
	ResolveTimeout           ResolutionMethod = "timeout"
)

// DeferDetails is the payload of a Defer decision (defer-details.json).
type DeferDetails struct {
	Reason              DeferReason      `json:"reason"`
	ResolutionMethod    ResolutionMethod `json:"resolution_method"`
	ResolutionTimeoutMS int64            `json:"resolution_timeout_ms"`
	// TimeoutDecision is deny or ask. §6 requires it on every Defer, so the
	// Guardian fills the default, deny, when an engine leaves it empty.
	TimeoutDecision Disposition `json:"timeout_decision"`
	RequiredContext []string    `json:"required_context,omitzero"`
}
