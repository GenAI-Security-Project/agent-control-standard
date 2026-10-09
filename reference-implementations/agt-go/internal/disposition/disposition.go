// Package disposition holds the standard's rules for a decision: the fields
// each disposition requires (§6), the composition of a modification (§6.3),
// and the decisions the Guardian substitutes when an Observed Agent cannot apply one
// (§6.5, §9.2).
package disposition

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// Reason codes the Guardian puts on the decisions it makes itself.
const (
	ReasonModifyUnsupported       = "modify_unsupported"
	ReasonApproverUnavailable     = "approver_unavailable"
	ReasonChainMismatch           = "chain_mismatch"
	ReasonEnvelopeInvalid         = "envelope_invalid"
	ReasonEvaluationFailed        = "evaluation_failed"
	ReasonAgentLayerUnavailable   = "agent_layer_unavailable"
	ReasonDispositionNotPermitted = "disposition_not_permitted"
	ReasonDeferralBoundExceeded   = "deferral_bound_exceeded"
	ReasonIntentMismatch          = "intent_mismatch"
	ReasonSessionClosed           = "session_closed"
	ReasonStoreUnavailable        = "store_unavailable"
	ReasonSessionContended        = "session_contended"
	ReasonStoreFull               = "store_full"
	ReasonSkillUnverifiable       = "skill_unverifiable"
	ReasonLineageMismatch         = "lineage_mismatch"
	ReasonGrantInvalid            = "grant_invalid"
	ReasonShuttingDown            = "shutting_down"
	ReasonEngineSaturated         = "engine_saturated"
	ReasonPolicyStateTooLarge     = "policy_state_too_large"
	ReasonKeyNotBound             = "key_not_bound"
	ReasonAgentIDNotBound         = "agent_id_not_bound"
)

// ErrUnfit reports a decision that breaks a rule of §6 or §6.3.
var ErrUnfit = errors.New("decision is not fit to send")

// Check reports what makes d unfit to send, nil when nothing does: an
// unknown disposition, a missing field its disposition requires, or a
// modification that breaks §6.3's composition rules.
func Check(d acs.Decision) error {
	return CheckWithOverridePointer(d, toolArgumentPointer)
}

// CheckWithOverridePointer applies Check using the payload path an override
// addresses for the request format being governed.
func CheckWithOverridePointer(d acs.Decision, overridePointer func(string) string) error {
	switch d.Disposition {
	case acs.Allow:
		return nil
	case acs.Deny, acs.Modify, acs.Ask, acs.Defer:
	default:
		return fmt.Errorf("%w: unknown disposition %q", ErrUnfit, d.Disposition)
	}
	if d.Reasoning == "" {
		return fmt.Errorf("%w: %s requires reasoning", ErrUnfit, d.Disposition)
	}
	switch d.Disposition {
	case acs.Modify:
		if d.Modifications == nil {
			return fmt.Errorf("%w: modify requires modifications", ErrUnfit)
		}
		return checkModifications(*d.Modifications, overridePointer)
	case acs.Ask:
		if d.AskDetails == nil {
			return fmt.Errorf("%w: ask requires ask_details", ErrUnfit)
		}
	case acs.Defer:
		if d.DeferDetails == nil {
			return fmt.Errorf("%w: defer requires defer_details", ErrUnfit)
		}
	}
	return nil
}

// checkModifications applies §6.3: modified_content stands alone, and
// redactions and parameter_overrides address disjoint fields.
func checkModifications(m acs.Modifications, overridePointer func(string) string) error {
	structured := len(m.Redactions) > 0 || len(m.ParameterOverrides) > 0
	switch {
	case m.ModifiedContent != nil && (m.Redactions != nil || m.ParameterOverrides != nil):
		return fmt.Errorf("%w: modified_content combined with structured edits", ErrUnfit)
	case m.ModifiedContent == nil && !structured:
		return fmt.Errorf("%w: modifications carries no edit", ErrUnfit)
	}
	for _, r := range m.Redactions {
		for key := range m.ParameterOverrides {
			if overlaps(r.Path, overridePointer(key)) {
				return fmt.Errorf("%w: redaction %q and parameter override %q address overlapping fields", ErrUnfit, r.Path, key)
			}
		}
	}
	return nil
}

// toolArgumentPointer is the payload field a parameter override addresses: the
// tool argument of that name (modifications.json).
func toolArgumentPointer(argument string) string {
	return "/arguments/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(argument)
}

// overlaps reports whether one JSON pointer addresses the same field as the
// other or an ancestor or descendant of it.
func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(b, a+"/") || strings.HasPrefix(a, b+"/") || a == "" || b == ""
}

// Deny is the Guardian's own denial.
func Deny(reason, reasoning string) acs.Decision {
	return acs.Decision{Disposition: acs.Deny, Reasoning: reasoning, ReasonCodes: []string{reason}, PolicyReferences: []acs.PolicyReference{}}
}

// ModifyUnsupported is §6.5's substitute for a Modify an Observed Agent cannot apply:
// DENY with reason code modify_unsupported and reasoning that names the
// intended modification.
func ModifyUnsupported(intended acs.Decision) acs.Decision {
	d := Deny(ReasonModifyUnsupported, "The Observed Agent cannot apply the modification the policy required ("+describe(intended.Modifications)+"), so the step is denied. "+intended.Reasoning)
	d.PolicyReferences = intended.PolicyReferences
	return d
}

// ModifyUnsupportedAtPostCompact is §6.5's exception: postCompact permits no
// DENY, so the summary stands, and the Guardian records the rewrite it could
// not deliver.
func ModifyUnsupportedAtPostCompact(intended acs.Decision) acs.Decision {
	return acs.Decision{
		Disposition:      acs.Allow,
		Reasoning:        "The Observed Agent cannot apply the modification the policy required (" + describe(intended.Modifications) + "); the summary stands unmodified.",
		ReasonCodes:      []string{ReasonModifyUnsupported},
		PolicyReferences: intended.PolicyReferences,
	}
}

// AskAsDefer is §9.2's first substitute for an Ask an Observed Agent cannot resolve:
// DEFER with timeout_decision deny, resolved out of band within the Ask's
// own timeout.
func AskAsDefer(ask acs.Decision) acs.Decision {
	method := acs.ResolveTimeout
	var timeoutMS int64
	if ask.AskDetails != nil {
		timeoutMS = ask.AskDetails.TimeoutSeconds * 1000
		if ask.AskDetails.Approver.Type == acs.ApproverHuman {
			method = acs.ResolveHumanApproval
		}
	}
	return acs.Decision{
		Disposition:      acs.Defer,
		Reasoning:        "The Observed Agent cannot route an approval, so the step is deferred until it is approved out of band. " + ask.Reasoning,
		ReasonCodes:      []string{ReasonApproverUnavailable},
		PolicyReferences: ask.PolicyReferences,
		DeferDetails: &acs.DeferDetails{
			Reason:              acs.DeferPendingDependency,
			ResolutionMethod:    method,
			ResolutionTimeoutMS: timeoutMS,
			TimeoutDecision:     acs.Deny,
		},
	}
}

// AskAsDeny is §9.2's second substitute: DENY with reason code
// approver_unavailable and reasoning that names the missing capability.
func AskAsDeny(ask acs.Decision) acs.Decision {
	d := Deny(ReasonApproverUnavailable, "The step needs approval and the Observed Agent cannot route an approval request, so the step is denied. "+ask.Reasoning)
	d.PolicyReferences = ask.PolicyReferences
	return d
}

// WithDeferDefaults fills timeout_decision, which §6 requires on every
// Defer and defaults to deny.
func WithDeferDefaults(d acs.Decision) acs.Decision {
	if d.Disposition == acs.Defer && d.DeferDetails != nil && d.DeferDetails.TimeoutDecision == "" {
		details := *d.DeferDetails
		details.TimeoutDecision = acs.Deny
		d.DeferDetails = &details
	}
	return d
}

func describe(m *acs.Modifications) string {
	if m == nil {
		return "none"
	}
	var parts []string
	if m.ModifiedContent != nil {
		parts = append(parts, "replace the payload")
	}
	for _, r := range m.Redactions {
		parts = append(parts, "redact "+r.Path)
	}
	for _, key := range slices.Sorted(maps.Keys(m.ParameterOverrides)) {
		parts = append(parts, "override argument "+key)
	}
	return strings.Join(parts, ", ")
}
