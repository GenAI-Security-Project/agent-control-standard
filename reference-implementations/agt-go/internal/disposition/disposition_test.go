package disposition

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func TestCheck(t *testing.T) {
	content := "x"
	override := map[string]json.RawMessage{"command": json.RawMessage(`"ls"`)}
	tests := []struct {
		name string
		d    acs.Decision
		fit  bool
	}{
		{"allow", acs.Decision{Disposition: acs.Allow}, true},
		{"unknown", acs.Decision{Disposition: "maybe"}, false},
		{"deny_without_reasoning", acs.Decision{Disposition: acs.Deny}, false},
		{"deny", acs.Decision{Disposition: acs.Deny, Reasoning: "r"}, true},
		{"modify_without_modifications", acs.Decision{Disposition: acs.Modify, Reasoning: "r"}, false},
		{"modify_empty", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{}}, false},
		{"modify_replacement", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{ModifiedContent: &content}}, true},
		{"modify_replacement_and_override", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{ModifiedContent: &content, ParameterOverrides: override}}, false},
		{"modify_disjoint", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/raw_command"}}, ParameterOverrides: override}}, true},
		{"modify_same_field", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/arguments/command"}}, ParameterOverrides: override}}, false},
		{"modify_descendant", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/arguments/command/value"}}, ParameterOverrides: override}}, false},
		{"modify_ancestor", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/arguments"}}, ParameterOverrides: override}}, false},
		{"modify_root", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: ""}}, ParameterOverrides: override}}, false},
		{"modify_sibling_prefix", acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/arguments/commander"}}, ParameterOverrides: override}}, true},
		{"ask_without_details", acs.Decision{Disposition: acs.Ask, Reasoning: "r"}, false},
		{"defer_without_details", acs.Decision{Disposition: acs.Defer, Reasoning: "r"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.d)
			if (err == nil) != tt.fit || (err != nil && !errors.Is(err, ErrUnfit)) {
				t.Fatalf("Check: %v, want fit=%v", err, tt.fit)
			}
		})
	}
}

func TestSubstitutes(t *testing.T) {
	refs := []acs.PolicyReference{{PolicyID: "p", RuleID: "r"}}
	modify := acs.Decision{Disposition: acs.Modify, Reasoning: "why", PolicyReferences: refs, Modifications: &acs.Modifications{
		Redactions: []acs.Redaction{{Path: "/b"}}, ParameterOverrides: map[string]json.RawMessage{"z": nil, "a": nil},
	}}
	d := ModifyUnsupported(modify)
	if d.Disposition != acs.Deny || d.ReasonCodes[0] != ReasonModifyUnsupported || d.Reasoning != "The Observed Agent cannot apply the modification the policy required (redact /b, override argument a, override argument z), so the step is denied. why" || len(d.PolicyReferences) != 1 {
		t.Fatalf("%+v", d)
	}
	if d := ModifyUnsupportedAtPostCompact(modify); d.Disposition != acs.Allow || d.ReasonCodes[0] != ReasonModifyUnsupported {
		t.Fatalf("%+v", d)
	}
	ask := acs.Decision{Disposition: acs.Ask, Reasoning: "approve", AskDetails: &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverAgent, ID: "a"}, TimeoutSeconds: 2}}
	if d := AskAsDefer(ask); d.DeferDetails.ResolutionMethod != acs.ResolveTimeout || d.DeferDetails.ResolutionTimeoutMS != 2000 || d.DeferDetails.TimeoutDecision != acs.Deny {
		t.Fatalf("%+v", d.DeferDetails)
	}
	if d := AskAsDeny(ask); d.Disposition != acs.Deny || d.ReasonCodes[0] != ReasonApproverUnavailable {
		t.Fatalf("%+v", d)
	}
	deferral := acs.Decision{Disposition: acs.Defer, DeferDetails: &acs.DeferDetails{}}
	if got := WithDeferDefaults(deferral); got.DeferDetails.TimeoutDecision != acs.Deny || deferral.DeferDetails.TimeoutDecision != "" {
		t.Fatal("WithDeferDefaults must fill a copy")
	}
}
