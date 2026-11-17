package method

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

type stub struct{}

func (stub) Protocol() string                    { return "MCP" }
func (stub) Supports(m string) bool              { return m == "tools/call" }
func (stub) Check(string, json.RawMessage) error { return nil }
func (stub) ParameterOverridePointer(argument string) string {
	return "/params/arguments/" + argument
}

func TestRoute(t *testing.T) {
	table := NewTable(stub{})
	tests := map[string]Kind{
		acs.MethodHandshakeHello:   Handshake,
		acs.MethodSystemPing:       Ping,
		acs.StepToolCallRequest:    Hook,
		acs.StepSessionEnd:         Hook,
		"protocols/MCP/tools/call": Wrapped,
		"protocols/A2A/x":          Wrapped,
		acs.MethodAgBOMSnapshot:    Unsupported,
		"wrapped:mcp-1/tools/call": Wrapped,
		"steps/unknown":            Undefined,
		"system/deferredDecision":  Undefined,
		"trace/x":                  Undefined,
	}
	for name, want := range tests {
		if got := table.Route(name); got != want {
			t.Errorf("%s routes to %d, want %d", name, got, want)
		}
	}
	if h, m, ok := table.WrappedHandler("protocols/MCP/tools/call"); !ok || h.Protocol() != "MCP" || m != "tools/call" {
		t.Fatal("the registered handler was not found")
	}
	if h, m, ok := table.WrappedHandler("wrapped:mcp-2025-06-18/tools/call"); !ok || h.Protocol() != "MCP" || m != "tools/call" {
		t.Fatal("the explicit-version form did not find the handler")
	}
	for _, name := range []string{"protocols/A2A/x", "protocols/MCP", "protocols//x", "protocols/MCP/tools/list", "wrapped:mcp/tools/call", "wrapped:a2a-0.2/message/send", acs.StepToolCallRequest} {
		if _, _, ok := table.WrappedHandler(name); ok {
			t.Errorf("%s found a handler", name)
		}
	}
	if len(Hooks()) != 19 {
		t.Fatalf("%d hooks, want the 19 of §5", len(Hooks()))
	}
}

func TestHookRules(t *testing.T) {
	table := NewTable()
	for name, allowed := range map[string][]acs.Disposition{
		acs.StepToolCallRequest: {acs.Allow, acs.Deny, acs.Modify, acs.Ask, acs.Defer},
		acs.StepPostCompact:     {acs.Allow, acs.Modify},
		acs.StepSessionEnd:      {acs.Allow},
		acs.StepSessionStart:    {acs.Allow, acs.Deny},
	} {
		rule := table.HookRule(name)
		for _, d := range []acs.Disposition{acs.Allow, acs.Deny, acs.Modify, acs.Ask, acs.Defer} {
			want := false
			for _, a := range allowed {
				want = want || a == d
			}
			if rule.Permits(d) != want {
				t.Errorf("%s permits %s: %v", name, d, !want)
			}
		}
	}
}

// TestDenyFollowsTheHooksDecisionLines: whether a hook permits DENY is what
// a host's refusal at that hook rests on, so it is read from each hook's
// Decision line in hooks.md. Each line must start with one of the forms in
// decisionForms; a new form fails the test until it is classified.
func TestDenyFollowsTheHooksDecisionLines(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/spec/instrument/hooks.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	hook := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if name, ok := strings.CutPrefix(line, "## "); ok {
			hook = ""
			if !strings.Contains(name, "/") && name != "Overview" && name != "Common envelope" {
				hook = acs.StepsPrefix + name
			}
			continue
		}
		if decision, ok := strings.CutPrefix(line, "**Decision:** "); ok && hook != "" {
			permits, known := permitsDeny(decision)
			if !known {
				t.Fatalf("%s: unclassified Decision line %q; add its form to decisionForms", hook, decision)
			}
			documented[hook] = permits
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(documented)), Hooks()) {
		t.Fatalf("hooks.md documents %v, and the method table holds %v", slices.Sorted(maps.Keys(documented)), Hooks())
	}
	table := NewTable()
	for hook, permitsDeny := range documented {
		if table.HookRule(hook).Permits(acs.Deny) != permitsDeny {
			t.Errorf("%s permits DENY: hooks.md says %v, the method table says %v", hook, permitsDeny, !permitsDeny)
		}
	}
}

// decisionForms are the openings of the Decision lines in hooks.md, and
// whether each permits DENY.
var decisionForms = []struct {
	prefix, states string
	deny           bool
}{
	{"ALLOW / DENY", "", true},
	{"Decision-eligible", "MAY deny", true},
	{"Decision-eligible", "MAY DENY", true},
	{"Decision-eligible", "MAY return DENY", true},
	{"Normally ALLOW. Guardian MAY DENY", "", true},
	{"Not decision-eligible", "", false},
	{"Audit only", "", false},
}

// permitsDeny classifies a Decision line by its opening and, where the
// opening alone does not say, by the sentence that grants DENY.
func permitsDeny(decision string) (permits, known bool) {
	for _, f := range decisionForms {
		if strings.HasPrefix(decision, f.prefix) && strings.Contains(decision, f.states) {
			return f.deny, true
		}
	}
	return false, false
}
