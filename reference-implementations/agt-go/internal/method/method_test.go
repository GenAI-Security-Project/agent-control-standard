package method

import (
	"encoding/json"
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
