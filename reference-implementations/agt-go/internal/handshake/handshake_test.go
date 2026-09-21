package handshake

import (
	"slices"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		offered []string
		want    string
		ok      bool
	}{
		{[]string{"0.1.0"}, "0.1.0", true},
		{[]string{"0.2.0", "0.1.0"}, "0.1.0", true},
		{[]string{"0.1.3", "0.1.10", "0.1.2"}, "0.1.10", true},
		{[]string{"1.0.0"}, "", false},
		{[]string{"x.y.z", "0.1"}, "", false},
	}
	for _, tt := range tests {
		got, ok := selectVersion(tt.offered, "0.1.0")
		if got != tt.want || ok != tt.ok {
			t.Errorf("%v: got %q, %v", tt.offered, got, ok)
		}
	}
}

type wrapped []string

func (w wrapped) Evaluates(m string) bool { return slices.Contains(w, m) }

func coreHello(extra ...string) acs.ClientHello {
	return acs.ClientHello{
		ACSVersionsSupported: []string{acs.Version},
		MethodsImplemented:   append(CoreMethods(), extra...),
		TransportsSupported:  []string{acs.TransportHTTP},
		ProvenanceProducer:   acs.ProvenanceNone,
		WrappedProtocols:     []acs.WrappedProtocol{{Protocol: "MCP", Version: "2025-06-18"}},
		ProfilesSupported:    []string{acs.ProfileCore},
	}
}

func TestEvaluatedMethods(t *testing.T) {
	client := coreHello(acs.StepToolCallRequest, "steps/unknown", "protocols/MCP/tools/call", "protocols/MCP/tools/list", "protocols/A2A/x", acs.MethodSystemPing)
	hooks := CoreMethods()
	o := Offer{Version: acs.Version, Hooks: hooks, Wrapped: wrapped{"protocols/MCP/tools/call", "protocols/A2A/x"}, Transport: acs.TransportHTTP}
	server, refusal := Negotiate(client, o)
	if refusal != nil {
		t.Fatal(refusal)
	}
	// A2A is not in wrapped_protocols; tools/list has no handler that reads
	// it; the duplicate is listed once.
	want := append(CoreMethods(), "protocols/MCP/tools/call")
	if !slices.Equal(server.MethodsEvaluated, want) {
		t.Fatalf("methods_evaluated %v, want %v", server.MethodsEvaluated, want)
	}
	if !slices.Equal(server.ProfilesAccepted, []string{acs.ProfileCore}) {
		t.Fatalf("profiles_accepted %v", server.ProfilesAccepted)
	}
	// An explicit-version method is evaluated only at the version the client
	// declared.
	pinned := coreHello("wrapped:mcp-2025-06-18/tools/call", "wrapped:mcp-2099-01-01/tools/call")
	o.Wrapped = wrapped{"wrapped:mcp-2025-06-18/tools/call", "wrapped:mcp-2099-01-01/tools/call"}
	server, _ = Negotiate(pinned, o)
	if want := append(CoreMethods(), "wrapped:mcp-2025-06-18/tools/call"); !slices.Equal(server.MethodsEvaluated, want) {
		t.Fatalf("methods_evaluated %v, want %v", server.MethodsEvaluated, want)
	}
	o.Wrapped = wrapped{"protocols/MCP/tools/call"}
	o.Hooks = nil
	if server, _ := Negotiate(client, o); server.MethodsEvaluated == nil || len(server.MethodsEvaluated) != 1 {
		t.Fatalf("methods_evaluated %v", server.MethodsEvaluated)
	}
}

// A Guardian negotiates the capabilities an Observed Agent actually offers.
// ACS-Core is a deployment claim, not a precondition that turns a tool-only
// harness into a rejected session.
func TestPartialObservedAgentIsNegotiated(t *testing.T) {
	o := Offer{Version: acs.Version, Hooks: CoreMethods(), Transport: acs.TransportHTTP}
	client := acs.ClientHello{
		ACSVersionsSupported: []string{acs.Version},
		MethodsImplemented:   []string{acs.StepToolCallRequest, acs.StepToolCallResult},
		TransportsSupported:  []string{acs.TransportHTTP},
		ProvenanceProducer:   acs.ProvenanceNone,
	}
	server, refusal := Negotiate(client, o)
	if refusal != nil {
		t.Fatalf("partial client refused: %+v", refusal)
	}
	if !slices.Equal(server.MethodsEvaluated, client.MethodsImplemented) {
		t.Fatalf("methods_evaluated %v, want %v", server.MethodsEvaluated, client.MethodsImplemented)
	}
	if len(server.ProfilesAccepted) != 0 {
		t.Fatalf("profiles_accepted %v, want none", server.ProfilesAccepted)
	}
}
