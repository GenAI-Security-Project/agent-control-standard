package agtbridge

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func mcpRequest(t *testing.T, message map[string]any) acs.Request {
	t.Helper()
	payload, err := jsonv2.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return acs.Request{Method: "protocols/MCP/tools/call", Params: acs.Params{Payload: payload}}
}

// A call the decision stops is not remembered, so no response can be
// answered as though it ran.
func TestProjectionRemembersOnlyWhatRuns(t *testing.T) {
	var state policyState
	call := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "Bash", "arguments": map[string]any{"command": "ls"}}})
	p, err := project(call, &state)
	if err != nil {
		t.Fatal(err)
	}
	p.settle(&state, acs.Deny)
	if len(state.MCPCalls) != 0 {
		t.Fatalf("a denied call is pending: %v", state.MCPCalls)
	}
	response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 7, "result": map[string]any{"content": []any{}}})
	if _, err := project(response, &state); err == nil {
		t.Fatal("a response to a denied call was projected")
	}
	p.settle(&state, acs.Modify)
	if state.MCPCalls["7"] != "Bash" {
		t.Fatalf("a call let through is not pending: %v", state.MCPCalls)
	}
}

func TestProjectionReaddress(t *testing.T) {
	var state policyState
	call := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "Bash", "arguments": map[string]any{"command": "ls"}}})
	p, err := project(call, &state)
	if err != nil {
		t.Fatal(err)
	}
	override := func(name string) *acs.Modifications {
		return &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{name: json.RawMessage(`"ls -l"`)}}
	}
	if err := p.readdress(override("command")); err != nil {
		t.Fatalf("an override of the call's argument: %v", err)
	}
	for name, mods := range map[string]*acs.Modifications{
		"unknown_argument": override("url"),
		"redaction":        {Redactions: []acs.Redaction{{Path: "/arguments/command/value"}}},
		"whole_message":    {ModifiedContent: new(string)},
	} {
		if err := p.readdress(mods); err == nil {
			t.Errorf("%s: applied to a wrapped MCP request", name)
		}
	}
	p.settle(&state, acs.Allow)
	response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "a"}}}})
	r, err := project(response, &state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.readdress(override("command")); err == nil {
		t.Error("an override was applied to a wrapped MCP response")
	}
	outOfRange := &acs.Modifications{Redactions: []acs.Redaction{{Path: "/outputs/1/value"}}}
	if err := r.readdress(outOfRange); err == nil {
		t.Error("a redaction of an output the response lacks was applied")
	}
}

func TestProjectionKeepsEveryMCPResultShape(t *testing.T) {
	state := policyState{MCPCalls: map[string]string{"1": "Read"}}
	response := mcpRequest(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": "plain"},
				map[string]any{"type": "image", "data": "secret", "mimeType": "image/png"},
				map[string]any{"type": "resource", "resource": map[string]any{"uri": "file:///secret"}},
			},
			"structuredContent": map[string]any{"token": "secret"},
			"_meta":             map[string]any{"trace": "private"},
		},
	})
	p, err := project(response, &state)
	if err != nil {
		t.Fatal(err)
	}
	var result acs.ToolCallResultPayload
	if err := jsonv2.Unmarshal(p.req.Params.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 5 {
		t.Fatalf("projected %d outputs, want text, image, resource, structured content and metadata", len(result.Outputs))
	}
	wantPaths := []string{
		"/result/content/0/text",
		"/result/content/1",
		"/result/content/2",
		"/result/structuredContent",
		"/result/_meta",
	}
	if !slices.Equal(p.outputs, wantPaths) {
		t.Fatalf("output paths %v, want %v", p.outputs, wantPaths)
	}
	mods := &acs.Modifications{Redactions: []acs.Redaction{{Path: "/outputs/3/value"}}}
	if err := p.readdress(mods); err != nil {
		t.Fatal(err)
	}
	if mods.Redactions[0].Path != "/result/structuredContent" {
		t.Fatalf("structured-content redaction points to %q", mods.Redactions[0].Path)
	}
}

// Two calls in flight under one MCP id would make their results
// indistinguishable, so the second is refused until the first is answered.
func TestProjectionRefusesAPendingID(t *testing.T) {
	var state policyState
	call := func(tool string) acs.Request {
		return mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{}}})
	}
	p, err := project(call("Bash"), &state)
	if err != nil {
		t.Fatal(err)
	}
	p.settle(&state, acs.Allow)
	if _, err := project(call("WebFetch"), &state); !errors.Is(err, errMCPCallPending) {
		t.Fatalf("a second call under a pending id: %v", err)
	}
	if _, err := project(mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 3, "result": map[string]any{"content": []any{}}}), &state); err != nil {
		t.Fatal(err)
	}
	if _, err := project(call("WebFetch"), &state); err != nil {
		t.Fatalf("the id once answered: %v", err)
	}
}

func TestProjectionCanonicalizesMCPIDs(t *testing.T) {
	for _, tt := range []struct {
		name, first, equivalent string
	}{
		{"escaped_string", `"a"`, `"\u0061"`},
		{"equivalent_number", `1`, `1.0`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := func(id, tool string) acs.Request {
				payload := json.RawMessage(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`)
				return acs.Request{Method: "protocols/MCP/tools/call", Params: acs.Params{Payload: payload}}
			}
			response := func(id string) acs.Request {
				payload := json.RawMessage(`{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[]}}`)
				return acs.Request{Method: "protocols/MCP/tools/call", Params: acs.Params{Payload: payload}}
			}
			var state policyState
			pending, err := project(request(tt.first, "Bash"), &state)
			if err != nil {
				t.Fatal(err)
			}
			pending.settle(&state, acs.Allow)
			if _, err := project(request(tt.equivalent, "WebFetch"), &state); !errors.Is(err, errMCPCallPending) {
				t.Fatalf("equivalent pending id: %v", err)
			}
			if _, err := project(response(tt.equivalent), &state); err != nil {
				t.Fatalf("equivalent response id: %v", err)
			}
		})
	}
}
