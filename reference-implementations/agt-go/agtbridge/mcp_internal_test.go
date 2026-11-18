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

// A response names only its id; the Guardian's record of open calls gives
// its tool, and a response to no open call is refused.
func TestProjectionFindsTheToolOfAResponse(t *testing.T) {
	response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 7, "result": map[string]any{"content": []any{}}})
	if _, err := project(response, nil); err == nil {
		t.Fatal("a response to no open call was projected")
	}
	p, err := project(response, map[string]string{"7": "Bash"})
	if err != nil {
		t.Fatal(err)
	}
	var result acs.ToolCallResultPayload
	if err := jsonv2.Unmarshal(p.req.Params.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if p.req.Method != acs.StepToolCallResult || result.Tool.Name != "Bash" {
		t.Fatalf("projected as %s %s", p.req.Method, p.req.Params.Payload)
	}
}

func TestProjectionReaddress(t *testing.T) {
	call := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "Bash", "arguments": map[string]any{"command": "ls"}}})
	p, err := project(call, nil)
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
	response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "a"}}}})
	r, err := project(response, map[string]string{"1": "Bash"})
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
	p, err := project(response, map[string]string{"1": "Read"})
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

// The policy cannot check a response whose result does not decode, so
// project refuses it.
func TestProjectionRefusesAnUndecodableResponse(t *testing.T) {
	for name, result := range map[string]map[string]any{
		"content_not_a_list":    {"content": "token ghp_abcdef123456"},
		"is_error_not_bool":     {"content": []any{}, "isError": "true"},
		"content_missing":       {"structuredContent": map[string]any{"a": 1}},
		"content_null":          {"content": nil},
		"type_empty":            {"resultType": "", "content": []any{}},
		"type_null":             {"resultType": nil, "content": []any{}},
		"type_not_a_string":     {"resultType": 1, "content": []any{}},
		"unknown_type":          {"resultType": "partial", "content": []any{}},
		"input_required_empty":  {"resultType": "input_required"},
		"input_requests_null":   {"resultType": "input_required", "inputRequests": nil},
		"input_requests_list":   {"resultType": "input_required", "inputRequests": []any{}},
		"request_state_number":  {"resultType": "input_required", "requestState": 7},
		"request_state_and_bad": {"resultType": "input_required", "requestState": "s", "inputRequests": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
			if p, err := project(response, map[string]string{"1": "Read"}); !errors.Is(err, errMCPResultUnreadable) {
				t.Fatalf("got %v, projected as %s", err, p.req.Params.Payload)
			}
		})
	}
}

// An MCP error response has no result. Its message and data reach the policy
// as outputs of a failed call.
func TestProjectionKeepsAnMCPError(t *testing.T) {
	response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32000, "message": "denied", "data": map[string]any{"path": "/etc"}}})
	p, err := project(response, map[string]string{"1": "Read"})
	if err != nil {
		t.Fatal(err)
	}
	var result acs.ToolCallResultPayload
	if err := jsonv2.Unmarshal(p.req.Params.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitStatus != exitFailure || len(result.Outputs) != 2 || string(result.Outputs[0].Value) != `"denied"` || string(result.Outputs[1].Value) != `{"path":"/etc"}` {
		t.Fatalf("projected as %s", p.req.Params.Payload)
	}
	if !slices.Equal(p.outputs, []string{"/error/message", "/error/data"}) {
		t.Fatalf("output paths %v", p.outputs)
	}
}

// A response's id finds its call by canonical JSON value, as the Guardian
// records it, not by spelling.
func TestProjectionCanonicalizesMCPIDs(t *testing.T) {
	for _, tt := range []struct {
		name, recorded, response string
	}{
		{"escaped_string", `"a"`, `"\u0061"`},
		{"equivalent_number", `1`, `1.0`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := json.RawMessage(`{"jsonrpc":"2.0","id":` + tt.response + `,"result":{"content":[]}}`)
			response := acs.Request{Method: "protocols/MCP/tools/call", Params: acs.Params{Payload: payload}}
			if _, err := project(response, map[string]string{tt.recorded: "Bash"}); err != nil {
				t.Fatalf("equivalent response id: %v", err)
			}
		})
	}
}

// An input_required result (MCP 2026-07-28) has no content. Its input
// requests reach the policy as an output.
func TestProjectionKeepsAnInputRequiredResult(t *testing.T) {
	requests := json.RawMessage(`{"login":{"method":"elicitation/create","params":{"message":"name?"}}}`)
	for name, tt := range map[string]struct {
		result map[string]any
		// want is the projected outputs, by pointer into the message.
		want map[string]string
	}{
		"requests_and_state": {result: map[string]any{"resultType": "input_required", "inputRequests": requests, "requestState": "opaque"}, want: map[string]string{"/result/inputRequests": `{"login":{"method":"elicitation/create","params":{"message":"name?"}}}`}},
		"state_only":         {result: map[string]any{"resultType": "input_required", "requestState": "opaque"}, want: map[string]string{}},
		"complete_named":     {result: map[string]any{"resultType": "complete", "content": []any{map[string]any{"type": "text", "text": "data"}}}, want: map[string]string{"/result/content/0/text": `"data"`}},
	} {
		t.Run(name, func(t *testing.T) {
			response := mcpRequest(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": tt.result})
			p, err := project(response, map[string]string{"1": "Read"})
			if err != nil {
				t.Fatal(err)
			}
			var result acs.ToolCallResultPayload
			if err := jsonv2.Unmarshal(p.req.Params.Payload, &result); err != nil {
				t.Fatal(err)
			}
			if len(p.outputs) != len(tt.want) {
				t.Fatalf("output paths %v, want %v", p.outputs, tt.want)
			}
			for i, path := range p.outputs {
				if got := string(result.Outputs[i].Value); got != tt.want[path] {
					t.Fatalf("output %s is %s, want %s", path, got, tt.want[path])
				}
			}
		})
	}
}
