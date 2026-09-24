package mcp

import (
	"encoding/json"
	"testing"
)

func TestSupports(t *testing.T) {
	for m, want := range map[string]bool{
		"initialize":                           true,
		"tools/call":                           true,
		"notifications/resources/list_changed": true,
		"server/discover":                      true,
		"":                                     false,
		"tools/":                               false,
		"/tools":                               false,
		"tools//call":                          false,
		"tools/call?x":                         false,
	} {
		if got := (Handler{}).Supports(m); got != want {
			t.Errorf("Supports(%q) = %v, want %v", m, got, want)
		}
	}
}

// The examples are extend_mcp.md's own: a tools/call request and its
// response, both wrapped under protocols/MCP/tools/call.
func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		payload string
		ok      bool
	}{
		{"request", "tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Barcelona"}}}`, true},
		{"notification", "notifications/initialized", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true},
		{"result", "tools/call", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sunny"}]}}`, true},
		{"error", "tools/call", `{"jsonrpc":"2.0","id":"a","error":{"code":-32602,"message":"unknown tool"}}`, true},
		{"other_method", "tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, false},
		{"version", "tools/call", `{"jsonrpc":"1.0","id":1,"method":"tools/call"}`, false},
		{"params_array", "tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1]}`, false},
		{"id_object", "tools/call", `{"jsonrpc":"2.0","id":{},"method":"tools/call"}`, false},
		{"request_with_result", "tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}`, false},
		{"response_without_id", "tools/call", `{"jsonrpc":"2.0","result":{}}`, false},
		{"result_and_error", "tools/call", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}`, false},
		{"neither", "tools/call", `{"jsonrpc":"2.0","id":1}`, false},
		{"result_not_object", "tools/call", `{"jsonrpc":"2.0","id":1,"result":"x"}`, false},
		{"error_without_code", "tools/call", `{"jsonrpc":"2.0","id":1,"error":{"message":"m"}}`, false},
		{"not_json_rpc", "tools/call", `{"text":"hi"}`, false},
		{"duplicate_member", "tools/call", `{"jsonrpc":"2.0","jsonrpc":"2.0","method":"tools/call"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Handler{}.Check(tt.method, json.RawMessage(tt.payload))
			if (err == nil) != tt.ok {
				t.Fatalf("Check = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
