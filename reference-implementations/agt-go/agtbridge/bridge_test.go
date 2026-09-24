package agtbridge_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// agtTree is the TypeScript reference tree, whose manifest, bundle and
// mapping this engine reads unchanged.
const agtTree = "../../agt"

func newEngine(t *testing.T, opts agtbridge.Options) *agtbridge.Engine {
	t.Helper()
	e, err := agtbridge.New(context.Background(), os.DirFS(agtTree), "policy/manifest.yaml", "mapping.yaml", opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func input(t *testing.T, method string, payload any) guardian.PolicyInput {
	t.Helper()
	b, err := jsonv2.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return guardian.PolicyInput{
		Request: acs.Request{Method: method, Params: acs.Params{RequestID: "6a22a0f7-5547-448a-add7-3327aed144df", Payload: b}},
		Session: guardian.SessionContext{SessionID: "s1"},
	}
}

func toolCall(tool, argument, value string, raw *string) map[string]any {
	p := map[string]any{"tool": map[string]any{"name": tool}, "arguments": map[string]any{argument: map[string]any{"value": value}}}
	if raw != nil {
		p["raw_command"] = *raw
	}
	return p
}

func shell(command string) map[string]any { return toolCall("Bash", "command", command, &command) }

func TestDecisions(t *testing.T) {
	e := newEngine(t, agtbridge.Options{})
	tests := []struct {
		name        string
		method      string
		payload     any
		disposition acs.Disposition
		reason      string
		reasoning   string
	}{
		{"destructive_command", acs.StepToolCallRequest, shell("rm -rf /"), acs.Deny, "destructive_shell_command_blocked",
			"This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."},
		{"destructive_command_echoed", acs.StepToolCallRequest, shell("echo rm -rf /"), acs.Deny, "destructive_shell_command_blocked", ""},
		{"benign_command", acs.StepToolCallRequest, shell("ls -la"), acs.Allow, "", ""},
		{"egress_off_the_allowlist", acs.StepToolCallRequest, shell("git clone https://example.org/repo"), acs.Deny, "egress_destination_not_allowed", ""},
		{"egress_on_the_allowlist", acs.StepToolCallRequest, shell("curl https://docs.example.com/x"), acs.Allow, "", ""},
		{"fetch_on_the_allowlist", acs.StepToolCallRequest, toolCall("WebFetch", "url", "https://docs.example.com/en", nil), acs.Allow, "", ""},
		{"fetch_off_the_allowlist", acs.StepToolCallRequest, toolCall("WebFetch", "url", "https://evil.example.net/", nil), acs.Deny, "egress_destination_not_allowed", ""},
		{"unregistered_tool", acs.StepToolCallRequest, toolCall("Write", "command", "x", nil), acs.Deny, "runtime_error:tool_unknown", ""},
		{"not_governed_by_agt", acs.StepUserMessage, map[string]any{"content": []any{}}, acs.Allow, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := e.Decide(context.Background(), input(t, tt.method, tt.payload))
			if err != nil {
				t.Fatal(err)
			}
			if d.Disposition != tt.disposition {
				t.Fatalf("got %+v, want %s", d.Decision, tt.disposition)
			}
			if tt.reason != "" && !slices.Equal(d.ReasonCodes, []string{tt.reason}) {
				t.Fatalf("reason codes %v, want [%s]", d.ReasonCodes, tt.reason)
			}
			if tt.reason != "" && (len(d.PolicyReferences) != 1 || d.PolicyReferences[0] != (acs.PolicyReference{PolicyID: "agt_stock", RuleID: tt.reason})) {
				t.Fatalf("policy references %+v", d.PolicyReferences)
			}
			if tt.reasoning != "" && d.Reasoning != tt.reasoning {
				t.Fatalf("reasoning %q\nwant      %q", d.Reasoning, tt.reasoning)
			}
		})
	}
}

func TestToolAliasesArePolicyInputOnly(t *testing.T) {
	aliases := map[string]string{"shell": "bash"}
	e := newEngine(t, agtbridge.Options{ToolAliases: aliases})
	aliases["shell"] = "unknown"

	for _, tt := range []struct {
		command string
		want    acs.Disposition
	}{
		{"printf safe", acs.Allow},
		{"echo rm -rf /", acs.Deny},
	} {
		d, err := e.Decide(context.Background(), input(t, acs.StepToolCallRequest, toolCall("shell", "command", tt.command, &tt.command)))
		if err != nil {
			t.Fatal(err)
		}
		if d.Disposition != tt.want {
			t.Fatalf("%q: got %+v, want %s", tt.command, d.Decision, tt.want)
		}
	}

	withoutAlias := newEngine(t, agtbridge.Options{})
	d, err := withoutAlias.Decide(context.Background(), input(t, acs.StepToolCallRequest, toolCall("shell", "command", "printf safe", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Disposition != acs.Deny || !slices.Contains(d.ReasonCodes, "runtime_error:tool_unknown") {
		t.Fatalf("unregistered host tool got %+v", d.Decision)
	}
}

func TestResultRedaction(t *testing.T) {
	e := newEngine(t, agtbridge.Options{})
	secret := "token ghp_abcdef123456 here"
	d, err := e.Decide(context.Background(), input(t, acs.StepToolCallResult, map[string]any{
		"tool": map[string]any{"name": "Bash"}, "exit_status": "success", "outputs": []any{map[string]any{"value": secret}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Disposition != acs.Modify || d.Modifications == nil || len(d.Modifications.Redactions) != 1 {
		t.Fatalf("got %+v", d.Decision)
	}
	r := d.Modifications.Redactions[0]
	if r.Path != "/outputs/0/value" || r.Replacement == nil || strings.Contains(*r.Replacement, "ghp_") || !strings.Contains(*r.Replacement, "[REDACTED]") {
		t.Fatalf("redaction %s -> %v", r.Path, *r.Replacement)
	}
}

func TestNewRefusesAnUnsupportedManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/manifest.yaml", []byte("agent_control_specification_version: \"0.3.1-beta\"\nextends: [\"https://example.com/m.yaml\"]\nintervention_points: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mapping, err := os.ReadFile(agtTree + "/mapping.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/mapping.yaml", mapping, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agtbridge.New(context.Background(), os.DirFS(dir), "manifest.yaml", "mapping.yaml", agtbridge.Options{}); err == nil {
		t.Fatal("accepted a manifest with extends")
	}
}

// TestEscalate drives AGT's escalate verdict through a policy that answers
// it, since the checked-in policy configuration never escalates.
func TestEscalate(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "policy/manifest.yaml", `agent_control_specification_version: "0.3.1-beta"
policies:
  escalating: {type: rego, bundle: lib, query: data.escalating.verdict}
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args.acs_policy_target"
    tool_name_from: "$.tool_call.name"
    policy: {id: escalating}
tools:
  Bash: {type: Tool}
`)
	mustWrite(t, dir, "policy/lib/escalating.rego", "package escalating\n\nverdict := {\"decision\": \"escalate\", \"reason\": \"approval_required\", \"message\": \"needs a human\"}\n")
	mapping, err := os.ReadFile(agtTree + "/mapping.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dir, "mapping.yaml", string(mapping))

	endpoint := "https://approver.example.com"
	authMethod := "mTLS"
	for _, tt := range []struct {
		name     string
		approver *acs.Approver
		want     acs.Disposition
	}{
		{"no_approver", nil, acs.Deny},
		{"approver", &acs.Approver{Type: acs.ApproverService, ID: "security-service", Endpoint: &endpoint, Auth: &acs.ApproverAuth{Method: &authMethod}}, acs.Ask},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, err := agtbridge.New(context.Background(), os.DirFS(dir), "policy/manifest.yaml", "mapping.yaml", agtbridge.Options{Approver: tt.approver})
			if err != nil {
				t.Fatal(err)
			}
			if tt.approver != nil {
				tt.approver.ID = "mutated"
				*tt.approver.Endpoint = "https://mutated.example.com"
				*tt.approver.Auth.Method = "mutated"
			}
			d, err := e.Decide(context.Background(), input(t, acs.StepToolCallRequest, shell("deploy")))
			if err != nil {
				t.Fatal(err)
			}
			if d.Disposition != tt.want {
				t.Fatalf("got %+v", d.Decision)
			}
			if tt.approver == nil {
				if !slices.Contains(d.ReasonCodes, "approver_unavailable") || len(e.Policy().ApproverTypes) != 0 {
					t.Fatalf("got %+v", d.Decision)
				}
				return
			}
			if d.AskDetails == nil || d.AskDetails.Approver.ID != "security-service" || d.AskDetails.Approver.Endpoint == nil ||
				*d.AskDetails.Approver.Endpoint != "https://approver.example.com" || d.AskDetails.Approver.Auth == nil ||
				d.AskDetails.Approver.Auth.Method == nil || *d.AskDetails.Approver.Auth.Method != "mTLS" ||
				d.AskDetails.TimeoutSeconds != 300 || d.AskDetails.Question != d.Reasoning {
				t.Fatalf("ask details %+v", d.AskDetails)
			}
			if !slices.Equal(e.Policy().ApproverTypes, []acs.ApproverType{acs.ApproverService}) {
				t.Fatalf("approver types %v", e.Policy().ApproverTypes)
			}
		})
	}
}

func TestAskTimeoutUsesWholeSeconds(t *testing.T) {
	for _, timeout := range []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond} {
		if _, err := agtbridge.New(context.Background(), os.DirFS("."), "missing", "missing", agtbridge.Options{AskTimeout: timeout}); err == nil {
			t.Errorf("accepted AskTimeout %s", timeout)
		}
	}
}

// TestLabelsRoundTrip: the labels a verdict returns are the source labels of
// the session's next step, and warn arrives as allow with a policy
// reference.
func TestLabelsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "policy/manifest.yaml", `agent_control_specification_version: "0.3.1-beta"
policies:
  labels: {type: rego, bundle: lib, query: data.labels.verdict}
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args.acs_policy_target"
    tool_name_from: "$.tool_call.name"
    policy: {id: labels}
tools:
  Bash: {type: Tool}
`)
	mustWrite(t, dir, "policy/lib/labels.rego", `package labels

import rego.v1

source := input.snapshot.input.ifc.source_labels

verdict := {"decision": "warn", "reason": sprintf("labels_%d", [count(source)]), "result_labels": array.concat(source, ["seen"])}
`)
	mapping, err := os.ReadFile(agtTree + "/mapping.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dir, "mapping.yaml", string(mapping))
	e, err := agtbridge.New(context.Background(), os.DirFS(dir), "policy/manifest.yaml", "mapping.yaml", agtbridge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The engine keeps nothing itself: the labels travel as the session's
	// policy state, which the Guardian stores with the chain.
	var state json.RawMessage
	for _, want := range []string{"labels_1", "labels_2", "labels_3"} {
		in := input(t, acs.StepToolCallRequest, shell("ls"))
		in.Session.PolicyState = state
		d, err := e.Decide(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if d.Disposition != acs.Allow || !slices.Equal(d.ReasonCodes, []string{want}) || len(d.PolicyReferences) != 1 {
			t.Fatalf("got %+v, want allow with %s", d.Decision, want)
		}
		state = d.State
	}
	if d, _ := e.Decide(context.Background(), input(t, acs.StepToolCallRequest, shell("ls"))); !slices.Equal(d.ReasonCodes, []string{"labels_1"}) {
		t.Fatalf("a session with no policy state saw %v", d.ReasonCodes)
	}
}

func TestEmptyLabelsClearSessionState(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "policy/manifest.yaml", `agent_control_specification_version: "0.3.1-beta"
policies:
  labels: {type: rego, bundle: lib, query: data.labels.verdict}
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args.acs_policy_target"
    tool_name_from: "$.tool_call.name"
    policy: {id: labels}
tools:
  Bash: {type: Tool}
`)
	mustWrite(t, dir, "policy/lib/labels.rego", `package labels

import rego.v1

verdict := {"decision": "allow", "result_labels": []}
`)
	mapping, err := os.ReadFile(agtTree + "/mapping.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dir, "mapping.yaml", string(mapping))
	e, err := agtbridge.New(context.Background(), os.DirFS(dir), "policy/manifest.yaml", "mapping.yaml", agtbridge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Decide(context.Background(), input(t, acs.StepToolCallRequest, shell("ls")))
	if err != nil {
		t.Fatal(err)
	}
	if string(d.State) != `{"ifc_labels":[]}` {
		t.Fatalf("state %s, want cleared labels", d.State)
	}
}

func mustWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A tool called through wrapped MCP meets the same AGT gates as one called
// directly, and a redaction of its result is addressed into the MCP message.
func TestWrappedMCPToolCalls(t *testing.T) {
	e := newEngine(t, agtbridge.Options{})
	var state json.RawMessage
	decide := func(method string, payload any) guardian.PolicyDecision {
		t.Helper()
		in := input(t, method, payload)
		in.Session.PolicyState = state
		d, err := e.Decide(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if d.State != nil {
			state = d.State
		}
		return d
	}
	call := func(id int, tool, command string) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{"command": command}}}
	}
	for _, m := range []string{"protocols/MCP/tools/call", "wrapped:mcp-2025-06-18/tools/call"} {
		if d := decide(m, call(1, "Bash", "rm -rf /")); d.Disposition != acs.Deny || !slices.Contains(d.ReasonCodes, "destructive_shell_command_blocked") {
			t.Fatalf("%s: a destructive command through MCP got %+v", m, d.Decision)
		}
	}
	if d := decide("protocols/MCP/tools/call", call(2, "Write", "x")); d.Disposition != acs.Deny || !slices.Contains(d.ReasonCodes, "runtime_error:tool_unknown") {
		t.Fatalf("an unregistered tool through MCP got %+v", d.Decision)
	}
	if d := decide("protocols/MCP/tools/call", call(3, "Bash", "ls")); d.Disposition != acs.Allow {
		t.Fatalf("a benign command through MCP got %+v", d.Decision)
	}
	response := map[string]any{"jsonrpc": "2.0", "id": 3, "result": map[string]any{"content": []any{
		map[string]any{"type": "image", "data": "", "mimeType": "image/png"},
		map[string]any{"type": "text", "text": "token ghp_abcdef123456 here"},
	}}}
	d := decide("protocols/MCP/tools/call", response)
	if d.Disposition != acs.Modify || len(d.Modifications.Redactions) != 1 || d.Modifications.Redactions[0].Path != "/result/content/1/text" {
		t.Fatalf("a secret in an MCP result got %+v", d.Decision)
	}
	// Answered once, the call is no longer pending.
	in := input(t, "protocols/MCP/tools/call", response)
	in.Session.PolicyState = state
	if _, err := e.Decide(context.Background(), in); err == nil {
		t.Fatal("a second response to the same MCP id was decided")
	}
	if d := decide("protocols/MCP/tools/list", map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/list"}); d.Disposition != acs.Allow {
		t.Fatalf("an MCP method AGT has no gate for got %+v", d.Decision)
	}
}
