package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type testEngine struct {
	decisions []acs.Decision
	requests  atomic.Int64
}

func (*testEngine) Policy() guardian.PolicyDescription {
	return guardian.PolicyDescription{ApproverTypes: []acs.ApproverType{acs.ApproverHuman}}
}

func (e *testEngine) Decide(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
	index := int(e.requests.Add(1)) - 1
	if index >= len(e.decisions) {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
	}
	return guardian.PolicyDecision{Decision: e.decisions[index]}, nil
}

func TestRunGovernsRequestAndResult(t *testing.T) {
	engine := &testEngine{decisions: []acs.Decision{
		{
			Disposition: acs.Modify,
			Reasoning:   "rewrite command",
			Modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{
				"command": json.RawMessage(`"printf rewritten"`),
			}},
		},
		{
			Disposition: acs.Modify,
			Reasoning:   "redact output",
			Modifications: &acs.Modifications{Redactions: []acs.Redaction{
				{Path: "/outputs/0/value/content"},
			}},
		},
	}}
	url, calls := testGuardian(t, engine)
	args := optionsFor(url, writeSecret(t), t.TempDir())

	before := runEvent(t, args, `{"event":"execute.before","session_id":"session","message_id":"message","call_id":"call","tool":"bash","input":{"command":"printf original"}}`)
	if before.Decision != acs.Modify || before.UpdatedInput.(map[string]any)["command"] != "printf rewritten" {
		t.Fatalf("before response = %+v", before)
	}
	after := runEvent(t, args, `{"event":"execute.after","session_id":"session","message_id":"message","call_id":"call","tool":"bash","input":{"command":"printf original"},"status":"completed","result":{"content":"secret","metadata":{"safe":true}}}`)
	result := after.UpdatedResult.(map[string]any)
	if after.Decision != acs.Modify || result["content"] != "[REDACTED]" {
		t.Fatalf("after response = %+v", after)
	}
	if calls.Load() != 3 {
		t.Fatalf("Guardian calls = %d, want handshake and two steps", calls.Load())
	}
}

func TestRunBlocksEveryNonProceedingDisposition(t *testing.T) {
	for _, disposition := range []acs.Disposition{acs.Deny, acs.Ask, acs.Defer} {
		t.Run(string(disposition), func(t *testing.T) {
			decision := acs.Decision{Disposition: disposition, Reasoning: "blocked"}
			switch disposition {
			case acs.Ask:
				decision.AskDetails = &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}, Question: "allow?", TimeoutSeconds: 1}
			case acs.Defer:
				decision.DeferDetails = &acs.DeferDetails{Reason: acs.DeferPendingDependency, ResolutionMethod: acs.ResolveTimeout, ResolutionTimeoutMS: 1, TimeoutDecision: acs.Deny}
			}
			engine := &testEngine{decisions: []acs.Decision{decision}}
			url, _ := testGuardian(t, engine)
			response := runEvent(t, optionsFor(url, writeSecret(t), t.TempDir()), `{"event":"execute.before","session_id":"session","message_id":"message","call_id":"call","tool":"bash","input":{"command":"echo safe"}}`)
			if response.Decision != disposition || response.Reasoning != "blocked" {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestExecuteFailsClosed(t *testing.T) {
	var output, diagnostics bytes.Buffer
	status := execute([]string{"--hmac-secret-file", "/missing"}, bytes.NewBufferString("not JSON"), &output, &diagnostics)
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	var response hookOutput
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Decision != acs.Deny || diagnostics.Len() == 0 {
		t.Fatalf("response = %+v, diagnostics = %q", response, diagnostics.String())
	}
}

func TestFailedEventKeepsTheCompleteOpenCodeError(t *testing.T) {
	payload, method, err := payloadFor(hookInput{
		Event: "execute.after", SessionID: "session", MessageID: "message", CallID: "call", Tool: "bash",
		Input: json.RawMessage(`{"command":"false"}`), Status: "error",
		Error: json.RawMessage(`{"message":"failed","error":{"token":"secret"},"metadata":{"exit":1}}`),
	}, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if method != acs.StepToolCallResult {
		t.Fatalf("method = %s", method)
	}
	result := payload.(acs.ToolCallResultPayload)
	if len(result.Outputs) != 1 || !strings.Contains(string(result.Outputs[0].Value), `"token":"secret"`) {
		t.Fatalf("failed result payload = %+v", result)
	}
}

func TestProjectPluginConfiguration(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "..", ".opencode", "plugins", "acs.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{`ctx.tool.hook("execute.before"`, `ctx.tool.hook("execute.after"`, ".acs/bin/acs-opencode-hook"} {
		if !strings.Contains(text, required) {
			t.Fatalf("plugin does not contain %q", required)
		}
	}
	if strings.Contains(text, "setTimeout(") {
		t.Fatal("plugin imposes a process deadline outside the negotiated ACS timeout")
	}
}

func runEvent(t *testing.T, args []string, event string) hookOutput {
	t.Helper()
	var output bytes.Buffer
	if err := run(args, bytes.NewBufferString(event), &output); err != nil {
		t.Fatal(err)
	}
	var response hookOutput
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func testGuardian(t *testing.T, engine guardian.PolicyEngine) (string, *atomic.Int64) {
	t.Helper()
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "default", Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: engine, Signer: signer, OnDecisionFailure: acs.FailureDeny})
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		g.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL, calls
}

func writeSecret(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hmac-secret")
	if err := os.WriteFile(path, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func optionsFor(url, secretFile, stateDir string) []string {
	return []string{"--guardian-url", url, "--hmac-secret-file", secretFile, "--state-dir", stateDir}
}
