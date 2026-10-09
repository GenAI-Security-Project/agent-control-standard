package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/envelope"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type testEngine struct {
	decision acs.Decision
	policy   guardian.PolicyDescription
	requests atomic.Int64
}

func (e *testEngine) Policy() guardian.PolicyDescription { return e.policy }

func (e *testEngine) Decide(_ context.Context, _ guardian.PolicyInput) (guardian.PolicyDecision, error) {
	e.requests.Add(1)
	return guardian.PolicyDecision{Decision: e.decision}, nil
}

func TestRunSendsSignedDecisionAndReusesHandshake(t *testing.T) {
	engine := &testEngine{decision: acs.Decision{Disposition: acs.Allow}}
	url, calls := testGuardian(t, engine)
	secretFile := writeSecret(t)
	stateDir := t.TempDir()
	for _, toolUseID := range []string{"tool-1", "tool-2"} {
		var output bytes.Buffer
		if err := run(optionsFor(url, secretFile, stateDir), bytes.NewBufferString(event(toolUseID)), &output); err != nil {
			t.Fatal(err)
		}
		assertOutput(t, output.Bytes(), "", "", "")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("Guardian calls = %d, want handshake + two steps", got)
	}
	if got := engine.requests.Load(); got != 2 {
		t.Fatalf("policy calls = %d, want 2", got)
	}
}

func TestRunTranslatesDecisions(t *testing.T) {
	tests := []struct {
		name, wantDecision, wantReason, wantCommand string
		disposition                                 acs.Disposition
		modifications                               *acs.Modifications
	}{
		{name: "allow", disposition: acs.Allow},
		{name: "deny", disposition: acs.Deny, wantDecision: "deny", wantReason: "policy decision"},
		{name: "ask", disposition: acs.Ask, wantDecision: "deny", wantReason: "policy decision"},
		{name: "modify", disposition: acs.Modify, wantDecision: "allow", wantReason: "policy decision", wantCommand: "printf rewritten", modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{"command": json.RawMessage(`"printf rewritten"`)}}},
		{name: "modify_raw_command", disposition: acs.Modify, wantDecision: "deny", wantReason: "the Codex hook cannot apply the Guardian modification", modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/raw_command"}}}},
		{name: "modify_non_string_command", disposition: acs.Modify, wantDecision: "deny", wantReason: "the Codex hook cannot apply the Guardian modification", modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{"command": json.RawMessage(`42`)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := acs.Decision{Disposition: tt.disposition, Reasoning: "policy decision", Modifications: tt.modifications}
			if tt.disposition == acs.Ask {
				decision.AskDetails = &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}, Question: "approve?", TimeoutSeconds: 1}
			}
			engine := &testEngine{decision: decision}
			if tt.disposition == acs.Ask {
				engine.policy.ApproverTypes = []acs.ApproverType{acs.ApproverHuman}
			}
			url, _ := testGuardian(t, engine)
			stateDir := t.TempDir()
			var output bytes.Buffer
			if err := run(optionsFor(url, writeSecret(t), stateDir), bytes.NewBufferString(event("tool-1")), &output); err != nil {
				t.Fatal(err)
			}
			assertOutput(t, output.Bytes(), tt.wantDecision, tt.wantReason, tt.wantCommand)
			audit := readAudit(t, stateDir)
			refused := tt.wantReason == "the Codex hook cannot apply the Guardian modification"
			if refused != strings.Contains(audit, `"event":"modify_unsupported"`) ||
				refused != strings.Contains(audit, `"reason_codes":["modify_unsupported"]`) {
				t.Fatalf("audit log = %q", audit)
			}
		})
	}
}

func TestRunDeniesAHandshakeRefusal(t *testing.T) {
	engine := &testEngine{policy: guardian.PolicyDescription{RequiresProvenance: true}}
	url, _ := testGuardian(t, engine)
	var output bytes.Buffer
	if err := run(optionsFor(url, writeSecret(t), t.TempDir()), bytes.NewBufferString(event("tool-1")), &output); err != nil {
		t.Fatal(err)
	}
	assertOutput(t, output.Bytes(), "deny", "the Guardian did not accept this ACS session", "")
}

func TestRunRecordsAProceedFailure(t *testing.T) {
	engine := &testEngine{decision: acs.Decision{Disposition: acs.Allow}}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "default", Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: engine, Signer: signer, OnDecisionFailure: acs.FailureProceed})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			g.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	var output bytes.Buffer
	if err := run(optionsFor(server.URL, writeSecret(t), stateDir), bytes.NewBufferString(event("tool-1")), &output); err != nil {
		t.Fatal(err)
	}
	assertOutput(t, output.Bytes(), "", "", "")
	if audit := readAudit(t, stateDir); !strings.Contains(audit, `"event":"decision_failure"`) {
		t.Fatalf("audit event = %s", audit)
	}
}

// A refused modification stays denied when its audit record cannot be written,
// and the reason says so.
func TestRunDeniesWhenTheAuditRecordFails(t *testing.T) {
	engine := &testEngine{decision: acs.Decision{Disposition: acs.Modify, Reasoning: "policy decision", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/raw_command"}}}}}
	url, _ := testGuardian(t, engine)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(optionsFor(url, writeSecret(t), t.TempDir()), "--audit-log", filepath.Join(blocker, "audit.jsonl"))
	var output bytes.Buffer
	if err := run(args, bytes.NewBufferString(event("tool-1")), &output); err != nil {
		t.Fatal(err)
	}
	assertOutput(t, output.Bytes(), "deny", "the Codex hook cannot apply the Guardian modification; the local audit record could not be written", "")
}

// §6.3: a signed MODIFY combining a replacement with edits is DENY, and the
// substitution is recorded.
func TestRunRecordsAnInvalidModification(t *testing.T) {
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "default", Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: &testEngine{}, Signer: signer, OnDecisionFailure: acs.FailureProceed})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var request acs.Request
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		if request.Method != acs.StepToolCallRequest {
			r.Body = io.NopCloser(bytes.NewReader(body))
			g.ServeHTTP(w, r)
			return
		}
		unsigned := `{"jsonrpc":"2.0","id":` + string(request.ID) + `,"result":{"type":"final","acs_version":"0.1.0","request_id":"` + request.Params.RequestID + `","decision":"modify","reasoning":"rewrite command","modifications":{"modified_content":"{}","parameter_overrides":{}}}}`
		input, _, err := envelope.ResponseSigningInput([]byte(unsigned))
		if err != nil {
			t.Error(err)
			return
		}
		signature, err := signer.Sign(r.Context(), request.Params.Metadata.SessionID, "", input)
		if err != nil {
			t.Error(err)
			return
		}
		signed, err := json.Marshal(signature)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write([]byte(strings.TrimSuffix(unsigned, "}}") + `,"signature":` + string(signed) + `}}`))
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	var output bytes.Buffer
	if err := run(optionsFor(server.URL, writeSecret(t), stateDir), bytes.NewBufferString(event("tool-1")), &output); err != nil {
		t.Fatal(err)
	}
	assertOutput(t, output.Bytes(), "deny", "rewrite command", "")
	if audit := readAudit(t, stateDir); !strings.Contains(audit, `"event":"modify_invalid"`) {
		t.Fatalf("audit log = %q", audit)
	}
}

func TestExecuteDeniesAdapterFailure(t *testing.T) {
	var output, errOutput bytes.Buffer
	status := execute([]string{"--hmac-secret-file", "/missing"}, bytes.NewBufferString(`not JSON`), &output, &errOutput)
	if status != 0 {
		t.Fatalf("exit status = %d, want 0", status)
	}
	assertOutput(t, output.Bytes(), "deny", "the ACS policy adapter could not evaluate this tool call", "")
	if errOutput.Len() == 0 {
		t.Fatal("expected diagnostic on stderr")
	}
}

func TestProjectHookConfiguration(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "..", ".codex", "hooks.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout *int   `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	preToolUse := config.Hooks["PreToolUse"]
	if len(preToolUse) != 1 || preToolUse[0].Matcher != "^Bash$" || len(preToolUse[0].Hooks) != 1 {
		t.Fatalf("PreToolUse configuration = %s", raw)
	}
	hook := preToolUse[0].Hooks[0]
	if hook.Type != "command" || !strings.Contains(hook.Command, ".acs/bin/acs-codex-hook") || strings.Contains(hook.Command, "127.0.0.1:8787") {
		t.Fatalf("PreToolUse command = %q", hook.Command)
	}
	if hook.Timeout != nil {
		t.Fatal("Codex hook imposes a deadline outside the negotiated ACS timeout")
	}
}

func TestGuardianURLComesFromTheEnvironment(t *testing.T) {
	t.Setenv("ACS_GUARDIAN_URL", "http://127.0.0.1:43210/acs")
	got, err := parseOptions([]string{"--hmac-secret-file", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got.guardianURL != "http://127.0.0.1:43210/acs" {
		t.Fatalf("guardian URL = %q", got.guardianURL)
	}
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
	return []string{"--guardian-url", url, "--hmac-secret-file", secretFile, "--state-dir", stateDir, "--audit-log", filepath.Join(stateDir, "audit.jsonl")}
}

// readAudit returns the audit log optionsFor names, or "" when nothing was recorded.
func readAudit(t *testing.T, stateDir string) string {
	t.Helper()
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(audit)
}

func event(toolUseID string) string {
	return `{"session_id":"thr_example","turn_id":"turn-1","tool_use_id":"` + toolUseID + `","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf original"}}`
}

func assertOutput(t *testing.T, raw []byte, decision, reason, command string) {
	t.Helper()
	var output struct {
		HookSpecificOutput struct {
			Decision string         `json:"permissionDecision"`
			Reason   string         `json:"permissionDecisionReason"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	if output.HookSpecificOutput.Decision != decision || output.HookSpecificOutput.Reason != reason {
		t.Fatalf("output = %s", raw)
	}
	if command == "" {
		if output.HookSpecificOutput.Updated != nil {
			t.Fatalf("unexpected updated input: %s", raw)
		}
		return
	}
	if output.HookSpecificOutput.Updated["command"] != command {
		t.Fatalf("updated input = %s", raw)
	}
}
