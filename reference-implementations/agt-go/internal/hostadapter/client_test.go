package hostadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/envelope"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
)

func TestDecisionTimeoutUsesMethodOverride(t *testing.T) {
	hello := acs.ServerHello{TimeoutConfig: acs.TimeoutConfig{
		DefaultMS:   1000,
		PerMethodMS: map[string]int64{acs.StepToolCallRequest: 25},
	}}
	if got := decisionTimeout(hello, acs.StepToolCallRequest, 10*time.Second); got != 25*time.Millisecond {
		t.Fatalf("method timeout = %s, want 25ms", got)
	}
}

func TestHandshakeErrorIsRefusal(t *testing.T) {
	for name, test := range map[string]struct {
		code acs.ErrorCode
		want bool
	}{
		"session_refused":     {acs.SessionRefused, true},
		"unsupported_version": {acs.UnsupportedVersion, true},
		"provenance_required": {acs.ProvenanceRequired, true},
		"internal_error":      {acs.InternalError, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := handshakeErrorIsRefusal(test.code); got != test.want {
				t.Fatalf("handshakeErrorIsRefusal(%d) = %v, want %v", test.code, got, test.want)
			}
		})
	}
}

func TestLoadStateDefaultsAnOmittedFailurePosture(t *testing.T) {
	dir := t.TempDir()
	hello := acs.ServerHello{
		NegotiatedVersion: acs.Version,
		MethodsEvaluated:  []string{acs.StepToolCallRequest},
		SelectedTransport: acs.TransportHTTP,
		TimeoutConfig:     acs.TimeoutConfig{DefaultMS: 1000},
	}
	if err := saveState(dir, "agent", "session", sessionState{Hello: hello}); err != nil {
		t.Fatal(err)
	}
	state, ok := loadState(dir, "agent", "session")
	if !ok || state.Hello.OnDecisionFailure != acs.FailureProceed {
		t.Fatalf("state = %+v, loaded = %v", state, ok)
	}
}

func TestSessionUUIDIsStableAndAgentScoped(t *testing.T) {
	first := SessionUUID("codex", "session")
	if first != SessionUUID("codex", "session") {
		t.Fatal("the same host session produced different ACS session IDs")
	}
	if first == SessionUUID("opencode", "session") {
		t.Fatal("two agent identities produced the same ACS session ID")
	}
	if len(first) != 36 || first[14] != '5' {
		t.Fatalf("session ID = %q, want a version 5 UUID", first)
	}
}

func TestRequestUUIDIsMethodScoped(t *testing.T) {
	sessionID := SessionUUID("agent", "session")
	request := RequestUUID(sessionID, acs.StepToolCallRequest, "call")
	result := RequestUUID(sessionID, acs.StepToolCallResult, "call")
	if request == result {
		t.Fatal("request and result hooks produced the same request ID")
	}
}

func TestRefusalProceedsWhereTheHookPermitsNoDeny(t *testing.T) {
	for _, hook := range method.Hooks() {
		t.Run(hook, func(t *testing.T) {
			auditLog := filepath.Join(t.TempDir(), "audit.jsonl")
			client := testClient(t, failingGuardian(t), auditLog, hook)
			decision := client.RefuseModification(Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: hook}, "cannot apply")
			want := acs.Deny
			if !methods.HookRule(hook).Permits(acs.Deny) {
				want = acs.Allow
			}
			if decision.Disposition != want || decision.ReasonCodes[0] != disposition.ReasonModifyUnsupported {
				t.Fatalf("decision = %+v, want %s modify_unsupported", decision, want)
			}
			if audit := readFile(t, auditLog); !strings.Contains(audit, `"event":"modify_unsupported"`) {
				t.Fatalf("audit log = %q", audit)
			}
		})
	}
	if methods.HookRule(acs.StepPostCompact).Permits(acs.Deny) {
		t.Fatal("the method table permits DENY at postCompact, so this test no longer covers §6.5's exception")
	}
}

// A decision failure proceeds, and is recorded, at a hook whose action has
// already happened. When the audit log refuses the record, the host refuses
// the step as far as the hook allows, and the record of that outcome goes to
// stderr instead.
func TestDecisionFailureProceedsWhereTheHookPermitsNoDeny(t *testing.T) {
	blocker := unwritableDir(t)
	for name, tt := range map[string]struct {
		method     string
		posture    acs.FailurePosture
		auditLog   string
		want       acs.Disposition
		wantRecord bool
		wantStderr bool
	}{
		"post_compact":                        {acs.StepPostCompact, acs.FailureDeny, filepath.Join(t.TempDir(), "audit.jsonl"), acs.Allow, true, false},
		"post_compact_audit_unwritten":        {acs.StepPostCompact, acs.FailureDeny, filepath.Join(blocker, "audit.jsonl"), acs.Allow, false, true},
		"tool_call_request":                   {acs.StepToolCallRequest, acs.FailureDeny, filepath.Join(t.TempDir(), "audit.jsonl"), acs.Deny, true, false},
		"tool_call_request_deny_unwritten":    {acs.StepToolCallRequest, acs.FailureDeny, filepath.Join(blocker, "audit.jsonl"), acs.Deny, false, true},
		"tool_call_request_proceed_unwritten": {acs.StepToolCallRequest, acs.FailureProceed, filepath.Join(blocker, "audit.jsonl"), acs.Deny, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			client := testClient(t, failingGuardian(t), tt.auditLog, tt.method)
			var stderr bytes.Buffer
			client.config.Stderr = &stderr
			hello := acs.ServerHello{
				NegotiatedVersion: acs.Version,
				MethodsEvaluated:  []string{tt.method},
				SelectedTransport: acs.TransportHTTP,
				TimeoutConfig:     acs.TimeoutConfig{DefaultMS: 1000},
				OnDecisionFailure: tt.posture,
			}
			if err := saveState(client.config.StateDir, client.config.AgentID, "session", sessionState{Hello: hello}); err != nil {
				t.Fatal(err)
			}
			evaluation, err := client.Evaluate(context.Background(), Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: tt.method, Payload: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.Decision.Disposition != tt.want {
				t.Fatalf("decision = %+v, want %s", evaluation.Decision, tt.want)
			}
			if tt.wantRecord && !strings.Contains(readFile(t, tt.auditLog), `"event":"decision_failure"`) {
				t.Fatal("the decision failure was not recorded")
			}
			assertStderrRecord(t, stderr.String(), tt.wantStderr, "decision_failure", tt.method, tt.want)
		})
	}
}

// Every decision failure leaves one decision_failure record that names its
// class (§6.5), at the deny posture, where the step is denied.
func TestDecisionFailureRecordsItsClass(t *testing.T) {
	payload := bashPayload(t)
	tests := map[string]struct {
		guardianURL func(t *testing.T) string
		negotiated  bool
		decisionMS  int64
		payload     any
		want        string
	}{
		"timeout":           {blockingGuardian, true, 50, payload, failureTimeout},
		"unreachable":       {closedGuardian, true, 1000, payload, failureUnreachable},
		"guardian_error":    {realGuardian, false, 1000, map[string]any{}, failureGuardian},
		"signature_invalid": {tamperingGuardian, false, 1000, payload, failureSignature},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auditLog := filepath.Join(t.TempDir(), "audit.jsonl")
			client := testClient(t, tt.guardianURL(t), auditLog, acs.StepToolCallRequest)
			if tt.negotiated {
				hello := acs.ServerHello{
					NegotiatedVersion: acs.Version,
					MethodsEvaluated:  []string{acs.StepToolCallRequest},
					SelectedTransport: acs.TransportHTTP,
					TimeoutConfig:     acs.TimeoutConfig{DefaultMS: tt.decisionMS},
					OnDecisionFailure: acs.FailureDeny,
				}
				if err := saveState(client.config.StateDir, client.config.AgentID, "session", sessionState{Hello: hello}); err != nil {
					t.Fatal(err)
				}
			}
			evaluation, err := client.Evaluate(context.Background(), Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: acs.StepToolCallRequest, Payload: tt.payload})
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.Decision.Disposition != acs.Deny {
				t.Fatalf("decision = %+v, want DENY", evaluation.Decision)
			}
			assertOneFailure(t, auditLog, tt.want, acs.Deny)
		})
	}
}

// A handshake that fails without a refusal leaves a handshake_failure record
// and returns the error to the caller.
func TestHandshakeFailureRecordsItsClass(t *testing.T) {
	auditLog := filepath.Join(t.TempDir(), "audit.jsonl")
	client := testClient(t, closedGuardian(t), auditLog, acs.StepToolCallRequest)
	payload := bashPayload(t)
	if _, err := client.Evaluate(context.Background(), Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: acs.StepToolCallRequest, Payload: payload}); err == nil {
		t.Fatal("a failed handshake returned no error")
	}
	assertOneFailure(t, auditLog, failureHandshake, acs.Deny)
}

func assertOneFailure(t *testing.T, auditLog, class string, disposition acs.Disposition) {
	t.Helper()
	var records []auditRecord
	for _, line := range strings.Split(strings.TrimSuffix(readFile(t, auditLog), "\n"), "\n") {
		var record auditRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		records = append(records, record)
	}
	if len(records) != 1 || records[0].Event != "decision_failure" || records[0].FailureClass != class || records[0].Disposition != disposition {
		t.Fatalf("audit records = %+v, want one decision_failure of class %s with disposition %s", records, class, disposition)
	}
}

// bashPayload is a valid tool call the Guardian evaluates.
func bashPayload(t *testing.T) acs.ToolCallRequestPayload {
	t.Helper()
	payload, err := ToolCallRequest("Bash", json.RawMessage(`{"command":"ls"}`))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// blockingGuardian answers no request: every step times out at the client.
// It reads the body first, so the server notices the client going away.
func blockingGuardian(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// closedGuardian is an address no server listens on.
func closedGuardian(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	return server.URL
}

// realGuardian is a Guardian that denies on failure, serving its real answers.
func realGuardian(t *testing.T) string {
	t.Helper()
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: testKeyID, Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: allowEngine{}, Signer: signer, OnDecisionFailure: acs.FailureDeny})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	return server.URL
}

// tamperingGuardian is realGuardian with each decision's reasoning changed
// after signing, so no answer to a step verifies.
func tamperingGuardian(t *testing.T) string {
	t.Helper()
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: testKeyID, Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: allowEngine{}, Signer: signer, OnDecisionFailure: acs.FailureDeny})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		g.ServeHTTP(recorder, r)
		body := bytes.Replace(recorder.Body.Bytes(), []byte(`"reasoning":"`+allowReasoning), []byte(`"reasoning":"tampered`), 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// A refusal the host substitutes at a hook that permits no DENY is an ALLOW;
// when the audit log refuses its record, the record goes to stderr.
func TestSubstitutedAllowReachesStderrWhenTheAuditLogFails(t *testing.T) {
	client := testClient(t, failingGuardian(t), filepath.Join(unwritableDir(t), "audit.jsonl"), acs.StepPostCompact)
	var stderr bytes.Buffer
	client.config.Stderr = &stderr
	decision := client.RefuseModification(Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: acs.StepPostCompact, Payload: map[string]any{}}, "cannot apply")
	if decision.Disposition != acs.Allow {
		t.Fatalf("decision = %+v, want ALLOW", decision)
	}
	assertStderrRecord(t, stderr.String(), true, "modify_unsupported", acs.StepPostCompact, acs.Allow)
}

// A signed MODIFY that fails §6.3 is refused as far as the hook allows: at
// postCompact the step proceeds unmodified and modify_invalid is recorded,
// in the audit log or, when that refuses it, on stderr.
func TestInvalidModificationProceedsWhereTheHookPermitsNoDeny(t *testing.T) {
	for name, tt := range map[string]struct {
		auditLog   string
		wantStderr bool
	}{
		"audit_written":   {filepath.Join(t.TempDir(), "audit.jsonl"), false},
		"audit_unwritten": {filepath.Join(unwritableDir(t), "audit.jsonl"), true},
	} {
		t.Run(name, func(t *testing.T) {
			client := testClient(t, invalidModifyGuardian(t, acs.StepPostCompact), tt.auditLog, acs.StepPostCompact)
			var stderr bytes.Buffer
			client.config.Stderr = &stderr
			evaluation, err := client.Evaluate(context.Background(), Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: acs.StepPostCompact, Payload: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.Decision.Disposition != acs.Allow || evaluation.ModifiedPayload != nil {
				t.Fatalf("evaluation = %+v, want ALLOW with nothing modified", evaluation)
			}
			if !tt.wantStderr && !strings.Contains(readFile(t, tt.auditLog), `"event":"modify_invalid"`) {
				t.Fatal("modify_invalid was not recorded")
			}
			assertStderrRecord(t, stderr.String(), tt.wantStderr, "modify_invalid", acs.StepPostCompact, acs.Allow)
			if tt.wantStderr && !strings.HasSuffix(evaluation.Decision.Reasoning, "the record went to stderr") {
				t.Fatalf("reasoning = %q, want it to say the record went to stderr", evaluation.Decision.Reasoning)
			}
		})
	}
}

// When neither the audit log nor stderr takes the record, the refusal's
// reasoning names both failures, so the host can tell the record is missing.
func TestRefusalNamesEverySinkThatFailed(t *testing.T) {
	client := testClient(t, failingGuardian(t), filepath.Join(unwritableDir(t), "audit.jsonl"), acs.StepPostCompact)
	client.config.Stderr = failingWriter{}
	hello := acs.ServerHello{
		NegotiatedVersion: acs.Version,
		MethodsEvaluated:  []string{acs.StepPostCompact},
		SelectedTransport: acs.TransportHTTP,
		TimeoutConfig:     acs.TimeoutConfig{DefaultMS: 1000},
		OnDecisionFailure: acs.FailureDeny,
	}
	if err := saveState(client.config.StateDir, client.config.AgentID, "session", sessionState{Hello: hello}); err != nil {
		t.Fatal(err)
	}
	evaluation, err := client.Evaluate(context.Background(), Step{SessionKey: "session", TurnID: "turn", CallID: "call", Method: acs.StepPostCompact, Payload: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	reasoning := evaluation.Decision.Reasoning
	if evaluation.Decision.Disposition != acs.Allow || !strings.HasSuffix(reasoning, "to the audit log or to stderr") {
		t.Fatalf("decision = %+v, want ALLOW naming the audit log and stderr failures", evaluation.Decision)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func assertStderrRecord(t *testing.T, stderr string, want bool, event, method string, outcome acs.Disposition) {
	t.Helper()
	if !want {
		if stderr != "" {
			t.Fatalf("stderr = %q, want nothing", stderr)
		}
		return
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stderr has %d lines, want one JSON line: %q", len(lines), stderr)
	}
	var record auditRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("stderr is not a JSON line: %v: %q", err, stderr)
	}
	if record.Event != event || record.Method != method || record.SessionKey != "session" || record.Disposition != outcome || record.AuditError == "" {
		t.Fatalf("stderr record = %+v, want event %s at %s with outcome %s and the audit error", record, event, method, outcome)
	}
}

// unwritableDir returns a path under which no file can be created: it names
// a regular file.
func unwritableDir(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return blocker
}

func failingGuardian(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

type allowEngine struct{}

const allowReasoning = "allowed by the test engine"

func (allowEngine) Policy() guardian.PolicyDescription { return guardian.PolicyDescription{} }

func (allowEngine) Decide(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
	return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow, Reasoning: allowReasoning}}, nil
}

// invalidModifyGuardian answers the handshake as a real Guardian and every
// step of hook with a signed MODIFY that combines a replacement with edits,
// which §6.3 forbids.
func invalidModifyGuardian(t *testing.T, hook string) string {
	t.Helper()
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: testKeyID, Secret: []byte(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: allowEngine{}, Signer: signer})
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
		if request.Method != hook {
			r.Body = io.NopCloser(bytes.NewReader(body))
			g.ServeHTTP(w, r)
			return
		}
		unsigned := `{"jsonrpc":"2.0","id":` + string(request.ID) + `,"result":{"type":"final","acs_version":"0.1.0","request_id":"` + request.Params.RequestID + `","decision":"modify","reasoning":"rewrite summary","modifications":{"modified_content":"{}","parameter_overrides":{}}}}`
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
	return server.URL
}

const (
	testSecret = "0123456789abcdef0123456789abcdef"
	testKeyID  = "2026-10"
)

func testClient(t *testing.T, guardianURL, auditLog, hook string) *Client {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(secret, []byte(base64.StdEncoding.EncodeToString([]byte(testSecret))), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{
		GuardianURL: guardianURL, HMACKeyID: testKeyID, HMACSecretFile: secret, StateDir: t.TempDir(), AuditLog: auditLog,
		AgentID: "agent", Methods: []string{hook}, Timeout: time.Second, MaxBodyBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
