package hostadapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
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
			client, auditLog := testClient(t, filepath.Join(t.TempDir(), "audit.jsonl"), hook)
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

// A decision failure under the deny posture proceeds, and is recorded, at a
// hook whose action has already happened.
func TestDecisionFailureProceedsWhereTheHookPermitsNoDeny(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		method     string
		auditLog   string
		want       acs.Disposition
		wantRecord bool
	}{
		"post_compact":                 {acs.StepPostCompact, filepath.Join(t.TempDir(), "audit.jsonl"), acs.Allow, true},
		"post_compact_audit_unwritten": {acs.StepPostCompact, filepath.Join(blocker, "audit.jsonl"), acs.Allow, false},
		"tool_call_request":            {acs.StepToolCallRequest, filepath.Join(t.TempDir(), "audit.jsonl"), acs.Deny, false},
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := testClient(t, tt.auditLog, tt.method)
			hello := acs.ServerHello{
				NegotiatedVersion: acs.Version,
				MethodsEvaluated:  []string{tt.method},
				SelectedTransport: acs.TransportHTTP,
				TimeoutConfig:     acs.TimeoutConfig{DefaultMS: 1000},
				OnDecisionFailure: acs.FailureDeny,
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
		})
	}
}

func testClient(t *testing.T, auditLog, hook string) (*Client, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	secret := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(secret, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{
		GuardianURL: server.URL, HMACSecretFile: secret, StateDir: t.TempDir(), AuditLog: auditLog,
		AgentID: "agent", Methods: []string{hook}, Timeout: time.Second, MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, auditLog
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
