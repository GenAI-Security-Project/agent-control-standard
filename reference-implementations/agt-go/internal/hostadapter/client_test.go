package hostadapter

import (
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
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
