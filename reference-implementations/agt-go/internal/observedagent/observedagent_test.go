package observedagent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

type acceptingSigner struct{}

func (acceptingSigner) Verify(context.Context, string, []byte, acs.Signature) error { return nil }

func (acceptingSigner) Sign(context.Context, string, string, []byte) (acs.Signature, error) {
	return acs.Signature{Algorithm: acs.SignatureAlgorithmHMACSHA256, KeyID: "test", Value: "test"}, nil
}

// §6.4: a verified decision is applied as it is; anything else falls to the
// failure posture, and only proceed fails open.
func TestHonour(t *testing.T) {
	deny := &acs.Result{Decision: acs.Decision{Disposition: acs.Deny, Reasoning: "no"}}
	tests := []struct {
		name    string
		outcome Outcome
		err     error
	}{
		{"transport_failure", Outcome{}, errors.New("connection refused")},
		{"timeout", Outcome{}, context.DeadlineExceeded},
		{"error_answer", Outcome{Error: &acs.Error{Code: acs.InternalError}}, nil},
		{"unverified_result", Outcome{Result: deny, Verified: false}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d, open := Honour(tt.outcome, tt.err, acs.FailureProceed); d.Disposition != acs.Allow || !open {
				t.Fatalf("proceed: %s, failed open %v", d.Disposition, open)
			}
			if d, open := Honour(tt.outcome, tt.err, acs.FailureDeny); d.Disposition != acs.Deny || open {
				t.Fatalf("deny: %s, failed open %v", d.Disposition, open)
			}
		})
	}
	if d, open := Honour(Outcome{Result: deny, Verified: true}, nil, acs.FailureProceed); d.Disposition != acs.Deny || open {
		t.Fatalf("a verified decision became %s", d.Disposition)
	}
}

func TestSendRejectsAResponseForAnotherRequest(t *testing.T) {
	client := &Client{
		Signer:    acceptingSigner{},
		AgentID:   "agent",
		SessionID: "session",
		Transport: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"jsonrpc":"2.0","id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","result":{"type":"final","acs_version":"0.1.0","request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","decision":"allow","signature":{"algorithm":"HMAC-SHA256","key_id":"test","value":"test"}}}`), nil
		},
	}
	_, err := client.Send(context.Background(), Request{
		Method:    acs.StepToolCallRequest,
		Payload:   map[string]any{},
		RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	if err == nil {
		t.Fatal("accepted a verified response for another request")
	}
}

func TestSendAcceptsAnUncorrelatedError(t *testing.T) {
	client := &Client{
		Signer:    acceptingSigner{},
		AgentID:   "agent",
		SessionID: "session",
		Transport: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"shutting down"}}`), nil
		},
	}
	outcome, err := client.Send(context.Background(), Request{
		Method:    acs.StepToolCallRequest,
		Payload:   map[string]any{},
		RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	if err != nil || outcome.Error == nil {
		t.Fatalf("outcome = %+v, error = %v", outcome, err)
	}
}

func TestSendIgnoresUnknownResultFields(t *testing.T) {
	client := &Client{
		Signer:    acceptingSigner{},
		AgentID:   "agent",
		SessionID: "session",
		Transport: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"jsonrpc":"2.0","id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","result":{"type":"final","acs_version":"0.1.0","request_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","decision":"deny","reasoning":"policy denied","negotiated_version":42,"signature":{"algorithm":"HMAC-SHA256","key_id":"test","value":"test"}}}`), nil
		},
	}
	outcome, err := client.Send(context.Background(), Request{
		Method:    acs.StepToolCallRequest,
		Payload:   map[string]any{},
		RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	if err != nil || outcome.Result == nil || outcome.Result.Disposition != acs.Deny {
		t.Fatalf("outcome = %+v, error = %v", outcome, err)
	}
	if decision, failedOpen := Honour(outcome, nil, acs.FailureProceed); decision.Disposition != acs.Deny || failedOpen {
		t.Fatalf("honoured decision = %+v, failed open = %v", decision, failedOpen)
	}
}

func TestSendRejectsMalformedHandshakeResult(t *testing.T) {
	client := &Client{
		Signer:    acceptingSigner{},
		AgentID:   "agent",
		SessionID: "session",
		Transport: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"jsonrpc":"2.0","id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","result":{"negotiated_version":"0.1.0","signature":{"algorithm":"HMAC-SHA256","key_id":"test","value":"test"}}}`), nil
		},
	}
	_, err := client.Handshake(context.Background(), DefaultHello(acs.StepToolCallRequest))
	if err == nil {
		t.Fatal("accepted an incomplete ServerHello")
	}
}

func TestHandshakeIgnoresUnknownResultFields(t *testing.T) {
	client := &Client{
		Signer:    acceptingSigner{},
		AgentID:   "agent",
		SessionID: "session",
		Transport: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"jsonrpc":"2.0","id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","result":{"negotiated_version":"0.1.0","methods_evaluated":["steps/toolCallRequest"],"selected_transport":"http","timeout_config":{"default_ms":1000},"type":42,"signature":{"algorithm":"HMAC-SHA256","key_id":"test","value":"test"}}}`), nil
		},
	}
	outcome, err := client.Send(context.Background(), Request{
		Method:    acs.MethodHandshakeHello,
		Payload:   DefaultHello(acs.StepToolCallRequest),
		RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	if err != nil || outcome.Hello == nil || outcome.Hello.NegotiatedVersion != acs.Version {
		t.Fatalf("outcome = %+v, error = %v", outcome, err)
	}
}

func TestSendFailsClosedForMixedModifyShapes(t *testing.T) {
	for name, modifications := range map[string]string{
		"redactions": `{"modified_content":"{}","redactions":[]}`,
		"overrides":  `{"modified_content":"{}","parameter_overrides":{}}`,
		"both":       `{"modified_content":"{}","redactions":[],"parameter_overrides":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := &Client{
				Signer:    acceptingSigner{},
				AgentID:   "agent",
				SessionID: "session",
				Transport: func(context.Context, []byte) ([]byte, error) {
					return []byte(`{"jsonrpc":"2.0","id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","result":{"type":"final","acs_version":"0.1.0","request_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","decision":"modify","reasoning":"rewrite command","modifications":` + modifications + `,"signature":{"algorithm":"HMAC-SHA256","key_id":"test","value":"test"}}}`), nil
				},
			}
			outcome, err := client.Send(context.Background(), Request{
				Method:    acs.StepToolCallRequest,
				Payload:   map[string]any{},
				RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			})
			if err != nil || outcome.Result == nil || outcome.Result.Disposition != acs.Deny || !outcome.Verified {
				t.Fatalf("outcome = %+v, error = %v", outcome, err)
			}
			if decision, failedOpen := Honour(outcome, nil, acs.FailureProceed); decision.Disposition != acs.Deny || failedOpen {
				t.Fatalf("honoured decision = %+v, failed open = %v", decision, failedOpen)
			}
		})
	}
}

func TestApplyRejectsOverlappingStructuredEdits(t *testing.T) {
	decision := acs.Decision{
		Disposition: acs.Modify,
		Reasoning:   "rewrite the command",
		Modifications: &acs.Modifications{
			Redactions: []acs.Redaction{{Path: "/arguments/command"}},
			ParameterOverrides: map[string]json.RawMessage{
				"command": json.RawMessage(`"printf rewritten"`),
			},
		},
	}
	_, err := Apply(decision, json.RawMessage(`{"arguments":{"command":{"value":"printf original"}}}`))
	if err == nil {
		t.Fatal("accepted overlapping structured edits")
	}
}
