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

// §6.4: a verified decision is applied as it is; a refusal or an answer that
// cannot be trusted denies under any posture (#32); anything else falls to
// the failure posture, and only proceed fails open.
func TestHonour(t *testing.T) {
	deny := &acs.Result{Decision: acs.Decision{Disposition: acs.Deny, Reasoning: "no"}}
	tests := []struct {
		name    string
		outcome Outcome
		err     error
	}{
		{"transport_failure", Outcome{}, errors.New("connection refused")},
		{"timeout", Outcome{}, context.DeadlineExceeded},
		{"signed_internal_error", Outcome{Error: &acs.Error{Code: acs.InternalError}, Verified: true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d, verified := Honour(tt.outcome, tt.err, acs.FailureProceed); d.Disposition != acs.Allow || verified {
				t.Fatalf("proceed: %s, verified %v", d.Disposition, verified)
			}
			if d, verified := Honour(tt.outcome, tt.err, acs.FailureDeny); d.Disposition != acs.Deny || verified {
				t.Fatalf("deny: %s, verified %v", d.Disposition, verified)
			}
		})
	}
	refused := []struct {
		name    string
		outcome Outcome
		err     error
	}{
		{"unverified_result", Outcome{Result: &acs.Result{Decision: acs.Decision{Disposition: acs.Allow}}}, nil},
		{"malformed_answer", Outcome{}, malformed(errors.New("not JSON"))},
		{"unsigned_body_too_large", Outcome{Error: &acs.Error{Code: acs.InvalidRequest}}, nil},
		{"signed_replay", Outcome{Error: &acs.Error{Code: acs.ReplayDetected}, Verified: true}, nil},
		{"signed_invalid_params", Outcome{Error: &acs.Error{Code: acs.InvalidParams}, Verified: true}, nil},
		{"signed_chain_mismatch", Outcome{Error: &acs.Error{Code: acs.ChainMismatch}, Verified: true}, nil},
		{"signature_invalid", Outcome{Error: &acs.Error{Code: acs.SignatureInvalid}}, nil},
		{"unsigned_internal_error", Outcome{Error: &acs.Error{Code: acs.InternalError}}, nil},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			if d, verified := Honour(tt.outcome, tt.err, acs.FailureProceed); d.Disposition != acs.Deny || verified {
				t.Fatalf("proceed: %s, verified %v", d.Disposition, verified)
			}
		})
	}
	if d, verified := Honour(Outcome{Result: deny, Verified: true}, nil, acs.FailureProceed); d.Disposition != acs.Deny || !verified {
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
	if decision, verified := Honour(outcome, nil, acs.FailureProceed); decision.Disposition != acs.Deny || !verified {
		t.Fatalf("honoured decision = %+v, verified = %v", decision, verified)
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
			if err != nil || outcome.Result == nil || outcome.Result.Disposition != acs.Deny || !outcome.Verified || !outcome.InvalidModification {
				t.Fatalf("outcome = %+v, error = %v", outcome, err)
			}
			if decision, verified := Honour(outcome, nil, acs.FailureProceed); decision.Disposition != acs.Deny || !verified {
				t.Fatalf("honoured decision = %+v, verified = %v", decision, verified)
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
