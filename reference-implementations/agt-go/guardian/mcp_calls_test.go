package guardian_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

const wrappedCall = "protocols/MCP/tools/call"

// mcpSession returns a client whose session is negotiated for every native
// hook and wrapped MCP.
func mcpSession(h *harness) *observedagent.Client {
	h.t.Helper()
	c := h.client(observedagent.NewUUID())
	hello := observedagent.DefaultHello(append(method.Hooks(), wrappedCall)...)
	// MCP 2026-07-28 lets a client reuse an id once its request has an answer.
	hello.WrappedProtocols = []acs.WrappedProtocol{{Protocol: "MCP", Version: "2026-07-28"}}
	if o, err := c.Handshake(context.Background(), hello); err != nil || o.Hello == nil {
		h.t.Fatalf("handshake: %v %s", err, o.Raw)
	}
	return c
}

func mcpRequest(id any, tool string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{"path": "a"}}}
}

func mcpResponse(id any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "data"}}}}
}

// openCalls is the session's record of open MCP calls, as the engine sees it
// on the next step.
func openCalls(h *harness, c *observedagent.Client) map[string]string {
	h.t.Helper()
	h.engine.set(nil)
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	return h.engine.last().Session.MCPCalls
}

// The Guardian records a wrapped tools/call from its final decision. A
// request it lets through stays open until its response. A response ends its
// call whatever the decision on it. TestPolicyStateFollowsTheAnswer covers
// the engine's state.
func TestMCPCallsFollowTheFinalAnswer(t *testing.T) {
	override := acs.Decision{Disposition: acs.Modify, Reasoning: "rewrite", Modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{"path": json.RawMessage(`"b"`)}}}
	redact := acs.Decision{Disposition: acs.Modify, Reasoning: "redact", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/result/content/0/text"}}}}
	ask := acs.Decision{Disposition: acs.Ask, Reasoning: "approve", AskDetails: &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverHuman, ID: "r"}, Question: "q", TimeoutSeconds: 30}}
	redactAt := func(path string) acs.Decision {
		return acs.Decision{Disposition: acs.Modify, Reasoning: "redact", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: path}}}}
	}
	replacement := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"Write"}}`
	replace := acs.Decision{Disposition: acs.Modify, Reasoning: "replace", Modifications: &acs.Modifications{ModifiedContent: &replacement}}
	sameCall := `{"jsonrpc":"2.0","id":3.0,"method":"tools/call","params":{"name":"Read","arguments":{"path":"b"}}}`
	replaceArguments := acs.Decision{Disposition: acs.Modify, Reasoning: "replace", Modifications: &acs.Modifications{ModifiedContent: &sameCall}}
	noID := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"Read","arguments":{}}}`)
	deferral := acs.Decision{Disposition: acs.Defer, Reasoning: "wait", DeferDetails: &acs.DeferDetails{Reason: acs.DeferPendingDependency, ResolutionMethod: acs.ResolveTimeout, ResolutionTimeoutMS: 1000, TimeoutDecision: acs.Deny}}
	cannotModify := guardian.ClientCapability{CannotApplyModify: true}
	open := map[string]string{"3": "Read"}
	for name, tt := range map[string]struct {
		// opened: call 3 is open before the step.
		opened  bool
		payload any
		answer  acs.Decision
		client  guardian.ClientCapability
		// fails: the engine returns an error instead of answer.
		fails bool
		// stale: the step carries a chain_hash that is not the session's head.
		stale bool
		// want is the final disposition and reason; calls the record after.
		want   acs.Disposition
		reason string
		calls  map[string]string
	}{
		"request_allowed":            {payload: mcpRequest(3, "Read"), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Allow, calls: open},
		"request_modified":           {payload: mcpRequest(3, "Read"), answer: override, want: acs.Modify, calls: open},
		"request_engine_denies":      {payload: mcpRequest(3, "Read"), answer: deny("no"), want: acs.Deny, calls: nil},
		"request_guardian_denies":    {payload: mcpRequest(3, "Read"), answer: override, client: cannotModify, want: acs.Deny, reason: disposition.ReasonModifyUnsupported, calls: nil},
		"request_asked":              {payload: mcpRequest(3, "Read"), answer: ask, client: guardian.ClientCapability{CannotResolveAsk: true, AskSubstitute: acs.Defer}, want: acs.Defer, reason: disposition.ReasonApproverUnavailable, calls: nil},
		"request_ask_denied":         {payload: mcpRequest(3, "Read"), answer: ask, client: guardian.ClientCapability{CannotResolveAsk: true, AskSubstitute: acs.Deny}, want: acs.Deny, reason: disposition.ReasonApproverUnavailable, calls: nil},
		"request_deferred":           {payload: mcpRequest(3, "Read"), answer: deferral, want: acs.Defer, calls: nil},
		"request_engine_fails":       {payload: mcpRequest(3, "Read"), fails: true, want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_tool_redacted":      {payload: mcpRequest(3, "Read"), answer: redactAt("/params/name"), want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_id_redacted":        {payload: mcpRequest(3, "Read"), answer: redactAt("/id"), want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_method_redacted":    {payload: mcpRequest(3, "Read"), answer: redactAt("/method"), want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_params_redacted":    {payload: mcpRequest(3, "Read"), answer: redactAt("/params"), want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_replaced":           {payload: mcpRequest(3, "Read"), answer: replace, want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"request_arguments_replaced": {payload: mcpRequest(3, "Read"), answer: replaceArguments, want: acs.Modify, calls: open},
		"request_without_id":         {payload: noID, answer: acs.Decision{Disposition: acs.Allow}, want: acs.Allow, calls: nil},
		"request_stale_chain":        {payload: mcpRequest(3, "Read"), answer: acs.Decision{Disposition: acs.Allow}, stale: true, want: acs.Deny, reason: disposition.ReasonChainMismatch, calls: nil},
		"request_under_open_id":      {opened: true, payload: mcpRequest(3, "Write"), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Deny, reason: disposition.ReasonMCPCallPending, calls: open},
		"request_under_other_id":     {opened: true, payload: mcpRequest(4, "Write"), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Allow, calls: map[string]string{"3": "Read", "4": "Write"}},
		"response_allowed":           {opened: true, payload: mcpResponse(3), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Allow, calls: nil},
		"response_redacted":          {opened: true, payload: mcpResponse(3), answer: redact, want: acs.Modify, calls: nil},
		"response_engine_denies":     {opened: true, payload: mcpResponse(3), answer: deny("no"), want: acs.Deny, calls: nil},
		"response_guardian_denies":   {opened: true, payload: mcpResponse(3), answer: redact, client: cannotModify, want: acs.Deny, reason: disposition.ReasonModifyUnsupported, calls: nil},
		"response_engine_fails":      {opened: true, payload: mcpResponse(3), fails: true, want: acs.Deny, reason: disposition.ReasonEvaluationFailed, calls: nil},
		"response_stale_chain":       {opened: true, payload: mcpResponse(3), answer: acs.Decision{Disposition: acs.Allow}, stale: true, want: acs.Deny, reason: disposition.ReasonChainMismatch, calls: nil},
		"response_to_no_call":        {payload: mcpResponse(3), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Deny, reason: disposition.ReasonMCPCallNotOpen, calls: nil},
		"response_equivalent_id":     {opened: true, payload: json.RawMessage(`{"jsonrpc":"2.0","id":3.0,"result":{"content":[]}}`), answer: acs.Decision{Disposition: acs.Allow}, want: acs.Allow, calls: nil},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c := mcpSession(h)
			if tt.opened {
				h.engine.set(nil)
				if r := h.decision(c, wrappedCall, mcpRequest(3, "Read")); r.Disposition != acs.Allow {
					t.Fatalf("opening call 3 got %+v", r)
				}
			}
			calls := h.engine.callCount()
			h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
				if tt.fails {
					return guardian.PolicyDecision{}, errors.New("engine down")
				}
				return guardian.PolicyDecision{Decision: tt.answer, Client: tt.client}, nil
			})
			var r *acs.Result
			if tt.stale {
				o := h.send(c, observedagent.Request{Method: wrappedCall, Payload: tt.payload, ChainHash: hash64})
				if o.Result == nil {
					t.Fatalf("no decision: %s", o.Raw)
				}
				r = o.Result
			} else {
				r = h.decision(c, wrappedCall, tt.payload)
			}
			if r.Disposition != tt.want || (tt.reason != "" && !slices.Contains(r.ReasonCodes, tt.reason)) {
				t.Fatalf("got %s %v, want %s %s", r.Disposition, r.ReasonCodes, tt.want, tt.reason)
			}
			if (tt.reason == disposition.ReasonMCPCallPending || tt.reason == disposition.ReasonMCPCallNotOpen) && h.engine.callCount() != calls {
				t.Fatal("the engine decided a message the Guardian refuses before it")
			}
			if got := openCalls(h, c); !maps.Equal(got, tt.calls) {
				t.Fatalf("open calls %v, want %v", got, tt.calls)
			}
		})
	}
}

// A stale record broke two cases: the Guardian denies a request, or a
// response, in the engine's place. MCP lets a client reuse an id once its
// request has an answer. In both cases the engine decides the request that
// reuses the id.
func TestMCPIDReusableAfterAGuardianDenial(t *testing.T) {
	redact := acs.Decision{Disposition: acs.Modify, Reasoning: "redact", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/result/content/0/text"}}}}
	override := acs.Decision{Disposition: acs.Modify, Reasoning: "rewrite", Modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{"path": json.RawMessage(`"b"`)}}}
	for name, steps := range map[string][]map[string]any{
		"request_denied":  {mcpRequest(3, "Read")},
		"response_denied": {mcpRequest(3, "Read"), mcpResponse(3)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c := mcpSession(h)
			for i, payload := range steps {
				answer := acs.Decision{Disposition: acs.Allow}
				if i == len(steps)-1 {
					answer = override
					if _, response := payload["result"]; response {
						answer = redact
					}
				}
				h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
					return guardian.PolicyDecision{Decision: answer, Client: guardian.ClientCapability{CannotApplyModify: true}}, nil
				})
				h.decision(c, wrappedCall, payload)
			}
			h.engine.set(nil)
			if r := h.decision(c, wrappedCall, mcpRequest(3, "Write")); r.Disposition != acs.Allow {
				t.Fatalf("a request reusing MCP id 3 got %s %v", r.Disposition, r.ReasonCodes)
			}
		})
	}
}

// MaxPolicyStateBytes bounds the open MCP calls. A request that would grow
// them past it is denied before the engine is asked. The record keeps the
// calls it had.
func TestMCPCallsAreBounded(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.MaxPolicyStateBytes = 12 })
	c := mcpSession(h)
	h.engine.set(nil)
	if r := h.decision(c, wrappedCall, mcpRequest(3, "Read")); r.Disposition != acs.Allow {
		t.Fatalf("a call within the bound got %+v", r)
	}
	calls := h.engine.callCount()
	if r := h.decision(c, wrappedCall, mcpRequest(4, "WriteManyFiles")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonPolicyStateTooLarge) {
		t.Fatalf("a call past the bound got %s %v", r.Disposition, r.ReasonCodes)
	}
	if h.engine.callCount() != calls {
		t.Fatal("the engine decided a call past the bound")
	}
	if got := openCalls(h, c); !maps.Equal(got, map[string]string{"3": "Read"}) {
		t.Fatalf("open calls %v, want only 3", got)
	}
}
