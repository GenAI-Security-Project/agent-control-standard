package guardian_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/chain"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/schema"
)

var hash64 = strings.Repeat("a", 64)

// hookPayloads holds a minimal valid payload for every native hook.
var hookPayloads = map[string]any{
	acs.StepSessionStart:           map[string]any{},
	acs.StepAgentTrigger:           map[string]any{"trigger_type": "user_message"},
	acs.StepTurnStart:              map[string]any{"turn_id": "t1", "triggered_by": "user_message"},
	acs.StepUserMessage:            map[string]any{"content": []any{map[string]any{"type": "text", "value": "hello"}}},
	acs.StepAgentResponse:          map[string]any{"content": []any{map[string]any{"type": "text", "value": "hi"}}},
	acs.StepKnowledgeRetrieval:     map[string]any{"query": map[string]any{"value": "q"}, "results": []any{}},
	acs.StepMemoryContextRetrieval: map[string]any{"results": []any{}},
	acs.StepMemoryStore:            map[string]any{"content": map[string]any{"value": "m"}},
	acs.StepToolCallRequest:        toolCall("ls -la"),
	acs.StepToolCallResult:         map[string]any{"tool": map[string]any{"name": "Bash"}, "exit_status": "success", "outputs": []any{map[string]any{"value": "ok"}}},
	acs.StepPreCompact:             map[string]any{"entries_to_compact": []any{"s1"}, "triggered_by": "manual"},
	acs.StepPostCompact:            map[string]any{"summary": map[string]any{"value": "sum", "provenance": map[string]any{"provenance_id": "p", "origin": "agent_generated"}}, "entries_compacted": []any{"s1"}, "pre_compact_chain_hash": hash64, "post_compact_chain_hash": hash64},
	acs.StepSubagentStart:          map[string]any{"subagent_session_id": observedagent.NewUUID(), "parent_session_id": observedagent.NewUUID(), "parent_step_id": "s1", "intent_derivation": "fresh"},
	acs.StepSubagentStop:           map[string]any{"subagent_session_id": observedagent.NewUUID(), "outcome": "completed", "final_chain_hash": hash64},
	acs.StepSkillRegister:          map[string]any{"skill_id": "sk", "definition": map[string]any{"digest": map[string]any{"algorithm": "sha-256", "value": "v"}}, "declared_capabilities": []any{}},
	acs.StepSkillLoad:              map[string]any{"skill_id": "sk", "load_trigger": "user", "load_path": []any{map[string]any{"skill_id": "sk"}}, "digest": map[string]any{"algorithm": "sha-256", "value": "v"}},
	acs.StepSkillUnload:            map[string]any{"skill_id": "sk", "reason": "explicit_unload"},
	acs.StepTurnEnd:                map[string]any{"turn_id": "t1", "outcome": "completed"},
	acs.StepSessionEnd:             map[string]any{"reason": "completed"},
}

func TestHandshake(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.OnDecisionFailure = acs.FailureDeny })
	c := h.client(observedagent.NewUUID())
	hello := observedagent.DefaultHello(append(handshake.CoreMethods(), "steps/notAHook", "protocols/MCP/tools/call", "protocols/A2A/message/send", acs.MethodSystemPing)...)
	hello.WrappedProtocols = []acs.WrappedProtocol{{Protocol: "MCP", Version: "2025-06-18"}}
	o, err := c.Handshake(context.Background(), hello)
	if err != nil {
		t.Fatal(err)
	}
	if o.Hello == nil || !o.Verified {
		t.Fatalf("no signed ServerHello: %s", o.Raw)
	}
	s := o.Hello
	if s.NegotiatedVersion != acs.Version || s.SelectedTransport != acs.TransportHTTP || s.OnDecisionFailure != acs.FailureDeny {
		t.Fatalf("ServerHello %+v", s)
	}
	if want := append(handshake.CoreMethods(), "protocols/MCP/tools/call"); !slices.Equal(s.MethodsEvaluated, want) {
		t.Fatalf("methods_evaluated %v: must be exactly the declared hooks and MCP methods this Guardian evaluates, %v", s.MethodsEvaluated, want)
	}
	if s.SkewWindowMS != 300000 || s.TimeoutConfig.DefaultMS != 5000 || !slices.Equal(s.SignatureAlgorithmsSupported, []string{acs.SignatureAlgorithmHMACSHA256}) {
		t.Fatalf("ServerHello %+v", s)
	}
	if !slices.Equal(s.ProfilesAccepted, []string{acs.ProfileCore}) {
		t.Fatalf("profiles_accepted %v", s.ProfilesAccepted)
	}
	registry, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateJSON(schema.ResponseEnvelope, o.Raw); err != nil {
		t.Fatalf("the handshake response fails response-envelope.json: %v", err)
	}
	if h.engine.callCount() != 0 {
		t.Fatal("the handshake called the engine")
	}
	// An agent that restarts sends the same ClientHello again and gets the
	// negotiated terms back; other terms would renegotiate, and are refused.
	again := h.send(c, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: hello})
	if again.Hello == nil || !again.Verified || !slices.Equal(again.Hello.MethodsEvaluated, s.MethodsEvaluated) {
		t.Fatalf("the same ClientHello again got %s", again.Raw)
	}
	reordered := hello
	reordered.MethodsImplemented = slices.Clone(hello.MethodsImplemented)
	slices.Reverse(reordered.MethodsImplemented)
	again = h.send(c, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: reordered})
	if again.Hello == nil || !again.Verified || !slices.Equal(again.Hello.MethodsEvaluated, s.MethodsEvaluated) {
		t.Fatalf("the same ClientHello set in another order got %s", again.Raw)
	}
	other := hello
	other.MethodsImplemented = handshake.CoreMethods()
	h.refusal(c, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: other}, acs.SessionRefused)
	h.decision(c, acs.StepSessionEnd, hookPayloads[acs.StepSessionEnd])
	h.refusal(c, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: hello}, acs.SessionRefused)
}

func TestRecoveredSessionUsesNegotiatedTerms(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	store, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{
		MaxSessions: 4, MaxEntries: 32, MaxReservations: 64, MaxSkillApprovals: 4, Retention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k1", Secret: ikm})
	if err != nil {
		t.Fatal(err)
	}
	firstEngine := &testEngine{policy: guardian.PolicyDescription{ApproverTypes: []acs.ApproverType{acs.ApproverHuman}}}
	first := mustGuardian(t, guardian.Config{
		Engine: firstEngine, Signer: signer, Store: store,
		DecisionTimeout: 40 * time.Millisecond, SkewWindow: time.Second,
		Now: func() time.Time { return now },
	})
	client := &observedagent.Client{
		Transport: func(ctx context.Context, body []byte) ([]byte, error) { return first.Handle(ctx, body), nil },
		Signer:    signer, AgentID: "agent", SessionID: observedagent.NewUUID(), Now: func() time.Time { return now },
	}
	hello := observedagent.DefaultHello(acs.StepToolCallRequest)
	initial, err := client.Handshake(context.Background(), hello)
	if err != nil || initial.Hello == nil {
		t.Fatalf("initial handshake: %v %s", err, initial.Raw)
	}

	secondEngine := &testEngine{policy: guardian.PolicyDescription{ApproverTypes: []acs.ApproverType{acs.ApproverService}}}
	second := mustGuardian(t, guardian.Config{
		Engine: secondEngine, Signer: signer, Store: store,
		DecisionTimeout: time.Second, SkewWindow: time.Minute,
		Now: func() time.Time { return now },
	})
	client.Transport = func(ctx context.Context, body []byte) ([]byte, error) { return second.Handle(ctx, body), nil }
	recovered, err := client.Handshake(context.Background(), hello)
	if err != nil || recovered.Hello == nil || recovered.Hello.TimeoutConfig.DefaultMS != 40 || recovered.Hello.SkewWindowMS != 1000 ||
		!slices.Equal(recovered.Hello.ApproverTypesSupported, []acs.ApproverType{acs.ApproverHuman}) {
		t.Fatalf("recovered handshake: %v %s", err, recovered.Raw)
	}

	stale, err := client.Send(context.Background(), observedagent.Request{
		Method: acs.StepToolCallRequest, Payload: toolCall("stale"), Timestamp: now.Add(-10 * time.Second),
	})
	if err != nil || stale.Error == nil || stale.Error.Code != acs.TimestampOutOfWindow || secondEngine.callCount() != 0 {
		t.Fatalf("stale request: %v %s; engine calls %d", err, stale.Raw, secondEngine.callCount())
	}

	deadline := make(chan time.Duration, 1)
	requestedAt := time.Now()
	secondEngine.set(func(ctx context.Context, _ guardian.PolicyInput) (guardian.PolicyDecision, error) {
		limit, ok := ctx.Deadline()
		if !ok {
			deadline <- 0
		} else {
			deadline <- limit.Sub(requestedAt)
		}
		<-ctx.Done()
		return guardian.PolicyDecision{}, ctx.Err()
	})
	timed, err := client.Send(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("slow")})
	engineTimeout := <-deadline
	if err != nil || timed.Result == nil || timed.Result.Disposition != acs.Deny || engineTimeout <= 0 || engineTimeout > 100*time.Millisecond {
		t.Fatalf("negotiated timeout: %v %s; engine deadline %s", err, timed.Raw, engineTimeout)
	}

	secondEngine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "approval required", AskDetails: &acs.AskDetails{
		Approver: acs.Approver{Type: acs.ApproverHuman, ID: "operator"}, Question: "allow?", TimeoutSeconds: 30,
	}})
	asked, err := client.Send(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ask")})
	if err != nil || asked.Result == nil || asked.Result.Disposition != acs.Ask {
		t.Fatalf("negotiated approver types: %v %s", err, asked.Raw)
	}
}

// A handshake replayed into the session it opened is a replay (§10.3), not
// a second negotiation.
func TestHandshakeReplay(t *testing.T) {
	h := newHarness(t)
	c := h.client(observedagent.NewUUID())
	body, err := c.Envelope(context.Background(), observedagent.Request{Method: acs.MethodHandshakeHello, Payload: observedagent.DefaultHello(method.Hooks()...)})
	if err != nil {
		t.Fatal(err)
	}
	if o, err := c.SendBody(context.Background(), body); err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v %s", err, o.Raw)
	}
	o, err := c.SendBody(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if o.Error == nil || o.Error.Code != acs.ReplayDetected {
		t.Fatalf("replayed handshake got %s, want -32005", o.Raw)
	}
}

func TestHandshakeReplayAfterSessionEnd(t *testing.T) {
	h := newHarness(t)
	c := h.client(observedagent.NewUUID())
	body, err := c.Envelope(context.Background(), observedagent.Request{
		Method: acs.MethodHandshakeHello, Payload: observedagent.DefaultHello(acs.StepSessionEnd),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := c.SendBody(context.Background(), body); err != nil || out.Hello == nil {
		t.Fatalf("handshake: %v %s", err, out.Raw)
	}
	h.decision(c, acs.StepSessionEnd, hookPayloads[acs.StepSessionEnd])
	out, err := c.SendBody(context.Background(), body)
	if err != nil || out.Error == nil || out.Error.Code != acs.ReplayDetected {
		t.Fatalf("replayed closed-session handshake: %v %s", err, out.Raw)
	}
}

func TestReplayReservationsAreBounded(t *testing.T) {
	t.Run("restart handshakes", func(t *testing.T) {
		store, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{
			MaxSessions: 1, MaxEntries: 8, MaxReservations: 2, MaxSkillApprovals: 1, Retention: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, func(cfg *guardian.Config) { cfg.Store = store })
		c := h.client(observedagent.NewUUID())
		hello := observedagent.DefaultHello(acs.StepToolCallRequest)
		for i := 0; i < 2; i++ {
			if out, err := c.Handshake(context.Background(), hello); err != nil || out.Hello == nil {
				t.Fatalf("handshake %d: %v %s", i+1, err, out.Raw)
			}
		}
		if out, err := c.Handshake(context.Background(), hello); err != nil || out.Error == nil || out.Error.Code != acs.SessionRefused {
			t.Fatalf("handshake past reservation capacity: %v %s", err, out.Raw)
		}
	})

	t.Run("closed session", func(t *testing.T) {
		store, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{
			MaxSessions: 1, MaxEntries: 8, MaxReservations: 3, MaxSkillApprovals: 1, Retention: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, func(cfg *guardian.Config) { cfg.Store = store })
		c := h.client(observedagent.NewUUID())
		if out, err := c.Handshake(context.Background(), observedagent.DefaultHello(acs.StepSessionEnd, acs.StepToolCallRequest)); err != nil || out.Hello == nil {
			t.Fatalf("handshake: %v %s", err, out.Raw)
		}
		if result := h.decision(c, acs.StepSessionEnd, hookPayloads[acs.StepSessionEnd]); result.Disposition != acs.Allow {
			t.Fatalf("session end: %+v", result.Decision)
		}
		if result := h.decision(c, acs.StepToolCallRequest, toolCall("first")); result.Disposition != acs.Deny || !slices.Contains(result.ReasonCodes, disposition.ReasonSessionClosed) {
			t.Fatalf("first closed-session request: %+v", result.Decision)
		}
		if result := h.decision(c, acs.StepToolCallRequest, toolCall("second")); result.Disposition != acs.Deny || !slices.Contains(result.ReasonCodes, disposition.ReasonStoreFull) {
			t.Fatalf("request past reservation capacity: %+v", result.Decision)
		}
	})
}

// A full store refuses the session; it never drops a live one to make room.
func TestHandshakeAtCapacity(t *testing.T) {
	store, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{MaxSessions: 1, MaxEntries: 8, MaxReservations: 16, MaxSkillApprovals: 1, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *guardian.Config) { c.Store = store })
	first := h.session()
	e := h.refusal(h.client(observedagent.NewUUID()), observedagent.Request{Method: acs.MethodHandshakeHello, Payload: observedagent.DefaultHello(method.Hooks()...)}, acs.SessionRefused)
	if e.Data == nil || e.Data.Reason != "capacity" {
		t.Fatalf("refusal %+v", e)
	}
	if r := h.decision(first, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Allow {
		t.Fatalf("the live session lost its state: %+v", r)
	}
}

func TestHandshakeRefusals(t *testing.T) {
	h2 := newHarness(t)
	tests := []struct {
		name  string
		h     *harness
		hello func(acs.ClientHello) acs.ClientHello
		code  acs.ErrorCode
	}{
		{"no_common_major_version", h2, func(c acs.ClientHello) acs.ClientHello { c.ACSVersionsSupported = []string{"1.0.0"}; return c }, acs.UnsupportedVersion},
		{"provenance_required", newHarness(t, requiresProvenance), func(c acs.ClientHello) acs.ClientHello { return c }, acs.ProvenanceRequired},
		{"no_common_transport", h2, func(c acs.ClientHello) acs.ClientHello { c.TransportsSupported = []string{"stdio"}; return c }, acs.SessionRefused},
		{"client_hello_invalid", h2, func(c acs.ClientHello) acs.ClientHello { c.ACSVersionsSupported = nil; return c }, acs.InvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.h.client(observedagent.NewUUID())
			e := tt.h.refusal(c, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: tt.hello(observedagent.DefaultHello(handshake.CoreMethods()...))}, tt.code)
			if tt.code == acs.UnsupportedVersion && !slices.Equal(e.Data.SupportedVersions, []string{acs.Version}) {
				t.Fatalf("data %+v", e.Data)
			}
		})
	}
}

func requiresProvenance(c *guardian.Config) {
	c.Engine.(*testEngine).policy.RequiresProvenance = true
}

func TestSignatureRequired(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.refusal(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), Unsigned: true}, acs.SignatureInvalid)

	other, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k1", Secret: []byte(strings.Repeat("x", 32))})
	if err != nil {
		t.Fatal(err)
	}
	forged := *c
	forged.Signer = other
	h.refusal(&forged, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")}, acs.SignatureInvalid)

	body, err := c.Envelope(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(body), `ls`, `rm`, 1))
	o, err := c.SendBody(context.Background(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if o.Error == nil || o.Error.Code != acs.SignatureInvalid {
		t.Fatalf("a tampered request got %s", o.Raw)
	}
	if h.engine.callCount() != 0 {
		t.Fatal("an unauthenticated request reached the engine")
	}
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
}

func TestKeyBoundToSession(t *testing.T) {
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k1", Secret: ikm}, guardian.HMACKey{ID: "k2", Secret: []byte(strings.Repeat("y", 32))})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *guardian.Config) { c.Signer = signer })
	h.signer = signer
	c := h.session()
	other := *c
	other.KeyID = "k2"
	// The request authenticates, under another key: a signed DENY, and
	// nothing enters the session.
	o := h.send(&other, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result == nil || !o.Verified || o.Result.Disposition != acs.Deny || !slices.Contains(o.Result.ReasonCodes, disposition.ReasonKeyNotBound) || o.Result.Signature.KeyID != "k2" {
		t.Fatalf("a step under another key got %s", o.Raw)
	}
	if sess, _, _ := h.store.Load(context.Background(), c.SessionID); len(sess.Entries) != 0 {
		t.Fatalf("a step under another key entered the chain: %+v", sess.Entries)
	}
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
}

func TestAgentIDBoundToSession(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	other := *c
	other.AgentID = "other-agent"
	o := h.send(&other, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result == nil || !o.Verified || o.Result.Disposition != acs.Deny || !slices.Contains(o.Result.ReasonCodes, disposition.ReasonAgentIDNotBound) {
		t.Fatalf("a step from another agent got %s", o.Raw)
	}
	if sess, _, _ := h.store.Load(context.Background(), c.SessionID); len(sess.Entries) != 0 {
		t.Fatalf("a step from another agent entered the chain: %+v", sess.Entries)
	}
	h.refusal(&other, observedagent.Request{Method: acs.MethodHandshakeHello, Payload: observedagent.DefaultHello(handshake.CoreMethods()...)}, acs.SessionRefused)
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
}

func TestReplayAndSkew(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	first := observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), RequestID: observedagent.NewUUID(), Nonce: strings.Repeat("n", 16)}
	h.send(c, first)
	sess, _, _ := h.store.Load(context.Background(), c.SessionID)

	h.refusal(c, first, acs.ReplayDetected)
	sameNonce := first
	sameNonce.RequestID = observedagent.NewUUID()
	h.refusal(c, sameNonce, acs.ReplayDetected)
	after, _, _ := h.store.Load(context.Background(), c.SessionID)
	if after.Head != sess.Head || len(after.Entries) != len(sess.Entries) {
		t.Fatal("a replay was appended to the chain")
	}

	for _, skew := range []time.Duration{-301 * time.Second, 301 * time.Second} {
		e := h.refusal(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), Timestamp: time.Now().Add(skew)}, acs.TimestampOutOfWindow)
		if e.Data == nil || e.Data.SkewWindowMS == nil || *e.Data.SkewWindowMS != 300000 {
			t.Fatalf("data %+v, want skew_window_ms 300000", e.Data)
		}
	}
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
}

func TestRejectedAuthenticatedRequestsCannotBeReplayed(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		request observedagent.Request
		code    acs.ErrorCode
	}{
		{
			name:    "method not negotiated",
			methods: []string{acs.StepToolCallRequest},
			request: observedagent.Request{Method: acs.StepUserMessage, Payload: hookPayloads[acs.StepUserMessage]},
			code:    acs.CapabilityNotNegotiated,
		},
		{
			name:    "invalid payload",
			methods: []string{acs.StepToolCallRequest},
			request: observedagent.Request{Method: acs.StepToolCallRequest, Payload: map[string]any{"tool": map[string]any{"name": "Bash"}}},
			code:    acs.InvalidParams,
		},
		{
			name:    "unsupported ACS method",
			methods: []string{acs.StepToolCallRequest},
			request: observedagent.Request{Method: acs.MethodAgBOMSnapshot, Payload: map[string]any{}},
			code:    acs.CapabilityNotNegotiated,
		},
		{
			name:    "undefined method",
			methods: []string{acs.StepToolCallRequest},
			request: observedagent.Request{Method: "steps/unknown", Payload: map[string]any{}},
			code:    acs.MethodNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			c := h.client(observedagent.NewUUID())
			if out, err := c.Handshake(context.Background(), observedagent.DefaultHello(tt.methods...)); err != nil || out.Hello == nil {
				t.Fatalf("handshake: %v %s", err, out.Raw)
			}
			tt.request.RequestID = observedagent.NewUUID()
			body, err := c.Envelope(context.Background(), tt.request)
			if err != nil {
				t.Fatal(err)
			}
			first, err := c.SendBody(context.Background(), body)
			if err != nil || first.Error == nil || first.Error.Code != tt.code {
				t.Fatalf("first request: %v %s", err, first.Raw)
			}
			second, err := c.SendBody(context.Background(), body)
			if err != nil || second.Error == nil || second.Error.Code != acs.ReplayDetected {
				t.Fatalf("replay: %v %s", err, second.Raw)
			}
		})
	}

	t.Run("unsupported ACS version", func(t *testing.T) {
		h := newHarness(t)
		c := h.session()
		body, err := c.Envelope(context.Background(), observedagent.Request{
			Method:    acs.StepToolCallRequest,
			Payload:   toolCall("ls"),
			RequestID: observedagent.NewUUID(),
		})
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]any
		if err := jsonv2.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		params := request["params"].(map[string]any)
		params["acs_version"] = "1.0.0"
		delete(params, "signature")
		unsigned, err := jsonv2.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		body = resign(t, c, unsigned)

		first, err := c.SendBody(context.Background(), body)
		if err != nil || first.Error == nil || first.Error.Code != acs.UnsupportedVersion {
			t.Fatalf("first request: %v %s", err, first.Raw)
		}
		second, err := c.SendBody(context.Background(), body)
		if err != nil || second.Error == nil || second.Error.Code != acs.ReplayDetected {
			t.Fatalf("replay: %v %s", err, second.Raw)
		}
	})
}

func TestReplayHistoryOutlivesEveryAcceptedTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	h := newHarness(t, func(cfg *guardian.Config) {
		cfg.Store = nil
		cfg.MaxSessions = 2
		cfg.SkewWindow = time.Minute
		cfg.SessionRetention = 2 * time.Minute
		cfg.Now = func() time.Time { return now }
	})
	c := h.client(observedagent.NewUUID())
	c.Now = func() time.Time { return now }
	hello := observedagent.Request{
		Method:    acs.MethodHandshakeHello,
		Payload:   observedagent.DefaultHello(acs.StepToolCallRequest),
		RequestID: observedagent.NewUUID(),
		Timestamp: now.Add(time.Minute),
	}
	body, err := c.Envelope(context.Background(), hello)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := c.SendBody(context.Background(), body); err != nil || out.Hello == nil {
		t.Fatalf("initial handshake: %v %s", err, out.Raw)
	}
	second := h.client(observedagent.NewUUID())
	second.Now = func() time.Time { return now }
	if out, err := second.Handshake(context.Background(), observedagent.DefaultHello(acs.StepToolCallRequest)); err != nil || out.Hello == nil {
		t.Fatalf("second session: %v %s", err, out.Raw)
	}

	now = now.Add(2 * time.Minute)
	third := h.client(observedagent.NewUUID())
	third.Now = func() time.Time { return now }
	if out, err := third.Handshake(context.Background(), observedagent.DefaultHello(acs.StepToolCallRequest)); err != nil || out.Error == nil || out.Error.Code != acs.SessionRefused {
		t.Fatalf("session evicted at the freshness boundary: %v %s", err, out.Raw)
	}
	if out, err := c.SendBody(context.Background(), body); err != nil || out.Error == nil || out.Error.Code != acs.ReplayDetected {
		t.Fatalf("captured handshake at the freshness boundary: %v %s", err, out.Raw)
	}

	now = now.Add(time.Nanosecond)
	if out, err := third.Handshake(context.Background(), observedagent.DefaultHello(acs.StepToolCallRequest)); err != nil || out.Hello == nil {
		t.Fatalf("session after replay window: %v %s", err, out.Raw)
	}
	if out, err := c.SendBody(context.Background(), body); err != nil || out.Error == nil || out.Error.Code != acs.TimestampOutOfWindow {
		t.Fatalf("captured handshake after eviction: %v %s", err, out.Raw)
	}
}

func TestEnvelopeGate(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		t.Error("the engine was called for an invalid envelope")
		return guardian.PolicyDecision{}, nil
	})
	missingArguments := map[string]any{"tool": map[string]any{"name": "Bash"}}
	h.refusal(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: missingArguments}, acs.InvalidParams)

	// An envelope missing a required member, re-signed so only the schema
	// can refuse it.
	body, err := c.Envelope(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := jsonv2.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	params := m["params"].(map[string]any)
	delete(params, "timestamp")
	delete(params, "signature")
	unsigned, _ := jsonv2.Marshal(m)
	o, err := c.SendBody(context.Background(), resign(t, c, unsigned))
	if err != nil {
		t.Fatal(err)
	}
	if o.Error == nil || o.Error.Code != acs.InvalidRequest {
		t.Fatalf("an envelope without timestamp got %s, want -32600", o.Raw)
	}
}

// resign signs an arbitrary body with the client's key.
func resign(t *testing.T, c *observedagent.Client, body []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := jsonv2.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	input, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Signer.Sign(context.Background(), c.SessionID, c.KeyID, input)
	if err != nil {
		t.Fatal(err)
	}
	m["params"].(map[string]any)["signature"] = map[string]any{"algorithm": sig.Algorithm, "value": sig.Value, "key_id": sig.KeyID}
	out, _ := jsonv2.Marshal(m)
	return out
}

func canonicalJSON(b []byte) ([]byte, error) {
	var v any
	if err := jsonv2.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	var s strings.Builder
	if err := canonical(&s, toNumbers(v)); err != nil {
		return nil, err
	}
	return []byte(s.String()), nil
}

// toNumbers turns the float64 of a decoded tree into json.Number for the
// independent canonicalizer.
func toNumbers(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = toNumbers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = toNumbers(e)
		}
	case float64:
		b, _ := json.Marshal(v)
		return json.Number(b)
	}
	return v
}

func TestChainPublication(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	allowed := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	h.engine.answer(deny("destructive"))
	denied := h.decision(c, acs.StepToolCallRequest, toolCall("rm -rf /"))
	if denied.Disposition != acs.Deny {
		t.Fatalf("got %s", denied.Disposition)
	}
	sess, _, err := h.store.Load(context.Background(), c.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.Entries) != 2 || sess.Entries[0].EntryHash != allowed.ChainHash || sess.Entries[1].EntryHash != denied.ChainHash || sess.Head != denied.ChainHash {
		t.Fatalf("published heads %s %s, chain %+v", allowed.ChainHash, denied.ChainHash, sess.Entries)
	}
	if sess.Entries[0].PreviousHash != nil || *sess.Entries[1].PreviousHash != allowed.ChainHash {
		t.Fatal("the chain does not link")
	}
	registry, _ := schema.Load()
	for _, e := range sess.Entries {
		recomputed, err := chain.EntryHash(e)
		if err != nil || recomputed != e.EntryHash {
			t.Fatalf("entry %s: recomputed %s", e.EntryID, recomputed)
		}
		if e.RequestHash == "" || e.StepID != e.EntryID || e.StepType != acs.StepToolCallRequest {
			t.Fatalf("entry %+v", e)
		}
		b, _ := jsonv2.Marshal(e)
		if err := registry.ValidateJSON(schema.ContextEntry, b); err != nil {
			t.Fatalf("entry fails context-entry.json: %v", err)
		}
	}
	if got := h.engine.last().Session.ChainHash; got != denied.ChainHash {
		t.Fatalf("the engine saw head %s, want the entry just written", got)
	}

	// The published head is covered by the signature: changing it breaks
	// verification.
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	tampered := []byte(strings.Replace(string(o.Raw), o.Result.ChainHash, hash64, 1))
	if err := verifyResponse(tampered, ikm, c.SessionID); err == nil {
		t.Fatal("a response with a rewritten chain_hash still verifies")
	}
}

func TestChainMismatch(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	first := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	ok := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), ChainHash: first.ChainHash})
	if ok.Result.Disposition != acs.Allow {
		t.Fatalf("a matching chain_hash got %s", ok.Raw)
	}
	bad := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), ChainHash: hash64})
	if bad.Result.Disposition != acs.Deny || !slices.Contains(bad.Result.ReasonCodes, disposition.ReasonChainMismatch) || bad.Result.ChainHash == "" {
		t.Fatalf("a stale chain_hash got %s", bad.Raw)
	}
	if !slices.Contains(h.audit.eventKinds(), guardian.EventChainMismatch) {
		t.Fatal("no chain_mismatch audit event")
	}
}

// TestCoreFloor sends every native hook and requires a signed decision
// with the chain head, then every disposition from the engine.
func TestCoreFloor(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	for _, name := range method.Hooks() {
		if name == acs.StepSessionEnd || name == acs.StepSkillLoad {
			continue
		}
		r := h.decision(c, name, hookPayloads[name])
		if r.Disposition != acs.Allow || r.ChainHash == "" {
			t.Errorf("%s: %+v", name, r)
		}
	}

	// The skillRegister above was allowed, so a load of the same skill_id
	// and digest is bound to it; any other digest is not (skill-load.json).
	if r := h.decision(c, acs.StepSkillLoad, hookPayloads[acs.StepSkillLoad]); r.Disposition != acs.Allow {
		t.Fatalf("a load of the registered skill got %+v", r)
	}
	swapped := map[string]any{"skill_id": "sk", "load_trigger": "user", "load_path": []any{map[string]any{"skill_id": "sk"}}, "digest": map[string]any{"algorithm": "sha-256", "value": "other"}}
	if r := h.decision(c, acs.StepSkillLoad, swapped); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonSkillUnverifiable) {
		t.Fatalf("a load with another digest got %+v", r)
	}

	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	dispositions := []acs.Decision{
		{Disposition: acs.Allow},
		deny("rule"),
		{Disposition: acs.Modify, Reasoning: "redacted", Modifications: &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{"command": json.RawMessage(`"ls"`)}}},
		{Disposition: acs.Ask, Reasoning: "needs approval", AskDetails: &acs.AskDetails{Approver: approver, Question: "run it?", TimeoutSeconds: 60}},
		{Disposition: acs.Defer, Reasoning: "later", DeferDetails: &acs.DeferDetails{Reason: acs.DeferInsufficientContext, ResolutionMethod: acs.ResolveAdditionalContext, ResolutionTimeoutMS: 1000}},
	}
	for _, d := range dispositions {
		h.engine.answer(d)
		r := h.decision(c, acs.StepToolCallRequest, toolCall("rm x"))
		if r.Disposition != d.Disposition {
			t.Fatalf("%s came back as %+v", d.Disposition, r)
		}
		if d.Disposition == acs.Defer && r.DeferDetails.TimeoutDecision != acs.Deny {
			t.Fatalf("timeout_decision %q, want the default deny", r.DeferDetails.TimeoutDecision)
		}
		if d.Disposition == acs.Modify {
			out, err := observedagent.Apply(r.Decision, mustJSON(toolCall("rm x")))
			if err != nil || !strings.Contains(string(out), `"value":"ls"`) {
				t.Fatalf("the client could not apply the modification: %s, %v", out, err)
			}
		}
	}

	h.engine.answer(acs.Decision{Disposition: acs.Allow})
	end := h.decision(c, acs.StepSessionEnd, hookPayloads[acs.StepSessionEnd])
	if end.Disposition != acs.Allow || end.ChainHash == "" {
		t.Fatalf("sessionEnd %+v", end)
	}
	afterEnd := observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), RequestID: observedagent.NewUUID()}
	closed := h.send(c, afterEnd)
	if closed.Result == nil || closed.Result.Disposition != acs.Deny || !slices.Contains(closed.Result.ReasonCodes, disposition.ReasonSessionClosed) || closed.Result.ChainHash != "" {
		t.Fatalf("a step after sessionEnd got %s", closed.Raw)
	}
	// A closed session still refuses replays (§10.3).
	h.refusal(c, afterEnd, acs.ReplayDetected)
}

// A skill whose registration was denied is never approved.
func TestSkillLoadNeedsApprovedRegistration(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	if r := h.decision(c, acs.StepSkillLoad, hookPayloads[acs.StepSkillLoad]); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonSkillUnverifiable) {
		t.Fatalf("a load with no registration got %+v", r)
	}
	h.engine.answer(deny("unvetted"))
	h.decision(c, acs.StepSkillRegister, hookPayloads[acs.StepSkillRegister])
	h.engine.answer(acs.Decision{Disposition: acs.Allow})
	if r := h.decision(c, acs.StepSkillLoad, hookPayloads[acs.StepSkillLoad]); r.Disposition != acs.Deny {
		t.Fatalf("a load after a denied registration got %+v", r)
	}
	// The approval outlives the session that made it.
	h.decision(c, acs.StepSkillRegister, hookPayloads[acs.StepSkillRegister])
	if r := h.decision(h.session(), acs.StepSkillLoad, hookPayloads[acs.StepSkillLoad]); r.Disposition != acs.Allow {
		t.Fatalf("a load in a later session got %+v", r)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := jsonv2.Marshal(v)
	return b
}

func TestPing(t *testing.T) {
	h := newHarness(t)
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{}, errors.New("engine down")
	})
	c := h.client(observedagent.NewUUID())
	echo := "probe-1"
	for _, unsigned := range []bool{true, false} {
		o := h.send(c, observedagent.Request{Method: acs.MethodSystemPing, Payload: acs.SystemPingPayload{Echo: &echo}, Unsigned: unsigned})
		if o.Result == nil || o.Result.Disposition != acs.Allow || o.Result.ChainHash != "" {
			t.Fatalf("ping got %s", o.Raw)
		}
		// An unsigned ping never obtains the session key's signature over an
		// answer whose request_id and echo the caller chose.
		if signed := o.Result.Signature != nil; signed == unsigned || o.Verified == unsigned {
			t.Fatalf("unsigned=%v ping answered with signature %v, verified %v", unsigned, o.Result.Signature, o.Verified)
		}
		var answer acs.SystemPingResponse
		if err := jsonv2.Unmarshal(o.Result.Payload, &answer); err != nil || answer.Status != acs.PingStatusOK || *answer.Echo != echo || answer.ServerTimestamp == "" {
			t.Fatalf("ping payload %s", o.Result.Payload)
		}
	}
	if h.engine.callCount() != 0 {
		t.Fatal("ping called the engine")
	}
	if _, ok, _ := h.store.Load(context.Background(), c.SessionID); ok {
		t.Fatal("ping created session state")
	}
}

func TestMethodRouting(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.refusal(c, observedagent.Request{Method: "system/deferredDecision", Payload: map[string]any{}}, acs.MethodNotFound)
	h.refusal(c, observedagent.Request{Method: "steps/notAHook", Payload: map[string]any{}}, acs.MethodNotFound)
	h.refusal(c, observedagent.Request{Method: acs.MethodAgBOMSnapshot, Payload: map[string]any{}}, acs.CapabilityNotNegotiated)
	e := h.refusal(c, observedagent.Request{Method: "protocols/MCP/tools/call", Payload: map[string]any{}}, acs.CapabilityNotNegotiated)
	if e.Data.Method != "protocols/MCP/tools/call" {
		t.Fatalf("data %+v", e.Data)
	}

	narrow := h.client(observedagent.NewUUID())
	withoutUserMessage := append(slices.DeleteFunc(handshake.CoreMethods(), func(m string) bool { return m == acs.StepUserMessage }), acs.StepAgentTrigger)
	if o, _ := narrow.Handshake(context.Background(), observedagent.DefaultHello(withoutUserMessage...)); o.Hello == nil {
		t.Fatal("handshake refused")
	}
	h.refusal(narrow, observedagent.Request{Method: acs.StepUserMessage, Payload: hookPayloads[acs.StepUserMessage]}, acs.CapabilityNotNegotiated)
	h.refusal(h.client(observedagent.NewUUID()), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")}, acs.CapabilityNotNegotiated)
}

func TestTransportErrors(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name string
		body string
		code acs.ErrorCode
	}{
		{"not_json", `{"jsonrpc":`, acs.ParseError},
		{"duplicate_member", `{"id":1,"id":2}`, acs.ParseError},
		{"batch", `[{"jsonrpc":"2.0"}]`, acs.InvalidRequest},
		{"not_an_object", `"hello"`, acs.InvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := h.post(context.Background(), []byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			var resp acs.Response
			if err := jsonv2.Unmarshal(raw, &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Error == nil || resp.Error.Code != tt.code || string(resp.ID) != "null" {
				t.Fatalf("got %s", raw)
			}
		})
	}
}

func TestInvalidJSONRPCPrecedesSignatureVerification(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name, body string
	}{
		{"missing_jsonrpc", `{"id":1,"method":"steps/toolCallRequest","params":{}}`},
		{"unsupported_jsonrpc_version", `{"jsonrpc":"1.0","id":1,"method":"steps/toolCallRequest","params":{}}`},
		{"response_shaped_input", `{"jsonrpc":"2.0","id":1,"result":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := h.post(context.Background(), []byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			var response acs.Response
			if err := jsonv2.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error == nil || response.Error.Code != acs.InvalidRequest || string(response.ID) != "1" {
				t.Fatalf("got %s", raw)
			}
		})
	}
}

func TestBodyCap(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.MaxBodyBytes = 1024 })
	c := h.session()
	big := toolCall(strings.Repeat("x", 2048))
	body, err := c.Envelope(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: big})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.post(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	var resp acs.Response
	if err := jsonv2.Unmarshal(raw, &resp); err != nil || resp.Error == nil || resp.Error.Code != acs.InvalidRequest {
		t.Fatalf("an oversize body got %s", raw)
	}
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
}

type unreadableBody struct{}

func (unreadableBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (unreadableBody) Close() error             { return nil }

func TestUnreadableBodyReturnsInvalidRequest(t *testing.T) {
	h := newHarness(t)
	request := httptest.NewRequest(http.MethodPost, h.server.URL, nil)
	request.Body = unreadableBody{}
	response := httptest.NewRecorder()
	h.g.ServeHTTP(response, request)

	var result acs.Response
	if err := jsonv2.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.Error == nil || result.Error.Code != acs.InvalidRequest || string(result.ID) != "null" {
		t.Fatalf("got HTTP %d: %s", response.Code, response.Body.Bytes())
	}
}

var _ io.ReadCloser = unreadableBody{}

func TestEngineFailuresAreDenials(t *testing.T) {
	tests := []struct {
		name   string
		decide func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error)
		reason string
	}{
		{"error", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{}, errors.New("boom")
		}, disposition.ReasonEvaluationFailed},
		{"panic", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) { panic("boom") }, disposition.ReasonEvaluationFailed},
		{"timeout", func(ctx context.Context, _ guardian.PolicyInput) (guardian.PolicyDecision, error) {
			<-ctx.Done()
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
		}, disposition.ReasonEvaluationFailed},
		{"deny_without_reasoning", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Deny}}, nil
		}, disposition.ReasonEvaluationFailed},
		{"modify_breaking_composition", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			content := "x"
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{
				ModifiedContent: &content, Redactions: []acs.Redaction{{Path: "/raw_command"}},
			}}}, nil
		}, disposition.ReasonEvaluationFailed},
		{"overlapping_edits", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Modify, Reasoning: "r", Modifications: &acs.Modifications{
				Redactions:         []acs.Redaction{{Path: "/arguments/command/value"}},
				ParameterOverrides: map[string]json.RawMessage{"command": json.RawMessage(`"ls"`)},
			}}}, nil
		}, disposition.ReasonEvaluationFailed},
		{"ask_to_undeclared_approver", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Ask, Reasoning: "r", AskDetails: &acs.AskDetails{
				Approver: acs.Approver{Type: acs.ApproverService, ID: "svc"}, Question: "q", TimeoutSeconds: 1,
			}}}, nil
		}, disposition.ReasonEvaluationFailed},
		{"delegate_to_agent", func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, DelegateToAgent: true}, nil
		}, disposition.ReasonAgentLayerUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(c *guardian.Config) { c.DecisionTimeout = 50 * time.Millisecond })
			c := h.session()
			h.engine.set(tt.decide)
			r := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
			if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, tt.reason) || r.Reasoning == "" || r.ChainHash == "" {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestClientSubstitutions(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	modify := acs.Decision{Disposition: acs.Modify, Reasoning: "rewrite", Modifications: &acs.Modifications{Redactions: []acs.Redaction{{Path: "/summary/value"}}}}
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: modify, Client: guardian.ClientCapability{CannotApplyModify: true}}, nil
	})
	r := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonModifyUnsupported) {
		t.Fatalf("§6.5 substitution got %+v", r)
	}
	r = h.decision(c, acs.StepPostCompact, hookPayloads[acs.StepPostCompact])
	if r.Disposition != acs.Allow || !slices.Contains(r.ReasonCodes, disposition.ReasonModifyUnsupported) {
		t.Fatalf("§6.5 postCompact exception got %+v", r)
	}

	ask := acs.Decision{Disposition: acs.Ask, Reasoning: "approve", AskDetails: &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverHuman, ID: "r"}, Question: "q", TimeoutSeconds: 30}}
	for _, substitute := range []acs.Disposition{acs.Defer, acs.Deny} {
		h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: ask, Client: guardian.ClientCapability{CannotResolveAsk: true, AskSubstitute: substitute}}, nil
		})
		r = h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
		if r.Disposition != substitute || !slices.Contains(r.ReasonCodes, disposition.ReasonApproverUnavailable) {
			t.Fatalf("§9.2 substitution %s got %+v", substitute, r)
		}
		if substitute == acs.Defer && (r.DeferDetails.TimeoutDecision != acs.Deny || r.DeferDetails.ResolutionTimeoutMS != 30000) {
			t.Fatalf("defer details %+v", r.DeferDetails)
		}
	}
	kinds := h.audit.eventKinds()
	if count(kinds, guardian.EventModifyUnsupported) != 2 || count(kinds, guardian.EventAskSubstituted) != 2 {
		t.Fatalf("audit events %v", kinds)
	}
}

func count[T comparable](s []T, v T) int {
	n := 0
	for _, e := range s {
		if e == v {
			n++
		}
	}
	return n
}

func TestHookPermittedDispositions(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.engine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "a", AskDetails: &acs.AskDetails{Approver: acs.Approver{Type: acs.ApproverHuman, ID: "r"}, Question: "q", TimeoutSeconds: 1}})
	r := h.decision(c, acs.StepUserMessage, hookPayloads[acs.StepUserMessage])
	if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonDispositionNotPermitted) {
		t.Fatalf("ask at userMessage got %+v", r)
	}
	h.engine.answer(deny("x"))
	r = h.decision(c, acs.StepPostCompact, hookPayloads[acs.StepPostCompact])
	if r.Disposition != acs.Allow || !slices.Contains(r.ReasonCodes, disposition.ReasonDispositionNotPermitted) {
		t.Fatalf("deny at postCompact got %+v", r)
	}
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{}, errors.New("down")
	})
	r = h.decision(c, acs.StepTurnEnd, hookPayloads[acs.StepTurnEnd])
	if r.Disposition != acs.Allow {
		t.Fatalf("an engine failure at an audit-only hook got %+v", r)
	}
	if count(h.audit.eventKinds(), guardian.EventDispositionNotPermitted) != 3 {
		t.Fatalf("audit events %v", h.audit.eventKinds())
	}
}

func TestDeferralBound(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.MaxDeferrals = 2 })
	c := h.session()
	h.engine.answer(acs.Decision{Disposition: acs.Defer, Reasoning: "wait", DeferDetails: &acs.DeferDetails{Reason: acs.DeferPendingDependency, ResolutionMethod: acs.ResolveHumanApproval, ResolutionTimeoutMS: 1}})
	for range 2 {
		if r := h.decision(c, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Defer {
			t.Fatalf("got %+v", r)
		}
	}
	r := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonDeferralBoundExceeded) {
		t.Fatalf("the third deferral got %+v", r)
	}
}

func TestIntent(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	raw := "list files"
	provenance := map[string]any{"provenance_id": "p1", "origin": "user_input"}
	intent := map[string]any{"raw": raw, "parsed": []any{map[string]any{"tool": "Bash", "operation": "list"}, map[string]any{"tool": "Read", "operation": "file"}}, "parser_provenance": provenance}
	h.decision(c, acs.StepSessionStart, map[string]any{"intent": intent})
	if got := h.engine.last().Session.Intent; got == nil || *got.Raw != raw || len(got.Parsed) != 2 {
		t.Fatalf("the engine saw intent %+v", got)
	}
	reordered := map[string]any{"raw": raw, "parsed": []any{map[string]any{"tool": "Read", "operation": "file"}, map[string]any{"tool": "Bash", "operation": "list"}}, "parser_provenance": provenance}
	same := h.decision(c, acs.StepAgentTrigger, map[string]any{"trigger_type": "user_message", "intent": reordered})
	if same.Disposition != acs.Allow {
		t.Fatalf("restating the Intent got %+v", same)
	}
	wider := map[string]any{"raw": raw, "parsed": []any{map[string]any{"tool": "Bash", "operation": "list"}, map[string]any{"tool": "Read", "operation": "file"}, map[string]any{"tool": "curl"}}, "parser_provenance": provenance}
	r := h.decision(c, acs.StepAgentTrigger, map[string]any{"trigger_type": "user_message", "intent": wider})
	if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonIntentMismatch) || r.ChainHash == "" {
		t.Fatalf("widening the Intent got %+v", r)
	}
	if !slices.Contains(h.audit.eventKinds(), guardian.EventIntentMutationRejected) {
		t.Fatal("no intent_mutation_rejected audit event")
	}
	sess, _, _ := h.store.Load(context.Background(), c.SessionID)
	if len(sess.Intent.Parsed) != 2 {
		t.Fatalf("the Intent changed to %+v", sess.Intent)
	}
}

func TestIntentExtension(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	h.engine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "curl is outside the Intent", AskDetails: &acs.AskDetails{Approver: approver, Question: "allow curl?", TimeoutSeconds: 60}})
	asked := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))
	h.engine.answer(acs.Decision{Disposition: acs.Allow})
	allowed := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))

	source := "reviewer"
	grant := guardian.IntentGrant{
		Approver: approver,
		Extension: acs.IntentExtension{Capabilities: []acs.Capability{{Tool: "curl"}}, Scope: acs.ScopeSession,
			Provenance: &acs.Provenance{ProvenanceID: "grant-1", Origin: "user_input", SourceID: &source}},
		AskStepID: asked.RequestID,
	}
	withGrant := func(g guardian.IntentGrant) {
		h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
			return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, Grant: &g}, nil
		})
	}

	// A grant must answer an ASK this session was given.
	notAsked := grant
	notAsked.AskStepID = allowed.RequestID
	withGrant(notAsked)
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("curl x")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonGrantInvalid) {
		t.Fatalf("a grant for a step that was not asked got %+v", r)
	}

	invalidScope := grant
	invalidScope.Extension.Scope = "future"
	withGrant(invalidScope)
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("curl x")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonGrantInvalid) {
		t.Fatalf("a grant with an undefined scope got %+v", r)
	}
	beforeGrant, _, _ := h.store.Load(context.Background(), c.SessionID)
	if beforeGrant.Intent != nil {
		t.Fatalf("an invalid grant changed the Intent to %+v", beforeGrant.Intent)
	}

	withGrant(grant)
	r := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))
	sess, _, _ := h.store.Load(context.Background(), c.SessionID)
	last := sess.Entries[len(sess.Entries)-1]
	if last.StepType != acs.StepTypeIntentExtension || last.StepID != grant.AskStepID || r.ChainHash != last.EntryHash {
		t.Fatalf("intent_extension entry %+v, published head %s", last, r.ChainHash)
	}
	// §9.1: the entry records the approver, the capabilities and the
	// extension's own provenance, and its hash commits to them.
	if last.Approver == nil || last.Approver.ID != "reviewer" || last.IntentExtension == nil ||
		len(last.IntentExtension.Capabilities) != 1 || last.IntentExtension.Provenance == nil || last.IntentExtension.Provenance.ProvenanceID != "grant-1" {
		t.Fatalf("intent_extension entry records %+v", last)
	}
	if recomputed, err := chain.EntryHash(last); err != nil || recomputed != last.EntryHash {
		t.Fatalf("the entry's hash does not commit to its grant: %s, %v", recomputed, err)
	}
	if sess.Intent == nil || len(sess.Intent.Parsed) != 1 || sess.Intent.Parsed[0].Tool != "curl" {
		t.Fatalf("Intent %+v", sess.Intent)
	}
}

func TestIntentExtensionPreservesPostCompactLineage(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	h.engine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "approval required", AskDetails: &acs.AskDetails{
		Approver: approver, Question: "allow curl?", TimeoutSeconds: 60,
	}})
	asked := h.decision(c, acs.StepToolCallRequest, withProvenance(toolCall("curl x"), "p1"))
	source := "reviewer"
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{
			Decision: acs.Decision{Disposition: acs.Allow},
			Grant: &guardian.IntentGrant{
				Approver: approver,
				Extension: acs.IntentExtension{
					Capabilities: []acs.Capability{{Tool: "curl"}},
					Scope:        acs.ScopeSession,
					Provenance:   &acs.Provenance{ProvenanceID: "grant-1", Origin: "user_input", SourceID: &source},
				},
				AskStepID: asked.RequestID,
			},
		}, nil
	})
	granted := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))
	h.engine.answer(acs.Decision{Disposition: acs.Allow})
	compacted := h.decision(c, acs.StepPostCompact, map[string]any{
		"summary": map[string]any{
			"value": "sum",
			"provenance": map[string]any{
				"provenance_id": "summary-1",
				"origin":        "agent_generated",
				"derived_from":  []any{"grant-1", "p1"},
			},
		},
		"entries_compacted":       []any{asked.RequestID},
		"pre_compact_chain_hash":  granted.ChainHash,
		"post_compact_chain_hash": hash64,
	})
	if compacted.Disposition != acs.Allow || slices.Contains(compacted.ReasonCodes, disposition.ReasonLineageMismatch) {
		t.Fatalf("a faithful summary after an intent extension got %+v", compacted)
	}
	missingGrant := h.decision(c, acs.StepPostCompact, map[string]any{
		"summary": map[string]any{
			"value": "sum",
			"provenance": map[string]any{
				"provenance_id": "summary-2",
				"origin":        "agent_generated",
				"derived_from":  []any{"p1"},
			},
		},
		"entries_compacted":       []any{asked.RequestID},
		"pre_compact_chain_hash":  compacted.ChainHash,
		"post_compact_chain_hash": hash64,
	})
	if missingGrant.Disposition != acs.Allow || !slices.Contains(missingGrant.ReasonCodes, disposition.ReasonLineageMismatch) {
		t.Fatalf("a summary missing intent extension provenance got %+v", missingGrant)
	}
}

func TestSessionsRunInParallel(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.engine.set(func(ctx context.Context, in guardian.PolicyInput) (guardian.PolicyDecision, error) {
		if in.Request.Method == acs.StepUserMessage {
			<-release
		}
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
	})
	a, b := h.session(), h.session()
	done := make(chan struct{})
	go func() {
		h.decision(a, acs.StepUserMessage, hookPayloads[acs.StepUserMessage])
		close(done)
	}()
	h.decision(b, acs.StepToolCallRequest, toolCall("ls"))
	close(release)
	<-done
}

func TestShutdownAnswersInFlightSteps(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	started := make(chan struct{})
	h.engine.set(func(ctx context.Context, _ guardian.PolicyInput) (guardian.PolicyDecision, error) {
		close(started)
		<-ctx.Done()
		return guardian.PolicyDecision{}, ctx.Err()
	})
	answered := make(chan *acs.Result)
	go func() { answered <- h.decision(c, acs.StepToolCallRequest, toolCall("ls")) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.g.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	if r := <-answered; r.Disposition != acs.Deny {
		t.Fatalf("the in-flight step got %+v", r)
	}
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Error == nil {
		t.Fatalf("a step after Shutdown got %s", o.Raw)
	}
}

func TestAuditLogReceivesEveryEnvelope(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	_, _ = h.post(context.Background(), []byte("not json"))
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	var directions []guardian.Direction
	for _, e := range h.audit.envelopes {
		directions = append(directions, e.Direction)
	}
	want := []guardian.Direction{guardian.Inbound, guardian.Outbound, guardian.Inbound, guardian.Outbound, guardian.Outbound}
	if !slices.Equal(directions, want) {
		t.Fatalf("recorded %v, want %v", directions, want)
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	signer, _ := guardian.NewHMACSigner(guardian.HMACKey{ID: "k", Secret: ikm})
	engine := &testEngine{}
	badPolicy := &testEngine{policy: guardian.PolicyDescription{ApproverTypes: []acs.ApproverType{"unknown"}}}
	for name, cfg := range map[string]guardian.Config{
		"no_engine":                 {Signer: signer},
		"no_signer":                 {Engine: engine},
		"unknown_posture":           {Engine: engine, Signer: signer, OnDecisionFailure: "maybe"},
		"unknown_transport":         {Engine: engine, Signer: signer, Transport: "grpc"},
		"unknown_ask_substitution":  {Engine: engine, Signer: signer, AskSubstitution: "ask"},
		"negative_window":           {Engine: engine, Signer: signer, SkewWindow: -time.Second},
		"retention_one_window":      {Engine: engine, Signer: signer, SkewWindow: time.Minute, SessionRetention: time.Minute},
		"window_too_large":          {Engine: engine, Signer: signer, SkewWindow: time.Duration(1<<63 - 1), SessionRetention: time.Duration(1<<63 - 1)},
		"invalid_policy_descriptor": {Engine: badPolicy, Signer: signer},
	} {
		if _, err := guardian.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := guardian.New(guardian.Config{Engine: engine, Signer: signer, SkewWindow: time.Minute, SessionRetention: 2 * time.Minute}); err != nil {
		t.Fatalf("retention of two skew windows: %v", err)
	}
	if _, err := guardian.New(guardian.Config{Engine: engine, Signer: signerWithAlgorithms{Signer: signer}}); err == nil {
		t.Fatal("accepted a signer that declares no algorithms")
	}
	if _, err := guardian.New(guardian.Config{Engine: panickingPolicyDescription{PolicyEngine: engine}, Signer: signer}); err == nil {
		t.Fatal("accepted an engine whose Policy method panics")
	}
	if _, err := guardian.New(guardian.Config{Engine: engine, Signer: panickingAlgorithms{Signer: signer}}); err == nil {
		t.Fatal("accepted a signer whose Algorithms method panics")
	}
}

type signerWithAlgorithms struct {
	guardian.Signer
}

func (signerWithAlgorithms) Algorithms() []string { return nil }

type panickingPolicyDescription struct {
	guardian.PolicyEngine
}

func (panickingPolicyDescription) Policy() guardian.PolicyDescription { panic("policy") }

type panickingAlgorithms struct {
	guardian.Signer
}

func (panickingAlgorithms) Algorithms() []string { panic("algorithms") }

func TestConfiguredAskSubstitution(t *testing.T) {
	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	ask := acs.Decision{Disposition: acs.Ask, Reasoning: "approval required", AskDetails: &acs.AskDetails{Approver: approver, Question: "allow?", TimeoutSeconds: 30}}
	for _, tt := range []struct {
		name, substitution string
		want               acs.Disposition
	}{
		{"none", string(guardian.AskSubstitutionNone), acs.Ask},
		{"deny", string(guardian.AskSubstitutionDeny), acs.Deny},
		{"defer", string(guardian.AskSubstitutionDefer), acs.Defer},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(c *guardian.Config) { c.AskSubstitution = guardian.AskSubstitution(tt.substitution) })
			h.engine.answer(ask)
			r := h.decision(h.session(), acs.StepToolCallRequest, toolCall("deploy"))
			if r.Disposition != tt.want {
				t.Fatalf("got %+v, want %s", r, tt.want)
			}
		})
	}
}

// Wrapped MCP is governed by the Guardian New returns: a request and its
// response each get a signed decision and a chain entry, the engine sees the
// message intact, and a malformed message is Invalid params.
func TestWrappedMCP(t *testing.T) {
	h := newHarness(t)
	c := h.client(observedagent.NewUUID())
	const call, explicit = "protocols/MCP/tools/call", "wrapped:mcp-2025-06-18/tools/call"
	hello := observedagent.DefaultHello(append(method.Hooks(), call, explicit)...)
	hello.WrappedProtocols = []acs.WrappedProtocol{{Protocol: "MCP", Version: "2025-06-18"}}
	if o, err := c.Handshake(context.Background(), hello); err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v %s", err, o.Raw)
	}
	request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "get_weather", "arguments": map[string]any{"city": "Barcelona"}}}
	response := map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "sunny"}}}}
	for _, m := range []string{call, explicit} {
		for _, payload := range []any{request, response} {
			if r := h.decision(c, m, payload); r.Disposition != acs.Allow || r.ChainHash == "" {
				t.Fatalf("%s got %+v", m, r)
			}
			var got, want any
			_ = jsonv2.Unmarshal(h.engine.last().Request.Params.Payload, &got)
			_ = jsonv2.Unmarshal(mustJSON(payload), &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("the engine saw %v, want %v", got, want)
			}
		}
	}
	h.refusal(c, observedagent.Request{Method: call, Payload: map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}, acs.InvalidParams)
}

func TestWrappedMCPRefusesOverlappingModifications(t *testing.T) {
	for _, methodName := range []string{"protocols/MCP/tools/call", "wrapped:mcp-2025-06-18/tools/call"} {
		for _, path := range []string{
			"/params/arguments/command",
			"/params/arguments",
			"/params/arguments/command/value",
		} {
			t.Run(methodName+path, func(t *testing.T) {
				h := newHarness(t)
				c := h.client(observedagent.NewUUID())
				hello := observedagent.DefaultHello(methodName)
				hello.WrappedProtocols = []acs.WrappedProtocol{{Protocol: "MCP", Version: "2025-06-18"}}
				if out, err := c.Handshake(context.Background(), hello); err != nil || out.Hello == nil {
					t.Fatalf("handshake: %v %s", err, out.Raw)
				}
				h.engine.answer(acs.Decision{
					Disposition: acs.Modify,
					Reasoning:   "conflicting changes",
					Modifications: &acs.Modifications{
						Redactions:         []acs.Redaction{{Path: path}},
						ParameterOverrides: map[string]json.RawMessage{"command": json.RawMessage(`"changed"`)},
					},
				})
				payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"echo hello"}}}`)
				result := h.decision(c, methodName, payload)
				if result.Disposition != acs.Deny || !slices.Contains(result.Decision.ReasonCodes, disposition.ReasonEvaluationFailed) {
					t.Fatalf("overlapping edits got %+v", result.Decision)
				}
			})
		}
	}
}
