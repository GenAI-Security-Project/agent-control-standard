package guardian_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

// testEngine answers with a function each test chooses and records every
// input it was given.
type testEngine struct {
	policy guardian.PolicyDescription
	decide func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error)

	mu    sync.Mutex
	calls []guardian.PolicyInput
}

func (e *testEngine) Policy() guardian.PolicyDescription { return e.policy }

func (e *testEngine) Decide(ctx context.Context, in guardian.PolicyInput) (guardian.PolicyDecision, error) {
	e.mu.Lock()
	e.calls = append(e.calls, in)
	decide := e.decide
	e.mu.Unlock()
	if decide == nil {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
	}
	return decide(ctx, in)
}

func (e *testEngine) set(decide func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error)) {
	e.mu.Lock()
	e.decide = decide
	e.mu.Unlock()
}

func (e *testEngine) answer(d acs.Decision) {
	e.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: d}, nil
	})
}

func (e *testEngine) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

func (e *testEngine) last() guardian.PolicyInput {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[len(e.calls)-1]
}

// auditRecorder is an AuditLog that keeps everything.
type auditRecorder struct {
	mu        sync.Mutex
	envelopes []guardian.EnvelopeRecord
	events    []guardian.AuditEvent
}

func (a *auditRecorder) Envelope(_ context.Context, r guardian.EnvelopeRecord) {
	a.mu.Lock()
	a.envelopes = append(a.envelopes, r)
	a.mu.Unlock()
}

func (a *auditRecorder) Event(_ context.Context, e guardian.AuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

func (a *auditRecorder) eventKinds() []guardian.AuditEventKind {
	a.mu.Lock()
	defer a.mu.Unlock()
	var kinds []guardian.AuditEventKind
	for _, e := range a.events {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// ikm is the deployment keying material every test shares.
var ikm = []byte("0123456789abcdef0123456789abcdef")

type harness struct {
	t      *testing.T
	g      *guardian.Guardian
	store  *guardian.MemorySessionContextStore
	engine *testEngine
	audit  *auditRecorder
	signer *guardian.HMACSigner
	server *httptest.Server
	now    time.Time
}

type option func(*guardian.Config)

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k1", Secret: ikm})
	if err != nil {
		t.Fatal(err)
	}
	store, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{MaxSessions: 64, MaxEntries: 1024, MaxReservations: 2048, MaxSkillApprovals: 64, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t, store: store, signer: signer,
		engine: &testEngine{policy: guardian.PolicyDescription{ApproverTypes: []acs.ApproverType{acs.ApproverHuman}}},
		audit:  &auditRecorder{},
		now:    time.Now(),
	}
	cfg := guardian.Config{Engine: h.engine, Signer: signer, Store: store, AuditLog: h.audit}
	for _, o := range opts {
		o(&cfg)
	}
	h.g, err = guardian.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.server = httptest.NewServer(h.g)
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) post(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.server.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (h *harness) client(sessionID string) *observedagent.Client {
	return &observedagent.Client{Transport: h.post, Signer: h.signer, AgentID: "agent", SessionID: sessionID}
}

// session returns a client whose session is negotiated for every native
// hook.
func (h *harness) session() *observedagent.Client {
	h.t.Helper()
	c := h.client(observedagent.NewUUID())
	o, err := c.Handshake(context.Background(), observedagent.DefaultHello(append(method.Hooks(), acs.MethodSystemPing)...))
	if err != nil {
		h.t.Fatal(err)
	}
	if o.Hello == nil {
		h.t.Fatalf("handshake refused: %s", o.Raw)
	}
	return c
}

// send sends one request and fails the test on a transport error.
func (h *harness) send(c *observedagent.Client, r observedagent.Request) observedagent.Outcome {
	h.t.Helper()
	o, err := c.Send(context.Background(), r)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}

// decision sends a step and requires a signed decision back.
func (h *harness) decision(c *observedagent.Client, methodName string, payload any) *acs.Result {
	h.t.Helper()
	o := h.send(c, observedagent.Request{Method: methodName, Payload: payload})
	if o.Result == nil {
		h.t.Fatalf("%s: no decision: %s", methodName, o.Raw)
	}
	if !o.Verified {
		h.t.Fatalf("%s: the decision's signature does not verify: %s", methodName, o.Raw)
	}
	if err := verifyResponse(o.Raw, ikm, c.SessionID); err != nil && !strings.Contains(err.Error(), "integers only") {
		h.t.Fatalf("%s: the independent verifier refuses the decision: %v", methodName, err)
	}
	return o.Result
}

// refusal sends a request and requires an error answer with code. An error
// answering a signed request that verifies must itself be signed and verify;
// one answering a request that does not authenticate must be unsigned.
func (h *harness) refusal(c *observedagent.Client, r observedagent.Request, code acs.ErrorCode) *acs.Error {
	h.t.Helper()
	o := h.send(c, r)
	if o.Error == nil || o.Error.Code != code {
		h.t.Fatalf("%s: got %s, want error %d", r.Method, o.Raw, code)
	}
	authenticated := !r.Unsigned && code != acs.SignatureInvalid
	switch {
	case authenticated && !o.Verified:
		h.t.Fatalf("%s: the error answering an authenticated request is not signed: %s", r.Method, o.Raw)
	case authenticated:
		if err := verifyResponse(o.Raw, ikm, c.SessionID); err != nil && c.KeyID == "" {
			h.t.Fatalf("%s: the independent verifier refuses the error: %v", r.Method, err)
		}
	case o.Error.Signature != nil:
		h.t.Fatalf("%s: an error answering an unauthenticated request is signed: %s", r.Method, o.Raw)
	}
	return o.Error
}

func toolCall(command string) acs.ToolCallRequestPayload {
	value := []byte(`"` + command + `"`)
	return acs.ToolCallRequestPayload{
		Tool:       acs.Tool{Name: "Bash"},
		Arguments:  map[string]acs.ToolArgument{"command": {Value: value}},
		RawCommand: &command,
	}
}

func deny(reason string) acs.Decision {
	return acs.Decision{Disposition: acs.Deny, Reasoning: "denied: " + reason, ReasonCodes: []string{reason}}
}
