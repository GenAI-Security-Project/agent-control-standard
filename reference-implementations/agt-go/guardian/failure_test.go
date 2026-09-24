package guardian_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

// failingStore wraps the memory store and fails the operation named in
// failing with a message a deployment would not want on the wire.
type failingStore struct {
	*guardian.MemorySessionContextStore
	failing      string
	appendCalls  int
	failAppendAt int
}

type archivedStore struct {
	guardian.SessionContextStore
	archive bool
}

func (s *archivedStore) Load(ctx context.Context, sessionID string) (guardian.Session, bool, error) {
	session, ok, err := s.SessionContextStore.Load(ctx, sessionID)
	if s.archive {
		session.Entries = nil
	}
	return session, ok, err
}

type panickingStore struct {
	guardian.SessionContextStore
	panicOnLoad     bool
	panicOnConclude bool
}

type panickingAuditLog struct{}

func (panickingAuditLog) Envelope(context.Context, guardian.EnvelopeRecord) { panic("envelope") }
func (panickingAuditLog) Event(context.Context, guardian.AuditEvent)        { panic("event") }

func (s *panickingStore) Load(ctx context.Context, sessionID string) (guardian.Session, bool, error) {
	if s.panicOnLoad {
		panic("load failed")
	}
	return s.SessionContextStore.Load(ctx, sessionID)
}

func (s *panickingStore) Conclude(ctx context.Context, sessionID string, conclusion guardian.Conclusion) error {
	if s.panicOnConclude {
		panic("conclude failed")
	}
	return s.SessionContextStore.Conclude(ctx, sessionID, conclusion)
}

var errSecretStore = errors.New("pq: connection to 10.0.0.7:5432 refused for user acs_admin")

func (s *failingStore) fail(op string) error {
	if s.failing == op {
		return errSecretStore
	}
	return nil
}

func (s *failingStore) Lock(ctx context.Context, id string) (context.Context, func(), error) {
	if err := s.fail("lock"); err != nil {
		return nil, nil, err
	}
	return s.MemorySessionContextStore.Lock(ctx, id)
}

func (s *failingStore) Load(ctx context.Context, id string) (guardian.Session, bool, error) {
	if err := s.fail("load"); err != nil {
		return guardian.Session{}, false, err
	}
	return s.MemorySessionContextStore.Load(ctx, id)
}

func (s *failingStore) Append(ctx context.Context, id string, a guardian.Append) error {
	s.appendCalls++
	if s.failAppendAt == s.appendCalls {
		return errSecretStore
	}
	if err := s.fail("append"); err != nil {
		return err
	}
	return s.MemorySessionContextStore.Append(ctx, id, a)
}

func TestIntentExtensionStoreFailurePublishesLastCommittedHead(t *testing.T) {
	memory, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{MaxSessions: 8, MaxEntries: 64, MaxReservations: 128, MaxSkillApprovals: 8, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{MemorySessionContextStore: memory}
	h := newHarness(t, func(c *guardian.Config) { c.Store = store })
	c := h.session()
	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	h.engine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "approval required", AskDetails: &acs.AskDetails{Approver: approver, Question: "allow curl?", TimeoutSeconds: 60}})
	asked := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))

	source := "reviewer"
	grant := guardian.IntentGrant{
		Approver: approver,
		Extension: acs.IntentExtension{Capabilities: []acs.Capability{{Tool: "curl"}}, Scope: acs.ScopeSession,
			Provenance: &acs.Provenance{ProvenanceID: "grant-1", Origin: "user_input", SourceID: &source}},
		AskStepID: asked.RequestID,
	}
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, Grant: &grant}, nil
	})
	store.failAppendAt = store.appendCalls + 2
	r := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))
	if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonStoreUnavailable) || r.ChainHash == "" {
		t.Fatalf("an intent-extension append failure got %+v", r)
	}
	sess, _, err := store.Load(context.Background(), c.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	last := sess.Entries[len(sess.Entries)-1]
	if r.ChainHash != last.EntryHash {
		t.Fatalf("published head %q, want committed entry hash %q", r.ChainHash, last.EntryHash)
	}
}

func TestAuthenticatedStepProviderPanicIsSignedDeny(t *testing.T) {
	var store *panickingStore
	h := newHarness(t, func(c *guardian.Config) {
		store = &panickingStore{SessionContextStore: c.Store}
		c.Store = store
	})
	c := h.session()
	store.panicOnLoad = true
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result == nil || o.Result.Disposition != acs.Deny || !o.Verified {
		t.Fatalf("provider panic got %s", o.Raw)
	}
	if !slices.Contains(o.Result.ReasonCodes, disposition.ReasonEvaluationFailed) {
		t.Fatalf("provider panic reason codes %v", o.Result.ReasonCodes)
	}
}

func TestProviderPanicAfterAppendPublishesCommittedHead(t *testing.T) {
	var store *panickingStore
	h := newHarness(t, func(c *guardian.Config) {
		store = &panickingStore{SessionContextStore: c.Store}
		c.Store = store
	})
	c := h.session()
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{
			Decision: acs.Decision{Disposition: acs.Allow},
			State:    json.RawMessage(`{"reviewed":true}`),
		}, nil
	})
	store.panicOnConclude = true
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result == nil || o.Result.Disposition != acs.Deny || !o.Verified || o.Result.ChainHash == "" {
		t.Fatalf("provider panic after append got %s", o.Raw)
	}
	if !slices.Contains(o.Result.ReasonCodes, disposition.ReasonEvaluationFailed) {
		t.Fatalf("provider panic reason codes %v", o.Result.ReasonCodes)
	}
	session, ok, err := store.Load(context.Background(), c.SessionID)
	if err != nil || !ok || len(session.Entries) == 0 {
		t.Fatalf("load committed session: ok=%v err=%v", ok, err)
	}
	if want := session.Entries[len(session.Entries)-1].EntryHash; o.Result.ChainHash != want {
		t.Fatalf("published head %q, want committed entry hash %q", o.Result.ChainHash, want)
	}
}

func TestProviderPanicAfterGrantPublishesCommittedHead(t *testing.T) {
	var store *panickingStore
	h := newHarness(t, func(c *guardian.Config) {
		store = &panickingStore{SessionContextStore: c.Store}
		c.Store = store
	})
	c := h.session()
	approver := acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"}
	h.engine.answer(acs.Decision{Disposition: acs.Ask, Reasoning: "approval required", AskDetails: &acs.AskDetails{
		Approver: approver, Question: "allow curl?", TimeoutSeconds: 60,
	}})
	asked := h.decision(c, acs.StepToolCallRequest, toolCall("curl x"))
	source := "reviewer"
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{
			Decision: acs.Decision{Disposition: acs.Allow},
			State:    json.RawMessage(`{"reviewed":true}`),
			Grant: &guardian.IntentGrant{
				Approver: approver,
				Extension: acs.IntentExtension{Capabilities: []acs.Capability{{Tool: "curl"}}, Scope: acs.ScopeSession,
					Provenance: &acs.Provenance{ProvenanceID: "grant-1", Origin: "user_input", SourceID: &source}},
				AskStepID: asked.RequestID,
			},
		}, nil
	})
	store.panicOnConclude = true
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("curl x")})
	if o.Result == nil || o.Result.Disposition != acs.Deny || !o.Verified {
		t.Fatalf("provider panic after grant got %s", o.Raw)
	}
	session, ok, err := store.Load(context.Background(), c.SessionID)
	if err != nil || !ok || len(session.Entries) == 0 {
		t.Fatalf("load committed session: ok=%v err=%v", ok, err)
	}
	if want := session.Entries[len(session.Entries)-1].EntryHash; o.Result.ChainHash != want {
		t.Fatalf("published head %q, want committed intent-extension hash %q", o.Result.ChainHash, want)
	}
}

func TestAuditLogPanicDoesNotChangeDecision(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.AuditLog = panickingAuditLog{} })
	r := h.decision(h.session(), acs.StepToolCallRequest, toolCall("ls"))
	if r.Disposition != acs.Allow {
		t.Fatalf("audit panic changed the decision: %+v", r)
	}
}

func (s *failingStore) Conclude(ctx context.Context, id string, c guardian.Conclusion) error {
	if err := s.fail("conclude"); err != nil {
		return err
	}
	return s.MemorySessionContextStore.Conclude(ctx, id, c)
}

// An authenticated step whose store fails is answered with a signed DENY,
// never an error the Observed Agent's default posture would proceed on, and
// the store's own message stays in the audit log.
func TestStoreFailureIsSignedDenial(t *testing.T) {
	for _, op := range []string{"lock", "load", "append", "conclude"} {
		t.Run(op, func(t *testing.T) {
			memory, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{MaxSessions: 8, MaxEntries: 64, MaxReservations: 128, MaxSkillApprovals: 8, Retention: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			store := &failingStore{MemorySessionContextStore: memory}
			h := newHarness(t, func(c *guardian.Config) { c.Store = store })
			c := h.session()
			h.engine.answer(acs.Decision{Disposition: acs.Defer, Reasoning: "wait", DeferDetails: &acs.DeferDetails{Reason: acs.DeferPendingDependency, ResolutionMethod: acs.ResolveHumanApproval, ResolutionTimeoutMS: 1}})
			store.failing = op
			o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
			if o.Result == nil || !o.Verified || o.Result.Disposition != acs.Deny || !slices.Contains(o.Result.ReasonCodes, disposition.ReasonStoreUnavailable) {
				t.Fatalf("a store failure at %s got %s", op, o.Raw)
			}
			if op == "conclude" && o.Result.ChainHash == "" {
				t.Fatalf("a conclude failure after the ContextEntry was appended omitted its published chain head: %s", o.Raw)
			}
			if strings.Contains(string(o.Raw), "10.0.0.7") {
				t.Fatalf("the store's error reached the wire: %s", o.Raw)
			}
			if !slices.ContainsFunc(h.audit.events, func(e guardian.AuditEvent) bool {
				return e.Kind == guardian.EventFailure && strings.Contains(e.Message, "10.0.0.7")
			}) {
				t.Fatal("the store's error is not in the audit log")
			}
		})
	}
}

// A signer that returns a signature response-envelope.json refuses is not
// sent: the Guardian checks the bytes it is about to send.
func TestMalformedSignatureIsNotSent(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.g = mustGuardian(t, guardian.Config{Engine: h.engine, Signer: badSigner{h.signer}, Store: h.store, AuditLog: h.audit})
	c.Transport = func(ctx context.Context, body []byte) ([]byte, error) { return h.g.Handle(ctx, body), nil }
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result != nil || o.Error == nil || o.Error.Code != acs.InternalError {
		t.Fatalf("a malformed signature got %s", o.Raw)
	}
}

type badSigner struct{ *guardian.HMACSigner }

func (s badSigner) Sign(ctx context.Context, sessionID, keyID string, input []byte) (acs.Signature, error) {
	sig, err := s.HMACSigner.Sign(ctx, sessionID, keyID, input)
	sig.Algorithm = ""
	return sig, err
}

type panickingSignSigner struct {
	*guardian.HMACSigner
}

func (panickingSignSigner) Sign(context.Context, string, string, []byte) (acs.Signature, error) {
	panic("sign")
}

type blockingSignSigner struct {
	*guardian.HMACSigner
	block   atomic.Bool
	started chan struct{}
}

func (s *blockingSignSigner) Sign(ctx context.Context, sessionID, keyID string, input []byte) (acs.Signature, error) {
	if !s.block.Load() {
		return s.HMACSigner.Sign(ctx, sessionID, keyID, input)
	}
	close(s.started)
	<-ctx.Done()
	return acs.Signature{}, ctx.Err()
}

func TestSignerPanicReturnsUnsignedInternalError(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.g = mustGuardian(t, guardian.Config{
		Engine: h.engine, Signer: panickingSignSigner{HMACSigner: h.signer}, Store: h.store, AuditLog: h.audit,
	})
	c.Transport = func(ctx context.Context, body []byte) ([]byte, error) { return h.g.Handle(ctx, body), nil }
	o := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	if o.Result != nil || o.Error == nil || o.Error.Code != acs.InternalError || o.Verified {
		t.Fatalf("a signer panic got %s", o.Raw)
	}
}

func TestShutdownCancelsResponseSigning(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	signer := &blockingSignSigner{HMACSigner: h.signer, started: make(chan struct{})}
	h.g = mustGuardian(t, guardian.Config{
		Engine: h.engine, Signer: signer, Store: h.store, AuditLog: h.audit,
	})
	c.Transport = func(ctx context.Context, body []byte) ([]byte, error) { return h.g.Handle(ctx, body), nil }
	signer.block.Store(true)

	answered := make(chan error, 1)
	go func() {
		_, err := c.Send(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
		answered <- err
	}()
	<-signer.started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.g.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-answered:
	case <-time.After(time.Second):
		t.Fatal("response signing remained blocked after shutdown cancellation")
	}
}

func mustGuardian(t *testing.T, cfg guardian.Config) *guardian.Guardian {
	t.Helper()
	g, err := guardian.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// An engine that ignores cancellation cannot hold a step past Shutdown's
// grace: the step is answered DENY, and Shutdown returns at the grace.
func TestShutdownBoundsAnEngineThatIgnoresCancellation(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	started, never := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(never) })
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		close(started)
		<-never
		return guardian.PolicyDecision{}, nil
	})
	answered := make(chan *acs.Result, 1)
	go func() { answered <- h.decision(c, acs.StepToolCallRequest, toolCall("ls")) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	begun := time.Now()
	if err := h.g.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	if waited := time.Since(begun); waited > time.Second {
		t.Fatalf("Shutdown returned after %s", waited)
	}
	select {
	case r := <-answered:
		if r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonShuttingDown) {
			t.Fatalf("the in-flight step got %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("the in-flight step was not answered")
	}
}

// A turn_id supplied by the framework reaches every corresponding entry.
func TestTurnIDReachesTheChain(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.send(c, observedagent.Request{Method: acs.StepTurnStart, Payload: hookPayloads[acs.StepTurnStart], TurnID: "t1"})
	h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls"), TurnID: "t1"})
	h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	sess, _, _ := h.store.Load(context.Background(), c.SessionID)
	var turns []string
	for _, e := range sess.Entries {
		turns = append(turns, e.TurnID)
	}
	if !slices.Equal(turns, []string{"t1", "t1", ""}) {
		t.Fatalf("entries carry turns %v", turns)
	}
}

// A postCompact summary's lineage is held to the compacted entries. The
// hook permits no DENY, so the mismatch is recorded on an ALLOW.
func TestPostCompactLineage(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	first := h.decision(c, acs.StepToolCallRequest, withProvenance(toolCall("cat a"), "p1"))
	second := h.decision(c, acs.StepToolCallRequest, withProvenance(toolCall("cat b"), "p2"))
	head := second.ChainHash
	compact := func(before, origin string, derived ...string) map[string]any {
		return map[string]any{
			"summary":                 map[string]any{"value": "sum", "provenance": map[string]any{"provenance_id": "s", "origin": origin, "derived_from": derived}},
			"entries_compacted":       []any{first.RequestID, second.RequestID},
			"pre_compact_chain_hash":  before,
			"post_compact_chain_hash": hash64,
		}
	}
	r := h.decision(c, acs.StepPostCompact, compact(head, "agent_generated", "p2", "p1"))
	if r.Disposition != acs.Allow || slices.Contains(r.ReasonCodes, disposition.ReasonLineageMismatch) {
		t.Fatalf("a faithful summary got %+v", r)
	}
	head = r.ChainHash
	for name, payload := range map[string]func() map[string]any{
		"missing_lineage": func() map[string]any { return compact(head, "agent_generated", "p1") },
		"forged_origin":   func() map[string]any { return compact(head, "user_input", "p1", "p2") },
		"stale_pre_hash":  func() map[string]any { return compact(first.ChainHash, "agent_generated", "p1", "p2") },
	} {
		r := h.decision(c, acs.StepPostCompact, payload())
		if r.Disposition != acs.Allow || !slices.Contains(r.ReasonCodes, disposition.ReasonLineageMismatch) {
			t.Fatalf("%s got %+v", name, r)
		}
		head = r.ChainHash
	}
	if count(h.audit.eventKinds(), guardian.EventLineageMismatch) != 3 {
		t.Fatalf("audit events %v", h.audit.eventKinds())
	}
}

func TestPostCompactLineageSurvivesEntryArchival(t *testing.T) {
	var store *archivedStore
	h := newHarness(t, func(c *guardian.Config) {
		store = &archivedStore{SessionContextStore: c.Store}
		c.Store = store
	})
	c := h.session()
	first := h.decision(c, acs.StepToolCallRequest, withProvenance(toolCall("cat a"), "p1"))
	second := h.decision(c, acs.StepToolCallRequest, withProvenance(toolCall("cat b"), "p2"))
	store.archive = true
	r := h.decision(c, acs.StepPostCompact, map[string]any{
		"summary":                 map[string]any{"value": "sum", "provenance": map[string]any{"provenance_id": "s", "origin": "agent_generated", "derived_from": []any{"p1", "p2"}}},
		"entries_compacted":       []any{first.RequestID, second.RequestID},
		"pre_compact_chain_hash":  second.ChainHash,
		"post_compact_chain_hash": hash64,
	})
	if r.Disposition != acs.Allow || slices.Contains(r.ReasonCodes, disposition.ReasonLineageMismatch) {
		t.Fatalf("a faithful summary over archived entries got %+v", r)
	}
}

func withProvenance(p acs.ToolCallRequestPayload, id string) acs.ToolCallRequestPayload {
	arg := p.Arguments["command"]
	arg.Provenance = &acs.Provenance{ProvenanceID: id, Origin: "user_input"}
	p.Arguments["command"] = arg
	return p
}

// What an engine keeps for a session comes back on the session's later
// steps, and not on another session's.
func TestPolicyStateFollowsTheSession(t *testing.T) {
	h := newHarness(t)
	a, b := h.session(), h.session()
	h.engine.set(func(_ context.Context, in guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, State: json.RawMessage(`{"seen":"` + in.Request.Params.RequestID + `"}`)}, nil
	})
	first := h.decision(a, acs.StepToolCallRequest, toolCall("ls"))
	h.engine.set(nil)
	h.decision(a, acs.StepToolCallRequest, toolCall("ls"))
	if got := string(h.engine.last().Session.PolicyState); got != `{"seen":"`+first.RequestID+`"}` {
		t.Fatalf("the next step saw policy state %s", got)
	}
	h.decision(b, acs.StepToolCallRequest, toolCall("ls"))
	if got := h.engine.last().Session.PolicyState; got != nil {
		t.Fatalf("another session saw policy state %s", got)
	}
}

// End to end, a decision altered on the way fails verification, and the
// Observed Agent falls to the posture its ServerHello declared.
func TestTamperedDecisionFallsToThePosture(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.OnDecisionFailure = acs.FailureDeny })
	c := h.client(observedagent.NewUUID())
	o, err := c.Handshake(context.Background(), observedagent.DefaultHello(method.Hooks()...))
	if err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v", err)
	}
	posture := o.Hello.OnDecisionFailure
	h.engine.answer(deny("rule"))
	sent := h.send(c, observedagent.Request{Method: acs.StepToolCallRequest, Payload: toolCall("ls")})
	tampered, err := c.Read(context.Background(), []byte(strings.Replace(string(sent.Raw), `"decision":"deny"`, `"decision":"allow"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if d, open := observedagent.Honour(tampered, nil, posture); d.Disposition != acs.Deny || open {
		t.Fatalf("a tampered decision was applied as %s", d.Disposition)
	}
	if d, _ := observedagent.Honour(sent, nil, posture); d.Disposition != acs.Deny || d.Reasoning != "denied: rule" {
		t.Fatalf("the genuine decision was applied as %+v", d)
	}
}

// Engine calls that never return keep their places: once every place is
// taken, a step is denied without another call.
func TestEngineCallsAreBounded(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.MaxEngineCalls = 1; c.DecisionTimeout = 20 * time.Millisecond })
	c := h.session()
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		<-never
		return guardian.PolicyDecision{}, nil
	})
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonEvaluationFailed) {
		t.Fatalf("the first step got %+v", r)
	}
	calls := h.engine.callCount()
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonEngineSaturated) {
		t.Fatalf("a step with no place got %+v", r)
	}
	if h.engine.callCount() != calls {
		t.Fatal("the engine was called with no place free")
	}
}

// An engine state past the bound is not kept, and the step is denied.
func TestPolicyStateIsBounded(t *testing.T) {
	h := newHarness(t, func(c *guardian.Config) { c.MaxPolicyStateBytes = 16 })
	c := h.session()
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, State: json.RawMessage(`{"padding":"0123456789"}`)}, nil
	})
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonPolicyStateTooLarge) {
		t.Fatalf("an oversize state got %+v", r)
	}
	if sess, _, _ := h.store.Load(context.Background(), c.SessionID); sess.PolicyState != nil {
		t.Fatalf("the oversize state was kept: %s", sess.PolicyState)
	}
}

func TestPolicyStateMustBeJSON(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}, State: json.RawMessage(`not-json`)}, nil
	})
	if r := h.decision(c, acs.StepToolCallRequest, toolCall("ls")); r.Disposition != acs.Deny || !slices.Contains(r.ReasonCodes, disposition.ReasonEvaluationFailed) {
		t.Fatalf("invalid state got %+v", r)
	}
	if sess, _, _ := h.store.Load(context.Background(), c.SessionID); sess.PolicyState != nil {
		t.Fatalf("invalid state was kept: %s", sess.PolicyState)
	}
}

func TestInvalidPolicyDecisionLeavesNoDecisionState(t *testing.T) {
	h := newHarness(t)
	c := h.session()
	h.engine.set(func(context.Context, guardian.PolicyInput) (guardian.PolicyDecision, error) {
		return guardian.PolicyDecision{
			Decision: acs.Decision{
				Disposition: acs.Ask,
				Reasoning:   "approval required",
				AskDetails: &acs.AskDetails{
					Approver:       acs.Approver{Type: acs.ApproverHuman, ID: "reviewer"},
					Question:       "allow?",
					TimeoutSeconds: 0,
				},
			},
			State: json.RawMessage(`{"must_not_persist":true}`),
		}, nil
	})
	result := h.decision(c, acs.StepToolCallRequest, toolCall("ls"))
	if result.Disposition != acs.Deny || !slices.Contains(result.ReasonCodes, disposition.ReasonEvaluationFailed) {
		t.Fatalf("invalid policy decision got %+v", result)
	}
	sess, _, err := h.store.Load(context.Background(), c.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.AskSteps) != 0 || sess.Deferrals != 0 || sess.PolicyState != nil {
		t.Fatalf("invalid policy decision changed decision state: asks=%v deferrals=%d state=%s", sess.AskSteps, sess.Deferrals, sess.PolicyState)
	}
}
