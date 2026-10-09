// Package guardiantest checks implementations of the guardian interfaces
// against their contracts, so a host with its own implementation proves the
// same properties the defaults are tested for.
package guardiantest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// TestSessionContextStore runs the SessionContextStore contract against
// stores built by newStore, one fresh store per case. The store must hold at
// least two sessions.
func TestSessionContextStore(t *testing.T, newStore func(t *testing.T) guardian.SessionContextStore) {
	t.Run("negotiate_then_load", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		s, ok, err := store.Load(ctx, "s1")
		if err != nil || !ok {
			t.Fatalf("Load: ok=%v err=%v", ok, err)
		}
		if s.Handshake.Server.NegotiatedVersion != acs.Version || s.Head != "" || len(s.Entries) != 0 || s.Closed {
			t.Fatalf("fresh session is %+v", s)
		}
	})

	t.Run("load_unknown_session", func(t *testing.T) {
		if _, ok, err := newStore(t).Load(context.Background(), "nobody"); ok || err != nil {
			t.Fatalf("Load: ok=%v err=%v, want false and no error", ok, err)
		}
	})

	t.Run("negotiate_twice", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		err := store.Negotiate(context.Background(), "s1", guardian.Reservation{RequestID: "r1"}, handshake())
		if !errors.Is(err, guardian.ErrAlreadyNegotiated) {
			t.Fatalf("second Negotiate: %v, want ErrAlreadyNegotiated", err)
		}
	})

	t.Run("append_moves_head", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		intent := &acs.Intent{Parsed: []acs.Capability{{Tool: "Bash"}}}
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, ""), Intent: intent})
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2"}, ExpectedHead: digest(1), Entry: entry(2, digest(1)), Close: true})
		s, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if s.Head != digest(2) || len(s.Entries) != 2 || s.Entries[0].EntryHash != digest(1) || s.Entries[1].EntryHash != digest(2) {
			t.Fatalf("head %s, entries %+v", s.Head, s.Entries)
		}
		if s.Intent == nil || len(s.Intent.Parsed) != 1 || !s.Closed {
			t.Fatalf("intent %+v closed %v", s.Intent, s.Closed)
		}
	})

	t.Run("replayed_request_id_changes_nothing", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		for _, id := range []string{"r0", "r1"} {
			err := store.Append(context.Background(), "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: id}, ExpectedHead: digest(1), Entry: entry(2, digest(1))})
			if !errors.Is(err, guardian.ErrReplayDetected) {
				t.Fatalf("request_id %s: %v, want ErrReplayDetected", id, err)
			}
		}
		requireHead(t, store, "s1", digest(1), 1)
	})

	t.Run("replayed_nonce_changes_nothing", func(t *testing.T) {
		store := newStore(t)
		if err := store.Negotiate(context.Background(), "s1", guardian.Reservation{RequestID: "r0", Nonce: "n0"}, handshake()); err != nil {
			t.Fatal(err)
		}
		err := store.Append(context.Background(), "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1", Nonce: "n0"}, Entry: entry(1, "")})
		if !errors.Is(err, guardian.ErrReplayDetected) {
			t.Fatalf("%v, want ErrReplayDetected", err)
		}
		requireHead(t, store, "s1", "", 0)
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1", Nonce: "n1"}, Entry: entry(1, "")})
	})

	t.Run("moved_head_changes_nothing", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		stale := guardian.Append{Reservation: guardian.Reservation{RequestID: "r2", Nonce: "n2"}, Entry: entry(9, "")}
		if err := store.Append(context.Background(), "s1", stale); !errors.Is(err, guardian.ErrHeadMoved) {
			t.Fatalf("%v, want ErrHeadMoved", err)
		}
		requireHead(t, store, "s1", digest(1), 1)
		// Neither the request_id nor the nonce was reserved by the refused append.
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2", Nonce: "n2"}, ExpectedHead: digest(1), Entry: entry(2, digest(1))})
	})

	t.Run("append_to_unknown_session", func(t *testing.T) {
		err := newStore(t).Append(context.Background(), "nobody", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		if !errors.Is(err, guardian.ErrHeadMoved) {
			t.Fatalf("%v, want ErrHeadMoved", err)
		}
	})

	t.Run("sessions_are_separate", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		negotiate(t, store, "s2", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		appendOK(t, store, "s2", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		requireHead(t, store, "s1", digest(1), 1)
		requireHead(t, store, "s2", digest(1), 1)
	})

	t.Run("conclude_records_the_decision", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		for i := range 3 {
			if err := store.Conclude(ctx, "s1", guardian.Conclusion{Deferred: true, AskStepID: fmt.Sprintf("ask-%d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Conclude(ctx, "s1", guardian.Conclusion{PolicyState: json.RawMessage(`{"labels":["secret"]}`)}); err != nil {
			t.Fatal(err)
		}
		if err := store.Conclude(ctx, "s1", guardian.Conclusion{}); err != nil {
			t.Fatal(err)
		}
		s, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if s.Deferrals != 3 || !slices.Equal(s.AskSteps, []string{"ask-0", "ask-1", "ask-2"}) || string(s.PolicyState) != `{"labels":["secret"]}` {
			t.Fatalf("deferrals %d, ask steps %v, policy state %s", s.Deferrals, s.AskSteps, s.PolicyState)
		}
		if err := store.Conclude(ctx, "nobody", guardian.Conclusion{Deferred: true}); !errors.Is(err, guardian.ErrSessionNotFound) {
			t.Fatalf("%v, want ErrSessionNotFound", err)
		}
	})

	t.Run("replayed_handshake", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		err := store.Negotiate(context.Background(), "s1", guardian.Reservation{RequestID: "r0"}, handshake())
		if !errors.Is(err, guardian.ErrReplayDetected) {
			t.Fatalf("%v, want ErrReplayDetected", err)
		}
	})

	t.Run("reserve_without_entry", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		if err := store.Reserve(ctx, "s1", guardian.Reservation{RequestID: "r1", Nonce: "n1"}); err != nil {
			t.Fatal(err)
		}
		for _, r := range []guardian.Reservation{{RequestID: "r0"}, {RequestID: "r1"}, {RequestID: "r2", Nonce: "n1"}} {
			if err := store.Reserve(ctx, "s1", r); !errors.Is(err, guardian.ErrReplayDetected) {
				t.Fatalf("Reserve %+v: %v, want ErrReplayDetected", r, err)
			}
		}
		err := store.Append(ctx, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		if !errors.Is(err, guardian.ErrReplayDetected) {
			t.Fatalf("Append after Reserve: %v, want ErrReplayDetected", err)
		}
		requireHead(t, store, "s1", "", 0)
		if err := store.Reserve(ctx, "nobody", guardian.Reservation{RequestID: "r1"}); !errors.Is(err, guardian.ErrSessionNotFound) {
			t.Fatalf("%v, want ErrSessionNotFound", err)
		}
	})

	t.Run("lineage_is_kept_by_step", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, ""), Lineage: []string{"p1", "p2"}})
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2"}, ExpectedHead: digest(1), Entry: entry(2, digest(1))})
		s, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(s.Lineage["step-1"], []string{"p1", "p2"}) {
			t.Fatalf("lineage %v", s.Lineage)
		}
		if empty, ok := s.Lineage["step-2"]; !ok || len(empty) != 0 {
			t.Fatalf("empty lineage is not retained: %v", s.Lineage)
		}
	})

	t.Run("repeated_step_id_keeps_all_lineage", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, ""), Lineage: []string{"p1", "p2"}})
		extension := entry(2, digest(1))
		extension.StepID = "step-1"
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2"}, ExpectedHead: digest(1), Entry: extension, Lineage: []string{"p2", "p3"}})
		s, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		lineage := slices.Clone(s.Lineage["step-1"])
		slices.Sort(lineage)
		if !slices.Equal(lineage, []string{"p1", "p2", "p3"}) {
			t.Fatalf("lineage %v", s.Lineage)
		}
	})

	t.Run("skill_approvals_span_sessions", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		approved := guardian.SkillApproval{SkillID: "skill-a", DigestAlgorithm: "sha-256", DigestValue: "aa"}
		if ok, err := store.SkillApproved(ctx, approved); ok || err != nil {
			t.Fatalf("before approval: %v, %v", ok, err)
		}
		for range 2 {
			if err := store.Conclude(ctx, "s1", guardian.Conclusion{ApproveSkill: &approved}); err != nil {
				t.Fatalf("approving: %v", err)
			}
		}
		if ok, err := store.SkillApproved(ctx, approved); !ok || err != nil {
			t.Fatalf("after approval: %v, %v", ok, err)
		}
		other := approved
		other.DigestValue = "bb"
		if ok, _ := store.SkillApproved(ctx, other); ok {
			t.Fatal("another digest of the same skill is approved")
		}
	})

	// A holder whose lock was lost concludes against a head another holder
	// has moved: nothing it carries is recorded.
	t.Run("stale_conclusion_changes_nothing", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		approved := guardian.SkillApproval{SkillID: "skill-a", DigestAlgorithm: "sha-256", DigestValue: "aa"}
		stale := guardian.Conclusion{ExpectedHead: "", Deferred: true, AskStepID: "a", PolicyState: json.RawMessage(`{}`), ApproveSkill: &approved}
		if err := store.Conclude(ctx, "s1", stale); !errors.Is(err, guardian.ErrHeadMoved) {
			t.Fatalf("%v, want ErrHeadMoved", err)
		}
		s, _, _ := store.Load(ctx, "s1")
		if s.Deferrals != 0 || len(s.AskSteps) != 0 || s.PolicyState != nil {
			t.Fatalf("a stale conclusion changed the session: %+v", s)
		}
		if ok, _ := store.SkillApproved(ctx, approved); ok {
			t.Fatal("a stale conclusion approved a skill")
		}
	})

	t.Run("loaded_session_is_a_copy", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		intent := &acs.Intent{Parsed: []acs.Capability{{Tool: "Bash"}}}
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, ""), Intent: intent, Lineage: []string{"p1"}})
		if err := store.Conclude(ctx, "s1", guardian.Conclusion{ExpectedHead: digest(1), AskStepID: "ask", PolicyState: json.RawMessage(`{"a":1}`)}); err != nil {
			t.Fatal(err)
		}
		// The caller's own values are not kept by reference either.
		intent.Parsed[0].Tool = "changed by the caller"
		s, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		s.Entries[0].StepID = "changed"
		s.Intent.Parsed[0].Tool = "changed"
		s.Handshake.Server.NegotiatedVersion = "changed"
		s.AskSteps[0] = "changed"
		s.Lineage["step-1"][0] = "changed"
		s.PolicyState[0] = 'x'
		again, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if again.Entries[0].StepID != "step-1" || again.Intent.Parsed[0].Tool != "Bash" || again.Handshake.Server.NegotiatedVersion != acs.Version ||
			again.AskSteps[0] != "ask" || again.Lineage["step-1"][0] != "p1" || string(again.PolicyState) != `{"a":1}` {
			t.Fatalf("a change to a loaded session reached the store: %+v", again)
		}
	})

	t.Run("lock_excludes", func(t *testing.T) {
		store := newStore(t)
		lockCtx, release, err := store.Lock(context.Background(), "s1")
		if err != nil {
			t.Fatal(err)
		}
		if lockCtx == nil {
			t.Fatal("Lock returned a nil context")
		}
		release()
		select {
		case <-lockCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("the lock context remained live after release")
		}
		if !errors.Is(context.Cause(lockCtx), context.Canceled) {
			t.Fatalf("the released lock context ended with %v", context.Cause(lockCtx))
		}

		parent, cancelParent := context.WithCancel(context.Background())
		parentCtx, releaseParent, err := store.Lock(parent, "parent")
		if err != nil {
			t.Fatal(err)
		}
		cancelParent()
		select {
		case <-parentCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("the lock context remained live after its parent ended")
		}
		releaseParent()

		_, release, err = store.Lock(context.Background(), "s1")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, _, err := store.Lock(ctx, "s1"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second Lock of a held session: %v, want the context's deadline", err)
		}
		_, other, err := store.Lock(context.Background(), "s2")
		if err != nil {
			t.Fatalf("another session's lock: %v", err)
		}
		other()
		release()
		_, again, err := store.Lock(context.Background(), "s1")
		if err != nil {
			t.Fatalf("Lock after release: %v", err)
		}
		again()
	})

	// Holders of one session's lock never overlap, however many wait.
	t.Run("lock_serialises", func(t *testing.T) {
		store := newStore(t)
		var inside, overlaps atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				_, release, err := store.Lock(context.Background(), "s1")
				if err != nil {
					t.Error(err)
					return
				}
				if inside.Add(1) > 1 {
					overlaps.Add(1)
				}
				time.Sleep(time.Millisecond)
				inside.Add(-1)
				release()
			})
		}
		wg.Wait()
		if overlaps.Load() != 0 {
			t.Fatalf("%d holders overlapped", overlaps.Load())
		}
	})

	t.Run("loaded_entries_do_not_change", func(t *testing.T) {
		store, ctx := newStore(t), context.Background()
		negotiate(t, store, "s1", "r0")
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: entry(1, "")})
		before, _, err := store.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		appendOK(t, store, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2"}, ExpectedHead: digest(1), Entry: entry(2, digest(1))})
		if len(before.Entries) != 1 || before.Head != digest(1) {
			t.Fatalf("an earlier Load changed to %+v", before)
		}
	})

	// Concurrent appends against one head: exactly one wins, the rest see
	// ErrHeadMoved, which is what keeps two processes from extending one
	// chain twice.
	t.Run("one_append_wins_a_race", func(t *testing.T) {
		store := newStore(t)
		negotiate(t, store, "s1", "r0")
		const racers = 16
		var wg sync.WaitGroup
		errs := make([]error, racers)
		for i := range racers {
			wg.Go(func() {
				errs[i] = store.Append(context.Background(), "s1", guardian.Append{
					Reservation: guardian.Reservation{RequestID: fmt.Sprintf("race-%d", i)},
					Entry:       entry(100+i, ""),
				})
			})
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, guardian.ErrHeadMoved):
				t.Errorf("racer failed with %v, want ErrHeadMoved", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d appends won, want 1", won)
		}
		s, _, _ := store.Load(context.Background(), "s1")
		if len(s.Entries) != 1 {
			t.Fatalf("%d entries after the race, want 1", len(s.Entries))
		}
	})
}

func handshake() guardian.Handshake {
	return guardian.Handshake{
		Client: acs.ClientHello{ACSVersionsSupported: []string{acs.Version}, ProvenanceProducer: acs.ProvenanceNone},
		Server: acs.ServerHello{NegotiatedVersion: acs.Version, OnDecisionFailure: acs.FailureProceed},
	}
}

func negotiate(t *testing.T, store guardian.SessionContextStore, sessionID, requestID string) {
	t.Helper()
	if err := store.Negotiate(context.Background(), sessionID, guardian.Reservation{RequestID: requestID}, handshake()); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
}

func appendOK(t *testing.T, store guardian.SessionContextStore, sessionID string, a guardian.Append) {
	t.Helper()
	if err := store.Append(context.Background(), sessionID, a); err != nil {
		t.Fatalf("Append %s: %v", a.RequestID, err)
	}
}

func requireHead(t *testing.T, store guardian.SessionContextStore, sessionID, head string, entries int) {
	t.Helper()
	s, ok, err := store.Load(context.Background(), sessionID)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if s.Head != head || len(s.Entries) != entries {
		t.Fatalf("head %q with %d entries, want %q with %d", s.Head, len(s.Entries), head, entries)
	}
}

// digest is a stand-in entry_hash: the store keeps digests, it never
// computes them.
func digest(n int) string {
	return fmt.Sprintf("%064x", n)
}

func entry(n int, previous string) acs.ContextEntry {
	e := acs.ContextEntry{
		EntryID:   fmt.Sprint(n),
		StepID:    fmt.Sprintf("step-%d", n),
		StepType:  acs.StepToolCallRequest,
		EntryHash: digest(n),
	}
	if previous != "" {
		e.PreviousHash = &previous
	}
	return e
}
