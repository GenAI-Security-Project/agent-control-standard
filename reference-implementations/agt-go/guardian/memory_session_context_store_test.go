package guardian_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian/guardiantest"
)

func memoryLimits() guardian.MemoryStoreLimits {
	return guardian.MemoryStoreLimits{MaxSessions: 8, MaxEntries: 64, MaxReservations: 128, MaxSkillApprovals: 8, Retention: time.Hour}
}

func TestReserveAndAppendAtomicity(t *testing.T) {
	guardiantest.TestSessionContextStore(t, func(t *testing.T) guardian.SessionContextStore {
		store, err := guardian.NewMemorySessionContextStore(memoryLimits())
		if err != nil {
			t.Fatal(err)
		}
		return store
	})
}

// A full store refuses a new session rather than drop a live one, and gives
// a session's place away only after its retention has passed without a
// write.
func TestMemoryStoreRefusesWhenFull(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	limits := memoryLimits()
	limits.MaxSessions = 2
	limits.Now = func() time.Time { return now }
	store, err := guardian.NewMemorySessionContextStore(limits)
	if err != nil {
		t.Fatal(err)
	}
	negotiate := func(id string) error {
		return store.Negotiate(ctx, id, guardian.Reservation{RequestID: "r0"}, guardian.Handshake{})
	}
	for _, id := range []string{"a", "b"} {
		if err := negotiate(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := negotiate("c"); !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("third session: %v, want ErrStoreFull", err)
	}

	now = now.Add(30 * time.Minute)
	// A write to a keeps it; b is the least recently written.
	if err := store.Append(ctx, "a", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: acs.ContextEntry{EntryHash: "h"}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Minute)
	if err := negotiate("c"); err != nil {
		t.Fatalf("after b's retention: %v", err)
	}
	for id, want := range map[string]bool{"a": true, "b": false, "c": true} {
		if _, ok, _ := store.Load(ctx, id); ok != want {
			t.Errorf("session %s present=%v, want %v", id, ok, want)
		}
	}
	if err := negotiate("d"); !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("a was written within its retention and must stay: %v", err)
	}
}

func TestMemoryStoreBoundsEntriesAndApprovals(t *testing.T) {
	ctx := context.Background()
	limits := memoryLimits()
	limits.MaxEntries, limits.MaxSkillApprovals = 1, 1
	store, err := guardian.NewMemorySessionContextStore(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Negotiate(ctx, "s1", guardian.Reservation{RequestID: "r0"}, guardian.Handshake{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r1"}, Entry: acs.ContextEntry{EntryHash: "h1"}}); err != nil {
		t.Fatal(err)
	}
	err = store.Append(ctx, "s1", guardian.Append{Reservation: guardian.Reservation{RequestID: "r2"}, ExpectedHead: "h1", Entry: acs.ContextEntry{EntryHash: "h2"}})
	if !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("second entry: %v, want ErrStoreFull", err)
	}
	approve := func(id string) error {
		return store.Conclude(ctx, "s1", guardian.Conclusion{ExpectedHead: "h1", ApproveSkill: &guardian.SkillApproval{SkillID: id}})
	}
	if err := approve("a"); err != nil {
		t.Fatal(err)
	}
	if err := approve("b"); !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("second approval: %v, want ErrStoreFull", err)
	}
}

func TestMemoryStoreBoundsReplayReservations(t *testing.T) {
	ctx := context.Background()
	limits := memoryLimits()
	limits.MaxReservations = 2
	store, err := guardian.NewMemorySessionContextStore(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Negotiate(ctx, "s1", guardian.Reservation{RequestID: "r0"}, guardian.Handshake{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(ctx, "s1", guardian.Reservation{RequestID: "r1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(ctx, "s1", guardian.Reservation{RequestID: "r2"}); !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("third reservation: %v, want ErrStoreFull", err)
	}
	if err := store.Reserve(ctx, "s1", guardian.Reservation{RequestID: "r1"}); !errors.Is(err, guardian.ErrReplayDetected) {
		t.Fatalf("known reservation at capacity: %v, want ErrReplayDetected", err)
	}
}

// A session whose lock is held or awaited is never removed, however long
// its step runs: its holder still has to conclude it.
func TestMemoryStoreKeepsALockedSession(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	limits := memoryLimits()
	limits.MaxSessions = 1
	limits.Now = func() time.Time { return now }
	store, err := guardian.NewMemorySessionContextStore(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Negotiate(ctx, "a", guardian.Reservation{RequestID: "r0"}, guardian.Handshake{}); err != nil {
		t.Fatal(err)
	}
	_, release, err := store.Lock(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * limits.Retention)
	if err := store.Negotiate(ctx, "b", guardian.Reservation{RequestID: "r0"}, guardian.Handshake{}); !errors.Is(err, guardian.ErrStoreFull) {
		t.Fatalf("a locked session was removed: %v", err)
	}
	release()
	if err := store.Negotiate(ctx, "b", guardian.Reservation{RequestID: "r0"}, guardian.Handshake{}); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestMemoryStoreRefusesNoCapacity(t *testing.T) {
	for name, change := range map[string]func(*guardian.MemoryStoreLimits){
		"sessions":     func(l *guardian.MemoryStoreLimits) { l.MaxSessions = 0 },
		"entries":      func(l *guardian.MemoryStoreLimits) { l.MaxEntries = 0 },
		"reservations": func(l *guardian.MemoryStoreLimits) { l.MaxReservations = 0 },
		"approvals":    func(l *guardian.MemoryStoreLimits) { l.MaxSkillApprovals = 0 },
		"retention":    func(l *guardian.MemoryStoreLimits) { l.Retention = 0 },
	} {
		limits := memoryLimits()
		change(&limits)
		if _, err := guardian.NewMemorySessionContextStore(limits); err == nil {
			t.Errorf("%s: accepted a store with no capacity", name)
		}
	}
}

func TestMemoryStoreRefusesSkewWindowBeyondRetention(t *testing.T) {
	store, err := guardian.NewMemorySessionContextStore(memoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	handshake := guardian.Handshake{Server: acs.ServerHello{SkewWindowMS: int64(memoryLimits().Retention/time.Millisecond/2) + 1}}
	if err := store.Negotiate(context.Background(), "s1", guardian.Reservation{RequestID: "r0"}, handshake); err == nil {
		t.Fatal("accepted a skew window whose replay lifetime exceeds store retention")
	}
}
