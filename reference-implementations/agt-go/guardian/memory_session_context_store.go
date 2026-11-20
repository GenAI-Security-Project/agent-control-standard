package guardian

import (
	"container/list"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// MemorySessionContextStore is the default SessionContextStore: all state in
// process memory, lost on restart, and serialising a session's steps only
// within this process. Every bound is a refusal, never a silent loss: a
// session is removed only after Retention without a write, and when none
// can be removed a new session is refused.
type MemorySessionContextStore struct {
	limits MemoryStoreLimits

	mu       sync.Mutex
	sessions map[string]*list.Element // of *memorySession, most recently written at the front
	order    *list.List
	skills   map[SkillApproval]struct{}
	locks    map[string]*sessionLock
}

// MemoryStoreLimits bounds a MemorySessionContextStore.
type MemoryStoreLimits struct {
	// MaxSessions is how many sessions the store holds.
	MaxSessions int
	// MaxEntries is how many ContextEntries one session holds.
	MaxEntries int
	// MaxReservations is how many requests one session remembers for replay
	// detection, including requests answered without a ContextEntry.
	MaxReservations int
	// MaxSkillApprovals is how many skill approvals the store holds.
	MaxSkillApprovals int
	// Retention is how long a session is kept after its last write when
	// the store needs its place. It must be at least twice the Guardian's
	// skew window: a request accepted at the future edge remains fresh for
	// two windows after receipt.
	Retention time.Duration
	// Now is the store's clock; nil means time.Now.
	Now func() time.Time
}

type memorySession struct {
	id           string
	state        Session
	reserved     map[string]struct{} // request_id and nonce values, each prefixed by its kind
	reservations int
	writtenAt    time.Time
}

// sessionLock is one session's lock, a channel so that waiting honours a
// context; refs counts the holder and the waiters.
type sessionLock struct {
	held chan struct{}
	refs int
}

// NewMemorySessionContextStore returns an empty store bounded by limits.
func NewMemorySessionContextStore(limits MemoryStoreLimits) (*MemorySessionContextStore, error) {
	switch {
	case limits.MaxSessions < 1:
		return nil, fmt.Errorf("the store needs MaxSessions of at least 1, got %d", limits.MaxSessions)
	case limits.MaxEntries < 1:
		return nil, fmt.Errorf("the store needs MaxEntries of at least 1, got %d", limits.MaxEntries)
	case limits.MaxReservations < 1:
		return nil, fmt.Errorf("the store needs MaxReservations of at least 1, got %d", limits.MaxReservations)
	case limits.MaxSkillApprovals < 1:
		return nil, fmt.Errorf("the store needs MaxSkillApprovals of at least 1, got %d", limits.MaxSkillApprovals)
	case limits.Retention <= 0:
		return nil, fmt.Errorf("the store needs a positive Retention, got %s", limits.Retention)
	}
	if limits.Now == nil {
		limits.Now = time.Now
	}
	return &MemorySessionContextStore{
		limits:   limits,
		sessions: map[string]*list.Element{},
		order:    list.New(),
		skills:   map[SkillApproval]struct{}{},
		locks:    map[string]*sessionLock{},
	}, nil
}

// Lock implements SessionContextStore.
func (m *MemorySessionContextStore) Lock(ctx context.Context, sessionID string) (context.Context, func(), error) {
	m.mu.Lock()
	l, ok := m.locks[sessionID]
	if !ok {
		l = &sessionLock{held: make(chan struct{}, 1)}
		m.locks[sessionID] = l
	}
	l.refs++
	m.mu.Unlock()

	forget := func() {
		m.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(m.locks, sessionID)
		}
		m.mu.Unlock()
	}
	select {
	case l.held <- struct{}{}:
	case <-ctx.Done():
		forget()
		return nil, nil, ctx.Err()
	}
	lockCtx, cancel := context.WithCancelCause(ctx)
	var once sync.Once
	return lockCtx, func() {
		once.Do(func() {
			cancel(nil)
			<-l.held
			forget()
		})
	}, nil
}

// Load implements SessionContextStore.
func (m *MemorySessionContextStore) Load(_ context.Context, sessionID string) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.sessions[sessionID]
	if !ok {
		return Session{}, false, nil
	}
	s, err := el.Value.(*memorySession).state.clone()
	return s, err == nil, err
}

// Negotiate implements SessionContextStore.
func (m *MemorySessionContextStore) Negotiate(_ context.Context, sessionID string, r Reservation, h Handshake) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h.Server.SkewWindowMS < 0 || h.Server.SkewWindowMS > int64(m.limits.Retention/(2*time.Millisecond)) {
		return fmt.Errorf("the store retention %s is less than twice the negotiated skew window %dms", m.limits.Retention, h.Server.SkewWindowMS)
	}
	if el, ok := m.sessions[sessionID]; ok {
		if el.Value.(*memorySession).seen(r) {
			return ErrReplayDetected
		}
		return ErrAlreadyNegotiated
	}
	if m.order.Len() >= m.limits.MaxSessions && !m.removeExpired() {
		return ErrStoreFull
	}
	hs, err := cloneJSON(h)
	if err != nil {
		return err
	}
	s := &memorySession{id: sessionID, state: Session{Handshake: hs}, reserved: map[string]struct{}{}, writtenAt: m.limits.Now()}
	s.reserve(r)
	m.sessions[sessionID] = m.order.PushFront(s)
	return nil
}

// removeExpired removes the least recently written session whose retention
// has passed and whose lock nobody holds or awaits, and reports whether it
// did.
func (m *MemorySessionContextStore) removeExpired() bool {
	for el := m.order.Back(); el != nil; el = el.Prev() {
		s := el.Value.(*memorySession)
		if m.limits.Now().Sub(s.writtenAt) <= m.limits.Retention {
			return false
		}
		if _, locked := m.locks[s.id]; locked {
			continue
		}
		m.order.Remove(el)
		delete(m.sessions, s.id)
		return true
	}
	return false
}

// Reserve implements SessionContextStore.
func (m *MemorySessionContextStore) Reserve(_ context.Context, sessionID string, r Reservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	s := el.Value.(*memorySession)
	if s.seen(r) {
		return ErrReplayDetected
	}
	if s.reservations >= m.limits.MaxReservations {
		return ErrStoreFull
	}
	s.reserve(r)
	m.written(el)
	return nil
}

// Append implements SessionContextStore.
func (m *MemorySessionContextStore) Append(_ context.Context, sessionID string, a Append) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.sessions[sessionID]
	if !ok {
		return ErrHeadMoved
	}
	s := el.Value.(*memorySession)
	switch {
	case s.seen(a.Reservation):
		return ErrReplayDetected
	case s.reservations >= m.limits.MaxReservations:
		return ErrStoreFull
	case s.state.Head != a.ExpectedHead:
		return ErrHeadMoved
	case len(s.state.Entries) >= m.limits.MaxEntries:
		return ErrStoreFull
	}
	entry, err := cloneEntry(a.Entry)
	if err != nil {
		return err
	}
	var intent *acs.Intent
	if a.Intent != nil {
		i, err := cloneJSON(*a.Intent)
		if err != nil {
			return err
		}
		intent = &i
	}
	s.reserve(a.Reservation)
	s.state.Entries = append(s.state.Entries, entry)
	s.state.Head = entry.EntryHash
	if s.state.Lineage == nil {
		s.state.Lineage = map[string][]string{}
	}
	lineage := slices.Clone(s.state.Lineage[entry.StepID])
	for _, id := range a.Lineage {
		if !slices.Contains(lineage, id) {
			lineage = append(lineage, id)
		}
	}
	s.state.Lineage[entry.StepID] = lineage
	if intent != nil {
		s.state.Intent = intent
	}
	if a.Close {
		s.state.Closed = true
	}
	m.written(el)
	return nil
}

// Conclude implements SessionContextStore.
func (m *MemorySessionContextStore) Conclude(_ context.Context, sessionID string, c Conclusion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	s := el.Value.(*memorySession)
	if s.state.Head != c.ExpectedHead {
		return ErrHeadMoved
	}
	if a := c.ApproveSkill; a != nil {
		if _, ok := m.skills[*a]; !ok && len(m.skills) >= m.limits.MaxSkillApprovals {
			return ErrStoreFull
		}
		m.skills[*a] = struct{}{}
	}
	if c.AskStepID != "" {
		s.state.AskSteps = append(s.state.AskSteps, c.AskStepID)
	}
	if c.Deferred {
		s.state.Deferrals++
	}
	if c.PolicyState != nil {
		s.state.PolicyState = slices.Clone(c.PolicyState)
	}
	m.written(el)
	return nil
}

// SkillApproved implements SessionContextStore.
func (m *MemorySessionContextStore) SkillApproved(_ context.Context, s SkillApproval) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.skills[s]
	return ok, nil
}

func (m *MemorySessionContextStore) written(el *list.Element) {
	el.Value.(*memorySession).writtenAt = m.limits.Now()
	m.order.MoveToFront(el)
}

func (s *memorySession) seen(r Reservation) bool {
	if _, ok := s.reserved["request_id:"+r.RequestID]; ok {
		return true
	}
	if r.Nonce == "" {
		return false
	}
	_, ok := s.reserved["nonce:"+r.Nonce]
	return ok
}

func (s *memorySession) reserve(r Reservation) {
	s.reserved["request_id:"+r.RequestID] = struct{}{}
	if r.Nonce != "" {
		s.reserved["nonce:"+r.Nonce] = struct{}{}
	}
	s.reservations++
}

// clone returns a Session that shares no memory with s.
func (s Session) clone() (Session, error) {
	out := s
	var err error
	if out.Handshake, err = cloneJSON(s.Handshake); err != nil {
		return Session{}, err
	}
	if s.Intent != nil {
		intent, err := cloneJSON(*s.Intent)
		if err != nil {
			return Session{}, err
		}
		out.Intent = &intent
	}
	out.Entries = make([]acs.ContextEntry, len(s.Entries))
	for i, e := range s.Entries {
		if out.Entries[i], err = cloneEntry(e); err != nil {
			return Session{}, err
		}
	}
	out.AskSteps = slices.Clone(s.AskSteps)
	if s.Lineage != nil {
		out.Lineage = make(map[string][]string, len(s.Lineage))
		for k, v := range s.Lineage {
			out.Lineage[k] = slices.Clone(v)
		}
	}
	out.PolicyState = slices.Clone(s.PolicyState)
	return out, nil
}

// cloneEntry copies an entry; only the rare grant members go through JSON.
func cloneEntry(e acs.ContextEntry) (acs.ContextEntry, error) {
	if e.PreviousHash != nil {
		previous := *e.PreviousHash
		e.PreviousHash = &previous
	}
	if e.ProvenanceSummary != nil || e.Approver != nil || e.IntentExtension != nil {
		deep, err := cloneJSON(struct {
			P *acs.ProvenanceSummary
			A *acs.Approver
			X *acs.IntentExtension
		}{e.ProvenanceSummary, e.Approver, e.IntentExtension})
		if err != nil {
			return e, err
		}
		e.ProvenanceSummary, e.Approver, e.IntentExtension = deep.P, deep.A, deep.X
	}
	return e, nil
}

// cloneJSON copies v through its JSON encoding, which every stored type has.
func cloneJSON[T any](v T) (T, error) {
	var out T
	b, err := jsonv2.Marshal(v)
	if err != nil {
		return out, err
	}
	err = jsonv2.Unmarshal(b, &out)
	return out, err
}
