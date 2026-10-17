package guardian

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// SessionContextStore keeps the Guardian's state: every session's handshake,
// its SessionContext (the ContextEntry sequence, its head and the Intent), the
// request_id and nonce values already seen, what its decisions left behind,
// and the skill registrations approved across sessions.
//
// The Guardian computes every entry_hash itself; a store decides only where
// the state is kept and who may write it. Every Guardian sharing a store
// takes Lock before it reads a session and releases it once the answer is
// built. A durable store may implement Lock with an expiring claim: it then
// cancels the returned context when it detects lost ownership and fences every
// mutation against that claim. Append and Conclude also check the expected
// head before they change the session.
//
// A store keeps a session, and every request_id and nonce it has reserved,
// for at least twice that session's negotiated skew window after its last
// write. Removed sooner, the session's own handshake could be replayed to
// open it again and its steps replayed into it.
type SessionContextStore interface {
	// Lock orders work on a session across every Guardian sharing the store.
	// lockCtx derives from ctx and ends when ctx ends, release is called, or
	// the store detects that it lost ownership. The Guardian uses lockCtx for
	// all work in the protected step. release is safe to call more than once.
	//
	// A store backed by an expiring claim must renew it while work continues
	// and fence every mutation so a former owner cannot write. Cancellation is
	// cooperative: Lock does not promise that external effects of a
	// PolicyEngine stop exactly when a distributed claim expires. The session
	// need not exist.
	Lock(ctx context.Context, sessionID string) (lockCtx context.Context, release func(), err error)

	// Load returns a session's state, and false when the store holds none.
	// The returned Session shares nothing the store later modifies.
	Load(ctx context.Context, sessionID string) (Session, bool, error)

	// Negotiate records the handshake of a new session and reserves the
	// handshake's request_id and nonce. When the session exists it changes
	// nothing and returns ErrReplayDetected if r was seen in it, and
	// ErrAlreadyNegotiated otherwise. It returns ErrStoreFull when the store
	// cannot take another session.
	Negotiate(ctx context.Context, sessionID string, r Reservation, h Handshake) error

	// Reserve reserves r in a session for a request answered without an
	// entry, returning ErrReplayDetected when r was seen in the session and
	// ErrSessionNotFound when there is no session.
	Reserve(ctx context.Context, sessionID string, r Reservation) error

	// Append, in one operation that wholly succeeds or changes nothing:
	// reserves a.RequestID and a.Nonce, returning ErrReplayDetected when
	// either was seen in the session; checks that the session's head is
	// a.ExpectedHead, returning ErrHeadMoved when it is not or when the
	// session no longer exists; appends a.Entry and makes its entry_hash the
	// head; adds a.Lineage to the lineage already recorded under Entry.StepID;
	// replaces the Intent when a.Intent is set; and marks the session closed
	// when a.Close is set. It returns ErrStoreFull when the session cannot take
	// another entry.
	Append(ctx context.Context, sessionID string, a Append) error

	// Conclude records, in one operation that wholly succeeds or changes
	// nothing, what a step's final decision leaves: in the session, when its
	// head is still c.ExpectedHead (ErrHeadMoved otherwise, ErrSessionNotFound
	// when it is gone), and across sessions, c.ApproveSkill. It returns
	// ErrStoreFull when the store cannot take another skill approval.
	Conclude(ctx context.Context, sessionID string, c Conclusion) error

	// SkillApproved reports whether a Conclusion approved s.
	SkillApproved(ctx context.Context, s SkillApproval) (bool, error)
}

// Session is the state a SessionContextStore keeps for one session.
type Session struct {
	// Handshake is the negotiated handshake.
	Handshake Handshake
	// Entries is the ContextEntry sequence in order. A store that archives
	// entries (§8.5) may return only the retained ones.
	Entries []acs.ContextEntry
	// Head is the entry_hash of the last entry, empty before the first.
	Head string
	// Intent is the session's Intent, nil until one is established.
	Intent *acs.Intent
	// Closed is set once steps/sessionEnd has been appended.
	Closed bool
	// Deferrals is the number of Defer decisions the session has received.
	Deferrals int
	// AskSteps are the step_ids the session was answered Ask for, which an
	// approver's intent extension must name (§9.1).
	AskSteps []string
	// Lineage maps every step_id to the provenance_ids its payload carried,
	// which a postCompact summary's derived_from must equal the union of. A
	// store that archives Entries keeps this map so compacted steps remain
	// identifiable.
	Lineage map[string][]string
	// PolicyState is what the policy engine keeps across the session's
	// steps, nil until the engine keeps anything.
	PolicyState json.RawMessage
}

// Handshake is a completed handshake: what the Observed Agent offered and
// what the Guardian answered.
type Handshake struct {
	Client acs.ClientHello
	Server acs.ServerHello
	// AgentID is the authenticated agent_id that opened the session. Every
	// later step must carry the same value, so one signed session has one
	// policy identity.
	AgentID string
	// KeyID is the key_id the handshake was signed with. Every later step
	// of the session must be signed with the same key, so one holder of a
	// key cannot write into a session another key opened.
	KeyID string
}

// Reservation is the request_id, and the nonce when the request carried one,
// that a request consumes in its session (§10.3).
type Reservation struct {
	RequestID string
	Nonce     string
}

// Append is one ContextEntry and the session changes that go with it.
type Append struct {
	Reservation
	// ExpectedHead is the head Entry was sealed against, empty for the
	// first entry of the session.
	ExpectedHead string
	Entry        acs.ContextEntry
	// Lineage is the provenance_ids the step's payload carried. Append adds
	// them to the IDs already recorded under Entry.StepID because §9.1 gives an
	// intent_extension the step_id of the ASK it answers.
	Lineage []string
	Intent  *acs.Intent
	Close   bool
}

// Conclusion is what a step's final decision leaves.
type Conclusion struct {
	// ExpectedHead is the session's head after the step's entries.
	ExpectedHead string
	// AskStepID, when set, is recorded in Session.AskSteps.
	AskStepID string
	// Deferred counts one Defer decision.
	Deferred bool
	// PolicyState, when not nil, replaces Session.PolicyState.
	PolicyState json.RawMessage
	// ApproveSkill, when not nil, records an allowed steps/skillRegister,
	// keyed by the pair steps/skillLoad is bound against, for every session.
	ApproveSkill *SkillApproval
}

// SkillApproval is the durable correlation key of an approved skill
// registration: the skill_id and the digest of its artifact
// (skill-load.json).
type SkillApproval struct {
	SkillID         string
	DigestAlgorithm string
	DigestValue     string
}

// Errors a SessionContextStore returns.
var (
	// ErrSessionLockLost is the cause of lockCtx ending when a store detects
	// that another owner may write the session.
	ErrSessionLockLost   = errors.New("session lock lost")
	ErrReplayDetected    = errors.New("request_id or nonce already seen in this session")
	ErrHeadMoved         = errors.New("session head is not the expected head")
	ErrAlreadyNegotiated = errors.New("session already negotiated")
	ErrSessionNotFound   = errors.New("session not found")
	ErrStoreFull         = errors.New("the store is at capacity")
)
