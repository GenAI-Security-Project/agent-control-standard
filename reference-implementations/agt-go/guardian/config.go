package guardian

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// Defaults a zero Config field takes.
const (
	// DefaultMaxSessions bounds the default store, as the TypeScript
	// reference bounds its own.
	DefaultMaxSessions = 1024
	// DefaultDecisionTimeout is the decision timeout the ServerHello
	// declares, the TypeScript reference's value.
	DefaultDecisionTimeout = 5 * time.Second
	// DefaultMaxDeferrals bounds the Defer decisions one session receives
	// (§6).
	DefaultMaxDeferrals = 3
	// DefaultMaxBodyBytes caps a request body read over HTTP: sixteen times
	// a tool call carrying a 64 KiB file, the TypeScript reference's cap.
	DefaultMaxBodyBytes = 1 << 20
	// DefaultMaxEntries bounds the ContextEntries of one session in the
	// default store.
	DefaultMaxEntries = 10_000
	// DefaultMaxReservations bounds the requests remembered for replay
	// detection in one session.
	DefaultMaxReservations = 20_000
	// DefaultMaxSkillApprovals bounds the skill approvals the default store
	// holds.
	DefaultMaxSkillApprovals = 4096
	// DefaultSessionRetention is how long the default store keeps a session
	// after its last write when it needs the place.
	DefaultSessionRetention = time.Hour
	// DefaultMaxEngineCalls bounds the policy engine calls running at once,
	// an abandoned call that has not returned included.
	DefaultMaxEngineCalls = 256
	// DefaultMaxPolicyStateBytes bounds the state an engine keeps per
	// session.
	DefaultMaxPolicyStateBytes = 64 << 10
)

// AskSubstitution is the decision a Guardian returns instead of ASK for an
// endpoint whose Observed Agent cannot route approvals (§9.2).
type AskSubstitution string

const (
	// AskSubstitutionNone keeps ASK unchanged for an approver-capable endpoint.
	AskSubstitutionNone AskSubstitution = "none"
	// AskSubstitutionDeny returns DENY when an ASK cannot be routed.
	AskSubstitutionDeny AskSubstitution = "deny"
	// AskSubstitutionDefer returns DEFER when an ASK cannot be routed.
	AskSubstitutionDefer AskSubstitution = "defer"
)

// Config is what a deployment chooses. Engine and Signer are required: a
// decision needs an engine and a signature needs a key.
type Config struct {
	Engine PolicyEngine
	Signer Signer
	// Store keeps session state; nil selects a MemorySessionContextStore
	// bounded by MaxSessions.
	Store SessionContextStore
	// AuditLog receives envelopes and audit events; nil records nothing.
	AuditLog AuditLog

	// MaxSessions, MaxEntries, MaxReservations, MaxSkillApprovals and SessionRetention
	// bound the default store (MemoryStoreLimits); zero means the Default
	// of the same name. They are ignored when Store is set.
	MaxSessions       int
	MaxEntries        int
	MaxReservations   int
	MaxSkillApprovals int
	SessionRetention  time.Duration
	// DecisionTimeout bounds each engine call and is declared in the
	// ServerHello as timeout_config.default_ms; zero means
	// DefaultDecisionTimeout.
	DecisionTimeout time.Duration
	// SkewWindow is the §10.3 timestamp window, declared as skew_window_ms;
	// zero means DefaultSkewWindow.
	SkewWindow time.Duration
	// OnDecisionFailure is the posture the ServerHello declares (§6.4);
	// empty means proceed, the specification's default.
	OnDecisionFailure acs.FailurePosture
	// AskSubstitution is the deployment-defined §9.2 choice for this
	// endpoint. Empty means AskSubstitutionNone.
	AskSubstitution AskSubstitution
	// MaxDeferrals bounds the Defer decisions of one session; a Defer past
	// it is answered DENY. Zero means DefaultMaxDeferrals.
	MaxDeferrals int
	// Transport is the transport the Guardian is served on, selected in
	// every ServerHello; empty means http.
	Transport string
	// MaxBodyBytes caps a request body read by ServeHTTP; zero means
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// MaxEngineCalls bounds the engine calls running at once. A call the
	// Guardian stopped waiting for holds its place until the engine returns,
	// so an engine that ignores cancellation cannot grow without bound; a
	// step that finds no place is answered DENY. Zero means
	// DefaultMaxEngineCalls.
	MaxEngineCalls int
	// MaxPolicyStateBytes bounds PolicyDecision.State; a larger state is
	// not kept, and the step is answered DENY. Zero means
	// DefaultMaxPolicyStateBytes.
	MaxPolicyStateBytes int
	// Now is the Guardian's clock; nil means time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() (Config, error) {
	if c.Engine == nil {
		return c, errors.New("guardian: Config.Engine is required")
	}
	if c.Signer == nil {
		return c, errors.New("guardian: Config.Signer is required")
	}
	switch {
	case c.MaxSessions < 0:
		return c, fmt.Errorf("guardian: MaxSessions is %d, it cannot be negative", c.MaxSessions)
	case c.MaxEntries < 0:
		return c, fmt.Errorf("guardian: MaxEntries is %d, it cannot be negative", c.MaxEntries)
	case c.MaxReservations < 0:
		return c, fmt.Errorf("guardian: MaxReservations is %d, it cannot be negative", c.MaxReservations)
	case c.MaxSkillApprovals < 0:
		return c, fmt.Errorf("guardian: MaxSkillApprovals is %d, it cannot be negative", c.MaxSkillApprovals)
	case c.SessionRetention < 0:
		return c, fmt.Errorf("guardian: SessionRetention is %s, it cannot be negative", c.SessionRetention)
	case c.DecisionTimeout < 0:
		return c, fmt.Errorf("guardian: DecisionTimeout is %s, it cannot be negative", c.DecisionTimeout)
	case c.SkewWindow < 0:
		return c, fmt.Errorf("guardian: SkewWindow is %s, it cannot be negative", c.SkewWindow)
	case c.MaxDeferrals < 0:
		return c, fmt.Errorf("guardian: MaxDeferrals is %d, it cannot be negative", c.MaxDeferrals)
	case c.MaxBodyBytes < 0:
		return c, fmt.Errorf("guardian: MaxBodyBytes is %d, it cannot be negative", c.MaxBodyBytes)
	case c.MaxEngineCalls < 0:
		return c, fmt.Errorf("guardian: MaxEngineCalls is %d, it cannot be negative", c.MaxEngineCalls)
	case c.MaxPolicyStateBytes < 0:
		return c, fmt.Errorf("guardian: MaxPolicyStateBytes is %d, it cannot be negative", c.MaxPolicyStateBytes)
	}
	switch c.OnDecisionFailure {
	case "":
		c.OnDecisionFailure = acs.FailureProceed
	case acs.FailureProceed, acs.FailureDeny:
	default:
		return c, fmt.Errorf("guardian: OnDecisionFailure is %q, it must be proceed or deny", c.OnDecisionFailure)
	}
	switch c.AskSubstitution {
	case "":
		c.AskSubstitution = AskSubstitutionNone
	case AskSubstitutionNone, AskSubstitutionDeny, AskSubstitutionDefer:
	default:
		return c, fmt.Errorf("guardian: AskSubstitution is %q, it must be none, deny or defer", c.AskSubstitution)
	}
	switch c.Transport {
	case "":
		c.Transport = acs.TransportHTTP
	case acs.TransportHTTP, acs.TransportHTTPS, acs.TransportStdio:
	default:
		return c, fmt.Errorf("guardian: Transport is %q, it must be http, https or stdio", c.Transport)
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = DefaultMaxSessions
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = DefaultMaxEntries
	}
	if c.MaxReservations == 0 {
		c.MaxReservations = DefaultMaxReservations
	}
	if c.MaxSkillApprovals == 0 {
		c.MaxSkillApprovals = DefaultMaxSkillApprovals
	}
	if c.SessionRetention == 0 {
		c.SessionRetention = DefaultSessionRetention
	}
	if c.DecisionTimeout == 0 {
		c.DecisionTimeout = DefaultDecisionTimeout
	}
	if c.SkewWindow == 0 {
		c.SkewWindow = DefaultSkewWindow
	}
	if c.MaxDeferrals == 0 {
		c.MaxDeferrals = DefaultMaxDeferrals
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxEngineCalls == 0 {
		c.MaxEngineCalls = DefaultMaxEngineCalls
	}
	if c.MaxPolicyStateBytes == 0 {
		c.MaxPolicyStateBytes = DefaultMaxPolicyStateBytes
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.AuditLog == nil {
		c.AuditLog = noAuditLog{}
	}
	if c.Store == nil {
		minimumRetention := c.SkewWindow + c.SkewWindow
		if minimumRetention < c.SkewWindow || c.SessionRetention < minimumRetention {
			return c, fmt.Errorf("guardian: SessionRetention %s must be at least twice SkewWindow %s, so every accepted timestamp expires before its replay history is removed", c.SessionRetention, c.SkewWindow)
		}
		store, err := NewMemorySessionContextStore(MemoryStoreLimits{
			MaxSessions:       c.MaxSessions,
			MaxEntries:        c.MaxEntries,
			MaxReservations:   c.MaxReservations,
			MaxSkillApprovals: c.MaxSkillApprovals,
			Retention:         c.SessionRetention,
			Now:               c.Now,
		})
		if err != nil {
			return c, fmt.Errorf("guardian: %w", err)
		}
		c.Store = store
	}
	return c, nil
}

type noAuditLog struct{}

func (noAuditLog) Envelope(context.Context, EnvelopeRecord) {}
func (noAuditLog) Event(context.Context, AuditEvent)        {}
