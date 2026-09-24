package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/chain"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
)

var denial = disposition.Deny

// handshake negotiates a session (§4) and records it once.
func (g *Guardian) handshake(ctx context.Context, in *call, req acs.Request) reply {
	var hello acs.ClientHello
	if err := g.payload(in.Inbound, &hello); err != nil {
		return errorReply(in.ID, acs.InvalidParams, "client_hello_invalid", "the ClientHello fails handshake.json: "+err.Error())
	}
	lockCtx, release, err := g.cfg.Store.Lock(ctx, in.SessionID)
	if err != nil {
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store lock", err)
		return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be recorded")
	}
	defer release()
	ctx = lockCtx
	sess, exists, err := g.cfg.Store.Load(ctx, in.SessionID)
	if err != nil {
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store load", err)
		return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be read")
	}
	if exists {
		if outside := g.timestampOutsideWindow(in, sess.Handshake.Server.SkewWindowMS); outside != nil {
			return *outside
		}
		switch err := g.cfg.Store.Negotiate(ctx, in.SessionID, reservation(req), sess.Handshake); {
		case errors.Is(err, ErrReplayDetected):
			return replayDetected(in)
		case err == nil:
			err = errors.New("store negotiated a session that Load reported already exists")
			g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store negotiate", err)
			return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be recorded")
		case !errors.Is(err, ErrAlreadyNegotiated):
			g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store negotiate", err)
			return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be recorded")
		}
		return g.handshakeAgain(ctx, in, req, hello, sess)
	}
	if outside := g.timestampOutsideWindow(in, g.cfg.SkewWindow.Milliseconds()); outside != nil {
		return *outside
	}
	server, refusal := handshake.Negotiate(hello, g.offer())
	if refusal != nil {
		data := refusal.Data
		return reply{id: in.ID, err: &acs.Error{Code: refusal.Code, Message: data.Message, Data: &data}}
	}
	err = g.cfg.Store.Negotiate(ctx, in.SessionID, reservation(req), Handshake{Client: hello, Server: server, AgentID: req.Params.Metadata.AgentID, KeyID: in.KeyID})
	switch {
	case errors.Is(err, ErrReplayDetected):
		return replayDetected(in)
	case errors.Is(err, ErrAlreadyNegotiated):
		sess, ok, loadErr := g.cfg.Store.Load(ctx, in.SessionID)
		if loadErr != nil || !ok {
			if loadErr != nil {
				g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store load", loadErr)
			}
			return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be read")
		}
		return g.handshakeAgain(ctx, in, req, hello, sess)
	case errors.Is(err, ErrStoreFull):
		return errorReply(in.ID, acs.SessionRefused, "capacity", "the Guardian holds as many sessions as it can; retry later")
	case err != nil:
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store negotiate", err)
		return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be recorded")
	}
	return reply{id: in.ID, result: &server, sessionID: in.SessionID, keyID: in.KeyID}
}

// handshakeAgain answers a handshake for a session that exists. An Observed
// Agent that restarts has lost its ServerHello; the same ClientHello, signed
// by the key that opened the open session, gets the negotiated ServerHello
// back and changes nothing. Anything else would renegotiate, which v0.1 does
// not define, and is refused.
func (g *Guardian) handshakeAgain(ctx context.Context, in *call, req acs.Request, hello acs.ClientHello, sess Session) reply {
	refused := errorReply(in.ID, acs.SessionRefused, "already_negotiated", "the session is already negotiated with other terms, or has ended; v0.1 defines no renegotiation, so start a new session")
	if sess.Closed || sess.Handshake.KeyID != in.KeyID || sess.Handshake.AgentID != req.Params.Metadata.AgentID {
		return refused
	}
	if !sameClientHello(sess.Handshake.Client, hello) {
		return refused
	}
	switch err := g.cfg.Store.Reserve(ctx, in.SessionID, reservation(req)); {
	case errors.Is(err, ErrReplayDetected):
		return replayDetected(in)
	case errors.Is(err, ErrStoreFull):
		return errorReply(in.ID, acs.SessionRefused, "capacity", "the session holds as many replay reservations as this Guardian keeps; start a new session")
	case err != nil:
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "store reserve", err)
		return errorReply(in.ID, acs.InternalError, "store_failed", "the session could not be recorded")
	}
	server := sess.Handshake.Server
	return reply{id: in.ID, result: &server, sessionID: in.SessionID, keyID: in.KeyID}
}

func (g *Guardian) offer() handshake.Offer {
	return handshake.Offer{
		Version:                  acs.Version,
		Hooks:                    method.Hooks(),
		Wrapped:                  g.methods,
		Transport:                g.cfg.Transport,
		SignatureAlgorithms:      slices.Clone(g.algorithms),
		TimeoutConfig:            acs.TimeoutConfig{DefaultMS: g.cfg.DecisionTimeout.Milliseconds()},
		SkewWindowMS:             g.cfg.SkewWindow.Milliseconds(),
		OnDecisionFailure:        g.cfg.OnDecisionFailure,
		ApproverTypes:            g.policy.ApproverTypes,
		PolicyRequiresProvenance: g.policy.RequiresProvenance,
	}
}

func reservation(req acs.Request) Reservation {
	r := Reservation{RequestID: req.Params.RequestID}
	if req.Params.Nonce != nil {
		r.Nonce = *req.Params.Nonce
	}
	return r
}

func replayDetected(in *call) reply {
	return errorReply(in.ID, acs.ReplayDetected, "replay_detected", "request_id or nonce was already used in this session")
}

// step governs one hook or wrapped call under the session's lock: the
// ContextEntry is appended before the engine is asked, so a denied or
// failed step is in the chain, and everything the decision leaves is
// recorded before the answer is sent.
//
// Once a request is authenticated and names a negotiated method, every
// failure of the Guardian or its providers is answered with a signed DENY:
// an error would leave the Observed Agent to its failure posture, which by
// default proceeds.
func (g *Guardian) step(ctx context.Context, in *call, req acs.Request) (r reply) {
	chainHash := ""
	defer func() {
		if p := recover(); p != nil {
			g.failure(ctx, req.Method, in.SessionID, in.RequestID, "step panic", fmt.Errorf("panic: %v", p))
			r = g.answerStep(ctx, in, denial(disposition.ReasonEvaluationFailed, "the Guardian failed while deciding the step"), chainHash)
		}
	}()

	lockCtx, release, err := g.cfg.Store.Lock(ctx, in.SessionID)
	if err != nil {
		return g.storeFailed(ctx, in, "store lock", err)
	}
	defer release()
	ctx = lockCtx

	sess, ok, err := g.cfg.Store.Load(ctx, in.SessionID)
	switch {
	case err != nil:
		return g.storeFailed(ctx, in, "store load", err)
	case !ok:
		return notNegotiated(in.ID, req.Method, "the session has not completed handshake/hello")
	case sess.Handshake.KeyID != in.KeyID:
		// The signature verified, so the answer is a signed decision: an
		// error would leave the agent to its failure posture. Nothing is
		// appended, since the session belongs to another key.
		return g.answerStep(ctx, in, denial(disposition.ReasonKeyNotBound, "the request is signed with key_id "+in.KeyID+", and the session was opened with another; a session answers only the key that opened it"), "")
	case sess.Handshake.AgentID != req.Params.Metadata.AgentID:
		return g.answerStep(ctx, in, denial(disposition.ReasonAgentIDNotBound, "the request names agent_id "+req.Params.Metadata.AgentID+", and the session was opened by another agent; a session answers only the agent that opened it"), "")
	}
	chainHash = sess.Head
	if outside := g.timestampOutsideWindow(in, sess.Handshake.Server.SkewWindowMS); outside != nil {
		return *outside
	}
	switch {
	case !slices.Contains(sess.Handshake.Server.MethodsEvaluated, req.Method):
		return g.reserveRejected(ctx, in, req, notNegotiated(in.ID, req.Method, req.Method+" was not negotiated for this session"))
	case !handshake.SameMajor(req.Params.ACSVersion, sess.Handshake.Server.NegotiatedVersion):
		r := errorReply(in.ID, acs.UnsupportedVersion, "unsupported_version", "acs_version "+req.Params.ACSVersion+" does not share the negotiated major version")
		r.err.Data.SupportedVersions = []string{sess.Handshake.Server.NegotiatedVersion}
		return g.reserveRejected(ctx, in, req, r)
	}
	if err := g.checkPayload(in, req); err != nil {
		return g.reserveRejected(ctx, in, req, errorReply(in.ID, acs.InvalidParams, "payload_invalid", "the payload fails its schema: "+err.Error()))
	}
	if sess.Closed {
		switch err := g.cfg.Store.Reserve(ctx, in.SessionID, reservation(req)); {
		case errors.Is(err, ErrReplayDetected):
			return replayDetected(in)
		case errors.Is(err, ErrStoreFull):
			return g.answerStep(ctx, in, denial(disposition.ReasonStoreFull, "the session holds as many replay reservations as this Guardian keeps"), sess.Head)
		case err != nil:
			return g.storeFailed(ctx, in, "store reserve", err)
		}
		return g.answerStep(ctx, in, denial(disposition.ReasonSessionClosed, "the session has ended; no step enters after steps/sessionEnd"), "")
	}

	established, pre, err := g.preDecision(ctx, in, req, sess)
	if err != nil {
		return g.storeFailed(ctx, in, "store skill lookup", err)
	}
	entry, err := g.appendEntry(ctx, in, req, sess, established)
	switch {
	case errors.Is(err, ErrReplayDetected):
		return replayDetected(in)
	case errors.Is(err, ErrHeadMoved):
		return g.answerStep(ctx, in, denial(disposition.ReasonSessionContended, "another writer extended the session while this step held its lock"), sess.Head)
	case errors.Is(err, ErrStoreFull):
		return g.answerStep(ctx, in, denial(disposition.ReasonStoreFull, "the session holds as many steps as this Guardian keeps"), sess.Head)
	case err != nil:
		return g.storeFailed(ctx, in, "store append", err)
	}
	sess.Entries = append(slices.Clip(sess.Entries), entry)
	sess.Head = entry.EntryHash
	chainHash = sess.Head
	if established != nil {
		sess.Intent = established
	}

	var pd PolicyDecision
	if pre != nil {
		pd.Decision = *pre
	} else {
		pd = g.decide(ctx, in, req, sess)
	}
	if _, ok := g.decisionReply(in, pd.Decision, sess.Head); !ok {
		err := errors.New("the policy engine returned a decision that fails response-envelope.json")
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine decision", err)
		pd = PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the policy engine returned a decision that cannot be sent")}
	}
	d := g.guardianDecision(ctx, req.Method, in.SessionID, in.RequestID, g.substitute(ctx, in, req, sess, pd))
	if _, ok := g.decisionReply(in, d, sess.Head); !ok {
		err := errors.New("the final decision fails response-envelope.json")
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine decision", err)
		pd = PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the Guardian could not produce a valid decision")}
		d = g.guardianDecision(ctx, req.Method, in.SessionID, in.RequestID,
			pd.Decision)
	}

	if pd.Grant != nil && d.Disposition != acs.Deny {
		head, err := g.grant(ctx, in, req, sess, *pd.Grant)
		switch {
		case errors.Is(err, errGrantInvalid):
			pd = PolicyDecision{}
			d = g.guardianDecision(ctx, req.Method, in.SessionID, in.RequestID, denial(disposition.ReasonGrantInvalid, err.Error()))
		case err != nil:
			return g.storeFailed(ctx, in, "store append intent extension", err, sess.Head)
		default:
			sess.Head = head
			chainHash = head
		}
	}
	switch err := g.conclude(ctx, in, req, pd, d, sess.Head); {
	case errors.Is(err, ErrHeadMoved):
		return g.answerStep(ctx, in, denial(disposition.ReasonSessionContended, "another writer extended the session while this step held its lock"), sess.Head)
	case errors.Is(err, ErrStoreFull):
		return g.answerStep(ctx, in, denial(disposition.ReasonStoreFull, "the Guardian holds as many approved skills as it keeps"), sess.Head)
	case err != nil:
		return g.storeFailed(ctx, in, "store conclude", err, sess.Head)
	}
	return g.answerStep(ctx, in, d, sess.Head)
}

func (g *Guardian) reserveRejected(ctx context.Context, in *call, req acs.Request, rejected reply) reply {
	switch err := g.cfg.Store.Reserve(ctx, in.SessionID, reservation(req)); {
	case errors.Is(err, ErrReplayDetected):
		return replayDetected(in)
	case errors.Is(err, ErrStoreFull):
		return g.answerStep(ctx, in, denial(disposition.ReasonStoreFull, "the session holds as many replay reservations as this Guardian keeps"), "")
	case err != nil:
		return g.storeFailed(ctx, in, "store reserve", err)
	default:
		return rejected
	}
}

// storeFailed answers an authenticated step the store failed: the detail is
// recorded, and the Observed Agent receives a signed DENY.
func (g *Guardian) storeFailed(ctx context.Context, in *call, what string, err error, chainHash ...string) reply {
	g.failure(ctx, in.Method, in.SessionID, in.RequestID, what, err)
	reason, message := disposition.ReasonStoreUnavailable, "the Guardian's session store failed"
	if g.stop.Err() != nil {
		reason, message = disposition.ReasonShuttingDown, "the Guardian stopped before it could decide"
	}
	head := ""
	if len(chainHash) > 0 {
		head = chainHash[0]
	}
	return g.answerStep(ctx, in, g.guardianDecision(ctx, in.Method, in.SessionID, in.RequestID, denial(reason, message)), head)
}

// checkPayload validates the payload: a native hook against its schema, a
// wrapped call by its protocol's handler.
func (g *Guardian) checkPayload(in *call, req acs.Request) error {
	if g.methods.Route(req.Method) == method.Hook {
		return g.payload(in.Inbound, nil)
	}
	h, wrapped, ok := g.methods.WrappedHandler(req.Method)
	if !ok {
		return fmt.Errorf("no handler for %s", req.Method)
	}
	return h.Check(wrapped, req.Params.Payload)
}

// preDecision applies the rules the standard gives the Guardian itself,
// before any policy: the Intent a step establishes or would change (§8.4),
// the Observed Agent's view of the chain (§8.6), and a skill load's binding
// to an approved registration (skill-load.json). A non-nil decision
// replaces the engine's.
func (g *Guardian) preDecision(ctx context.Context, in *call, req acs.Request, sess Session) (*acs.Intent, *acs.Decision, error) {
	established, intentErr := g.intent(req, sess.Intent)
	switch {
	case intentErr != nil:
		g.event(ctx, EventIntentMutationRejected, req.Method, in.SessionID, in.RequestID, intentErr.Error())
		d := denial(disposition.ReasonIntentMismatch, intentErr.Error())
		return nil, &d, nil
	case chainMismatch(req, sess.Head):
		message := fmt.Sprintf("the client's chain_hash %s is not the session's head %s", *req.Params.Metadata.SessionState.ChainHash, sess.Head)
		g.event(ctx, EventChainMismatch, req.Method, in.SessionID, in.RequestID, message)
		d := denial(disposition.ReasonChainMismatch, message)
		return established, &d, nil
	case req.Method == acs.StepSkillLoad:
		var p acs.SkillLoadPayload
		if err := jsonv2.Unmarshal(req.Params.Payload, &p); err != nil {
			return nil, nil, err
		}
		approved, err := g.cfg.Store.SkillApproved(ctx, skillApproval(p.SkillID, p.Digest))
		if err != nil {
			return nil, nil, err
		}
		if !approved {
			d := denial(disposition.ReasonSkillUnverifiable, "no approved steps/skillRegister matches skill_id "+p.SkillID+" with this digest")
			return established, &d, nil
		}
	}
	return established, nil, nil
}

func skillApproval(skillID string, d acs.Digest) SkillApproval {
	return SkillApproval{SkillID: skillID, DigestAlgorithm: d.Algorithm, DigestValue: d.Value}
}

// intent returns the Intent a step establishes (§8.4), or an error when the
// step would change an established one. Only steps/sessionStart and
// steps/agentTrigger carry an Intent.
func (g *Guardian) intent(req acs.Request, current *acs.Intent) (*acs.Intent, error) {
	var carried *acs.Intent
	switch req.Method {
	case acs.StepSessionStart:
		var p acs.SessionStartPayload
		if err := jsonv2.Unmarshal(req.Params.Payload, &p); err != nil {
			return nil, err
		}
		carried = p.Intent
	case acs.StepAgentTrigger:
		var p acs.AgentTriggerPayload
		if err := jsonv2.Unmarshal(req.Params.Payload, &p); err != nil {
			return nil, err
		}
		carried = p.Intent
	}
	switch {
	case carried == nil:
		return nil, nil
	case current == nil:
		return carried, nil
	case sameIntent(*carried, *current):
		return nil, nil
	}
	return nil, errors.New("the step carries an Intent that differs from the session's established Intent; Intent.parsed grows only through an approver's intent_extension (§8.4)")
}

func sameClientHello(a, b acs.ClientHello) bool {
	aMethods, bMethods := a.MethodsImplemented, b.MethodsImplemented
	aVersions, bVersions := a.ACSVersionsSupported, b.ACSVersionsSupported
	aTransports, bTransports := a.TransportsSupported, b.TransportsSupported
	aProfiles, bProfiles := a.ProfilesSupported, b.ProfilesSupported
	aWrapped, bWrapped := a.WrappedProtocols, b.WrappedProtocols
	a.MethodsImplemented, b.MethodsImplemented = nil, nil
	a.ACSVersionsSupported, b.ACSVersionsSupported = nil, nil
	a.TransportsSupported, b.TransportsSupported = nil, nil
	a.ProfilesSupported, b.ProfilesSupported = nil, nil
	a.WrappedProtocols, b.WrappedProtocols = nil, nil
	return reflect.DeepEqual(a, b) && sameStrings(aMethods, bMethods) && sameStrings(aVersions, bVersions) &&
		sameStrings(aTransports, bTransports) && sameStrings(aProfiles, bProfiles) && sameWrapped(aWrapped, bWrapped)
}

func sameIntent(a, b acs.Intent) bool {
	aParsed, bParsed := a.Parsed, b.Parsed
	a.Parsed, b.Parsed = nil, nil
	return reflect.DeepEqual(a, b) && sameCapabilities(aParsed, bParsed)
}

func sameStrings(a, b []string) bool {
	return sameSet(a, b)
}

func sameWrapped(a, b []acs.WrappedProtocol) bool {
	return sameSet(a, b)
}

func sameCapabilities(a, b []acs.Capability) bool {
	return sameSet(a, b)
}

func sameSet[T comparable](a, b []T) bool {
	aSet := make(map[T]struct{}, len(a))
	bSet := make(map[T]struct{}, len(b))
	for _, value := range a {
		aSet[value] = struct{}{}
	}
	for _, value := range b {
		bSet[value] = struct{}{}
	}
	return reflect.DeepEqual(aSet, bSet)
}

func chainMismatch(req acs.Request, head string) bool {
	state := req.Params.Metadata.SessionState
	return state != nil && state.ChainHash != nil && *state.ChainHash != head
}

// appendEntry seals the step's ContextEntry against the session's head and
// appends it with the step's reservation and lineage, in one store
// operation.
func (g *Guardian) appendEntry(ctx context.Context, in *call, req acs.Request, sess Session, intent *acs.Intent) (acs.ContextEntry, error) {
	requestHash, err := chain.RequestHash(in.Params)
	if err != nil {
		return acs.ContextEntry{}, err
	}
	e := acs.ContextEntry{
		EntryID:     req.Params.RequestID,
		StepID:      req.Params.RequestID,
		StepType:    req.Method,
		RequestHash: requestHash,
		Timestamp:   g.cfg.Now().UTC().Format(time.RFC3339Nano),
	}
	if req.Params.Metadata.TurnID != nil {
		e.TurnID = *req.Params.Metadata.TurnID
	}
	entry, err := chain.Seal(e, sess.Head)
	if err != nil {
		return acs.ContextEntry{}, err
	}
	lineage, err := provenanceIDs(req.Params.Payload)
	if err != nil {
		return acs.ContextEntry{}, err
	}
	return entry, g.cfg.Store.Append(ctx, in.SessionID, Append{
		Reservation:  reservation(req),
		ExpectedHead: sess.Head,
		Entry:        entry,
		Lineage:      lineage,
		Intent:       intent,
		Close:        req.Method == acs.StepSessionEnd,
	})
}

// decide asks the engine. A failure, a delegation this Guardian cannot
// serve and a decision unfit to send are all answered DENY.
func (g *Guardian) decide(ctx context.Context, in *call, req acs.Request, sess Session) PolicyDecision {
	input, err := cloneJSON(PolicyInput{Request: req, Session: SessionContext{
		SessionID:   in.SessionID,
		ChainHash:   sess.Head,
		Entries:     sess.Entries,
		Intent:      sess.Intent,
		Handshake:   sess.Handshake,
		PolicyState: sess.PolicyState,
	}})
	if sess.PolicyState == nil {
		input.Session.PolicyState = nil
	}
	if err != nil {
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy input", err)
		return PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the Guardian could not isolate the policy input")}
	}
	pd, err := g.callEngine(ctx, negotiatedTimeout(sess.Handshake.Server, req.Method), input)
	switch {
	case errors.Is(err, errEngineSaturated):
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine", err)
		return PolicyDecision{Decision: denial(disposition.ReasonEngineSaturated, "the Guardian is running as many policy evaluations as it allows")}
	case err != nil:
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine", err)
		if g.stop.Err() != nil {
			return PolicyDecision{Decision: denial(disposition.ReasonShuttingDown, "the Guardian stopped before the policy engine decided")}
		}
		return PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the policy engine failed")}
	case pd.DelegateToAgent:
		return PolicyDecision{Decision: denial(disposition.ReasonAgentLayerUnavailable, "the policy delegated this step to an agent layer, which this Guardian does not have (§12.2)")}
	case len(pd.State) > g.cfg.MaxPolicyStateBytes:
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine", fmt.Errorf("state of %d bytes exceeds %d", len(pd.State), g.cfg.MaxPolicyStateBytes))
		return PolicyDecision{Decision: denial(disposition.ReasonPolicyStateTooLarge, "the policy's state for this session outgrew what this Guardian keeps")}
	case pd.State != nil && !json.Valid(pd.State):
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine", errors.New("state is not valid JSON"))
		return PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the policy engine returned state that is not valid JSON")}
	}
	pd.Decision = disposition.WithDeferDefaults(pd.Decision)
	if err := g.fit(req.Method, sess.Handshake.Server.ApproverTypesSupported, pd.Decision); err != nil {
		g.failure(ctx, req.Method, in.SessionID, in.RequestID, "policy engine decision", err)
		return PolicyDecision{Decision: denial(disposition.ReasonEvaluationFailed, "the policy engine returned a decision that cannot be sent: "+err.Error())}
	}
	if req.Method == acs.StepPostCompact {
		pd.Decision = g.checkLineage(ctx, in, req, sess, pd.Decision)
	}
	return pd
}

// substitute applies the standard's rules to the engine's decision: what a
// client that cannot apply a disposition receives (§6.5, §9.2), and the
// bound on a session's deferrals (§6).
func (g *Guardian) substitute(ctx context.Context, in *call, req acs.Request, sess Session, pd PolicyDecision) acs.Decision {
	d := pd.Decision
	switch {
	case d.Disposition == acs.Modify && pd.Client.CannotApplyModify:
		g.event(ctx, EventModifyUnsupported, req.Method, in.SessionID, in.RequestID, "modification not delivered: "+d.Reasoning)
		if req.Method == acs.StepPostCompact {
			return disposition.ModifyUnsupportedAtPostCompact(d)
		}
		return disposition.ModifyUnsupported(d)
	case d.Disposition == acs.Ask:
		substitution := g.cfg.AskSubstitution
		if substitution == AskSubstitutionNone && pd.Client.CannotResolveAsk {
			substitution = AskSubstitutionDeny
			if pd.Client.AskSubstitute == acs.Defer {
				substitution = AskSubstitutionDefer
			}
		}
		if substitution != AskSubstitutionNone {
			replacement := disposition.AskAsDeny(d)
			if substitution == AskSubstitutionDefer {
				replacement = disposition.AskAsDefer(d)
			}
			g.event(ctx, EventAskSubstituted, req.Method, in.SessionID, in.RequestID, fmt.Sprintf("ask answered %s for a client that cannot route an approval", replacement.Disposition))
			d = replacement
		}
	}
	if d.Disposition == acs.Defer && sess.Deferrals+1 > g.cfg.MaxDeferrals {
		return denial(disposition.ReasonDeferralBoundExceeded, fmt.Sprintf("the session has deferred %d times, the most this Guardian allows (§6)", sess.Deferrals))
	}
	return d
}

// conclude records what the final decision leaves in the session: an ASK
// step an approver may answer, a deferral, the engine's state, and an
// approved skill registration.
func (g *Guardian) conclude(ctx context.Context, in *call, req acs.Request, pd PolicyDecision, d acs.Decision, head string) error {
	c := Conclusion{ExpectedHead: head, Deferred: d.Disposition == acs.Defer, PolicyState: pd.State}
	if d.Disposition == acs.Ask {
		c.AskStepID = req.Params.RequestID
	}
	if req.Method == acs.StepSkillRegister && (d.Disposition == acs.Allow || d.Disposition == acs.Modify) {
		var p acs.SkillRegisterPayload
		if err := jsonv2.Unmarshal(req.Params.Payload, &p); err != nil {
			return err
		}
		approval := skillApproval(p.SkillID, p.Definition.Digest)
		c.ApproveSkill = &approval
	}
	if !c.Deferred && c.AskStepID == "" && c.PolicyState == nil && c.ApproveSkill == nil {
		return nil
	}
	return g.cfg.Store.Conclude(ctx, in.SessionID, c)
}

var errEngineSaturated = errors.New("every engine call place is taken")

// callEngine runs the engine under the decision timeout and ctx, which
// Shutdown cancels, and turns a panic into an error. It stops waiting when
// ctx ends even if the engine does not, so an engine that ignores
// cancellation cannot hold the answer; the call keeps its place in
// engineCalls until the engine returns.
func (g *Guardian) callEngine(ctx context.Context, timeout time.Duration, in PolicyInput) (PolicyDecision, error) {
	select {
	case g.engineCalls <- struct{}{}:
	default:
		return PolicyDecision{}, errEngineSaturated
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type outcome struct {
		pd  PolicyDecision
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() { <-g.engineCalls }()
		defer func() {
			if p := recover(); p != nil {
				done <- outcome{err: fmt.Errorf("panic: %v", p)}
			}
		}()
		pd, err := g.cfg.Engine.Decide(ctx, in)
		done <- outcome{pd, err}
	}()
	select {
	case o := <-done:
		if o.err == nil && ctx.Err() != nil {
			o.err = context.Cause(ctx)
		}
		return o.pd, o.err
	case <-ctx.Done():
		return PolicyDecision{}, context.Cause(ctx)
	}
}

// fit checks an engine's decision against the rules of §6 and §6.3 and
// against what the ServerHello declared.
func (g *Guardian) fit(methodName string, approverTypes []acs.ApproverType, d acs.Decision) error {
	check := disposition.Check
	if handler, _, ok := g.methods.WrappedHandler(methodName); ok {
		check = func(d acs.Decision) error {
			return disposition.CheckWithOverridePointer(d, handler.ParameterOverridePointer)
		}
	}
	if err := check(d); err != nil {
		return err
	}
	if d.Disposition == acs.Ask && !slices.Contains(approverTypes, d.AskDetails.Approver.Type) {
		return fmt.Errorf("approver type %q is not in approver_types_supported", d.AskDetails.Approver.Type)
	}
	return nil
}

var errGrantInvalid = errors.New("the intent extension is not valid")

// grant records an approver's intent extension (§9.1). The engine has
// authenticated the approver and applied the session's scope_mode, which
// are policy; the Guardian checks that the grant answers an ASK this
// session was given and names an approver type it routes to. A
// session-scoped extension grows Intent.parsed and is written as its own
// ContextEntry holding the approver, the capabilities and the extension's
// provenance; one scoped to this request changes nothing that persists. It
// returns the session's head after the grant.
func (g *Guardian) grant(ctx context.Context, in *call, req acs.Request, sess Session, grant IntentGrant) (string, error) {
	switch {
	case !slices.Contains(sess.AskSteps, grant.AskStepID):
		return "", fmt.Errorf("%w: step %s was not answered ask in this session", errGrantInvalid, grant.AskStepID)
	case !slices.Contains(sess.Handshake.Server.ApproverTypesSupported, grant.Approver.Type):
		return "", fmt.Errorf("%w: approver type %q is not in approver_types_supported", errGrantInvalid, grant.Approver.Type)
	case len(grant.Extension.Capabilities) == 0:
		return "", fmt.Errorf("%w: it grants no capability", errGrantInvalid)
	case grant.Extension.Scope != acs.ScopeThisRequest && grant.Extension.Scope != acs.ScopeSession:
		return "", fmt.Errorf("%w: intent extension scope %q is not defined", errGrantInvalid, grant.Extension.Scope)
	}
	if grant.Extension.Scope != acs.ScopeSession {
		return sess.Head, nil
	}
	intent := acs.Intent{}
	if sess.Intent != nil {
		intent = *sess.Intent
	}
	intent.Parsed = append(slices.Clip(intent.Parsed), grant.Extension.Capabilities...)
	approver, extension := grant.Approver, grant.Extension
	entry, err := chain.Seal(acs.ContextEntry{
		EntryID:         req.Params.RequestID + "/" + acs.StepTypeIntentExtension,
		StepID:          grant.AskStepID,
		StepType:        acs.StepTypeIntentExtension,
		Timestamp:       g.cfg.Now().UTC().Format(time.RFC3339Nano),
		Approver:        &approver,
		IntentExtension: &extension,
	}, sess.Head)
	if err != nil {
		return "", err
	}
	var lineage []string
	if extension.Provenance != nil {
		lineage = []string{extension.Provenance.ProvenanceID}
	}
	err = g.cfg.Store.Append(ctx, in.SessionID, Append{
		Reservation:  Reservation{RequestID: entry.EntryID},
		ExpectedHead: sess.Head,
		Entry:        entry,
		Lineage:      lineage,
		Intent:       &intent,
	})
	if err != nil {
		return "", err
	}
	return entry.EntryHash, nil
}

func negotiatedTimeout(server acs.ServerHello, methodName string) time.Duration {
	milliseconds := server.TimeoutConfig.DefaultMS
	if override, ok := server.TimeoutConfig.PerMethodMS[methodName]; ok {
		milliseconds = override
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// guardianDecision applies the hook's permitted dispositions (hooks.md): a
// disposition the hook does not permit becomes DENY where DENY is permitted,
// and ALLOW with the reason recorded where it is not, as at an audit-only
// hook.
func (g *Guardian) guardianDecision(ctx context.Context, methodName, sessionID, requestID string, d acs.Decision) acs.Decision {
	rule := g.methods.HookRule(methodName)
	if rule.Permits(d.Disposition) {
		return d
	}
	message := fmt.Sprintf("%s is not a disposition %s permits", d.Disposition, methodName)
	if d.Reasoning != "" {
		message += ": " + d.Reasoning
	}
	g.event(ctx, EventDispositionNotPermitted, methodName, sessionID, requestID, message)
	codes := append(slices.Clip(d.ReasonCodes), disposition.ReasonDispositionNotPermitted)
	if rule.Permits(acs.Deny) {
		out := denial(disposition.ReasonDispositionNotPermitted, message)
		out.ReasonCodes = codes
		out.PolicyReferences = d.PolicyReferences
		return out
	}
	return acs.Decision{Disposition: acs.Allow, Reasoning: message, ReasonCodes: codes, PolicyReferences: d.PolicyReferences}
}

// answerStep answers a step with its decision and the published head,
// falling back to the Guardian's own denial when the decision would not
// pass the response schema.
func (g *Guardian) answerStep(ctx context.Context, in *call, d acs.Decision, chainHash string) reply {
	d = g.guardianDecision(ctx, in.Method, in.SessionID, in.RequestID, d)
	if r, ok := g.decisionReply(in, d, chainHash); ok {
		return r
	}
	fallback := g.guardianDecision(ctx, in.Method, in.SessionID, in.RequestID,
		denial(disposition.ReasonEvaluationFailed, "the decision does not pass response-envelope.json"))
	if r, ok := g.decisionReply(in, fallback, chainHash); ok {
		return r
	}
	return errorReply(in.ID, acs.InternalError, "response_invalid", "the Guardian could not build a valid answer")
}
