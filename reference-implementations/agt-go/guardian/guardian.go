package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/envelope"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/mcp"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/schema"
)

// Guardian answers ACS requests. It is safe for concurrent use: steps of
// different sessions run in parallel, and the steps of one session run one
// at a time, from reservation to answer, under the store's session lock.
type Guardian struct {
	cfg        Config
	schemas    *schema.Registry
	methods    *method.Table
	policy     PolicyDescription
	algorithms []string
	// engineCalls holds one token per engine call running, an abandoned
	// one included, up to Config.MaxEngineCalls.
	engineCalls chan struct{}

	// drain state: Shutdown stops new requests and, when its grace ends,
	// cancels the requests still running so each is answered.
	mu       sync.Mutex
	draining bool
	inflight sync.WaitGroup
	stop     context.Context
	cancel   context.CancelFunc
}

// New returns a Guardian ready to answer: the schemas are compiled and the
// configuration is checked. It governs the native hooks and wrapped MCP.
func New(cfg Config) (*Guardian, error) {
	return newGuardian(cfg, method.NewTable(mcp.Handler{}))
}

// newGuardian takes the method table separately so a test can register a
// wrapped-protocol handler of its own.
func newGuardian(cfg Config, methods *method.Table) (*Guardian, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	schemas, err := schema.Load()
	if err != nil {
		return nil, fmt.Errorf("guardian: %w", err)
	}
	policy, err := providerSnapshot("PolicyEngine.Policy", cfg.Engine.Policy)
	if err != nil {
		return nil, err
	}
	policy.ApproverTypes = slices.Clone(policy.ApproverTypes)
	algorithms, err := providerSnapshot("Signer.Algorithms", cfg.Signer.Algorithms)
	if err != nil {
		return nil, err
	}
	algorithms = slices.Clone(algorithms)
	if len(algorithms) == 0 {
		return nil, errors.New("guardian: Signer.Algorithms returned no algorithm, but every non-ping request must be signed")
	}
	hello := acs.ServerHello{
		NegotiatedVersion:            acs.Version,
		MethodsEvaluated:             []string{},
		SelectedTransport:            cfg.Transport,
		SignatureAlgorithmsSupported: algorithms,
		TimeoutConfig:                acs.TimeoutConfig{DefaultMS: cfg.DecisionTimeout.Milliseconds()},
		SkewWindowMS:                 cfg.SkewWindow.Milliseconds(),
		OnDecisionFailure:            cfg.OnDecisionFailure,
		ApproverTypesSupported:       policy.ApproverTypes,
		PolicyRequiresProvenance:     policy.RequiresProvenance,
		ProfilesAccepted:             []string{},
	}
	helloJSON, err := jsonv2.Marshal(hello)
	if err != nil {
		return nil, fmt.Errorf("guardian: describe ServerHello: %w", err)
	}
	if err := schemas.ValidateJSON(schema.ServerHello, helloJSON); err != nil {
		return nil, fmt.Errorf("guardian: provider capabilities do not form a valid ServerHello: %w", err)
	}
	stop, cancel := context.WithCancel(context.Background())
	return &Guardian{
		cfg:         cfg,
		schemas:     schemas,
		methods:     methods,
		policy:      policy,
		algorithms:  algorithms,
		engineCalls: make(chan struct{}, cfg.MaxEngineCalls),
		stop:        stop,
		cancel:      cancel,
	}, nil
}

func providerSnapshot[T any](name string, read func() T) (value T, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("guardian: %s panicked: %v", name, p)
		}
	}()
	return read(), nil
}

// Handle answers one request: body is the request as received and the
// result is the response to send. Every request gets a response. ctx is
// passed to the four interfaces, and ends early when Shutdown's grace ends.
func (g *Guardian) Handle(ctx context.Context, body []byte) []byte {
	if !g.begin() {
		return g.shuttingDown(ctx)
	}
	defer g.inflight.Done()
	return g.handle(ctx, body)
}

func (g *Guardian) handle(ctx context.Context, body []byte) []byte {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(g.stop, cancel)()
	r, method := g.answer(ctx, body)
	return g.encode(ctx, r, method)
}

// begin counts a request in flight, or reports false once Shutdown has
// begun.
func (g *Guardian) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return false
	}
	g.inflight.Add(1)
	return true
}

func (g *Guardian) shuttingDown(ctx context.Context) []byte {
	return g.encode(ctx, errorReply(nullID, acs.InternalError, "shutting_down", "the Guardian is shutting down"), "")
}

// Shutdown stops accepting requests and waits for the ones running. When ctx
// ends first, it cancels them and returns at once: each running step is
// answered DENY as its engine call, store call or lock wait returns, and a
// call to one of the four interfaces that ignores cancellation may finish
// after Shutdown has returned.
func (g *Guardian) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	g.draining = true
	g.mu.Unlock()
	done := make(chan struct{})
	go func() {
		g.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		g.cancel()
		return ctx.Err()
	}
}

// reply is a response before it is encoded and signed: a result or an
// error, never both.
type reply struct {
	id     jsontext.Value
	result any // *acs.Result or *acs.ServerHello
	err    *acs.Error
	// sessionID names the key the result is signed with, empty for no
	// signature.
	sessionID string
	// keyID is the key_id the request was verified with.
	keyID string
	// signatureOptional sends the result unsigned when signing fails.
	signatureOptional bool
}

var nullID = jsontext.Value("null")

// call is an authenticated request: what was read of it, and the key_id its
// signature verified under.
type call struct {
	*envelope.Inbound
	KeyID string
}

func errorReply(id jsontext.Value, code acs.ErrorCode, reason, message string) reply {
	return reply{id: id, err: &acs.Error{Code: code, Message: message, Data: &acs.ErrorData{Reason: reason, Message: message}}}
}

// answer routes a request. The order is a security property: nothing is
// decided before the request is authenticated, and nothing is read for a
// decision before it is validated.
func (g *Guardian) answer(ctx context.Context, body []byte) (r reply, methodName string) {
	responseID := nullID
	authenticatedSessionID, authenticatedKeyID := "", ""
	authenticatedStep := false
	authenticatedRequestID, authenticatedVersion := "", ""
	defer func() {
		if p := recover(); p != nil {
			g.failure(ctx, methodName, authenticatedSessionID, "", "guardian defect", fmt.Errorf("panic: %v", p))
			if authenticatedStep {
				r = reply{id: responseID, result: &acs.Result{
					Type:       acs.ResultTypeFinal,
					ACSVersion: authenticatedVersion,
					RequestID:  authenticatedRequestID,
					Decision:   denial(disposition.ReasonEvaluationFailed, "the Guardian failed while deciding the step"),
				}, sessionID: authenticatedSessionID, keyID: authenticatedKeyID}
			} else {
				r = errorReply(responseID, acs.InternalError, "guardian_defect", "the Guardian failed to answer")
				r.sessionID, r.keyID = authenticatedSessionID, authenticatedKeyID
			}
		}
	}()

	in, err := envelope.Parse(body)
	switch {
	case errors.Is(err, envelope.ErrBatch):
		return errorReply(nullID, acs.InvalidRequest, "batch_unsupported", "batch requests are not supported; send each request on its own"), ""
	case errors.Is(err, envelope.ErrNotObject):
		return errorReply(nullID, acs.InvalidRequest, "not_an_object", "the request is not a JSON object"), ""
	case err != nil:
		return errorReply(nullID, acs.ParseError, "parse_error", "the request is not a single valid I-JSON text"), ""
	}
	responseID, methodName = in.ID, in.Method
	g.record(ctx, Inbound, in.Method, body)
	if err := in.ValidateJSONRPCRequest(); err != nil {
		return errorReply(in.ID, acs.InvalidRequest, "invalid_jsonrpc_request", "the request is not a valid JSON-RPC 2.0 request: "+err.Error()), in.Method
	}

	route := g.methods.Route(in.Method)
	if route == method.Ping {
		return g.ping(ctx, in, body), in.Method
	}

	input, sig, err := envelope.RequestSigningInput(body)
	switch {
	case err != nil:
		return errorReply(in.ID, acs.SignatureInvalid, "signature_malformed", err.Error()), in.Method
	case sig == nil:
		return errorReply(in.ID, acs.SignatureInvalid, "signature_missing", "every request except system/ping must be signed (§10)"), in.Method
	case in.SessionID == "":
		return errorReply(in.ID, acs.SignatureInvalid, "session_missing", "metadata.session_id is required to derive the signing key"), in.Method
	}
	if err := g.cfg.Signer.Verify(ctx, in.SessionID, input, *sig); err != nil {
		if !errors.Is(err, ErrSignatureInvalid) {
			g.failure(ctx, in.Method, in.SessionID, in.RequestID, "signer", err)
		}
		return errorReply(in.ID, acs.SignatureInvalid, "signature_invalid", "the signature does not verify"), in.Method
	}
	authenticatedSessionID, authenticatedKeyID = in.SessionID, sig.KeyID
	// From here the request is authenticated, so an error answering it is
	// signed with the key it verified under.
	defer func() {
		if r.err != nil && r.sessionID == "" {
			r.sessionID, r.keyID = in.SessionID, sig.KeyID
		}
	}()

	if err := g.schemas.Validate(schema.RequestEnvelope, in.Tree); err != nil {
		return errorReply(in.ID, acs.InvalidRequest, "envelope_invalid", "the request fails request-envelope.json: "+err.Error()), in.Method
	}
	var req acs.Request
	if err := jsonv2.Unmarshal(body, &req); err != nil {
		return errorReply(in.ID, acs.InvalidRequest, "envelope_invalid", "the request cannot be read: "+err.Error()), in.Method
	}
	c := &call{Inbound: in, KeyID: sig.KeyID}
	if route == method.Hook || route == method.Wrapped {
		authenticatedStep = true
		authenticatedRequestID = in.RequestID
		authenticatedVersion = in.ACSVersion
	}

	switch route {
	case method.Handshake:
		return g.handshake(ctx, c, req), in.Method
	case method.Hook, method.Wrapped:
		return g.step(ctx, c, req), in.Method
	case method.Unsupported:
		return g.rejectOutsideStep(ctx, c, req, notNegotiated(in.ID, req.Method, "this Guardian does not negotiate "+req.Method)), in.Method
	default:
		return g.rejectOutsideStep(ctx, c, req, errorReply(in.ID, acs.MethodNotFound, "method_not_found", "ACS v0.1 defines no method "+req.Method)), in.Method
	}
}

func (g *Guardian) rejectOutsideStep(ctx context.Context, in *call, req acs.Request, rejected reply) reply {
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
		return g.answerStep(ctx, in, denial(disposition.ReasonKeyNotBound, "the request is signed by a key other than the key that opened this session"), "")
	case sess.Handshake.AgentID != req.Params.Metadata.AgentID:
		return g.answerStep(ctx, in, denial(disposition.ReasonAgentIDNotBound, "the request names an agent other than the agent that opened this session"), "")
	}
	if outside := g.timestampOutsideWindow(in, sess.Handshake.Server.SkewWindowMS); outside != nil {
		return *outside
	}
	return g.reserveRejected(ctx, in, req, rejected)
}

func (g *Guardian) timestampOutsideWindow(in *call, windowMS int64) *reply {
	window := time.Duration(windowMS) * time.Millisecond
	if withinSkew(in.Timestamp, g.cfg.Now(), window) {
		return nil
	}
	r := errorReply(in.ID, acs.TimestampOutOfWindow, "timestamp_out_of_window", "the request timestamp is outside the skew window")
	r.err.Data.SkewWindowMS = &windowMS
	return &r
}

func notNegotiated(id jsontext.Value, name, message string) reply {
	r := errorReply(id, acs.CapabilityNotNegotiated, "capability_not_negotiated", message)
	r.err.Data.Method = name
	return r
}

// decisionReply builds a result for in, checked against the response
// schema; false means the result cannot be sent, because the request's
// identifiers do not make a valid answer.
func (g *Guardian) decisionReply(in *call, d acs.Decision, chainHash string) (reply, bool) {
	version := in.ACSVersion
	if version == "" {
		version = acs.Version
	}
	result := &acs.Result{Type: acs.ResultTypeFinal, ACSVersion: version, RequestID: in.RequestID, Decision: d, ChainHash: chainHash}
	r := reply{id: in.ID, result: result, sessionID: in.SessionID, keyID: in.KeyID}
	if in.NullID() || g.checkResponse(r) != nil {
		return reply{}, false
	}
	return r, true
}

// checkResponse validates the response against response-envelope.json.
func (g *Guardian) checkResponse(r reply) error {
	b, err := marshalResponse(r)
	if err != nil {
		return err
	}
	return g.schemas.ValidateJSON(schema.ResponseEnvelope, b)
}

func marshalResponse(r reply) ([]byte, error) {
	resp := acs.Response{JSONRPC: acs.JSONRPCVersion, ID: json.RawMessage(r.id), Error: r.err}
	if r.result != nil {
		b, err := jsonv2.Marshal(r.result)
		if err != nil {
			return nil, err
		}
		resp.Result = b
	}
	return jsonv2.Marshal(resp)
}

// encode signs and serialises a reply, checks the bytes to be sent against
// response-envelope.json, and records them. A reply that cannot be signed
// or does not pass the schema is replaced by an unsigned error.
func (g *Guardian) encode(ctx context.Context, r reply, methodName string) (b []byte) {
	defer func() {
		if p := recover(); p != nil {
			g.failure(ctx, methodName, r.sessionID, "", "answer", fmt.Errorf("panic: %v", p))
			b, _ = marshalResponse(errorReply(r.id, acs.InternalError, "answer_failed", "the Guardian could not sign a valid answer"))
		}
	}()
	b, err := g.sign(ctx, r)
	if err != nil && r.signatureOptional {
		r.sessionID = ""
		b, err = marshalResponse(r)
	}
	if err == nil {
		err = g.schemas.ValidateJSON(schema.ResponseEnvelope, b)
	}
	if err != nil {
		g.failure(ctx, methodName, r.sessionID, "", "answer", err)
		b, _ = marshalResponse(errorReply(r.id, acs.InternalError, "answer_failed", "the Guardian could not sign a valid answer"))
	}
	g.record(ctx, Outbound, methodName, b)
	return b
}

// sign adds the §10 signature to a result or an error: the signed input is
// the response envelope with no signature, canonicalized. A reply with no
// sessionID, which answers a request that did not authenticate, is sent
// unsigned: no key is established for it.
func (g *Guardian) sign(ctx context.Context, r reply) ([]byte, error) {
	b, err := marshalResponse(r)
	if err != nil || r.sessionID == "" {
		return b, err
	}
	input, _, err := envelope.ResponseSigningInput(b)
	if err != nil {
		return nil, err
	}
	sig, err := g.cfg.Signer.Sign(ctx, r.sessionID, r.keyID, input)
	if err != nil {
		return nil, err
	}
	switch result := r.result.(type) {
	case *acs.Result:
		result.Signature = &sig
	case *acs.ServerHello:
		result.Signature = &sig
	case nil:
		r.err.Signature = &sig
	}
	return marshalResponse(r)
}

func (g *Guardian) record(ctx context.Context, d Direction, methodName string, body []byte) {
	defer func() { _ = recover() }()
	g.cfg.AuditLog.Envelope(ctx, EnvelopeRecord{Direction: d, Method: methodName, Body: json.RawMessage(slices.Clone(body)), RecordedAt: g.cfg.Now().UTC()})
}

func (g *Guardian) event(ctx context.Context, kind AuditEventKind, methodName, sessionID, requestID, message string) {
	defer func() { _ = recover() }()
	g.cfg.AuditLog.Event(ctx, AuditEvent{Kind: kind, SessionID: sessionID, RequestID: requestID, Method: methodName, Message: message, RecordedAt: g.cfg.Now().UTC()})
}

// failure records what a provider or the Guardian itself reported. The
// detail stays in the audit log: the wire carries a fixed message, since a
// store, key service or engine error may name internals.
func (g *Guardian) failure(ctx context.Context, methodName, sessionID, requestID, what string, err error) {
	g.event(ctx, EventFailure, methodName, sessionID, requestID, what+": "+err.Error())
}

// ping answers system/ping (§13): always ALLOW, never an ACS-specific
// error, no signature required, nothing written to the SessionContext. The
// answer is signed only when the ping was signed and verifies, so an
// unauthenticated caller cannot obtain the session key's signature over a
// result it chose; it is sent unsigned when signing fails, so liveness
// survives a key outage.
func (g *Guardian) ping(ctx context.Context, in *envelope.Inbound, body []byte) reply {
	if err := g.schemas.Validate(schema.RequestEnvelope, in.Tree); err != nil || in.NullID() {
		return errorReply(in.ID, acs.InvalidRequest, "envelope_invalid", "system/ping must be a valid request envelope")
	}
	var payload acs.SystemPingPayload
	if err := g.payload(in, &payload); err != nil {
		return errorReply(in.ID, acs.InvalidParams, "payload_invalid", err.Error())
	}
	answer, _ := jsonv2.Marshal(acs.SystemPingResponse{Status: acs.PingStatusOK, Echo: payload.Echo, ServerTimestamp: g.cfg.Now().UTC().Format(time.RFC3339Nano)})
	result := &acs.Result{Type: acs.ResultTypeFinal, ACSVersion: in.ACSVersion, RequestID: in.RequestID, Decision: acs.Decision{Disposition: acs.Allow}, Payload: answer}
	r := reply{id: in.ID, result: result, signatureOptional: true}
	if input, sig, err := envelope.RequestSigningInput(body); err == nil && sig != nil && in.SessionID != "" &&
		g.cfg.Signer.Verify(ctx, in.SessionID, input, *sig) == nil {
		r.sessionID, r.keyID = in.SessionID, sig.KeyID
	}
	return r
}

// payload validates params.payload of in against its method's schema and
// decodes it into v.
func (g *Guardian) payload(in *envelope.Inbound, v any) error {
	params, _ := in.Tree.(map[string]any)["params"].(map[string]any)
	if err := g.schemas.ValidatePayload(in.Method, params["payload"]); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	var p struct {
		Payload jsontext.Value `json:"payload"`
	}
	if err := jsonv2.Unmarshal(in.Params, &p); err != nil {
		return err
	}
	return jsonv2.Unmarshal(p.Payload, v)
}
