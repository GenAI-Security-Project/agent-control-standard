package hostadapter

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/schema"
)

const sessionNamespace = "11c79ebd-8469-4b4e-8de0-72674add484c"

type Config struct {
	GuardianURL string
	// HMACKeyID is the key_id the deployment gave the secret; it has no
	// default (§10).
	HMACKeyID      string
	HMACSecretFile string
	StateDir       string
	AuditLog       string
	AgentID        string
	Methods        []string
	Timeout        time.Duration
	MaxBodyBytes   int64
	// Stderr receives an audit record as one JSON line when AuditLog cannot
	// be written; nil means os.Stderr.
	Stderr io.Writer
}

type Step struct {
	SessionKey string
	TurnID     string
	CallID     string
	Method     string
	Payload    any
}

type Evaluation struct {
	Decision        acs.Decision
	ModifiedPayload json.RawMessage
}

type Client struct {
	config Config
	signer *guardian.HMACSigner
}

type sessionState struct {
	Hello acs.ServerHello `json:"hello"`
}

var methods = method.NewTable()

var (
	serverHelloSchemas     *schema.Registry
	serverHelloSchemasErr  error
	serverHelloSchemasOnce sync.Once
)

type handshakeRefusal struct{ message string }

func (e handshakeRefusal) Error() string { return e.message }

// errHandshake marks a handshake that failed other than by a refusal.
var errHandshake = errors.New("handshake failed")

func handshakeFailure(err error) error { return fmt.Errorf("%w: %w", errHandshake, err) }

// The failure classes a decision_failure record names (§6.5).
const (
	failureHandshake   = "handshake_failure"
	failureTimeout     = "timeout"
	failureUnreachable = "unreachable"
	failureMalformed   = "malformed_response"
	failureGuardian    = "guardian_error"
	failureSignature   = "signature_invalid"
	failureOther       = "other"
)

func New(config Config) (*Client, error) {
	if config.GuardianURL == "" || config.HMACKeyID == "" || config.HMACSecretFile == "" || config.StateDir == "" || config.AuditLog == "" || config.AgentID == "" {
		return nil, errors.New("guardian URL, HMAC key ID, HMAC secret file, state directory, audit log and agent ID must not be empty")
	}
	if len(config.Methods) == 0 {
		return nil, errors.New("at least one ACS method is required")
	}
	if config.Timeout <= 0 || config.MaxBodyBytes <= 0 {
		return nil, errors.New("timeout and maximum body size must be positive")
	}
	secret, err := guardian.ReadHMACSecretFile(config.HMACSecretFile)
	if err != nil {
		return nil, fmt.Errorf("HMAC secret file: %w", err)
	}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: config.HMACKeyID, Secret: secret})
	if err != nil {
		return nil, err
	}
	if config.Stderr == nil {
		config.Stderr = os.Stderr
	}
	return &Client{config: config, signer: signer}, nil
}

func (c *Client) Evaluate(ctx context.Context, step Step) (Evaluation, error) {
	if step.SessionKey == "" || step.TurnID == "" || step.CallID == "" || step.Method == "" || step.Payload == nil {
		return Evaluation{}, errors.New("session key, turn ID, call ID, method and payload are required")
	}
	if !contains(c.config.Methods, step.Method) {
		return Evaluation{}, fmt.Errorf("ACS method %q was not configured", step.Method)
	}
	sessionID := SessionUUID(c.config.AgentID, step.SessionKey)
	client := &observedagent.Client{
		Transport: httpTransport(c.config.GuardianURL, c.config.MaxBodyBytes),
		Signer:    c.signer,
		KeyID:     c.config.HMACKeyID,
		AgentID:   c.config.AgentID,
		SessionID: sessionID,
	}
	state, ok := loadState(c.config.StateDir, c.config.AgentID, step.SessionKey)
	if !ok {
		var err error
		state, err = c.handshake(ctx, client, c.config.Timeout)
		if err != nil {
			var refusal handshakeRefusal
			if errors.As(err, &refusal) {
				return Evaluation{Decision: c.substitute(step, "session_refused", acs.Decision{Reasoning: "the Guardian did not accept this ACS session"})}, nil
			}
			// The caller gets the handshake error. A record the audit log refused
			// has already gone to stderr (recordAuditEvent).
			_ = c.recordAuditEvent(step, "decision_failure", acs.Decision{Disposition: refusalAt(step.Method), Reasoning: err.Error()}, failureHandshake)
			return Evaluation{}, err
		}
		_ = saveState(c.config.StateDir, c.config.AgentID, step.SessionKey, state)
	}

	deadline := time.Now().Add(decisionTimeout(state.Hello, step.Method, c.config.Timeout))
	request := observedagent.Request{
		Method:    step.Method,
		Payload:   step.Payload,
		RequestID: RequestUUID(sessionID, step.Method, step.CallID),
		TurnID:    step.TurnID,
	}
	result, err := send(ctx, client, deadline, request)
	if err == nil && result.Error != nil && result.Verified && result.Error.Code == acs.CapabilityNotNegotiated {
		removeState(c.config.StateDir, c.config.AgentID, step.SessionKey)
		refreshed, handshakeErr := c.handshake(ctx, client, time.Until(deadline))
		if handshakeErr == nil {
			state = refreshed
			_ = saveState(c.config.StateDir, c.config.AgentID, step.SessionKey, state)
			result, err = send(ctx, client, deadline, request)
		} else {
			var refusal handshakeRefusal
			if errors.As(handshakeErr, &refusal) {
				return Evaluation{Decision: c.substitute(step, "session_refused", acs.Decision{Reasoning: "the Guardian did not accept this ACS session"})}, nil
			}
			err = handshakeErr
		}
	}
	posture := state.Hello.OnDecisionFailure
	if refusalAt(step.Method) != acs.Deny {
		posture = acs.FailureProceed
	}
	decision, verified := observedagent.Honour(result, err, posture)
	if !verified && decision.Disposition == acs.Deny && refusalAt(step.Method) != acs.Deny {
		decision = acs.Decision{Disposition: acs.Allow, Reasoning: "the Guardian refused the request, and this hook permits no DENY (§6.4)"}
	}
	if !verified {
		if auditErr := c.recordAuditEvent(step, "decision_failure", decision, failureClass(result, err)); auditErr != nil {
			return Evaluation{Decision: acs.Decision{Disposition: refusalAt(step.Method), Reasoning: "the Guardian decision failed and " + recordMissing(auditErr)}}, nil
		}
	}
	if result.InvalidModification {
		return Evaluation{Decision: c.substitute(step, "modify_invalid", decision)}, nil
	}
	evaluation := Evaluation{Decision: decision}
	if err != nil || result.Result == nil || !result.Verified || decision.Disposition != acs.Modify {
		return evaluation, nil
	}
	raw, err := json.Marshal(step.Payload)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.ModifiedPayload, err = observedagent.Apply(decision, raw)
	if err != nil {
		return Evaluation{Decision: c.RefuseModification(step, "the host cannot apply the Guardian modification")}, nil
	}
	return evaluation, nil
}

// RefuseModification answers a MODIFY the host cannot apply as §6.5 requires:
// DENY with modify_unsupported, or ALLOW at postCompact, where the original
// summary stands; either is recorded in the local audit log.
func (c *Client) RefuseModification(step Step, reasoning string) acs.Decision {
	decision := acs.Decision{Reasoning: reasoning, ReasonCodes: []string{disposition.ReasonModifyUnsupported}}
	return c.substitute(step, "modify_unsupported", decision)
}

// substitute records the refusal the host puts in place of a Guardian
// decision. The refusal stands when the record cannot be written; the
// reasoning says so.
func (c *Client) substitute(step Step, event string, decision acs.Decision) acs.Decision {
	decision.Disposition = refusalAt(step.Method)
	if err := c.recordAuditEvent(step, event, decision, ""); err != nil {
		decision.Reasoning += "; " + recordMissing(err)
	}
	return decision
}

// refusalAt is how the host refuses a step: DENY, or ALLOW at a hook that
// permits no DENY (hooks.md) because its action has already happened.
func refusalAt(stepMethod string) acs.Disposition {
	if methods.HookRule(stepMethod).Permits(acs.Deny) {
		return acs.Deny
	}
	return acs.Allow
}

func ToolCallRequest(toolName string, rawInput json.RawMessage) (acs.ToolCallRequestPayload, error) {
	var arguments map[string]json.RawMessage
	if err := json.Unmarshal(rawInput, &arguments); err != nil || arguments == nil {
		return acs.ToolCallRequestPayload{}, errors.New("tool input must be a JSON object")
	}
	payload := acs.ToolCallRequestPayload{Tool: acs.Tool{Name: toolName}, Arguments: make(map[string]acs.ToolArgument, len(arguments))}
	for name, value := range arguments {
		payload.Arguments[name] = acs.ToolArgument{Value: value}
	}
	if command, ok := arguments["command"]; ok {
		var value string
		if json.Unmarshal(command, &value) == nil {
			payload.RawCommand = &value
		}
	}
	return payload, nil
}

func ToolCallResult(toolName, requestIDRef, exitStatus string, output json.RawMessage) acs.ToolCallResultPayload {
	return acs.ToolCallResultPayload{
		Tool:         acs.Tool{Name: toolName},
		RequestIDRef: &requestIDRef,
		ExitStatus:   exitStatus,
		Outputs:      []acs.ToolOutput{{Value: output}},
	}
}

func SessionUUID(agentID, sessionKey string) string {
	return uuidV5(sessionNamespace, agentID+"\x00"+sessionKey)
}

func RequestUUID(sessionID, method, callID string) string {
	return uuidV5(sessionID, method+"\x00"+callID)
}

func (c *Client) handshake(ctx context.Context, client *observedagent.Client, timeout time.Duration) (sessionState, error) {
	if timeout <= 0 {
		return sessionState{}, handshakeFailure(errors.New("the negotiated decision timeout expired"))
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := client.Handshake(ctx, observedagent.DefaultHello(c.config.Methods...))
	if err != nil {
		return sessionState{}, handshakeFailure(err)
	}
	if result.Error != nil && result.Verified && handshakeErrorIsRefusal(result.Error.Code) {
		return sessionState{}, handshakeRefusal{message: "Guardian refused the handshake"}
	}
	if result.Error != nil {
		return sessionState{}, handshakeFailure(fmt.Errorf("the Guardian returned error %d", result.Error.Code))
	}
	if result.Hello == nil || !result.Verified {
		return sessionState{}, handshakeFailure(errors.New("the Guardian did not return a verified ServerHello"))
	}
	return sessionState{Hello: *result.Hello}, nil
}

func send(ctx context.Context, client *observedagent.Client, deadline time.Time, request observedagent.Request) (observedagent.Outcome, error) {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	return client.Send(ctx, request)
}

func httpTransport(url string, maxBytes int64) observedagent.Transport {
	return func(ctx context.Context, body []byte) ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("guardian answered HTTP %d", response.StatusCode)
		}
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(responseBody)) > maxBytes {
			return nil, fmt.Errorf("guardian response exceeds %d bytes", maxBytes)
		}
		return responseBody, nil
	}
}

// failureClass names why no verified decision arrived; err wins over the
// answer, and an answer that is neither a result nor an error is malformed.
func failureClass(result observedagent.Outcome, err error) string {
	var opErr *net.OpError
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errHandshake):
		return failureHandshake
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return failureTimeout
	case errors.Is(err, observedagent.ErrMalformedResponse):
		return failureMalformed
	case errors.As(err, &opErr), errors.As(err, &dnsErr):
		return failureUnreachable
	case err != nil:
		return failureOther
	case result.Error != nil && result.Verified:
		return failureGuardian
	case result.Error != nil || result.Result != nil:
		return failureSignature
	default:
		return failureMalformed
	}
}

type auditRecord struct {
	Event      string    `json:"event"`
	RecordedAt time.Time `json:"recorded_at"`
	SessionKey string    `json:"session_key"`
	TurnID     string    `json:"turn_id"`
	CallID     string    `json:"call_id"`
	Method     string    `json:"method"`
	// Disposition is what the host does with the step.
	Disposition acs.Disposition `json:"disposition"`
	Reason      string          `json:"reason"`
	ReasonCodes []string        `json:"reason_codes,omitempty"`
	// FailureClass is set on a decision_failure record: why no verified
	// decision arrived.
	FailureClass string `json:"failure_class,omitempty"`
	// AuditError is set only on the stderr copy of a record the audit log
	// refused.
	AuditError string `json:"audit_error,omitempty"`
}

// recordAuditEvent appends the record to the audit log. When the log refuses
// it, the host refuses the step as refusalAt does, and the record of that
// refusal goes to Config.Stderr instead; at a hook that permits no DENY the
// step still proceeds, and stderr is then its only record (§6.4). The
// error returned names every sink that failed.
func (c *Client) recordAuditEvent(step Step, event string, decision acs.Decision, failureClass string) error {
	record := auditRecord{
		Event: event, RecordedAt: time.Now().UTC(), SessionKey: step.SessionKey,
		TurnID: step.TurnID, CallID: step.CallID, Method: step.Method,
		Disposition: decision.Disposition, Reason: decision.Reasoning, ReasonCodes: decision.ReasonCodes,
		FailureClass: failureClass,
	}
	err := appendJSONLine(c.config.AuditLog, record)
	if err != nil {
		record.Disposition = refusalAt(step.Method)
		record.AuditError = err.Error()
		if stderrErr := json.NewEncoder(c.config.Stderr).Encode(record); stderrErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: %w", errStderrRefused, stderrErr))
		}
	}
	return err
}

var errStderrRefused = errors.New("stderr")

// recordMissing says where the record of a refusal went, for its reasoning.
// It names no path: a host may show the reasoning to the agent.
func recordMissing(err error) string {
	if errors.Is(err, errStderrRefused) {
		return "the local audit record could not be written, to the audit log or to stderr"
	}
	return "the audit log could not be written, and the record went to stderr"
}

func appendJSONLine(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(v); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func decisionTimeout(hello acs.ServerHello, method string, fallback time.Duration) time.Duration {
	if timeout := hello.TimeoutConfig.PerMethodMS[method]; timeout > 0 {
		return time.Duration(timeout) * time.Millisecond
	}
	if hello.TimeoutConfig.DefaultMS <= 0 {
		return fallback
	}
	return time.Duration(hello.TimeoutConfig.DefaultMS) * time.Millisecond
}

func handshakeErrorIsRefusal(code acs.ErrorCode) bool {
	return code == acs.SessionRefused || code == acs.UnsupportedVersion || code == acs.ProvenanceRequired
}

func uuidV5(namespace, value string) string {
	namespaceBytes, _ := hex.DecodeString(strings.ReplaceAll(namespace, "-", ""))
	hash := sha1.Sum(append(namespaceBytes, []byte(value)...))
	hash[6] = hash[6]&0x0f | 0x50
	hash[8] = hash[8]&0x3f | 0x80
	encoded := hex.EncodeToString(hash[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func statePath(dir, agentID, sessionKey string) string {
	digest := sha256.Sum256([]byte(agentID + "\x00" + sessionKey))
	return filepath.Join(dir, hex.EncodeToString(digest[:])+".json")
}

func loadState(dir, agentID, sessionKey string) (sessionState, bool) {
	data, err := os.ReadFile(statePath(dir, agentID, sessionKey))
	if err != nil {
		return sessionState{}, false
	}
	var state sessionState
	if err := jsonv2.Unmarshal(data, &state); err != nil {
		return sessionState{}, false
	}
	if state.Hello.OnDecisionFailure == "" {
		state.Hello.OnDecisionFailure = acs.FailureProceed
	}
	if validateServerHello(state.Hello) != nil {
		return sessionState{}, false
	}
	return state, true
}

func validateServerHello(hello acs.ServerHello) error {
	raw, err := jsonv2.Marshal(hello)
	if err != nil {
		return err
	}
	serverHelloSchemasOnce.Do(func() { serverHelloSchemas, serverHelloSchemasErr = schema.Load() })
	if serverHelloSchemasErr != nil {
		return serverHelloSchemasErr
	}
	return serverHelloSchemas.ValidateJSON(schema.ServerHello, raw)
}

func saveState(dir, agentID, sessionKey string, state sessionState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := jsonv2.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".session-")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(path, statePath(dir, agentID, sessionKey))
}

func removeState(dir, agentID, sessionKey string) {
	_ = os.Remove(statePath(dir, agentID, sessionKey))
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
