// Package observedagent is a minimal Observed Agent shared by tests and
// bundled host commands. It signs requests, sends them, checks each answer's
// signature, and applies a decision to the payload it governs (§6.3, §6.4,
// §6.5).
package observedagent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/envelope"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/jcs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/schema"
)

// Transport carries one request body and returns the response body.
type Transport func(ctx context.Context, body []byte) ([]byte, error)

// KeyedSigner signs and verifies as the Observed Agent's key holder.
type KeyedSigner interface {
	Verify(ctx context.Context, sessionID string, input []byte, sig acs.Signature) error
	Sign(ctx context.Context, sessionID, keyID string, input []byte) (acs.Signature, error)
}

// Client is one Observed Agent session.
type Client struct {
	Transport Transport
	Signer    KeyedSigner
	// KeyID is the key the client signs with; empty lets the Signer choose.
	KeyID     string
	AgentID   string
	SessionID string
	// Now is the clock the request timestamps come from; nil is time.Now.
	Now func() time.Time
}

// Outcome is one answer as received.
type Outcome struct {
	Raw      []byte
	Response acs.Response
	// Result is set for a decision, Hello for a handshake, Error for a
	// refusal.
	Result *acs.Result
	Hello  *acs.ServerHello
	Error  *acs.Error
	// Verified reports whether the answer's signature verified.
	Verified bool
}

// Request describes one request to send; zero fields take fresh values.
type Request struct {
	Method    string
	Payload   any
	RequestID string
	Timestamp time.Time
	Nonce     string
	// ChainHash, when set, is sent as metadata.session_state.chain_hash.
	ChainHash string
	// TurnID, when set, is sent as metadata.turn_id.
	TurnID string
	// Unsigned sends the request without a signature.
	Unsigned bool
}

var (
	responseSchemas     *schema.Registry
	responseSchemasErr  error
	responseSchemasOnce sync.Once
)

// NewUUID returns a random version 4 UUID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Envelope builds and signs the request body r describes.
func (c *Client) Envelope(ctx context.Context, r Request) ([]byte, error) {
	if r.RequestID == "" {
		r.RequestID = NewUUID()
	}
	if r.Timestamp.IsZero() {
		r.Timestamp = c.now()
	}
	payload, err := jsonv2.Marshal(r.Payload)
	if err != nil {
		return nil, err
	}
	params := acs.Params{
		ACSVersion: acs.Version,
		RequestID:  r.RequestID,
		Timestamp:  r.Timestamp.UTC().Format(time.RFC3339Nano),
		Metadata:   acs.Metadata{AgentID: c.AgentID, SessionID: c.SessionID},
		Payload:    payload,
	}
	if r.Nonce != "" {
		params.Nonce = &r.Nonce
	}
	if r.TurnID != "" {
		params.Metadata.TurnID = &r.TurnID
	}
	if r.ChainHash != "" {
		params.Metadata.SessionState = &acs.SessionState{ChainHash: &r.ChainHash}
	}
	id, _ := jsonv2.Marshal(r.RequestID)
	req := acs.Request{JSONRPC: acs.JSONRPCVersion, Method: r.Method, ID: id, Params: params}
	body, err := jsonv2.Marshal(req)
	if err != nil || r.Unsigned {
		return body, err
	}
	input, err := jcs.Canonicalize(body)
	if err != nil {
		return nil, err
	}
	sig, err := c.Signer.Sign(ctx, c.SessionID, c.KeyID, input)
	if err != nil {
		return nil, err
	}
	req.Params.Signature = &sig
	return jsonv2.Marshal(req)
}

// Send builds, signs and sends r, and reads the answer.
func (c *Client) Send(ctx context.Context, r Request) (Outcome, error) {
	if r.RequestID == "" {
		r.RequestID = NewUUID()
	}
	body, err := c.Envelope(ctx, r)
	if err != nil {
		return Outcome{}, err
	}
	raw, err := c.Transport(ctx, body)
	if err != nil {
		return Outcome{}, err
	}
	o, err := c.read(ctx, raw, r.Method)
	if err != nil {
		return o, err
	}
	if string(o.Response.ID) == "null" {
		if o.Error == nil {
			return Outcome{}, fmt.Errorf("successful response has null id for request_id %q", r.RequestID)
		}
	} else {
		var responseID string
		if err := json.Unmarshal(o.Response.ID, &responseID); err != nil || responseID != r.RequestID {
			return Outcome{}, fmt.Errorf("response id does not match request_id %q", r.RequestID)
		}
	}
	if o.Result != nil && o.Result.RequestID != r.RequestID {
		return Outcome{}, fmt.Errorf("result request_id does not match request_id %q", r.RequestID)
	}
	return o, nil
}

// SendBody sends a body as it is and reads the answer.
func (c *Client) SendBody(ctx context.Context, body []byte) (Outcome, error) {
	raw, err := c.Transport(ctx, body)
	if err != nil {
		return Outcome{}, err
	}
	return c.Read(ctx, raw)
}

// Read parses an answer and verifies its signature. Callers that know the
// request method should use Send, which also checks the response's shape for
// that method.
func (c *Client) Read(ctx context.Context, raw []byte) (Outcome, error) {
	return c.read(ctx, raw, "")
}

func (c *Client) read(ctx context.Context, raw []byte, requestMethod string) (Outcome, error) {
	o := Outcome{Raw: raw}
	if err := jsonv2.Unmarshal(raw, &o.Response); err != nil {
		return o, fmt.Errorf("answer is not a response envelope: %w", err)
	}
	if err := validateResponse(raw); err != nil {
		if denial, ok := c.invalidModifyDenial(ctx, raw, o.Response); ok {
			return denial, nil
		}
		return o, fmt.Errorf("answer fails response-envelope.json: %w", err)
	}
	o.Error = o.Response.Error
	if o.Error != nil {
		if o.Error.Signature != nil {
			input, _, err := envelope.ResponseSigningInput(raw)
			if err != nil {
				return o, err
			}
			o.Verified = c.Signer.Verify(ctx, c.SessionID, input, *o.Error.Signature) == nil
		}
		return o, nil
	}
	if o.Response.Result == nil {
		return o, nil
	}
	var sig *acs.Signature
	isHandshake := requestMethod == acs.MethodHandshakeHello
	if requestMethod == "" {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(o.Response.Result, &members); err != nil {
			return o, err
		}
		_, hasType := members["type"]
		_, hasNegotiatedVersion := members["negotiated_version"]
		isHandshake = !hasType && hasNegotiatedVersion
	}
	if isHandshake {
		o.Hello = &acs.ServerHello{}
		if err := jsonv2.Unmarshal(o.Response.Result, o.Hello); err != nil {
			return o, err
		}
		if err := validateServerHello(o.Response.Result); err != nil {
			return o, fmt.Errorf("handshake result fails handshake.json: %w", err)
		}
		sig = o.Hello.Signature
	} else {
		o.Result = &acs.Result{}
		if err := jsonv2.Unmarshal(o.Response.Result, o.Result); err != nil {
			return o, err
		}
		if o.Result.Type != acs.ResultTypeFinal {
			return o, fmt.Errorf("result type is %q, want %q", o.Result.Type, acs.ResultTypeFinal)
		}
		sig = o.Result.Signature
	}
	if sig != nil {
		input, _, err := envelope.ResponseSigningInput(raw)
		if err != nil {
			return o, err
		}
		o.Verified = c.Signer.Verify(ctx, c.SessionID, input, *sig) == nil
	}
	return o, nil
}

// invalidModifyDenial implements §6.3's receiver rule for the one invalid
// response shape that has a mandatory outcome: a signed MODIFY combining a
// wholesale replacement with structured edits is DENY, not a failure posture.
func (c *Client) invalidModifyDenial(ctx context.Context, raw []byte, response acs.Response) (Outcome, bool) {
	var result struct {
		Type          string                     `json:"type"`
		ACSVersion    string                     `json:"acs_version"`
		RequestID     string                     `json:"request_id"`
		Decision      acs.Disposition            `json:"decision"`
		Reasoning     string                     `json:"reasoning"`
		Signature     *acs.Signature             `json:"signature"`
		Modifications map[string]json.RawMessage `json:"modifications"`
	}
	if json.Unmarshal(response.Result, &result) != nil ||
		result.Type != acs.ResultTypeFinal ||
		result.Decision != acs.Modify ||
		result.Signature == nil {
		return Outcome{}, false
	}
	_, hasReplacement := result.Modifications["modified_content"]
	_, hasRedactions := result.Modifications["redactions"]
	_, hasOverrides := result.Modifications["parameter_overrides"]
	if !hasReplacement || (!hasRedactions && !hasOverrides) {
		return Outcome{}, false
	}
	input, _, err := envelope.ResponseSigningInput(raw)
	if err != nil || c.Signer.Verify(ctx, c.SessionID, input, *result.Signature) != nil {
		return Outcome{}, false
	}
	reason := result.Reasoning
	if reason == "" {
		reason = "the Guardian returned an invalid modification"
	}
	return Outcome{
		Raw:      raw,
		Response: response,
		Result: &acs.Result{
			Type:       result.Type,
			ACSVersion: result.ACSVersion,
			RequestID:  result.RequestID,
			Decision: acs.Decision{
				Disposition: acs.Deny,
				Reasoning:   reason,
			},
		},
		Verified: true,
	}, true
}

func responseSchemaRegistry() (*schema.Registry, error) {
	responseSchemasOnce.Do(func() { responseSchemas, responseSchemasErr = schema.Load() })
	return responseSchemas, responseSchemasErr
}

func validateResponse(raw []byte) error {
	registry, err := responseSchemaRegistry()
	if err != nil {
		return err
	}
	return registry.ValidateJSON(schema.ResponseEnvelope, raw)
}

func validateServerHello(raw []byte) error {
	registry, err := responseSchemaRegistry()
	if err != nil {
		return err
	}
	return registry.ValidateJSON(schema.ServerHello, raw)
}

// Handshake negotiates the session.
func (c *Client) Handshake(ctx context.Context, hello acs.ClientHello) (Outcome, error) {
	return c.Send(ctx, Request{Method: acs.MethodHandshakeHello, Payload: hello})
}

// DefaultHello declares every native hook and the ACS-Core profile.
func DefaultHello(methods ...string) acs.ClientHello {
	return acs.ClientHello{
		ACSVersionsSupported: []string{acs.Version},
		MethodsImplemented:   methods,
		TransportsSupported:  []string{acs.TransportHTTP},
		ProvenanceProducer:   acs.ProvenanceNone,
		ProfilesSupported:    []string{acs.ProfileCore},
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ErrBlocked reports a step the decision does not let proceed.
var ErrBlocked = errors.New("the decision blocks the step")

// Honour returns the decision the Observed Agent applies to a step it sent
// (§6.4): the Guardian's, when a result arrived and its signature verified;
// otherwise, on a transport failure, a timeout, an error answer or a result
// that does not verify, the negotiated failure posture, proceed as ALLOW
// and deny as DENY. failedOpen reports a posture that proceeded, which the
// Observed Agent must record as an audit event.
func Honour(o Outcome, err error, posture acs.FailurePosture) (d acs.Decision, failedOpen bool) {
	if err == nil && o.Result != nil && o.Verified {
		return o.Result.Decision, false
	}
	if posture == acs.FailureDeny {
		return acs.Decision{Disposition: acs.Deny, Reasoning: "no verified decision arrived, and the negotiated posture is deny"}, false
	}
	return acs.Decision{Disposition: acs.Allow, Reasoning: "no verified decision arrived, and the negotiated posture is proceed"}, true
}

// Apply honours a decision for a payload (§6.4): ALLOW proceeds unchanged,
// MODIFY proceeds with the modification applied (§6.3), and DENY, ASK and
// DEFER block. A modification that breaks §6.3 or addresses nothing is
// treated as DENY (§6.3, §6.5).
func Apply(d acs.Decision, payload json.RawMessage) (json.RawMessage, error) {
	if err := disposition.Check(d); err != nil {
		return nil, err
	}
	switch d.Disposition {
	case acs.Allow:
		return payload, nil
	case acs.Modify:
		if d.Modifications == nil {
			return nil, fmt.Errorf("%w: modify without modifications", ErrBlocked)
		}
		return modify(*d.Modifications, payload)
	default:
		return nil, fmt.Errorf("%w: %s", ErrBlocked, d.Disposition)
	}
}

func modify(m acs.Modifications, payload json.RawMessage) (json.RawMessage, error) {
	if m.ModifiedContent != nil {
		if m.Redactions != nil || m.ParameterOverrides != nil {
			return nil, fmt.Errorf("%w: modified_content combined with structured edits", ErrBlocked)
		}
		return jsonv2.Marshal(*m.ModifiedContent)
	}
	var doc any
	if err := jsonv2.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	for _, r := range m.Redactions {
		replacement := "[REDACTED]"
		if r.Replacement != nil {
			replacement = *r.Replacement
		}
		if err := set(doc, r.Path, replacement); err != nil {
			return nil, fmt.Errorf("%w: redaction %s: %v", ErrBlocked, r.Path, err)
		}
	}
	for name, value := range m.ParameterOverrides {
		var v any
		if err := jsonv2.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		if err := set(doc, "/arguments/"+escape(name)+"/value", v); err != nil {
			return nil, fmt.Errorf("%w: override %s: %v", ErrBlocked, name, err)
		}
	}
	return jsonv2.Marshal(doc)
}

// set replaces the existing value a JSON pointer (RFC 6901) addresses.
func set(doc any, pointer string, value any) error {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return errors.New("not a pointer to a member")
	}
	tokens := strings.Split(pointer[1:], "/")
	node := doc
	for i, raw := range tokens {
		token := strings.NewReplacer("~1", "/", "~0", "~").Replace(raw)
		last := i == len(tokens)-1
		switch n := node.(type) {
		case map[string]any:
			if _, ok := n[token]; !ok {
				return fmt.Errorf("%q is absent", token)
			}
			if last {
				n[token] = value
				return nil
			}
			node = n[token]
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || idx >= len(n) {
				return fmt.Errorf("index %q is out of range", token)
			}
			if last {
				n[idx] = value
				return nil
			}
			node = n[idx]
		default:
			return fmt.Errorf("%q addresses inside a scalar", token)
		}
	}
	return nil
}

func escape(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }
