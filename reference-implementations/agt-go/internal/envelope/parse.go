package envelope

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Errors Parse returns, each answered by its own JSON-RPC code.
var (
	// ErrNotJSON: the body is not one I-JSON text (Parse error).
	ErrNotJSON = errors.New("body is not a JSON text")
	// ErrBatch: the body is a JSON array, a batch this Guardian does not
	// support (§3, Invalid Request).
	ErrBatch = errors.New("batch requests are not supported")
	// ErrNotObject: the body is JSON but not an object (Invalid Request).
	ErrNotObject = errors.New("request is not a JSON object")
)

// nullID is the identifier of a response whose request's identifier could
// not be determined.
var nullID = jsontext.Value("null")

// Inbound is a request as far as it can be read before it is authenticated
// and validated. Every field is untrusted: it is read so the Guardian can
// address an answer and verify a signature, never to decide.
type Inbound struct {
	// Body is the request as received.
	Body []byte
	// Tree is the whole request decoded for schema validation.
	Tree any
	// ID is the JSON-RPC identifier as its JSON text when it is a string or
	// a number, and null otherwise.
	ID jsontext.Value
	// Params is params as its JSON text, nil when absent.
	Params jsontext.Value
	// The members below are empty when absent or not strings.
	Method     string
	ACSVersion string
	RequestID  string
	Timestamp  string
	Nonce      string
	SessionID  string
}

// NullID reports whether the identifier could not be determined.
func (in *Inbound) NullID() bool { return bytes.Equal(in.ID, nullID) }

// ValidateJSONRPCRequest verifies the JSON-RPC boundary before the Guardian
// interprets an ACS envelope or attempts signature verification. ACS uses
// -32600 for this boundary, while invalid ACS fields remain request-envelope
// validation failures.
func (in *Inbound) ValidateJSONRPCRequest() error {
	top := in.Tree.(map[string]any)
	version, ok := top["jsonrpc"].(string)
	if !ok || version != "2.0" {
		return errors.New(`jsonrpc must be "2.0"`)
	}
	method, ok := top["method"].(string)
	if !ok || method == "" {
		return errors.New("method must be a non-empty string")
	}
	if id, present := top["id"]; present {
		switch id.(type) {
		case nil, string, float64:
		default:
			return errors.New("id must be a string, number or null")
		}
	}
	if _, response := top["result"]; response {
		return errors.New("a request must not contain result")
	}
	if _, response := top["error"]; response {
		return errors.New("a request must not contain error")
	}
	if params, present := top["params"]; present {
		switch params.(type) {
		case map[string]any, []any:
		default:
			return errors.New("params must be an object or an array")
		}
	}
	return nil
}

// Parse reads body. The decoder refuses duplicate member names, invalid
// UTF-8 and unpaired surrogates, so every later reader sees the one meaning
// the signature covers.
func Parse(body []byte) (*Inbound, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if !jsontext.Value(body).IsValid() {
			return nil, ErrNotJSON
		}
		return nil, ErrBatch
	}
	in := &Inbound{Body: body, ID: nullID}
	if err := json.Unmarshal(body, &in.Tree); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	if _, ok := in.Tree.(map[string]any); !ok {
		return nil, ErrNotObject
	}
	var top struct {
		ID     jsontext.Value `json:"id"`
		Method any            `json:"method"`
		Params jsontext.Value `json:"params"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	if kind := top.ID.Kind(); kind == '"' || kind == '0' {
		in.ID = top.ID
	}
	in.Method, _ = top.Method.(string)
	in.Params = top.Params
	if top.Params.Kind() != '{' {
		return in, nil
	}
	var params struct {
		ACSVersion any `json:"acs_version"`
		RequestID  any `json:"request_id"`
		Timestamp  any `json:"timestamp"`
		Nonce      any `json:"nonce"`
		Metadata   any `json:"metadata"`
	}
	if err := json.Unmarshal(top.Params, &params); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	in.ACSVersion, _ = params.ACSVersion.(string)
	in.RequestID, _ = params.RequestID.(string)
	in.Timestamp, _ = params.Timestamp.(string)
	in.Nonce, _ = params.Nonce.(string)
	if metadata, ok := params.Metadata.(map[string]any); ok {
		in.SessionID, _ = metadata["session_id"].(string)
	}
	return in, nil
}
