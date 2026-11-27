// Package mcp reads wrapped MCP messages, protocols/MCP/* (extend_mcp.md).
// A wrapped call carries one MCP JSON-RPC 2.0 message intact in
// params.payload: a request or notification the Observed Agent is about to
// send, or the response it received, which it wraps under the method the
// response answers.
package mcp

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/jcs"
)

// Protocol is the name MCP carries in protocols/MCP/* and in
// wrapped_protocols.
const Protocol = "MCP"

// ToolsCall is the MCP method a tool call travels in.
const ToolsCall = "tools/call"

// methodName is the form every MCP method name takes: slash-separated
// segments of letters, digits and underscores (initialize,
// tools/call, notifications/resources/list_changed).
var methodName = regexp.MustCompile(`^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$`)

// Handler is the wrapped-protocol handler for MCP. It reads every MCP
// method, since it checks the JSON-RPC shape every MCP message shares and
// leaves the method's meaning to the policy engine; a list of methods would
// refuse the next MCP revision's.
type Handler struct{}

// Protocol implements method.WrappedHandler.
func (Handler) Protocol() string { return Protocol }

// Supports implements method.WrappedHandler.
func (Handler) Supports(method string) bool { return methodName.MatchString(method) }

// Message is the part of a wrapped MCP message the Guardian and the policy
// engine read. A request or notification has Method; a response has Result
// or Error.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      jsontext.Value  `json:"id,omitzero"`
	Method  string          `json:"method,omitzero"`
	Params  json.RawMessage `json:"params,omitzero"`
	Result  json.RawMessage `json:"result,omitzero"`
	Error   json.RawMessage `json:"error,omitzero"`
}

// IsResponse reports whether m is a response rather than a request or a
// notification.
func (m Message) IsResponse() bool { return m.Method == "" }

// Read decodes payload as the wrapped MCP message of method and checks it
// against JSON-RPC 2.0: version "2.0"; a request's method equal to the
// wrapped method and its params, when present, an object; a response's id
// present and exactly one of result, an object, and error, an object with
// an integer code and a string message.
func Read(method string, payload json.RawMessage) (Message, error) {
	var m Message
	if err := jsonv2.Unmarshal(payload, &m); err != nil {
		return m, fmt.Errorf("the wrapped MCP message cannot be read: %w", err)
	}
	if m.JSONRPC != "2.0" {
		return m, errors.New(`the wrapped MCP message must have jsonrpc "2.0"`)
	}
	if len(m.ID) > 0 && m.ID.Kind() != '"' && m.ID.Kind() != '0' {
		return m, errors.New("the wrapped MCP message's id must be a string or a number")
	}
	if !m.IsResponse() {
		if m.Method != method {
			return m, fmt.Errorf("the wrapped MCP message is %s, and the envelope wraps %s", m.Method, method)
		}
		if len(m.Result) > 0 || len(m.Error) > 0 {
			return m, errors.New("a wrapped MCP request carries neither result nor error")
		}
		if len(m.Params) > 0 && !isObject(m.Params) {
			return m, errors.New("the wrapped MCP message's params must be an object")
		}
		return m, nil
	}
	if len(m.ID) == 0 {
		return m, errors.New("a wrapped MCP response must carry the id of the request it answers")
	}
	switch {
	case len(m.Result) > 0 && len(m.Error) > 0, len(m.Result) == 0 && len(m.Error) == 0:
		return m, errors.New("a wrapped MCP response carries exactly one of result and error")
	case len(m.Result) > 0 && !isObject(m.Result):
		return m, errors.New("a wrapped MCP response's result must be an object")
	case len(m.Error) > 0:
		var e struct {
			Code    *int64  `json:"code"`
			Message *string `json:"message"`
		}
		if err := jsonv2.Unmarshal(m.Error, &e); err != nil || e.Code == nil || e.Message == nil {
			return m, errors.New("a wrapped MCP response's error must be an object with an integer code and a string message")
		}
	}
	return m, nil
}

// ToolCall is a wrapped tools/call as the Guardian tracks it from request to
// response. An MCP response names only the id of its request, so the
// Guardian keeps each request's tool by ID.
type ToolCall struct {
	// ID is the canonical JSON of the message's id, so equivalent spellings
	// of one id match. It is empty for a request without an id.
	ID string
	// Tool is a request's tool name, empty for a response.
	Tool string
	// Response is set for a response.
	Response bool
}

// ReadToolCall reads payload as a wrapped tools/call message.
func ReadToolCall(payload json.RawMessage) (ToolCall, error) {
	m, err := Read(ToolsCall, payload)
	if err != nil {
		return ToolCall{}, err
	}
	id, err := CorrelationID(m.ID)
	if err != nil {
		return ToolCall{}, err
	}
	if m.IsResponse() {
		return ToolCall{ID: id, Response: true}, nil
	}
	var params struct {
		Name string `json:"name"`
	}
	if len(m.Params) > 0 {
		if err := jsonv2.Unmarshal(m.Params, &params); err != nil {
			return ToolCall{}, fmt.Errorf("the wrapped tools/call's params cannot be read: %w", err)
		}
	}
	return ToolCall{ID: id, Tool: params.Name}, nil
}

// CorrelationID is the canonical JSON of an MCP id, empty for none.
func CorrelationID(id jsontext.Value) (string, error) {
	if len(id) == 0 {
		return "", nil
	}
	canonical, err := jcs.Canonicalize(id)
	if err != nil {
		return "", fmt.Errorf("canonicalize MCP id: %w", err)
	}
	return string(canonical), nil
}

// Check implements method.WrappedHandler.
func (Handler) Check(method string, payload json.RawMessage) error {
	if method == ToolsCall {
		_, err := ReadToolCall(payload)
		return err
	}
	_, err := Read(method, payload)
	return err
}

// ParameterOverridePointer implements method.WrappedHandler.
func (Handler) ParameterOverridePointer(argument string) string {
	escaped := strings.NewReplacer("~", "~0", "/", "~1").Replace(argument)
	return "/params/arguments/" + escaped
}

func isObject(b json.RawMessage) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{'
}
