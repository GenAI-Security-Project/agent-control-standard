package agtbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/jcs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/mcp"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
)

// mcpToolsCall is the MCP method a tool call travels in.
const mcpToolsCall = "tools/call"

// The exit_status values (tool-call-result.json) a projected MCP result
// takes.
const (
	exitSuccess = "success"
	exitFailure = "failure"
)

// projection is a wrapped MCP tools/call seen as the native tool step it
// is, so AGT's tool gates govern a tool called through MCP exactly as one
// called directly: the request as steps/toolCallRequest, with the MCP
// tool's name and arguments, and the response as steps/toolCallResult, with
// text outputs first for AGT compatibility and every other returned value
// preserved after them.
type projection struct {
	req acs.Request
	// call is the MCP id of a request, and tool its tool's name. An MCP
	// response does not name its tool, so a request the decision lets
	// through is remembered in the session's state until its response.
	call, tool string
	// arguments are a request's argument names, which a parameter override
	// must name.
	arguments []string
	// outputs are, for a response, the JSON pointer into the MCP message of
	// each projected output, by output index, which a redaction is moved to.
	outputs []string
	wrapped bool
}

// errMCPCallPending is a wrapped tools/call whose MCP id names a call still
// awaiting its response: a response could no longer be told apart.
var errMCPCallPending = errors.New("a tools/call with this MCP id is still awaiting its response")

// project returns the projection of req, which is req itself for anything
// but a wrapped MCP tools/call. A response to no request the session let
// through is an error; its pending call is removed from state.
func project(req acs.Request, state *policyState) (projection, error) {
	protocol, _, m, ok := method.SplitWrapped(req.Method)
	if !ok || !strings.EqualFold(protocol, mcp.Protocol) || m != mcpToolsCall {
		return projection{req: req}, nil
	}
	msg, err := mcp.Read(m, req.Params.Payload)
	if err != nil {
		return projection{}, err
	}
	p := projection{wrapped: true}
	id, err := mcpCorrelationID(msg.ID)
	if err != nil {
		return projection{}, err
	}
	var payload any
	if msg.IsResponse() {
		tool, ok := state.MCPCalls[id]
		if !ok {
			return projection{}, fmt.Errorf("the MCP response answers id %s, and no tools/call with that id was let through in this session", id)
		}
		delete(state.MCPCalls, id)
		var result acs.ToolCallResultPayload
		result, p.outputs = toolResult(msg, tool)
		req.Method, payload = acs.StepToolCallResult, result
	} else {
		call, err := toolRequest(msg)
		if err != nil {
			return projection{}, err
		}
		if _, pending := state.MCPCalls[id]; pending && id != "" {
			return projection{}, fmt.Errorf("%w: %s", errMCPCallPending, id)
		}
		p.call, p.tool = id, call.Tool.Name
		for name := range call.Arguments {
			p.arguments = append(p.arguments, name)
		}
		req.Method, payload = acs.StepToolCallRequest, call
	}
	req.Params.Payload, err = jsonv2.Marshal(payload)
	p.req = req
	return p, err
}

func mcpCorrelationID(id []byte) (string, error) {
	if len(id) == 0 {
		return "", nil
	}
	canonical, err := jcs.Canonicalize(id)
	if err != nil {
		return "", fmt.Errorf("canonicalize MCP id: %w", err)
	}
	return string(canonical), nil
}

// settle remembers a request the decision lets through, so its response
// can be matched to its tool.
func (p projection) settle(state *policyState, d acs.Disposition) {
	if p.call == "" || (d != acs.Allow && d != acs.Modify) {
		return
	}
	if state.MCPCalls == nil {
		state.MCPCalls = map[string]string{}
	}
	state.MCPCalls[p.call] = p.tool
}

// readdress fits a modification to the MCP message the Observed Agent
// holds: a response's redaction of a projected output moves to that
// output's place, and a request's parameter overrides name members of
// params.arguments, which a wrapped tools/call's arguments are. Anything
// else cannot be applied to the message, and is refused.
func (p projection) readdress(mods *acs.Modifications) error {
	if mods == nil || !p.wrapped {
		return nil
	}
	if mods.ModifiedContent != nil {
		return errors.New("a wrapped MCP message cannot be replaced whole")
	}
	if p.outputs == nil {
		if len(mods.Redactions) > 0 {
			return errors.New("a wrapped MCP request can only be modified by parameter overrides")
		}
		for name := range mods.ParameterOverrides {
			if !slices.Contains(p.arguments, name) {
				return fmt.Errorf("the override of %q names no argument of the wrapped MCP call", name)
			}
		}
		return nil
	}
	if len(mods.ParameterOverrides) > 0 {
		return errors.New("a wrapped MCP response can only be redacted")
	}
	for i, r := range mods.Redactions {
		rest, ok := strings.CutPrefix(r.Path, "/outputs/")
		index, leaf, found := strings.Cut(rest, "/")
		n, err := strconv.Atoi(index)
		if !ok || !found || leaf != "value" || err != nil || n < 0 || n >= len(p.outputs) {
			return fmt.Errorf("the redaction of %s addresses nothing in the wrapped MCP response", r.Path)
		}
		mods.Redactions[i].Path = p.outputs[n]
	}
	return nil
}

func toolRequest(msg mcp.Message) (acs.ToolCallRequestPayload, error) {
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := jsonv2.Unmarshal(msg.Params, &params); err != nil {
		return acs.ToolCallRequestPayload{}, err
	}
	p := acs.ToolCallRequestPayload{Tool: acs.Tool{Name: params.Name}, Arguments: map[string]acs.ToolArgument{}}
	for name, value := range params.Arguments {
		p.Arguments[name] = acs.ToolArgument{Value: value}
	}
	return p, nil
}

// toolResult carries every MCP content item, structured result and error
// detail as an output, and returns each output's pointer into the message.
// Text stays a string so the stock AGT egress policies see the same shape as
// a native text result. Other content stays in its original JSON shape.
func toolResult(msg mcp.Message, tool string) (acs.ToolCallResultPayload, []string) {
	p := acs.ToolCallResultPayload{Tool: acs.Tool{Name: tool}, ExitStatus: exitSuccess, Outputs: []acs.ToolOutput{}}
	var result struct {
		Content           []json.RawMessage `json:"content"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		Metadata          json.RawMessage   `json:"_meta"`
		IsError           bool              `json:"isError"`
	}
	_ = jsonv2.Unmarshal(msg.Result, &result)
	if result.IsError || len(msg.Error) > 0 {
		p.ExitStatus = exitFailure
	}
	var paths []string
	type projectedContent struct {
		value json.RawMessage
		path  string
	}
	var textOutputs, otherOutputs []projectedContent
	for i, content := range result.Content {
		var textContent struct {
			Type string  `json:"type"`
			Text *string `json:"text"`
		}
		if jsonv2.Unmarshal(content, &textContent) == nil && textContent.Type == "text" && textContent.Text != nil {
			text, _ := jsonv2.Marshal(*textContent.Text)
			textOutputs = append(textOutputs, projectedContent{value: text, path: fmt.Sprintf("/result/content/%d/text", i)})
			continue
		}
		otherOutputs = append(otherOutputs, projectedContent{value: slices.Clone(content), path: fmt.Sprintf("/result/content/%d", i)})
	}
	for _, output := range append(textOutputs, otherOutputs...) {
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: output.value})
		paths = append(paths, output.path)
	}
	if len(result.StructuredContent) > 0 {
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: slices.Clone(result.StructuredContent)})
		paths = append(paths, "/result/structuredContent")
	}
	if len(result.Metadata) > 0 {
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: slices.Clone(result.Metadata)})
		paths = append(paths, "/result/_meta")
	}
	if len(msg.Error) > 0 {
		var e struct {
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		}
		_ = jsonv2.Unmarshal(msg.Error, &e)
		text, _ := jsonv2.Marshal(e.Message)
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: text})
		paths = append(paths, "/error/message")
		if len(e.Data) > 0 {
			p.Outputs = append(p.Outputs, acs.ToolOutput{Value: slices.Clone(e.Data)})
			paths = append(paths, "/error/data")
		}
	}
	return p, append([]string{}, paths...)
}
