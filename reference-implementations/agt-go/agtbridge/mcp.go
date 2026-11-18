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
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/mcp"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
)

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
	// arguments are a request's argument names, which a parameter override
	// must name.
	arguments []string
	// outputs are, for a response, the JSON pointer into the MCP message of
	// each projected output, by output index, which a redaction is moved to.
	outputs []string
	wrapped bool
}

// errMCPResultUnreadable is a wrapped MCP response whose result or error does
// not decode.
var errMCPResultUnreadable = errors.New("the wrapped MCP response cannot be read")

// project returns the projection of req, which is req itself for anything
// but a wrapped MCP tools/call. calls is the Guardian's record of the
// session's open calls (SessionContext.MCPCalls); a response to none of them
// is an error.
func project(req acs.Request, calls map[string]string) (projection, error) {
	protocol, _, m, ok := method.SplitWrapped(req.Method)
	if !ok || !strings.EqualFold(protocol, mcp.Protocol) || m != mcp.ToolsCall {
		return projection{req: req}, nil
	}
	msg, err := mcp.Read(m, req.Params.Payload)
	if err != nil {
		return projection{}, err
	}
	p := projection{wrapped: true}
	var payload any
	if msg.IsResponse() {
		id, err := mcp.CorrelationID(msg.ID)
		if err != nil {
			return projection{}, err
		}
		tool, ok := calls[id]
		if !ok {
			// The Guardian refuses such a response before the engine
			// (mcp_call_not_open); reaching here is a defect of the caller.
			return projection{}, fmt.Errorf("the MCP response answers id %s, and no tools/call with that id was let through in this session", id)
		}
		result, outputs, err := toolResult(msg, tool)
		if err != nil {
			return projection{}, err
		}
		p.outputs = outputs
		req.Method, payload = acs.StepToolCallResult, result
	} else {
		call, err := toolRequest(msg)
		if err != nil {
			return projection{}, err
		}
		for name := range call.Arguments {
			p.arguments = append(p.arguments, name)
		}
		req.Method, payload = acs.StepToolCallRequest, call
	}
	req.Params.Payload, err = jsonv2.Marshal(payload)
	p.req = req
	return p, err
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

// toolResult carries every MCP content item, the input requests, the
// structured result, the metadata, and the error's message and data as
// outputs. It returns each output's pointer into the message. Text stays a
// string, so the stock AGT egress policies see the shape of a native text
// result. Other content keeps its JSON shape. The request state stays out:
// it is opaque to everyone but the MCP server. The projection fails on a
// result that does not decode and on a result that checkResult refuses.
func toolResult(msg mcp.Message, tool string) (acs.ToolCallResultPayload, []string, error) {
	p := acs.ToolCallResultPayload{Tool: acs.Tool{Name: tool}, ExitStatus: exitSuccess, Outputs: []acs.ToolOutput{}}
	var result struct {
		ResultType        json.RawMessage   `json:"resultType"`
		Content           []json.RawMessage `json:"content"`
		InputRequests     json.RawMessage   `json:"inputRequests"`
		RequestState      json.RawMessage   `json:"requestState"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		Metadata          json.RawMessage   `json:"_meta"`
		IsError           bool              `json:"isError"`
	}
	if len(msg.Result) > 0 {
		if err := jsonv2.Unmarshal(msg.Result, &result); err != nil {
			return acs.ToolCallResultPayload{}, nil, fmt.Errorf("%w: result: %w", errMCPResultUnreadable, err)
		}
		if err := checkResult(result.ResultType, result.Content != nil, result.InputRequests, result.RequestState); err != nil {
			return acs.ToolCallResultPayload{}, nil, fmt.Errorf("%w: result: %w", errMCPResultUnreadable, err)
		}
	}
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
	if len(result.InputRequests) > 0 {
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: slices.Clone(result.InputRequests)})
		paths = append(paths, "/result/inputRequests")
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
		if err := jsonv2.Unmarshal(msg.Error, &e); err != nil {
			return acs.ToolCallResultPayload{}, nil, fmt.Errorf("%w: error: %w", errMCPResultUnreadable, err)
		}
		text, _ := jsonv2.Marshal(e.Message)
		p.Outputs = append(p.Outputs, acs.ToolOutput{Value: text})
		paths = append(paths, "/error/message")
		if len(e.Data) > 0 {
			p.Outputs = append(p.Outputs, acs.ToolOutput{Value: slices.Clone(e.Data)})
			paths = append(paths, "/error/data")
		}
	}
	return p, append([]string{}, paths...), nil
}

// checkResult applies MCP 2026-07-28 to a result's type. An absent
// resultType means "complete", which needs a content list. Any other value
// than "complete" or "input_required" is invalid, an empty string or null
// included. An input_required result has an inputRequests object, a
// requestState string, or both.
func checkResult(resultType json.RawMessage, hasContent bool, inputRequests, requestState json.RawMessage) error {
	kind := "complete"
	if len(resultType) > 0 && (resultType[0] != '"' || jsonv2.Unmarshal(resultType, &kind) != nil) {
		return errors.New("the resultType is not a string")
	}
	switch kind {
	case "complete":
		if !hasContent {
			return errors.New("content is not a list")
		}
	case "input_required":
		if len(inputRequests) > 0 && inputRequests[0] != '{' {
			return errors.New("inputRequests is not an object")
		}
		if len(requestState) > 0 && requestState[0] != '"' {
			return errors.New("requestState is not a string")
		}
		if len(inputRequests) == 0 && len(requestState) == 0 {
			return errors.New("an input_required result has neither inputRequests nor requestState")
		}
	default:
		return errors.New("the resultType is not one this bridge reads")
	}
	return nil
}
