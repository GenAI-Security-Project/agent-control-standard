package agtbridge

import (
	"fmt"
	"maps"
	"slices"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// PolicyTargetLeaf is the argument the snapshot copies a tool's policy
// target into, the leaf the checked-in manifest's pre_tool_call policy_target
// addresses. The TypeScript reference's assemble-snapshot.ts writes the same
// leaf.
const PolicyTargetLeaf = "acs_policy_target"

// The snapshots below hold every member packages/guardian/src/assemble-snapshot.ts
// builds, plus what it does not send: the rest of the tool payload and
// ambientMembers.

func budgets() map[string]any {
	return map[string]any{"tool_call_count": 0.0, "token_count": 0.0, "elapsed_seconds": 0.0, "cost_usd": 0.0}
}

// envelope is AGT's envelope member (AGT-SNAPSHOT-1.0.md §1), filled from the
// request's params and metadata.
func envelope(req acs.Request, point string) map[string]any {
	metadata := req.Params.Metadata
	agent := map[string]any{"id": metadata.AgentID}
	addPresent(agent, "name", metadata.AgentName)
	e := map[string]any{
		"agent":              agent,
		"session":            map[string]any{"id": metadata.SessionID},
		"intervention_point": point,
		"timestamp":          req.Params.Timestamp,
		"budgets":            budgets(),
	}
	if req.Params.TenantID != nil {
		e["tenant"] = map[string]any{"id": *req.Params.TenantID}
	}
	return e
}

func ifcInput(labels []string) map[string]any {
	source := make([]any, len(labels))
	for i, l := range labels {
		source[i] = l
	}
	return map[string]any{"ifc": map[string]any{"source_labels": source}}
}

// preToolCallSnapshot copies each argument's value into args, and the policy
// target argument's value into the fixed leaf as well.
func preToolCallSnapshot(req acs.Request, labels []string, argument, policyToolName string) (map[string]any, error) {
	var payload acs.ToolCallRequestPayload
	if err := jsonv2.Unmarshal(req.Params.Payload, &payload); err != nil {
		return nil, err
	}
	if argument == "" {
		return nil, fmt.Errorf("mapping.yaml declares no policy_target_argument for the request gate, so there is no argument to copy to the %q leaf the manifest targets", PolicyTargetLeaf)
	}
	args := map[string]any{}
	for name, a := range payload.Arguments {
		var v any
		if err := jsonv2.Unmarshal(a.Value, &v); err != nil {
			return nil, err
		}
		args[name] = v
	}
	if _, clash := args[PolicyTargetLeaf]; clash {
		return nil, fmt.Errorf("tool %q sent an argument named %q, which is the leaf this Guardian writes its policy target to", payload.Tool.Name, PolicyTargetLeaf)
	}
	value, ok := args[argument]
	if !ok {
		sent := slices.Sorted(maps.Keys(args))
		return nil, fmt.Errorf("mapping.yaml reads tool %q's policy target from argument %q, but this call sent no such argument (it sent: %v)", payload.Tool.Name, argument, sent)
	}
	// The stock rules guard their targets with is_string; a target of any
	// other JSON type would pass every one of them.
	if _, isString := value.(string); !isString {
		return nil, fmt.Errorf("tool %q sent argument %q as a JSON %s, but its policy target must be a string", payload.Tool.Name, argument, jsonKind(value))
	}
	args[PolicyTargetLeaf] = value
	raw := ""
	if payload.RawCommand != nil {
		raw = *payload.RawCommand
	}
	call := map[string]any{"name": policyToolName, "args": args, "id": req.Params.RequestID, "raw_command": raw}
	addTool(call, payload.Tool)
	addPresent(call, "operation", payload.Operation)
	addPresent(call, "capability", payload.Capability)
	addPresent(call, "intent", payload.Intent)
	// args holds each argument's value, which AGT's rules read directly, so
	// each argument's provenance goes beside it, under the argument's name.
	provenance := map[string]any{}
	for name, a := range payload.Arguments {
		if a.Provenance != nil {
			provenance[name] = a.Provenance
		}
	}
	if len(provenance) > 0 {
		call["provenance"] = provenance
	}
	return map[string]any{
		"envelope":  envelope(req, PointPreToolCall),
		"tool_call": call,
		"input":     ifcInput(labels),
	}, nil
}

// addTool adds the tool's version and provider, which the payload names
// beside its name, to a snapshot's tool_call.
func addTool(call map[string]any, tool acs.Tool) {
	addPresent(call, "version", tool.Version)
	addPresent(call, "provider", tool.Provider)
}

// addPresent sets a snapshot member only when the payload carries it.
func addPresent[T any](members map[string]any, name string, value *T) {
	if value != nil {
		members[name] = *value
	}
}

func postToolCallSnapshot(req acs.Request, labels []string, policyToolName string) (map[string]any, error) {
	var payload acs.ToolCallResultPayload
	if err := jsonv2.Unmarshal(req.Params.Payload, &payload); err != nil {
		return nil, err
	}
	outputs := make([]any, len(payload.Outputs))
	for i, o := range payload.Outputs {
		var v any
		if err := jsonv2.Unmarshal(o.Value, &v); err != nil {
			return nil, err
		}
		output := map[string]any{"value": v}
		addPresent(output, "provenance", o.Provenance)
		outputs[i] = output
	}
	call := map[string]any{"name": policyToolName}
	addTool(call, payload.Tool)
	result := map[string]any{"outputs": outputs, "exit_status": payload.ExitStatus}
	addPresent(result, "operation", payload.Operation)
	addPresent(result, "request_id_ref", payload.RequestIDRef)
	addPresent(result, "duration_ms", payload.DurationMS)
	return map[string]any{
		"envelope":    envelope(req, PointPostToolCall),
		"tool_call":   call,
		"tool_result": result,
		"input":       ifcInput(labels),
	}, nil
}

// ambientMembers are the request metadata envelope has no place for, and the
// session's Intent. actor and metadata are AGT's ambient member names
// (snapshot-contract.md); every member and what is not sent: docs/architecture.md, "What the policy receives".
func ambientMembers(in guardian.PolicyInput) map[string]any {
	request := in.Request.Params.Metadata
	members := map[string]any{}
	addPresent(members, "actor", request.UserContext)
	addPresent(members, "intent", in.Session.Intent)
	metadata := map[string]any{}
	addPresent(metadata, "turn_id", request.TurnID)
	addPresent(metadata, "parent_turn_id", request.ParentTurnID)
	addPresent(metadata, "session_state", request.SessionState)
	addPresent(metadata, "environment", request.Environment)
	addPresent(metadata, "platform", request.Platform)
	addPresent(metadata, "platform_version", request.PlatformVersion)
	if len(metadata) > 0 {
		members["metadata"] = metadata
	}
	return members
}

// jsonKind names the JSON type of a value that jsonv2 decoded into any.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}
