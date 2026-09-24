package agtbridge

import (
	"fmt"
	"maps"
	"slices"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// policyTargetLeaf is the argument the snapshot copies a tool's policy
// target into, the leaf the checked-in manifest's pre_tool_call policy_target
// addresses. The TypeScript reference's assemble-snapshot.ts writes the same
// leaf.
const policyTargetLeaf = "acs_policy_target"

// The snapshots below have the shape packages/guardian/src/assemble-snapshot.ts
// builds, member for member, so the policy sees the same input.

func budgets() map[string]any {
	return map[string]any{"tool_call_count": 0.0, "token_count": 0.0, "elapsed_seconds": 0.0, "cost_usd": 0.0}
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
		return nil, fmt.Errorf("mapping.yaml declares no policy_target_argument for the request gate, so there is no argument to copy to the %q leaf the manifest targets", policyTargetLeaf)
	}
	args := map[string]any{}
	for name, a := range payload.Arguments {
		var v any
		if err := jsonv2.Unmarshal(a.Value, &v); err != nil {
			return nil, err
		}
		args[name] = v
	}
	if _, clash := args[policyTargetLeaf]; clash {
		return nil, fmt.Errorf("tool %q sent an argument named %q, which is the leaf this Guardian writes its policy target to", payload.Tool.Name, policyTargetLeaf)
	}
	value, ok := args[argument]
	if !ok {
		sent := slices.Sorted(maps.Keys(args))
		return nil, fmt.Errorf("mapping.yaml reads tool %q's policy target from argument %q, but this call sent no such argument (it sent: %v)", payload.Tool.Name, argument, sent)
	}
	args[policyTargetLeaf] = value
	raw := ""
	if payload.RawCommand != nil {
		raw = *payload.RawCommand
	}
	return map[string]any{
		"envelope":  map[string]any{"budgets": budgets()},
		"tool_call": map[string]any{"name": policyToolName, "args": args, "id": req.Params.RequestID, "raw_command": raw},
		"input":     ifcInput(labels),
	}, nil
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
		outputs[i] = map[string]any{"value": v}
	}
	return map[string]any{
		"envelope":    map[string]any{"budgets": budgets()},
		"tool_call":   map[string]any{"name": policyToolName},
		"tool_result": map[string]any{"outputs": outputs},
		"input":       ifcInput(labels),
	}, nil
}
