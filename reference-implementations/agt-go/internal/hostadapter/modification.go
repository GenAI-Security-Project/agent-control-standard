package hostadapter

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func ModifiedToolCallInput(updated json.RawMessage, original acs.ToolCallRequestPayload) (map[string]any, error) {
	var changed acs.ToolCallRequestPayload
	if err := json.Unmarshal(updated, &changed); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(changed.Tool, original.Tool) ||
		!reflect.DeepEqual(changed.Operation, original.Operation) ||
		!reflect.DeepEqual(changed.Capability, original.Capability) ||
		!reflect.DeepEqual(changed.RawCommand, original.RawCommand) ||
		!reflect.DeepEqual(changed.Intent, original.Intent) ||
		len(changed.Arguments) != len(original.Arguments) {
		return nil, errors.New("modification changes a field the host cannot apply")
	}
	input := make(map[string]any, len(changed.Arguments))
	for name, before := range original.Arguments {
		after, ok := changed.Arguments[name]
		if !ok || !reflect.DeepEqual(after.Provenance, before.Provenance) {
			return nil, errors.New("modification changes a field the host cannot apply")
		}
		var value any
		if err := json.Unmarshal(after.Value, &value); err != nil {
			return nil, err
		}
		input[name] = value
	}
	return input, nil
}

func ModifiedToolCallResult(updated json.RawMessage, original acs.ToolCallResultPayload) (any, error) {
	var changed acs.ToolCallResultPayload
	if err := json.Unmarshal(updated, &changed); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(changed.Tool, original.Tool) ||
		!reflect.DeepEqual(changed.Operation, original.Operation) ||
		!reflect.DeepEqual(changed.RequestIDRef, original.RequestIDRef) ||
		changed.ExitStatus != original.ExitStatus ||
		!reflect.DeepEqual(changed.DurationMS, original.DurationMS) ||
		len(changed.Outputs) != 1 || len(original.Outputs) != 1 ||
		!reflect.DeepEqual(changed.Outputs[0].Provenance, original.Outputs[0].Provenance) {
		return nil, errors.New("modification changes a field the host cannot apply")
	}
	var result any
	if err := json.Unmarshal(changed.Outputs[0].Value, &result); err != nil {
		return nil, err
	}
	return result, nil
}
