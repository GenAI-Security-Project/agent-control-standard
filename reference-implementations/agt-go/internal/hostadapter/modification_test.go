package hostadapter

import (
	"encoding/json"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func TestModifiedToolCallInput(t *testing.T) {
	original, err := ToolCallRequest("Bash", json.RawMessage(`{"command":"ls"}`))
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	argument := changed.Arguments["command"]
	argument.Value = json.RawMessage(`"pwd"`)
	changed.Arguments = map[string]acs.ToolArgument{"command": argument}
	updated, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	input, err := ModifiedToolCallInput(updated, original)
	if err != nil || input["command"] != "pwd" {
		t.Fatalf("valid modification: %v %#v", err, input)
	}

	changed.Tool.Name = "Other"
	updated, _ = json.Marshal(changed)
	if _, err := ModifiedToolCallInput(updated, original); err == nil {
		t.Fatal("a tool identity change was accepted")
	}
}

func TestModifiedToolCallResult(t *testing.T) {
	original := ToolCallResult("Bash", "request", "success", json.RawMessage(`{"stdout":"old"}`))
	changed := original
	changed.Outputs = append([]acs.ToolOutput(nil), original.Outputs...)
	changed.Outputs[0].Value = json.RawMessage(`{"stdout":"new"}`)
	updated, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ModifiedToolCallResult(updated, original)
	if err != nil || result.(map[string]any)["stdout"] != "new" {
		t.Fatalf("valid modification: %v %#v", err, result)
	}

	changed.ExitStatus = "failure"
	updated, _ = json.Marshal(changed)
	if _, err := ModifiedToolCallResult(updated, original); err == nil {
		t.Fatal("an exit-status change was accepted")
	}
}
