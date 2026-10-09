//go:build agteval

package main

import (
	"context"
	"os"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/agteval"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// agtSelection proves the shipped configuration decides in AGT's runtime
// library: the native call counter rises with each decision, and the
// library reports the AGT commit agt-native.lock pins.
func agtSelection(t *testing.T, c config) {
	evaluator, err := newEvaluator(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := evaluator.(*agteval.Evaluator)
	if !ok {
		t.Fatalf("policy.evaluator agt built %T", evaluator)
	}
	engine, err := agtbridge.New(os.DirFS(c.policyDir), c.mapping, evaluator, agtbridge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for command, want := range map[string]acs.Disposition{"ls": acs.Allow, "rm -rf /": acs.Deny} {
		before := native.Calls()
		payload, err := jsonv2.Marshal(map[string]any{
			"tool":        map[string]any{"name": "Bash"},
			"arguments":   map[string]any{"command": map[string]any{"value": command}},
			"raw_command": command,
		})
		if err != nil {
			t.Fatal(err)
		}
		d, err := engine.Decide(context.Background(), guardian.PolicyInput{Request: acs.Request{
			Method: acs.StepToolCallRequest,
			Params: acs.Params{RequestID: "6a22a0f7-5547-448a-add7-3327aed144df", Payload: payload},
		}})
		if err != nil || d.Disposition != want {
			t.Fatalf("%s: decision %+v, error %v; want %s", command, d.Decision, err, want)
		}
		if native.Calls() != before+1 {
			t.Fatalf("%s was decided without a call into AGT's runtime library", command)
		}
	}
	lock, err := os.ReadFile("../../agt-native.lock")
	if err != nil {
		t.Fatal(err)
	}
	var pin struct {
		AGTRef string `json:"agt_ref"`
	}
	if err := jsonv2.Unmarshal(lock, &pin); err != nil {
		t.Fatal(err)
	}
	if evaluator.AGTVersion() != pin.AGTRef {
		t.Fatalf("the loaded library reports AGT %s, and agt-native.lock pins %s", evaluator.AGTVersion(), pin.AGTRef)
	}
}
