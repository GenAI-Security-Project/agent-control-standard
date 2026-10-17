package goeval_test

import (
	"os"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/goeval"
)

// TestAGTVersionIsTheTypeScriptPin: the Go evaluator reproduces the AGT
// commit whose policy bundle the TypeScript reference vendors, so moving
// that pin fails here until the reproduction is checked against it.
func TestAGTVersionIsTheTypeScriptPin(t *testing.T) {
	raw, err := os.ReadFile("../../../agt/agt.lock")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		AGTRef string `json:"agt_ref"`
	}
	if err := jsonv2.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	if goeval.AGTVersion != lock.AGTRef {
		t.Fatalf("goeval reproduces AGT %s, and agt.lock pins %s", goeval.AGTVersion, lock.AGTRef)
	}
}
