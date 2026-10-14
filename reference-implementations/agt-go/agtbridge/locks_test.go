package agtbridge_test

import (
	"os"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
)

// TestAGTLocksPinOneCommit: the agt evaluator links the AGT that
// agt-native.lock pins, and runs the policy bundle agt.lock pins, so an AGT
// bump that moves one lock fails here until it moves the other. The npm
// package version and the crate version are not compared: AGT can publish
// one without the other.
func TestAGTLocksPinOneCommit(t *testing.T) {
	type pin struct {
		Repo string `json:"agt_repo"`
		Ref  string `json:"agt_ref"`
	}
	var typescript, native pin
	readLock(t, agtTree+"/agt.lock", &typescript)
	readLock(t, "../agt-native.lock", &native)
	if typescript.Repo == "" || typescript.Ref == "" {
		t.Fatalf("agt.lock names no repo or ref: %+v", typescript)
	}
	if typescript != native {
		t.Fatalf("agt.lock pins %s@%s, and agt-native.lock pins %s@%s", typescript.Repo, typescript.Ref, native.Repo, native.Ref)
	}
}

func readLock(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsonv2.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
