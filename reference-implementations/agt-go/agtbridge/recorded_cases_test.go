package agtbridge_test

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/tscases"
)

// TestRecordedCases replays the answers recorded from the TypeScript
// reference Guardian (scripts/record-ts-cases.sh) through the Go Guardian
// with this engine, over the whole request path, and requires the same
// disposition, reason codes, policy references, modifications and
// reasoning. The one declared exception: when the engine fails, both
// Guardians deny with evaluation_failed, and the reasoning is each
// Guardian's own sentence around the failure (docs/differences.md).
func TestRecordedCases(t *testing.T) {
	b, err := os.ReadFile("testdata/ts-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec tscases.Recording
	if err := jsonv2.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Cases) != len(tscases.Corpus()) {
		t.Fatalf("the recording holds %d cases and the corpus %d; run scripts/record-ts-cases.sh", len(rec.Cases), len(tscases.Corpus()))
	}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k", Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := guardian.New(guardian.Config{Engine: newEngine(t, agtbridge.Options{}), Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, c := range rec.Cases {
		t.Run(c.Name, func(t *testing.T) {
			client := &observedagent.Client{
				Transport: func(ctx context.Context, body []byte) ([]byte, error) { return g.Handle(ctx, body), nil },
				Signer:    signer, AgentID: "parity", SessionID: observedagent.NewUUID(),
			}
			if o, err := client.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil {
				t.Fatalf("handshake: %v", err)
			}
			for i, step := range c.Steps {
				if step.Result == nil {
					t.Fatalf("step %d: the TypeScript Guardian answered an error, %+v, which this replay does not compare", i, step.Error)
				}
				o, err := client.Send(ctx, observedagent.Request{Method: step.Method, Payload: step.Payload})
				if err != nil {
					t.Fatal(err)
				}
				if o.Result == nil {
					t.Fatalf("step %d: no decision: %s", i, o.Raw)
				}
				compare(t, i, *step.Result, o.Result.Decision)
			}
		})
	}
}

func compare(t *testing.T, step int, want, got acs.Decision) {
	t.Helper()
	failed := slices.Contains(want.ReasonCodes, disposition.ReasonEvaluationFailed)
	switch {
	case got.Disposition != want.Disposition:
		t.Errorf("step %d: disposition %s, TypeScript %s (%s)", step, got.Disposition, want.Disposition, want.Reasoning)
	case !slices.Equal(got.ReasonCodes, want.ReasonCodes):
		t.Errorf("step %d: reason codes %v, TypeScript %v", step, got.ReasonCodes, want.ReasonCodes)
	case !slices.Equal(got.PolicyReferences, want.PolicyReferences):
		t.Errorf("step %d: policy references %+v, TypeScript %+v", step, got.PolicyReferences, want.PolicyReferences)
	case !failed && got.Reasoning != want.Reasoning:
		t.Errorf("step %d: reasoning\n  %q\nTypeScript\n  %q", step, got.Reasoning, want.Reasoning)
	case !equalJSON(got.Modifications, want.Modifications):
		t.Errorf("step %d: modifications %s, TypeScript %s", step, mustJSON(got.Modifications), mustJSON(want.Modifications))
	}
}

func mustJSON(v any) string {
	b, _ := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	return string(b)
}

func equalJSON(a, b any) bool { return mustJSON(a) == mustJSON(b) }

// TestRecordingIsCurrent fails when the TypeScript tree changed what decides
// a step after the recording was made, so the parity cases cannot silently
// compare against an older reference. Re-record with
// scripts/record-ts-cases.sh.
func TestRecordingIsCurrent(t *testing.T) {
	b, err := os.ReadFile("testdata/ts-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec tscases.Recording
	if err := jsonv2.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", agtTree, "log", "-1", "--format=%H", "--",
		"packages/guardian/src", "packages/agt-bridge/src", "mapping.yaml", "policy").Output()
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if head := strings.TrimSpace(string(out)); head != rec.TSCommit {
		t.Fatalf("the recording is from %s, and the TypeScript tree's deciding code last changed in %s; run scripts/record-ts-cases.sh", rec.TSCommit, head)
	}
}
