package agtbridge_test

import (
	"context"
	"fmt"
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

// recordedEvaluators are the evaluators this build has, by
// policy.evaluator name; a build with the agteval tag adds agt.
var recordedEvaluators = map[string]func(testing.TB) agtbridge.Evaluator{
	"go": func(t testing.TB) agtbridge.Evaluator { return goEvaluator(t) },
}

// TestRecordedCases replays the answers recorded from the TypeScript
// reference Guardian (scripts/record-ts-cases.sh) through the Go Guardian
// over each evaluator, over the whole request path, and requires the same
// disposition, reason codes, policy references, modifications and
// reasoning. The one declared exception: when the engine fails, both
// Guardians deny with evaluation_failed, and the reasoning is each
// Guardian's own sentence around the failure (docs/differences.md).
func TestRecordedCases(t *testing.T) {
	rec := readRecording(t)
	if len(rec.Cases) != len(tscases.Corpus()) {
		t.Fatalf("the recording holds %d cases and the corpus %d; run scripts/record-ts-cases.sh", len(rec.Cases), len(tscases.Corpus()))
	}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k", Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	for name, evaluator := range recordedEvaluators {
		t.Run(name, func(t *testing.T) {
			g, err := guardian.New(guardian.Config{Engine: engineOver(t, evaluator(t)), Signer: signer})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range rec.Cases {
				t.Run(c.Name, func(t *testing.T) {
					for i, got := range replay(t, g, signer, c) {
						if d := difference(*c.Steps[i].Result, got); d != "" {
							t.Errorf("step %d: %s, against TypeScript", i, d)
						}
					}
				})
			}
		})
	}
}

func readRecording(t testing.TB) tscases.Recording {
	t.Helper()
	b, err := os.ReadFile("testdata/ts-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec tscases.Recording
	if err := jsonv2.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// replay sends a recorded case's steps through the Guardian over the whole
// request path, in a new session, and returns each step's decision.
func replay(t *testing.T, g *guardian.Guardian, signer guardian.Signer, c tscases.Case) []acs.Decision {
	t.Helper()
	ctx := context.Background()
	client := &observedagent.Client{
		Transport: func(ctx context.Context, body []byte) ([]byte, error) { return g.Handle(ctx, body), nil },
		Signer:    signer, AgentID: "parity", SessionID: observedagent.NewUUID(),
	}
	if o, err := client.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v", err)
	}
	decisions := make([]acs.Decision, len(c.Steps))
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
		decisions[i] = o.Result.Decision
	}
	return decisions
}

// difference names the first field in which got differs from want, or is
// empty. When the engine failed, the reasoning is each Guardian's own
// sentence around the failure and is not compared.
func difference(want, got acs.Decision) string {
	failed := slices.Contains(want.ReasonCodes, disposition.ReasonEvaluationFailed)
	switch {
	case got.Disposition != want.Disposition:
		return fmt.Sprintf("disposition %s, want %s (%s)", got.Disposition, want.Disposition, want.Reasoning)
	case !slices.Equal(got.ReasonCodes, want.ReasonCodes):
		return fmt.Sprintf("reason codes %v, want %v", got.ReasonCodes, want.ReasonCodes)
	case !slices.Equal(got.PolicyReferences, want.PolicyReferences):
		return fmt.Sprintf("policy references %+v, want %+v", got.PolicyReferences, want.PolicyReferences)
	case !failed && got.Reasoning != want.Reasoning:
		return fmt.Sprintf("reasoning\n  %q\nwant\n  %q", got.Reasoning, want.Reasoning)
	case !equalJSON(got.Modifications, want.Modifications):
		return fmt.Sprintf("modifications %s, want %s", mustJSON(got.Modifications), mustJSON(want.Modifications))
	}
	return ""
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
	rec := readRecording(t)
	out, err := exec.Command("git", "-C", agtTree, "log", "-1", "--format=%H", "--",
		"packages/guardian/src", "packages/agt-bridge/src", "mapping.yaml", "policy").Output()
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if head := strings.TrimSpace(string(out)); head != rec.TSCommit {
		t.Fatalf("the recording is from %s, and the TypeScript tree's deciding code last changed in %s; run scripts/record-ts-cases.sh", rec.TSCommit, head)
	}
}
