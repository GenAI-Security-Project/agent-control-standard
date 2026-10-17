package agtbridge_test

import (
	"context"
	"fmt"
	"os"
	"slices"
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
// reasoning. Two declared exceptions: when the engine fails, both
// Guardians deny with evaluation_failed, and the reasoning is each
// Guardian's own sentence around the failure (docs/differences.md); and
// the cases in aheadOfTypeScript.
func TestRecordedCases(t *testing.T) {
	rec := readRecording(t)
	if d := corpusDifference(rec.Cases, tscases.Corpus()); d != "" {
		t.Fatalf("the recording was made from another corpus (%s); run scripts/record-ts-cases.sh", d)
	}
	signer := testSigner(t)
	for name, evaluator := range recordedEvaluators {
		t.Run(name, func(t *testing.T) {
			g, err := guardian.New(guardian.Config{Engine: engineOver(t, evaluator(t)), Signer: signer})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range rec.Cases {
				t.Run(c.Name, func(t *testing.T) {
					for i, got := range replay(t, g, signer, c) {
						if reason, ahead := aheadOfTypeScript[c.Name]; ahead {
							requireAhead(t, reason, *c.Steps[i].Result, got)
							continue
						}
						if d := difference(*c.Steps[i].Result, got); d != "" {
							t.Errorf("step %d: %s, against TypeScript", i, d)
						}
					}
				})
			}
		})
	}
}

// aheadOfTypeScript names the recorded cases where the Go Guardian already
// follows a fix the TypeScript reference has in an open pull request, so the
// recording still holds the old answer. Each entry is deleted when a
// re-record carries the fix; requireAhead fails once it does.
var aheadOfTypeScript = map[string]string{
	"command_not_a_string":   "a non-string policy target is denied (#229, 96731db)",
	"fetch_url_not_a_string": "a non-string policy target is denied (#229, 96731db)",
}

func requireAhead(t *testing.T, reason string, recorded, got acs.Decision) {
	t.Helper()
	if recorded.Disposition != acs.Allow {
		t.Fatalf("the recording now answers %s: TypeScript carries the fix (%s); delete the aheadOfTypeScript entry", recorded.Disposition, reason)
	}
	if got.Disposition != acs.Deny || !slices.Equal(got.ReasonCodes, []string{disposition.ReasonEvaluationFailed}) {
		t.Fatalf("got %s %v, want DENY [evaluation_failed]: %s", got.Disposition, got.ReasonCodes, reason)
	}
}

// corpusDifference reports the first case or step whose name, method or
// payload the recording does not share with the corpus, so the answers are
// never replayed against inputs they were not given.
func corpusDifference(recorded, corpus []tscases.Case) string {
	if len(recorded) != len(corpus) {
		return fmt.Sprintf("%d cases recorded, %d in the corpus", len(recorded), len(corpus))
	}
	for i, c := range corpus {
		r := recorded[i]
		if r.Name != c.Name || len(r.Steps) != len(c.Steps) {
			return fmt.Sprintf("case %d is %s with %d steps, the corpus has %s with %d", i, r.Name, len(r.Steps), c.Name, len(c.Steps))
		}
		for j, s := range c.Steps {
			var got, want any
			if r.Steps[j].Method != s.Method || jsonv2.Unmarshal(r.Steps[j].Payload, &got) != nil || jsonv2.Unmarshal(s.Payload, &want) != nil || !equalJSON(got, want) {
				return fmt.Sprintf("%s step %d differs", c.Name, j)
			}
		}
	}
	return ""
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
	client := openSession(t, g, signer)
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

// openSession handshakes a new session with g and returns the client that
// signs its steps.
func openSession(t *testing.T, g *guardian.Guardian, signer guardian.Signer) *observedagent.Client {
	t.Helper()
	client := &observedagent.Client{
		Transport: func(ctx context.Context, body []byte) ([]byte, error) { return g.Handle(ctx, body), nil },
		Signer:    signer, AgentID: "parity", SessionID: observedagent.NewUUID(),
	}
	if o, err := client.Handshake(context.Background(), observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v", err)
	}
	return client
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
	trees, err := tscases.DecidingTrees(agtTree)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.TSTrees) != len(tscases.DecidingPaths) {
		t.Fatalf("the recording names %d paths and tscases.DecidingPaths %d; run scripts/record-ts-cases.sh", len(rec.TSTrees), len(tscases.DecidingPaths))
	}
	for _, p := range tscases.DecidingPaths {
		if trees[p] != rec.TSTrees[p] {
			t.Fatalf("%s is %s in the TypeScript tree and %s in the recording; run scripts/record-ts-cases.sh", p, trees[p], rec.TSTrees[p])
		}
	}
}
