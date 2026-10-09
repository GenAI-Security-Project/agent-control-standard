//go:build agteval

package agtbridge_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/agteval"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// knownDifference is a recorded step the two evaluators decide differently
// while they execute the given pair of AGT versions, with the reason.
// docs/differences.md describes each entry.
type knownDifference struct {
	GoVersion, AGTVersion string
	Case                  string
	Step                  int
	Reason                string
}

// knownDifferences is empty while both evaluators execute AGT 81955d4: any
// difference is a defect in one of them until it is explained here.
var knownDifferences []knownDifference

func init() {
	recordedEvaluators["agt"] = func(t testing.TB) agtbridge.Evaluator { return agtEvaluator(t) }
}

func agtEvaluator(t testing.TB) *agteval.Evaluator {
	t.Helper()
	e, err := agteval.New(agteval.Config{ManifestPath: agtTree + "/policy/manifest.yaml", OPAPath: "../.acs/agt/" + runtime.GOOS + "-" + runtime.GOARCH + "/bin", OPATimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestEvaluatorsAgree runs every recorded case through a Guardian over each
// evaluator and fails on a step they decide differently that
// knownDifferences does not list for their pair of AGT versions, and on a
// listed difference that no longer occurs.
func TestEvaluatorsAgree(t *testing.T) {
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k", Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	native := agtEvaluator(t)
	reproduced := goEvaluator(t)
	guardians := map[agtbridge.Evaluator]*guardian.Guardian{}
	for _, evaluator := range []agtbridge.Evaluator{native, reproduced} {
		g, err := guardian.New(guardian.Config{Engine: engineOver(t, evaluator), Signer: signer})
		if err != nil {
			t.Fatal(err)
		}
		guardians[evaluator] = g
	}
	listed := map[string]knownDifference{}
	for _, d := range knownDifferences {
		if d.GoVersion == reproduced.AGTVersion() && d.AGTVersion == native.AGTVersion() {
			listed[fmt.Sprintf("%s/%d", d.Case, d.Step)] = d
		}
	}
	seen := map[string]bool{}
	before := native.Calls()
	for _, c := range readRecording(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			agtDecisions := replay(t, guardians[native], signer, c)
			goDecisions := replay(t, guardians[reproduced], signer, c)
			for i := range c.Steps {
				key := fmt.Sprintf("%s/%d", c.Name, i)
				d := difference(agtDecisions[i], goDecisions[i])
				if d == "" {
					continue
				}
				seen[key] = true
				if _, ok := listed[key]; !ok {
					t.Errorf("step %d: the Go evaluator (AGT %s) differs from the AGT evaluator (AGT %s): %s", i, reproduced.AGTVersion(), native.AGTVersion(), d)
				}
			}
		})
	}
	for key := range listed {
		if !seen[key] {
			t.Errorf("knownDifferences lists %s, where the evaluators now agree", key)
		}
	}
	if native.Calls() == before {
		t.Fatal("no recorded case reached AGT's runtime library")
	}
}

// BenchmarkEvaluators reports each evaluator's median decision time over
// the recorded tool-call steps that decide without an engine failure,
// through the engine.
func BenchmarkEvaluators(b *testing.B) {
	reproduced := goEvaluator(b)
	screen := engineOver(b, reproduced)
	var inputs []guardian.PolicyInput
	for _, c := range readRecording(b).Cases {
		for _, step := range c.Steps {
			if step.Method != acs.StepToolCallRequest && step.Method != acs.StepToolCallResult {
				continue
			}
			in := guardian.PolicyInput{Request: acs.Request{
				Method: step.Method,
				Params: acs.Params{RequestID: "6a22a0f7-5547-448a-add7-3327aed144df", Payload: step.Payload},
			}}
			if _, err := screen.Decide(context.Background(), in); err == nil {
				inputs = append(inputs, in)
			}
		}
	}
	for name, evaluator := range map[string]agtbridge.Evaluator{"agt": agtEvaluator(b), "go": reproduced} {
		b.Run(name, func(b *testing.B) {
			engine := engineOver(b, evaluator)
			var durations []time.Duration
			i := 0
			for b.Loop() {
				start := time.Now()
				if _, err := engine.Decide(context.Background(), inputs[i%len(inputs)]); err != nil {
					b.Fatal(err)
				}
				durations = append(durations, time.Since(start))
				i++
			}
			slices.Sort(durations)
			b.ReportMetric(float64(durations[len(durations)/2].Microseconds()), "median-µs/decision")
		})
	}
}
