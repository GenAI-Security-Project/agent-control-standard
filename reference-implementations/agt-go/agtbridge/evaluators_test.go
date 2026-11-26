//go:build agteval

package agtbridge_test

import (
	"context"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/agteval"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

func init() {
	recordedEvaluators["agt"] = func(t testing.TB) agtbridge.Evaluator { return agtEvaluator(t) }
}

func agtEvaluator(t testing.TB) *agteval.Evaluator {
	t.Helper()
	e, err := agteval.New(agtConfig(agtTree + "/policy/manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func agtConfig(manifestPath string) agteval.Config {
	return agteval.Config{ManifestPath: manifestPath, OPAPath: "../.acs/agt/" + runtime.GOOS + "-" + runtime.GOARCH + "/bin", OPATimeout: 5 * time.Second}
}

// BenchmarkEvaluators reports each evaluator's median decision time over
// the recorded tool-call steps that decide without an engine failure,
// through the engine.
func BenchmarkEvaluators(b *testing.B) {
	native := agtEvaluator(b)
	screen := engineOver(b, native)
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
	for name, evaluator := range map[string]agtbridge.Evaluator{"agt": native} {
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
