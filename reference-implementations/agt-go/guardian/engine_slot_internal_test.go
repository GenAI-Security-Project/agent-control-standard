package guardian

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

type slotEngine struct{ panics bool }

func (slotEngine) Policy() PolicyDescription { return PolicyDescription{} }

func (e slotEngine) Decide(context.Context, PolicyInput) (PolicyDecision, error) {
	if e.panics {
		panic("engine defect")
	}
	return PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
}

// TestEngineSlotIsFreeWhenTheOutcomeArrives: callEngine gives its engine
// slot back before it delivers the outcome, on the normal path and when the
// engine panics. A slot given back later is still taken when the answer
// lets the client send its next step, which is refused engine_saturated
// with no call running (docs/load.md measured 3 to 14 such refusals among
// 640 steps at 32 clients on 32 slots).
func TestEngineSlotIsFreeWhenTheOutcomeArrives(t *testing.T) {
	for name, engine := range map[string]slotEngine{"decides": {}, "panics": {panics: true}} {
		t.Run(name, func(t *testing.T) {
			g := &Guardian{cfg: Config{Engine: engine}, engineCalls: make(chan struct{}, 1)}
			for i := range 50000 {
				_, err := g.callEngine(context.Background(), time.Second, PolicyInput{})
				if errors.Is(err, errEngineSaturated) {
					t.Fatalf("call %d was refused with no call running", i)
				}
				if taken := len(g.engineCalls); taken != 0 {
					t.Fatalf("call %d delivered its outcome with %d slot still taken", i, taken)
				}
			}
		})
	}
}
