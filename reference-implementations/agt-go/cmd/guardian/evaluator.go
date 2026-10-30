package main

import (
	"context"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
)

// The values of policy.evaluator.
const (
	evaluatorAGT = "agt"
)

func newEvaluator(ctx context.Context, c config) (agtbridge.Evaluator, error) {
	return newAGTEvaluator(c)
}
