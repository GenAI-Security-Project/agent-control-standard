package main

import (
	"context"
	"os"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/goeval"
)

// The values of policy.evaluator.
const (
	evaluatorAGT = "agt"
	evaluatorGo  = "go"
)

func newEvaluator(ctx context.Context, c config) (agtbridge.Evaluator, error) {
	if c.evaluator == evaluatorGo {
		return goeval.New(ctx, os.DirFS(c.policyDir), c.manifest)
	}
	return newAGTEvaluator(c)
}
