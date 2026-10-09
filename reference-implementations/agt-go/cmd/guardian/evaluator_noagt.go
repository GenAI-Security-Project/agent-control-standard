//go:build !agteval

package main

import (
	"errors"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
)

func newAGTEvaluator(config) (agtbridge.Evaluator, error) {
	return nil, errors.New("policy.evaluator is agt, but this guardian was built without the AGT evaluator: build it with make example-runtime, which builds AGT's runtime library and compiles with cgo and the agteval tag, or set policy.evaluator: go")
}
