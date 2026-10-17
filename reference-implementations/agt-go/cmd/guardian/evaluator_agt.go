//go:build agteval

package main

import (
	"path/filepath"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/agteval"
)

func newAGTEvaluator(c config) (agtbridge.Evaluator, error) {
	return agteval.New(agteval.Config{
		ManifestPath: filepath.Join(c.policyDir, filepath.FromSlash(c.manifest)),
		OPAPath:      c.opaPath,
		OPATimeout:   c.opaTimeout,
	})
}
