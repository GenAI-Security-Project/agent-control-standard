//go:build !agteval

package main_test

// The command under test is built without the AGT evaluator, so it runs
// the Go evaluator in place of the one guardian.yaml selects.
var (
	buildFlags   []string
	evaluatorEnv = []string{"ACS__POLICY__EVALUATOR=go"}
)
