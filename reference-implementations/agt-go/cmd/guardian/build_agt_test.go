//go:build agteval

package main_test

// The command under test is built with the AGT evaluator, which
// guardian.yaml selects.
var (
	buildFlags   = []string{"-tags", "agteval"}
	evaluatorEnv []string
)
