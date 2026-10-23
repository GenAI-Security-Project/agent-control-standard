package tscases

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestDecidingPathsTriggerTheGoWorkflow: a change to a deciding path makes the
// recording stale, so the Go workflow must run on it; otherwise a TypeScript
// pull request merges green and the next Go pull request fails on a
// recording it did not touch.
func TestDecidingPathsTriggerTheGoWorkflow(t *testing.T) {
	raw, err := os.ReadFile("../../../../.github/workflows/reference-implementation-go.yml")
	if err != nil {
		t.Fatal(err)
	}
	type trigger struct {
		Paths []string `yaml:"paths"`
	}
	var workflow struct {
		On struct {
			PullRequest trigger `yaml:"pull_request"`
			Push        trigger `yaml:"push"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	for event, on := range map[string]trigger{"pull_request": workflow.On.PullRequest, "push": workflow.On.Push} {
		filters := on.Paths
		if len(filters) == 0 {
			t.Fatalf("the Go workflow has no %s path filter", event)
		}
		for _, p := range DecidingPaths {
			if !covered("reference-implementations/agt/"+p, filters) {
				t.Errorf("%s: no path filter covers %s", event, p)
			}
		}
	}
}

// covered applies the filters as GitHub does: a filter starting with "!"
// excludes, and the last filter that matches decides. It reads exact paths
// and trailing "/**" only, the forms the Go workflow uses; another glob
// matches nothing here, so adding one fails this test until covered reads it.
func covered(path string, filters []string) bool {
	included := false
	for _, f := range filters {
		pattern, excluding := strings.CutPrefix(f, "!")
		dir, recursive := strings.CutSuffix(pattern, "/**")
		if pattern == path || recursive && (path == dir || strings.HasPrefix(path, dir+"/")) {
			included = !excluding
		}
	}
	return included
}
