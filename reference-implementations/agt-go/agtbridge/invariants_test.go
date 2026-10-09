package agtbridge_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// agtVocabulary is what only the AGT engine may know: AGT's verdicts,
// intervention points and manifest terms.
var agtVocabulary = regexp.MustCompile(`\b(escalate|intervention_point|pre_tool_call|post_tool_call|agent_control_specification|result_labels|policy_target_argument)\b`)

const module = "github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go"

// dependencyRules say which packages may depend on what, in the build
// without the agteval tag and in the build with it. OPA belongs to the Go
// evaluator alone: the projection and the AGT evaluator, which calls AGT's
// own runtime library, never link it. The AGT evaluator reaches only the
// command, so a program importing guardian or agtbridge links no native
// library unless it imports agtbridge/agteval itself.
var dependencyRules = []struct {
	dependency string
	allowed    []string
}{
	{"github.com/open-policy-agent/", []string{module + "/agtbridge/goeval", module + "/cmd/guardian"}},
	{module + "/agtbridge", []string{module + "/agtbridge/goeval", module + "/agtbridge/agteval", module + "/cmd/guardian"}},
	{module + "/agtbridge/agteval", []string{module + "/cmd/guardian"}},
}

// TestAGTConfinedToAgtbridge keeps AGT out of the protocol packages and each
// evaluator's dependencies in its own package, with and without the agteval
// build tag; and no protocol source names AGT's vocabulary. The corpus of
// recorded cases describe AGT's behaviour and are not protocol code.
func TestAGTConfinedToAgtbridge(t *testing.T) {
	for _, tags := range []string{"", "agteval"} {
		cmd := exec.Command("go", "list", "-C", "..", "-tags", tags, "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./...")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -tags %q: %v", tags, err)
		}
		listed := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			pkg, deps, _ := strings.Cut(line, " ")
			listed[pkg] = true
			for _, dep := range strings.Fields(deps) {
				for _, rule := range dependencyRules {
					if dependsOn(dep, rule.dependency) && !slices.Contains(rule.allowed, pkg) {
						t.Errorf("-tags %q: %s imports %s", tags, pkg, dep)
					}
				}
			}
		}
		if listed[module+"/agtbridge/agteval"] != (tags == "agteval") {
			t.Errorf("-tags %q: agtbridge/agteval listed=%v; it must compile only with the tag", tags, listed[module+"/agtbridge/agteval"])
		}
	}
	for _, dir := range []string{"../acs", "../guardian", "../internal"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasPrefix(path, "../internal/tscases") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if m := agtVocabulary.Find(b); m != nil {
				t.Errorf("%s names AGT's %q", path, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// dependsOn matches a package path, or every package under a path that ends
// in a slash.
func dependsOn(dep, rule string) bool {
	if strings.HasSuffix(rule, "/") {
		return strings.HasPrefix(dep, rule)
	}
	return dep == rule
}
