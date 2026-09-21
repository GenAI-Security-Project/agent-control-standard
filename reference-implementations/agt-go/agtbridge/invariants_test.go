package agtbridge_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// agtVocabulary is what only the AGT engine may know: AGT's verdicts,
// intervention points and manifest terms.
var agtVocabulary = regexp.MustCompile(`\b(escalate|intervention_point|pre_tool_call|post_tool_call|agent_control_specification|result_labels|policy_target_argument)\b`)

// TestAGTConfinedToAgtbridge keeps AGT out of the protocol packages: no
// package but agtbridge and the command that builds it imports OPA or
// agtbridge, and no protocol source names AGT's vocabulary. The corpus of
// recorded cases describe AGT's behaviour and are not protocol code.
func TestAGTConfinedToAgtbridge(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./...").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg, deps, _ := strings.Cut(line, " ")
		if strings.HasSuffix(pkg, "/agtbridge") || strings.HasSuffix(pkg, "/cmd/guardian") {
			continue
		}
		for _, dep := range strings.Fields(deps) {
			if strings.HasPrefix(dep, "github.com/open-policy-agent/") || strings.HasSuffix(dep, "/agtbridge") {
				t.Errorf("%s imports %s", pkg, dep)
			}
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
