package agtbridge

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestPathDialectsAgree checks the two places the reference's manifest and
// mapping.yaml name one leaf in two notations: the request gate's policy
// target is the leaf the snapshot writes, and the result gate's policy target
// and its redaction pointer address the same field. Every tool mapping.yaml
// names an argument for is one the manifest registers.
func TestPathDialectsAgree(t *testing.T) {
	src, err := os.ReadFile("../../agt/policy/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	points, err := m.compile()
	if err != nil {
		t.Fatal(err)
	}
	src, err = os.ReadFile("../../agt/mapping.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mp, err := parseMapping(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := points[pointPreToolCall].targetRaw; got != "$.tool_call.args."+policyTargetLeaf {
		t.Errorf("pre_tool_call targets %s, not the leaf the snapshot writes", got)
	}
	for name, row := range mp.InterventionPoints {
		if row.Modifications == nil || row.Modifications.Into != "redactions" {
			continue
		}
		p := points[name]
		if len(p.target.segments) < 2 || p.target.segments[0].field != "tool_result" {
			t.Fatalf("%s: target %s is not in the tool result", name, p.targetRaw)
		}
		var pointer strings.Builder
		for _, s := range p.target.segments[1:] {
			pointer.WriteByte('/')
			if s.isIdx {
				pointer.WriteString(strconv.Itoa(s.index))
			} else {
				pointer.WriteString(s.field)
			}
		}
		if pointer.String() != row.Modifications.IntoPath {
			t.Errorf("%s: the manifest targets %s and mapping.yaml redacts %s", name, pointer.String(), row.Modifications.IntoPath)
		}
	}
	for _, row := range mp.InterventionPoints {
		if row.PolicyTargetArgument == nil {
			continue
		}
		for tool := range row.PolicyTargetArgument.ByTool {
			if _, ok := m.Tools[tool]; !ok {
				t.Errorf("mapping.yaml names tool %s, which the manifest does not register", tool)
			}
		}
	}
}
