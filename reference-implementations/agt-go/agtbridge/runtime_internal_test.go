package agtbridge

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		in       string
		snapshot bool
		root     pathRoot
		segments int
		invalid  bool
	}{
		{"$", true, rootSnap, 0, false},
		{"$.tool_call.args.command", true, rootSnap, 3, false},
		{"$.tool_result.outputs[0].value", true, rootSnap, 4, false},
		{`$snap["a.b"][2]`, false, rootSnap, 2, false},
		{`$pi["x\"]y"]`, false, rootPI, 1, false},
		{"$policy_target", false, rootPolicyTarget, 0, false},
		{"$policy_target.a", false, rootPolicyTarget, 1, false},
		{"$tool.name", false, rootTool, 1, false},
		{"$.a[-1]", true, 0, 0, true},
		{"$.a[x]", true, 0, 0, true},
		{"$.a[0", true, 0, 0, true},
		{"$.a..b", true, 0, 0, true},
		{"$.a]b", true, 0, 0, true},
		{"tool_call.name", true, 0, 0, true},
		{"$policy", false, 0, 0, true},
		{`$snap["unterminated]`, false, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			parse := parsePath
			if tt.snapshot {
				parse = parseSnapshotPath
			}
			p, err := parse(tt.in)
			if (err != nil) != tt.invalid {
				t.Fatalf("error %v, want invalid=%v", err, tt.invalid)
			}
			if !tt.invalid && (p.root != tt.root || len(p.segments) != tt.segments) {
				t.Fatalf("root %d with %d segments", p.root, len(p.segments))
			}
		})
	}
}

func TestResolve(t *testing.T) {
	snap := map[string]any{"a": map[string]any{"b": []any{"x", map[string]any{"c": 1.0}}}, "s": "str"}
	pi := map[string]any{"policy_target": map[string]any{"value": map[string]any{"k": "v"}}, "tool": map[string]any{"name": "Bash"}}
	env := pathEnv{snap: snap, pi: pi}
	tests := []struct {
		path string
		want any
		err  error
	}{
		{"$snap.a.b[0]", "x", nil},
		{"$snap.a.b[1].c", 1.0, nil},
		{"$snap.a.missing", nil, errPathMissing},
		{"$snap.a.b[5]", nil, errPathMissing},
		{"$snap.a.b.c", nil, errPathTypeMismatch},
		{"$snap.a[0]", nil, errPathTypeMismatch},
		{"$snap.s.x", nil, errPathTypeMismatch},
		{"$policy_target.k", "v", nil},
		{"$tool.name", "Bash", nil},
		{"$pi.tool.name", "Bash", nil},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			p, err := parsePath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.resolve(env)
			if !errors.Is(err, tt.err) || (tt.err == nil && got != tt.want) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
	p, _ := parsePath("$pi.x")
	if _, err := p.resolve(pathEnv{snap: snap}); !errors.Is(err, errPathMissing) {
		t.Fatalf("a path from an absent root: %v", err)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name   string
		output any
		reason string // expected failure reason, empty for success
	}{
		{"allow", map[string]any{"decision": "allow"}, ""},
		{"deny_with_reason", map[string]any{"decision": "deny", "reason": "r", "message": "m"}, ""},
		{"not_an_object", "allow", reasonPolicyOutputInvalid},
		{"no_decision", map[string]any{}, reasonPolicyOutputInvalid},
		{"unknown_decision", map[string]any{"decision": "maybe"}, reasonPolicyOutputInvalid},
		{"reserved_reason", map[string]any{"decision": "deny", "reason": "runtime_error:x"}, reasonPolicyOutputInvalid},
		{"reason_not_a_string", map[string]any{"decision": "deny", "reason": 1.0}, reasonPolicyOutputInvalid},
		{"message_not_a_string", map[string]any{"decision": "deny", "message": true}, reasonPolicyOutputInvalid},
		{"effects", map[string]any{"decision": "allow", "effects": nil}, reasonPolicyOutputInvalid},
		{"labels", map[string]any{"decision": "allow", "result_labels": []any{"a"}}, ""},
		{"labels_not_strings", map[string]any{"decision": "allow", "result_labels": []any{1.0}}, reasonPolicyOutputInvalid},
		{"labels_not_an_array", map[string]any{"decision": "allow", "result_labels": "a"}, reasonPolicyOutputInvalid},
		{"transform", map[string]any{"decision": "transform", "transform": map[string]any{"path": "$policy_target", "value": "x"}}, ""},
		{"transform_missing", map[string]any{"decision": "transform"}, reasonPolicyOutputInvalid},
		{"transform_on_allow", map[string]any{"decision": "allow", "transform": map[string]any{}}, reasonPolicyOutputInvalid},
		{"transform_not_an_object", map[string]any{"decision": "transform", "transform": "x"}, reasonPolicyOutputInvalid},
		{"transform_no_path", map[string]any{"decision": "transform", "transform": map[string]any{"value": 1.0}}, reasonPolicyOutputInvalid},
		{"transform_bad_path", map[string]any{"decision": "transform", "transform": map[string]any{"path": "x", "value": 1.0}}, reasonPolicyOutputInvalid},
		{"transform_outside_target", map[string]any{"decision": "transform", "transform": map[string]any{"path": "$snap.x", "value": 1.0}}, reasonTransformTargetForbidden},
		{"transform_no_value", map[string]any{"decision": "transform", "transform": map[string]any{"path": "$policy_target"}}, reasonPolicyOutputInvalid},
		{"evidence", map[string]any{"decision": "allow", "evidence": map[string]any{"artefact": "a", "verification_pointers": map[string]any{"k": "v"}}}, ""},
		{"evidence_not_an_object", map[string]any{"decision": "allow", "evidence": "x"}, reasonPolicyOutputInvalid},
		{"evidence_artefact", map[string]any{"decision": "allow", "evidence": map[string]any{"artefact": 1.0}}, reasonPolicyOutputInvalid},
		{"evidence_pointer", map[string]any{"decision": "allow", "evidence": map[string]any{"verification_pointers": map[string]any{"k": 1.0}}}, reasonPolicyOutputInvalid},
		{"evidence_pointers", map[string]any{"decision": "allow", "evidence": map[string]any{"verification_pointers": "x"}}, reasonPolicyOutputInvalid},
		{"evidence_too_large", map[string]any{"decision": "allow", "evidence": map[string]any{"artefact": strings.Repeat("a", 5000)}}, reasonPolicyOutputInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, f := normalize(tt.output)
			switch {
			case tt.reason == "" && f != nil:
				t.Fatalf("failed: %v", f)
			case tt.reason != "" && (f == nil || f.reason != tt.reason):
				t.Fatalf("got %v, want %s", f, tt.reason)
			}
		})
	}
}

func TestNormalizeResultLabelsPresence(t *testing.T) {
	absent, f := normalize(map[string]any{"decision": "allow"})
	if f != nil || absent.ResultLabelsPresent {
		t.Fatalf("absent result_labels: verdict=%+v failure=%v", absent, f)
	}
	empty, f := normalize(map[string]any{"decision": "allow", "result_labels": []any{}})
	if f != nil || !empty.ResultLabelsPresent || len(empty.ResultLabels) != 0 {
		t.Fatalf("empty result_labels: verdict=%+v failure=%v", empty, f)
	}
}

func TestApplyTransform(t *testing.T) {
	p := &compiledPoint{}
	p.target, _ = parseSnapshotPath("$.a")
	snapshot := map[string]any{"a": map[string]any{"b": "x"}}
	target := snapshot["a"]
	if f := applyTransform(p, snapshot, target, transform{Path: "$policy_target.b", Value: "y"}); f != nil {
		t.Fatalf("a transform inside the target failed: %v", f)
	}
	if f := applyTransform(p, snapshot, target, transform{Path: "$policy_target.missing", Value: "y"}); f == nil || f.reason != reasonTransformInvalid {
		t.Fatalf("a transform of a missing field: %v", f)
	}
	if f := applyTransform(p, snapshot, target, transform{Path: "$snap.a", Value: "y"}); f == nil || f.reason != reasonTransformTargetForbidden {
		t.Fatalf("a transform outside the target: %v", f)
	}
	if f := applyTransform(p, snapshot, target, transform{Path: "$policy_target", Value: strings.Repeat("x", maxSnapshotBytes)}); f == nil || f.reason != reasonResourceLimitExceeded {
		t.Fatalf("a transform past the snapshot limit: %v", f)
	}
	if snapshot["a"].(map[string]any)["b"] != "x" {
		t.Fatal("applying a transform changed the snapshot")
	}
}

func TestAnnotatorOutputChecks(t *testing.T) {
	deep := any("leaf")
	for range maxDepth + 1 {
		deep = []any{deep}
	}
	for name, v := range map[string]any{
		"reserved_reason": map[string]any{"x": []any{map[string]any{"reason": "runtime_error:forged"}}},
		"too_deep":        deep,
		"too_large":       map[string]any{"x": strings.Repeat("a", maxAnnotatorOutputBytes)},
	} {
		if f := checkAnnotatorOutput("egress", v); f == nil || f.reason != reasonAnnotationFailed || !strings.HasPrefix(f.detail, "egress: ") {
			t.Errorf("%s: %v", name, f)
		}
	}
	if f := checkAnnotatorOutput("egress", map[string]any{"destination": "https://x.example.com"}); f != nil {
		t.Fatal(f)
	}
}

func TestFailureVerdict(t *testing.T) {
	v := fail(reasonAnnotationFailed, "egress: broke").verdict()
	if v.Decision != "deny" || *v.Reason != reasonAnnotationFailed || *v.Message != runtimeErrorMessage+" egress: broke" {
		t.Fatalf("%+v", v)
	}
	v = fail(reasonToolUnknown, "Write").verdict()
	if *v.Message != runtimeErrorMessage {
		t.Fatalf("%q", *v.Message)
	}
	if fail(reasonToolUnknown, "Write").Error() != "runtime_error:tool_unknown: Write" {
		t.Fatal("failure text")
	}
}

func TestWhatwgOrigin(t *testing.T) {
	tests := map[string]string{
		"https://docs.example.com/x":     "https://docs.example.com",
		"http://DOCS.example.com:80/":    "http://docs.example.com",
		"https://docs.example.com:443":   "https://docs.example.com",
		"https://docs.example.com:0443/": "https://docs.example.com",
		"https://docs.example.com:8443/": "https://docs.example.com:8443",
		"http://0x7f.1/":                 "http://127.0.0.1",
		"http://0177.0.0.1/":             "http://127.0.0.1",
		"http://2130706433/":             "http://127.0.0.1",
		"http://1.2.3/":                  "http://1.2.0.3",
		"https://docs.example.com./":     "https://docs.example.com.",
	}
	for in, want := range tests {
		if got, ok := whatwgOrigin(in); !ok || got != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"https://docs.example.com:70000/", "http://256.1.1.1.1/", "http://1.2.3.4.5/", "https://xn--zz.example.net/", "http://999.1.1.1/"} {
		if got, ok := whatwgOrigin(in); ok {
			t.Errorf("%s: parsed as %q, want a failure", in, got)
		}
	}
}
