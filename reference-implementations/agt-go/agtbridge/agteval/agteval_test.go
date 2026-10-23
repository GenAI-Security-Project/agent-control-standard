//go:build agteval

package agteval_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge/agteval"
)

const manifest = "../../../agt/policy/manifest.yaml"

var opa = "../../.acs/agt/" + runtime.GOOS + "-" + runtime.GOARCH + "/bin"

func TestMain(m *testing.M) {
	if delay := os.Getenv("ACS_TEST_OPA_DELAY"); delay != "" {
		duration, err := time.ParseDuration(delay)
		if err != nil {
			os.Exit(2)
		}
		time.Sleep(duration)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func slowOPA(t *testing.T, delay string) string {
	t.Helper()
	t.Setenv("ACS_TEST_OPA_DELAY", delay)
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func shell(command string) map[string]any {
	return map[string]any{
		"envelope":  map[string]any{"budgets": map[string]any{"tool_call_count": 0.0, "token_count": 0.0, "elapsed_seconds": 0.0, "cost_usd": 0.0}},
		"tool_call": map[string]any{"name": "Bash", "args": map[string]any{"command": command, agtbridge.PolicyTargetLeaf: command}, "id": "6a22a0f7-5547-448a-add7-3327aed144df", "raw_command": command},
		"input":     map[string]any{"ifc": map[string]any{"source_labels": []any{"public"}}},
	}
}

func newEvaluator(t *testing.T, c agteval.Config) *agteval.Evaluator {
	t.Helper()
	e, err := agteval.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func reference(t *testing.T) *agteval.Evaluator {
	return newEvaluator(t, agteval.Config{ManifestPath: manifest, OPAPath: opa, OPATimeout: 5 * time.Second})
}

// TestOneHandleServesParallelCalls: concurrent evaluations share the one
// runtime handle, each answers its own snapshot, and none depends on an
// earlier call.
func TestOneHandleServesParallelCalls(t *testing.T) {
	e := reference(t)
	want := map[string]string{"ls": "allow", "rm -rf /": "deny", "curl https://evil.example.net/x": "deny"}
	var wg sync.WaitGroup
	for i := range 48 {
		wg.Go(func() {
			command := []string{"ls", "rm -rf /", "curl https://evil.example.net/x"}[i%3]
			v, err := e.Evaluate(context.Background(), agtbridge.PointPreToolCall, shell(command))
			if err != nil || v.Decision != want[command] {
				t.Errorf("%s: verdict %+v, error %v; want %s", command, v, err, want[command])
			}
		})
	}
	wg.Wait()
	if e.Calls() != 48 {
		t.Fatalf("%d calls into AGT's runtime library, want 48", e.Calls())
	}
}

// TestEgressAnnotatorRunsInTheCallback: the manifest's egress classifier
// reaches the policy only through this Guardian's annotator callback.
func TestEgressAnnotatorRunsInTheCallback(t *testing.T) {
	e := reference(t)
	for command, want := range map[string]string{
		"curl https://evil.example.net/x": "egress_destination_not_allowed",
		"curl https://docs.example.com/x": "",
	} {
		v, err := e.Evaluate(context.Background(), agtbridge.PointPreToolCall, shell(command))
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if v.Reason != nil {
			got = *v.Reason
		}
		if got != want {
			t.Errorf("%s: reason %q, want %q", command, got, want)
		}
	}
}

// TestFailuresAreVerdicts: a failure inside AGT's evaluation is a
// fail-closed deny, as AGT's C ABI defines it, not an error.
func TestFailuresAreVerdicts(t *testing.T) {
	e := reference(t)
	for name, tt := range map[string]struct {
		point    string
		snapshot map[string]any
		reason   string
	}{
		"unknown_point": {"no_such_point", shell("ls"), "runtime_error:intervention_point_unknown"},
		"missing_path":  {agtbridge.PointPreToolCall, map[string]any{}, "runtime_error:path_missing"},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := e.Evaluate(context.Background(), tt.point, tt.snapshot)
			if err != nil || v.Decision != "deny" || v.Reason == nil || *v.Reason != tt.reason {
				t.Fatalf("verdict %+v, error %v; want deny %s", v, err, tt.reason)
			}
		})
	}
}

// TestCancellation: a call whose context already ended never reaches AGT;
// a context that ends during the call leaves the call running to
// completion and its verdict unused.
func TestCancellation(t *testing.T) {
	e := reference(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, agtbridge.PointPreToolCall, shell("ls")); err != context.Canceled {
		t.Fatalf("error %v, want context.Canceled", err)
	}
	if e.Calls() != 0 {
		t.Fatal("a call whose context had ended reached AGT")
	}

	slow := slowOPA(t, "1s")
	running := newEvaluator(t, agteval.Config{ManifestPath: manifest, OPAPath: slow, OPATimeout: 5 * time.Second})
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := running.Evaluate(ctx, agtbridge.PointPreToolCall, shell("ls")); err != context.DeadlineExceeded {
		t.Fatalf("error %v, want context.DeadlineExceeded", err)
	}
	if running.Calls() != 1 || time.Since(start) < time.Second {
		t.Fatalf("calls %d after %s; want the one call run to completion", running.Calls(), time.Since(start))
	}
}

// TestOPATimeoutReachesAGT: policy.opa_timeout is the bound AGT puts on
// each opa run; past it, AGT denies.
func TestOPATimeoutReachesAGT(t *testing.T) {
	slow := slowOPA(t, "5s")
	e := newEvaluator(t, agteval.Config{ManifestPath: manifest, OPAPath: slow, OPATimeout: 50 * time.Millisecond})
	start := time.Now()
	v, err := e.Evaluate(context.Background(), agtbridge.PointPreToolCall, shell("ls"))
	if err != nil || v.Decision != "deny" || v.Reason == nil || *v.Reason != "runtime_error:policy_invocation_failed" {
		t.Fatalf("verdict %+v, error %v; want deny policy_invocation_failed", v, err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("the evaluation took %s, past the 50ms opa timeout", elapsed)
	}
	if _, set := os.LookupEnv("ACS_OPA_PATH"); set {
		t.Fatal("ACS_OPA_PATH stayed in the process environment after the build")
	}
}

func TestNewRefuses(t *testing.T) {
	dir := t.TempDir()
	undispatched := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(undispatched, []byte(`agent_control_specification_version: "0.3.1-beta"
policies:
  p: {type: rego, bundle: lib, query: data.p.verdict}
annotators:
  other: {type: classifier}
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args.acs_policy_target"
    annotations:
      other: {from: "$.tool_call.raw_command"}
    policy: {id: p}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		config agteval.Config
		want   string
	}{
		"missing_manifest":        {agteval.Config{ManifestPath: filepath.Join(dir, "absent.yaml"), OPAPath: opa, OPATimeout: time.Second}, "from_path failed"},
		"undispatched_annotator":  {agteval.Config{ManifestPath: undispatched, OPAPath: opa, OPATimeout: time.Second}, `annotator "other"`},
		"missing_opa":             {agteval.Config{ManifestPath: manifest, OPAPath: filepath.Join(dir, "opa"), OPATimeout: time.Second}, "is not an opa executable"},
		"fractional_milliseconds": {agteval.Config{ManifestPath: manifest, OPAPath: opa, OPATimeout: 1500 * time.Microsecond}, "whole number of milliseconds"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := agteval.New(tt.config); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
		})
	}
}
