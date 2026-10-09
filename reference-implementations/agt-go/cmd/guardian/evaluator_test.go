package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// loadReferenceConfig loads guardian.yaml with environment overrides, as the
// command does.
func loadReferenceConfig(t *testing.T, overrides ...string) (config, error) {
	t.Helper()
	configPath, err := filepath.Abs("../../guardian.yaml")
	if err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(t.TempDir(), "hmac-secret")
	if err := os.WriteFile(secretFile, []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConfig([]string{"--config", configPath}, append([]string{
		"ACS__SECURITY__HMAC_SECRET_FILE=" + secretFile,
		"ACS__POLICY__OPA_PATH=.acs/agt/" + runtime.GOOS + "-" + runtime.GOARCH + "/bin",
	}, overrides...))
}

// TestEvaluatorSelection: policy.evaluator has no default, the go evaluator
// runs in every build, and agt runs only in a build with the agteval tag;
// agtSelection checks the agt half for this build.
func TestEvaluatorSelection(t *testing.T) {
	for name, tt := range map[string]struct {
		overrides []string
		want      string
	}{
		"missing":          {[]string{"ACS__POLICY__EVALUATOR="}, `policy.evaluator must be "agt" or "go"`},
		"unknown":          {[]string{"ACS__POLICY__EVALUATOR=rego"}, `policy.evaluator must be "agt" or "go"`},
		"agt_without_opa":  {[]string{"ACS__POLICY__OPA_PATH="}, "policy.opa_path must name the opa executable"},
		"agt_zero_timeout": {[]string{"ACS__POLICY__OPA_TIMEOUT=0s"}, "policy.opa_timeout must be positive"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadReferenceConfig(t, tt.overrides...); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("go", func(t *testing.T) {
		c, err := loadReferenceConfig(t, "ACS__POLICY__EVALUATOR=go", "ACS__POLICY__OPA_PATH=")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newEvaluator(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("agt", func(t *testing.T) {
		c, err := loadReferenceConfig(t)
		if err != nil {
			t.Fatal(err)
		}
		if c.evaluator != evaluatorAGT {
			t.Fatalf("guardian.yaml selects %q, want the AGT evaluator", c.evaluator)
		}
		agtSelection(t, c)
	})
}
