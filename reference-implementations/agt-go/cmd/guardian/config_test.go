package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

func TestConfigEnvironmentOverride(t *testing.T) {
	configPath, err := filepath.Abs("../../guardian.yaml")
	if err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(t.TempDir(), "hmac-secret")
	if err := os.WriteFile(secretFile, []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(
		[]string{"--config", configPath},
		[]string{
			"ACS__SECURITY__HMAC_SECRET_FILE=" + secretFile,
			"ACS__LIMITS__MAX_DEFERRALS=4",
			"ACS__POLICY__ASK_SUBSTITUTION=defer",
			"ACS__POLICY__TOOL_ALIASES__shell=run_shell",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.maxDeferrals != 4 {
		t.Fatalf("max deferrals = %d, want 4", c.maxDeferrals)
	}
	if c.askSubstitution != guardian.AskSubstitutionDefer {
		t.Fatalf("ask substitution = %q, want defer", c.askSubstitution)
	}
	if c.toolAliases["shell"] != "run_shell" {
		t.Fatalf("tool aliases = %v", c.toolAliases)
	}
}

// TestPolicyPathStaysInsideDeploymentDir covers the refusal documented in
// docs/configuration.md: a manifest or mapping path names a file under
// policy.deployment_dir and cannot leave it.
func TestPolicyPathStaysInsideDeploymentDir(t *testing.T) {
	refused := []string{
		"",
		".",
		"/etc/acs/manifest.yaml",
		"../manifest.yaml",
		"policy/../../manifest.yaml",
		"policy/./manifest.yaml",
		"/",
	}
	for _, value := range refused {
		t.Run("refuses_"+value, func(t *testing.T) {
			if got, err := policyPath("policy.manifest", value); err == nil {
				t.Fatalf("policyPath(%q) = %q, want a refusal", value, got)
			}
		})
	}
	accepted := map[string]string{
		"manifest.yaml":        "manifest.yaml",
		"policy/manifest.yaml": "policy/manifest.yaml",
	}
	for value, want := range accepted {
		t.Run("accepts_"+value, func(t *testing.T) {
			got, err := policyPath("policy.manifest", value)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("policyPath(%q) = %q, want %q", value, got, want)
			}
		})
	}
}
