//go:build agteval

package agteval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBuildRecord(t *testing.T) {
	const content = "library"
	const contentSHA256 = "b718f1354f7247312eca086d9a024afe5fa717ddea5adeddd6f12bcf945b2e8c"
	for name, tt := range map[string]struct {
		record string
		want   string
	}{
		"matches":     {`{"agt_ref":"abc","sha256":"` + contentSHA256 + `"}`, ""},
		"no_record":   {"", "has no build record"},
		"no_commit":   {`{"sha256":"` + contentSHA256 + `"}`, "does not name an AGT commit"},
		"other_bytes": {`{"agt_ref":"abc","sha256":"00"}`, "and its build record names 00"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			library := filepath.Join(dir, "libagt.so")
			if err := os.WriteFile(library, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.record != "" {
				if err := os.WriteFile(filepath.Join(dir, BuildRecord), []byte(tt.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ref, err := verifyBuildRecord(library)
			switch {
			case tt.want == "" && (err != nil || ref != "abc"):
				t.Fatalf("ref %q, error %v; want abc", ref, err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("error %v, want %q", err, tt.want)
			}
		})
	}
}
