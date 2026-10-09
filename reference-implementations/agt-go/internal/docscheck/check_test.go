package docscheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryDocuments(t *testing.T) {
	if err := Check("../.."); err != nil {
		t.Fatal(err)
	}
}

func TestConformanceRequiresTestsForClaims(t *testing.T) {
	problems := checkConformance("| ACS-Core item | Status | Tests | Note |\n| --- | --- | --- | --- |\n| Handshake | Met | | note |\n")
	if len(problems) != 1 || !strings.Contains(problems[0], "without naming a test") {
		t.Fatalf("problems = %v", problems)
	}
}

func TestCheckReportsMissingLinksAndTests(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	conformance := "| ACS-Core item | Status | Tests | Note |\n| --- | --- | --- | --- |\n| Handshake | Met | `guardian.TestMissing` | note |\n[missing](absent.md)\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "conformance.md"), []byte(conformance), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Check(root)
	if err == nil || !strings.Contains(err.Error(), "absent.md") || !strings.Contains(err.Error(), "guardian.TestMissing") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckReportsMissingTestInAnyDocument(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	conformance := "| ACS-Core item | Status | Tests | Note |\n| --- | --- | --- | --- |\n| Handshake | Not claimed | | note |\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "conformance.md"), []byte(conformance), 0o600); err != nil {
		t.Fatal(err)
	}
	canonicalForm := "# Canonical form\n\nCovered by `guardian.TestMissing`.\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "canonical-form.md"), []byte(canonicalForm), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Check(root)
	if err == nil || !strings.Contains(err.Error(), "canonical-form.md names guardian.TestMissing") {
		t.Fatalf("error = %v", err)
	}
}
