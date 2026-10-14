//go:build unix

package guardian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLogDirectoryIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	f, err := openRotatingFile(path, JSONLRotation{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("audit directory mode %04o, want 0700", got)
	}
}

func TestAuditLogRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "events.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := openRotatingFile(link, JSONLRotation{})
	if err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("a symbolic link as the audit log: got %v", err)
	}
}

func TestAuditLogRefusesAGroupOrOtherReadableFile(t *testing.T) {
	for name, tt := range map[string]struct {
		mode os.FileMode
		want string
	}{
		"group_readable": {0o640, "has mode 0640"},
		"world_readable": {0o644, "has mode 0644"},
		"private":        {0o600, ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatal(err)
			}
			f, err := openRotatingFile(path, JSONLRotation{})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("a %04o log refused: %v", tt.mode, err)
				}
				_ = f.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want a refusal naming %q", err, tt.want)
			}
		})
	}
}
