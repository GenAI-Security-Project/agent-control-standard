package guardian

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRotatingFileBoundsTheLog: a file that would grow past MaxFileBytes is
// renamed to .1, older ones move up, the one past MaxFiles is deleted, no
// record is split, and the files hold exactly the newest records, in order.
func TestRotatingFileBoundsTheLog(t *testing.T) {
	recordAt := func(seq int) []byte { return fmt.Appendf(nil, `{"seq":%02d,"padding":"0123456789"}`+"\n", seq) } // 35 bytes
	record := recordAt(0)
	for name, tt := range map[string]struct {
		rotation JSONLRotation
		files    []string
		kept     int
	}{
		"keeps_two":    {JSONLRotation{MaxFileBytes: 100, MaxFiles: 2}, []string{"log", "log.1", "log.2"}, 6},
		"keeps_all":    {JSONLRotation{}, []string{"log"}, 20},
		"one_per_file": {JSONLRotation{MaxFileBytes: 10, MaxFiles: 1}, []string{"log", "log.1"}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "log")
			f, err := openRotatingFile(path, tt.rotation)
			if err != nil {
				t.Fatal(err)
			}
			const records = 20
			for i := range records {
				if _, err := f.Write(recordAt(i)); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			var total int64
			for _, e := range entries {
				got = append(got, e.Name())
				info, _ := e.Info()
				total += info.Size()
				if tt.rotation.MaxFileBytes > 0 && info.Size() > max(tt.rotation.MaxFileBytes, int64(len(record))) {
					t.Errorf("%s has %d bytes, past the bound", e.Name(), info.Size())
				}
				content, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				if len(content)%len(record) != 0 {
					t.Errorf("%s holds a split record", e.Name())
				}
			}
			if !equalNames(got, tt.files) {
				t.Fatalf("files %v, want %v", got, tt.files)
			}
			var oldestFirst, want []byte
			for i := len(tt.files) - 1; i >= 0; i-- {
				content, _ := os.ReadFile(filepath.Join(dir, tt.files[len(tt.files)-1-i]))
				oldestFirst = append(content, oldestFirst...)
			}
			for i := records - tt.kept; i < records; i++ {
				want = append(want, recordAt(i)...)
			}
			if !bytes.Equal(oldestFirst, want) {
				t.Fatalf("the files hold, oldest first:\n%s\nwant the newest %d records:\n%s", oldestFirst, tt.kept, want)
			}
		})
	}
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestJSONLRotationRefusesAnInconsistentBound(t *testing.T) {
	for name, r := range map[string]JSONLRotation{
		"negative_bytes":       {MaxFileBytes: -1},
		"negative_files":       {MaxFileBytes: 1, MaxFiles: -1},
		"files_without_a_size": {MaxFiles: 2},
		"size_without_files":   {MaxFileBytes: 100},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := NewJSONLAuditLog(filepath.Join(dir, "e"), filepath.Join(dir, "v"), r, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestJSONLAuditLogRotates: the audit log's writer goes through the rotation,
// so a busy log stays within MaxFileBytes × (MaxFiles + 1).
func TestJSONLAuditLogRotates(t *testing.T) {
	dir := t.TempDir()
	rotation := JSONLRotation{MaxFileBytes: 2048, MaxFiles: 1}
	l, err := NewJSONLAuditLog(filepath.Join(dir, "envelopes.jsonl"), filepath.Join(dir, "events.jsonl"), rotation, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 200 {
		l.Envelope(context.Background(), EnvelopeRecord{Body: []byte(`{"jsonrpc":"2.0","id":"r1","method":"steps/toolCallRequest"}`), RecordedAt: time.Now()})
	}
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, name := range []string{"envelopes.jsonl", "envelopes.jsonl.1"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if _, err := os.Stat(filepath.Join(dir, "envelopes.jsonl.2")); err == nil {
		t.Fatal("a file past MaxFiles was kept")
	}
	if total > rotation.MaxFileBytes*int64(rotation.MaxFiles+1) {
		t.Fatalf("the log kept %d bytes, past %d", total, rotation.MaxFileBytes*int64(rotation.MaxFiles+1))
	}
}
