package guardian

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
			f, err := openRotatingFile(path, tt.rotation, false)
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

// TestJSONLAuditLogRefusesOverlappingPaths: the envelope file's rotation
// never reaches the event file.
func TestJSONLAuditLogRefusesOverlappingPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for name, paths := range map[string][2]string{
		"same_file":              {path, path},
		"event_file_is_rotated":  {path, path + ".1"},
		"envelope_file_is_event": {path + ".2026", path},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewJSONLAuditLog(paths[0], paths[1], JSONLRotation{MaxFileBytes: 1, MaxFiles: 1}, JSONLRotation{}, JSONLQueue{}, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestJSONLAuditLogRefusesPathsThatMeetThroughALink: a directory link does
// not hide that the event file is one the envelope file rotates to.
func TestJSONLAuditLogRefusesPathsThatMeetThroughALink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symbolic links are not available:", err)
	}
	if _, err := NewJSONLAuditLog(filepath.Join(real, "audit"), filepath.Join(link, "audit.1"), JSONLRotation{MaxFileBytes: 1, MaxFiles: 1}, JSONLRotation{}, JSONLQueue{}, nil); err == nil {
		t.Fatal("accepted an event file the envelope file rotates to")
	}
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
			if _, err := NewJSONLAuditLog(filepath.Join(dir, "e"), filepath.Join(dir, "v"), r, JSONLRotation{}, JSONLQueue{}, nil); err == nil {
				t.Fatal("accepted for the envelope file")
			}
			if _, err := NewJSONLAuditLog(filepath.Join(dir, "e"), filepath.Join(dir, "v"), JSONLRotation{}, r, JSONLQueue{}, nil); err == nil {
				t.Fatal("accepted for the event file")
			}
		})
	}
}

// TestJSONLAuditLogRotates: the audit log's writer goes through the rotation,
// so a busy log stays within MaxFileBytes × (MaxFiles + 1).
func TestJSONLAuditLogRotates(t *testing.T) {
	dir := t.TempDir()
	rotation := JSONLRotation{MaxFileBytes: 2048, MaxFiles: 1}
	l, err := NewJSONLAuditLog(filepath.Join(dir, "envelopes.jsonl"), filepath.Join(dir, "events.jsonl"), rotation, JSONLRotation{}, JSONLQueue{}, nil)
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

// TestJSONLAuditLogDropsAnAbandonedRequiredEvent: a required event whose
// waiter gave up before the writer took it is never written, so the log
// does not show a substitution the agent did not receive.
func TestJSONLAuditLogDropsAnAbandonedRequiredEvent(t *testing.T) {
	envelopes, events := newStalledAuditFile(), newStalledAuditFile()
	l := newJSONLAuditLog([2]auditFile{envelopes, events}, JSONLQueue{}.withDefaults(), nil)
	l.Envelope(context.Background(), EnvelopeRecord{Body: []byte(`{}`)})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.RequiredEvent(ctx, AuditEvent{Kind: EventAskSubstituted}); err == nil {
		t.Fatal("a required event the writer never reached reported success")
	}
	close(envelopes.proceed)
	close(events.proceed)
	if err := l.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "required event") || !strings.Contains(err.Error(), "dropped 1 records") {
		t.Fatalf("Close did not report and count the unwritten required event: %v", err)
	}
	if seqs := events.seqs(t); len(seqs) != 0 {
		t.Fatalf("the abandoned event was written: seq %v", seqs)
	}
}

// TestJSONLAuditLogRequiredEventFails: a required event reports an error,
// by its deadline, when its write stalls, when the queue is full, and when
// the write fails.
func TestJSONLAuditLogRequiredEventFails(t *testing.T) {
	stalled := newStalledAuditFile()
	t.Cleanup(func() { close(stalled.proceed) })
	full := newStalledAuditFile()
	t.Cleanup(func() { close(full.proceed) })
	for name, tt := range map[string]struct {
		files [2]auditFile
		queue JSONLQueue
		fill  bool
	}{
		"write_stalled": {files: [2]auditFile{closedFile(), stalled}},
		"queue_full":    {files: [2]auditFile{full, closedFile()}, queue: JSONLQueue{MaxQueueRecords: 1}, fill: true},
		"write_failed":  {files: [2]auditFile{closedFile(), failingAuditFile{err: errors.New("disk failed")}}},
	} {
		t.Run(name, func(t *testing.T) {
			reported := make(chan error, 4)
			l := newJSONLAuditLog(tt.files, tt.queue.withDefaults(), func(err error) { reported <- err })
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
				_ = l.Close(ctx)
			})
			if tt.fill {
				l.Envelope(context.Background(), EnvelopeRecord{Body: []byte(`{}`)})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- l.RequiredEvent(ctx, AuditEvent{Kind: EventAskSubstituted}) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a required event that was not written reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("the required event waited past its deadline")
			}
			select {
			case <-reported:
			case <-time.After(time.Second):
				t.Fatal("the failure did not reach onError")
			}
		})
	}
}

// TestRotatedEventFilesNeverReplaceEachOther: two rotations that read the
// same time keep both files.
func TestRotatedEventFilesNeverReplaceEachOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := openRotatingFile(path, JSONLRotation{MaxFileBytes: 8, MaxFiles: 10}, true)
	if err != nil {
		t.Fatal(err)
	}
	f.now = func() time.Time { return time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC) }
	for _, record := range []string{"first\n", "second\n", "third\n"} {
		if _, err := f.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		kept = append(kept, string(b))
	}
	slices.Sort(kept)
	if want := []string{"first\n", "second\n", "third\n"}; !slices.Equal(kept, want) {
		t.Fatalf("the files hold %q, want %q", kept, want)
	}
}

// TestJSONLAuditLogEventFileFull: an event file that holds all the rotated
// files it may keep fails each required event, reports it once, keeps the
// envelope file writing, and takes events again once its rotated files are
// archived. Its directory name holds characters a file pattern reads.
func TestJSONLAuditLogEventFileFull(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acs[prod]")
	events := filepath.Join(dir, "events.jsonl")
	reported := make(chan error, 4)
	l, err := NewJSONLAuditLog(filepath.Join(dir, "envelopes.jsonl"), events, JSONLRotation{}, JSONLRotation{MaxFileBytes: 256, MaxFiles: 1}, JSONLQueue{}, func(err error) { reported <- err })
	if err != nil {
		t.Fatal(err)
	}
	required := func() error {
		return l.RequiredEvent(context.Background(), AuditEvent{Kind: EventAskSubstituted, SessionID: "s", RequestID: "r", RecordedAt: time.Now()})
	}
	var full error
	for range 20 {
		if full = required(); full != nil {
			break
		}
	}
	if !errors.Is(full, errEventFileFull) {
		t.Fatalf("a full event file answered %v", full)
	}
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("the full event file did not reach onError")
	}
	l.Envelope(context.Background(), EnvelopeRecord{Body: []byte(`{}`)})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "events.jsonl.") {
			rotated = append(rotated, e.Name())
		}
	}
	if len(rotated) != 1 {
		t.Fatalf("rotated event files %v", rotated)
	}
	if err := os.Rename(filepath.Join(dir, rotated[0]), filepath.Join(dir, "archived.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := required(); err != nil {
		t.Fatalf("after archiving, a required event got %v", err)
	}
	for range 20 {
		if full = required(); full != nil {
			break
		}
	}
	if !errors.Is(full, errEventFileFull) {
		t.Fatalf("a refilled event file answered %v", full)
	}
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("the second fill did not reach onError")
	}
	if err := l.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("Close did not report the dropped event: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "envelopes.jsonl")); err != nil || len(b) == 0 {
		t.Fatalf("the envelope file stopped writing: %q, %v", b, err)
	}
}

// TestJSONLAuditLogKeepsEveryEvent: the event file rotates by size but
// deletes no rotated file, so every event, a required one included, stays
// on disk for the deployment to archive.
func TestJSONLAuditLogKeepsEveryEvent(t *testing.T) {
	dir := t.TempDir()
	l, err := NewJSONLAuditLog(filepath.Join(dir, "envelopes.jsonl"), filepath.Join(dir, "events.jsonl"), JSONLRotation{MaxFileBytes: 1024, MaxFiles: 1}, JSONLRotation{MaxFileBytes: 1024, MaxFiles: 100}, JSONLQueue{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const events = 100
	for range events {
		if err := l.RequiredEvent(context.Background(), AuditEvent{Kind: EventAskSubstituted, SessionID: "s", RequestID: "r", RecordedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "events.jsonl*"))
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines += strings.Count(string(b), "\n")
	}
	if len(files) < 3 || lines != events {
		t.Fatalf("%d event files hold %d lines, want several files holding %d", len(files), lines, events)
	}
}
