package guardian_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	s := bufio.NewScanner(f)
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatalf("line %q is not JSON: %v", s.Text(), err)
		}
		lines = append(lines, m)
	}
	return lines
}

func TestJSONLAuditLog(t *testing.T) {
	dir := t.TempDir()
	envelopes, events := filepath.Join(dir, "a", "envelopes.jsonl"), filepath.Join(dir, "b", "events.jsonl")
	var failures []error
	l, err := guardian.NewJSONLAuditLog(envelopes, events, func(err error) { failures = append(failures, err) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, at := context.Background(), time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	pretty := []byte("{\n  \"jsonrpc\": \"2.0\",\n  \"method\": \"steps/userMessage\",\n  \"id\": 7\n}")
	l.Envelope(ctx, guardian.EnvelopeRecord{Direction: guardian.Inbound, Method: "steps/userMessage", Body: pretty, RecordedAt: at})
	l.Envelope(ctx, guardian.EnvelopeRecord{Direction: guardian.Outbound, Body: []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`), RecordedAt: at})
	l.Event(ctx, guardian.AuditEvent{Kind: guardian.EventChainMismatch, SessionID: "s", RequestID: "r", Method: "m", Message: "msg", RecordedAt: at})
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := readLines(t, envelopes)
	if len(got) != 2 {
		t.Fatalf("%d envelope lines, want 2", len(got))
	}
	first, second := got[0], got[1]
	if first["seq"] != 1.0 || first["direction"] != "request" || first["method"] != "steps/userMessage" || first["rpc_id"] != 7.0 || first["recorded_at"] != "2026-09-19T10:00:00Z" {
		t.Fatalf("first line %v", first)
	}
	if first["envelope"].(map[string]any)["method"] != "steps/userMessage" {
		t.Fatalf("envelope %v", first["envelope"])
	}
	if second["seq"] != 2.0 || second["direction"] != "response" || second["method"] != nil || second["rpc_id"] != nil {
		t.Fatalf("second line %v", second)
	}
	ev := readLines(t, events)
	if len(ev) != 1 || ev[0]["seq"] != 1.0 || ev[0]["kind"] != "chain_mismatch" || ev[0]["session_id"] != "s" {
		t.Fatalf("event lines %v", ev)
	}
	if len(failures) != 0 {
		t.Fatalf("failures %v", failures)
	}
	l.Envelope(ctx, guardian.EnvelopeRecord{Direction: guardian.Inbound, Body: []byte(`{}`)})
	if b, _ := os.ReadFile(envelopes); strings.Count(string(b), "\n") != 2 {
		t.Fatal("a record sent after Close was written")
	}
}

func TestJSONLAuditLogRefusesAnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := guardian.NewJSONLAuditLog(filepath.Join(blocker, "x.jsonl"), filepath.Join(dir, "e.jsonl"), nil); err == nil {
		t.Fatal("opened a log under a regular file")
	}
}

// onError runs outside the log's lock: a callback that writes to the log
// itself, or closes it, returns instead of deadlocking the request that
// triggered it.
func TestJSONLAuditLogCallbackMayReenter(t *testing.T) {
	dir := t.TempDir()
	var l *guardian.JSONLAuditLog
	reentered := make(chan struct{})
	l, err := guardian.NewJSONLAuditLog(filepath.Join(dir, "e.jsonl"), filepath.Join(dir, "v.jsonl"), func(error) {
		l.Event(context.Background(), guardian.AuditEvent{Kind: guardian.EventFailure, Message: "reported"})
		close(reentered)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		l.Event(context.Background(), guardian.AuditEvent{Kind: guardian.EventFailure})
		close(done)
	}()
	select {
	case <-done:
		<-reentered
	case <-time.After(time.Second):
		t.Fatal("a re-entrant onError deadlocked the log")
	}
}

// The log keeps its own copy of a body: a caller reusing its buffer after
// Envelope returns does not change what is written.
func TestJSONLAuditLogCopiesTheBody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e.jsonl")
	l, err := guardian.NewJSONLAuditLog(path, filepath.Join(dir, "v.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"steps/userMessage"}`)
	l.Envelope(context.Background(), guardian.EnvelopeRecord{Direction: guardian.Inbound, Body: body})
	copy(body, strings.Repeat("x", len(body)))
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, path); len(got) != 1 || got[0]["envelope"].(map[string]any)["method"] != "steps/userMessage" {
		t.Fatalf("written %v", got)
	}
}
