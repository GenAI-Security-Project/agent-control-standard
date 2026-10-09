package guardian

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failingAuditFile struct{ err error }

func (f failingAuditFile) Write([]byte) (int, error) { return 0, f.err }
func (f failingAuditFile) Close() error              { return nil }

func TestJSONLAuditLogCloseHonorsContext(t *testing.T) {
	l := &JSONLAuditLog{queue: make(chan line), done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want deadline exceeded", err)
	}
}

func TestJSONLAuditLogWriterFailureCallbackMayClose(t *testing.T) {
	diskFailure := errors.New("disk failed")
	callbackDone := make(chan error, 1)
	var l *JSONLAuditLog
	l = newJSONLAuditLog(
		[2]auditFile{failingAuditFile{err: diskFailure}, failingAuditFile{}},
		func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			callbackDone <- l.Close(ctx)
		},
	)
	l.Envelope(context.Background(), EnvelopeRecord{Body: []byte(`{"jsonrpc":"2.0","id":"r1"}`), RecordedAt: time.Now()})
	select {
	case err := <-callbackDone:
		if !errors.Is(err, diskFailure) {
			t.Fatalf("Close from failure callback: %v, want disk failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer failure callback blocked while closing the log")
	}
}
