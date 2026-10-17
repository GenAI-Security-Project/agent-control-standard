package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type failingAuditFile struct{ err error }

func (f failingAuditFile) Write([]byte) (int, error) { return 0, f.err }
func (f failingAuditFile) Close() error              { return nil }

// stalledAuditFile holds every Write until proceed is closed. It then keeps
// the first failFrom records and fails every later Write with err; a zero
// failFrom keeps every record. Each kept record is announced on wrote.
type stalledAuditFile struct {
	proceed  chan struct{}
	failFrom int
	err      error
	wrote    chan struct{}

	mu    sync.Mutex
	lines [][]byte
}

func newStalledAuditFile() *stalledAuditFile {
	return &stalledAuditFile{proceed: make(chan struct{}), wrote: make(chan struct{}, DefaultMaxQueueRecords)}
}

func (f *stalledAuditFile) Write(b []byte) (int, error) {
	<-f.proceed
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFrom > 0 && len(f.lines) >= f.failFrom {
		return 0, f.err
	}
	f.lines = append(f.lines, slices.Clone(b))
	select {
	case f.wrote <- struct{}{}:
	default:
	}
	return len(b), nil
}

func (f *stalledAuditFile) Close() error { return nil }

func (f *stalledAuditFile) seqs(t *testing.T) []int {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var seqs []int
	for _, b := range f.lines {
		var ln struct {
			Seq int `json:"seq"`
		}
		if err := json.Unmarshal(b, &ln); err != nil {
			t.Fatalf("line %q: %v", b, err)
		}
		seqs = append(seqs, ln.Seq)
	}
	return seqs
}

// paddedBody is a JSON-RPC request of about size bytes.
func paddedBody(id, size int) []byte {
	return fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%d,"pad":"%s"}`, id, strings.Repeat("x", size))
}

func (l *JSONLAuditLog) queuedBytesNow() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.queuedBytes
}

// smallRecordBytes is what one paddedBody(1, 32) envelope counts against the
// queue: the overhead, the body and its one-byte rpc_id.
var smallRecordBytes = lineOverheadBytes + int64(len(paddedBody(1, 32))) + 1

func closedFile() *stalledAuditFile {
	f := newStalledAuditFile()
	close(f.proceed)
	return f
}

func closeLog(t *testing.T, l *JSONLAuditLog) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.Close(ctx)
}

// With the writer stalled, the queue keeps the records that fit, the one in
// the writer included, and drops and counts the rest.
func TestJSONLAuditLogQueueIsBounded(t *testing.T) {
	const mib = 1 << 20
	for name, tt := range map[string]struct {
		queue     JSONLQueue
		bodyBytes int
		offered   int
		written   int
	}{
		"bytes":                 {queue: JSONLQueue{MaxQueueBytes: 4 * mib}, bodyBytes: mib, offered: 40, written: 3},
		"default_records":       {bodyBytes: 16, offered: DefaultMaxQueueRecords + 10, written: DefaultMaxQueueRecords},
		"configured_records":    {queue: JSONLQueue{MaxQueueRecords: 2}, bodyBytes: 16, offered: 3, written: 2},
		"one_record_over_limit": {queue: JSONLQueue{MaxQueueBytes: mib}, bodyBytes: mib, offered: 1, written: 0},
	} {
		t.Run(name, func(t *testing.T) {
			envelopes := newStalledAuditFile()
			l := newJSONLAuditLog([2]auditFile{envelopes, closedFile()}, tt.queue, nil)
			maxBytes := tt.queue.withDefaults().MaxQueueBytes
			for i := range tt.offered {
				l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(i+1, tt.bodyBytes)})
				if got := l.queuedBytesNow(); got > maxBytes {
					t.Fatalf("after %d offers the queue holds %d bytes, limit %d", i+1, got, maxBytes)
				}
			}
			close(envelopes.proceed)
			err := closeLog(t, l)
			want := make([]int, tt.written)
			for i := range want {
				want[i] = i + 1
			}
			if got := envelopes.seqs(t); !slices.Equal(got, want) {
				t.Fatalf("written seq %v, want %v", got, want)
			}
			if wantErr := fmt.Sprintf("the audit log dropped %d records", tt.offered-tt.written); err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("Close() = %v, want %q", err, wantErr)
			}
		})
	}
}

// The queue's byte count is what the queued records keep alive: a record
// holds its own copy of the body and nothing of the caller's.
func TestJSONLAuditLogRetainsOnlyWhatItCounts(t *testing.T) {
	const mib = 1 << 20
	envelopes := newStalledAuditFile()
	l := newJSONLAuditLog([2]auditFile{envelopes, closedFile()}, JSONLQueue{MaxQueueBytes: 32 * mib}, nil)
	heap := func() int64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	before := heap()
	for i := range 64 {
		l.Envelope(context.Background(), EnvelopeRecord{Direction: Inbound, Method: "steps/userMessage", Body: paddedBody(i+1, mib)})
	}
	retained, counted := heap()-before, l.queuedBytesNow()
	close(envelopes.proceed)
	_ = closeLog(t, l)
	if retained > counted+4*mib {
		t.Fatalf("queued records keep %d bytes alive, the queue counts %d", retained, counted)
	}
}

// A queue-full drop, then a write failure: both are reported, and Close
// counts every record offered and not written.
func TestJSONLAuditLogCountsEveryLoss(t *testing.T) {
	diskFailure := errors.New("disk failed")
	envelopes := newStalledAuditFile()
	envelopes.failFrom, envelopes.err = 1, diskFailure
	reports := make(chan error, 8)
	size := smallRecordBytes
	l := newJSONLAuditLog([2]auditFile{envelopes, closedFile()}, JSONLQueue{MaxQueueBytes: 3 * size}, func(err error) { reports <- err })
	offer := func(n int) {
		for range n {
			l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
		}
	}
	offer(5) // three queued, two dropped from the full queue
	close(envelopes.proceed)
	var got []error
	for len(got) < 2 {
		select {
		case err := <-reports:
			got = append(got, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("reports %v, want a queue-full and a write-failure report", got)
		}
	}
	queueFull := slices.ContainsFunc(got, func(err error) bool { return strings.Contains(err.Error(), "queue full") })
	writeFailed := slices.ContainsFunc(got, func(err error) bool { return errors.Is(err, diskFailure) })
	if !queueFull || !writeFailed {
		t.Fatalf("reports %v, want one queue-full and one write-failure report", got)
	}
	offer(2) // after the failure
	err := closeLog(t, l)
	offer(1) // after Close
	err = errors.Join(err, closeLog(t, l))
	if written := len(envelopes.seqs(t)); written != 1 {
		t.Fatalf("%d records written, want 1", written)
	}
	if !errors.Is(err, diskFailure) || !strings.Contains(err.Error(), "the audit log dropped 6 records") || !strings.Contains(err.Error(), "the audit log dropped 7 records") {
		t.Fatalf("Close() = %v, want the write failure, then 6 and 7 of 8 records dropped", err)
	}
}

// Producers racing each other, a backlog meeting a write failure, and Close: every record
// offered is written or counted, each file's numbers rise in write order, and
// each failure kind is reported once.
func TestJSONLAuditLogAccountingUnderConcurrency(t *testing.T) {
	const producers, offers = 8, 400
	diskFailure := errors.New("disk failed")
	envelopes, events := newStalledAuditFile(), closedFile()
	envelopes.failFrom, envelopes.err = 10, diskFailure
	var reportsMu sync.Mutex
	reports := map[string]int{}
	writeFailed := make(chan struct{})
	l := newJSONLAuditLog([2]auditFile{envelopes, events}, JSONLQueue{MaxQueueBytes: 16 * smallRecordBytes}, func(err error) {
		reportsMu.Lock()
		defer reportsMu.Unlock()
		kind := strings.SplitN(err.Error(), ";", 2)[0]
		if reports[kind]++; errors.Is(err, diskFailure) && reports[kind] == 1 {
			close(writeFailed)
		}
	})
	var extra atomic.Int64
	var wg sync.WaitGroup
	for p := range producers {
		wg.Go(func() {
			for i := range offers {
				if i%2 == 0 {
					l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
				} else {
					l.Event(context.Background(), AuditEvent{Kind: EventFailure, Message: fmt.Sprint(p)})
				}
				if p == 0 && i == offers/4 {
					close(envelopes.proceed) // the backlog meets the write failure
				}
				if p == 0 && i == offers/2 {
					// Close races the other producers only once the write has
					// failed; until then this producer keeps the writer fed.
					deadline := time.Now().Add(5 * time.Second)
					for waiting := true; waiting; {
						select {
						case <-writeFailed:
							waiting = false
						default:
							if time.Now().After(deadline) {
								t.Error("no write-failure report within 5s")
								waiting = false
							}
							l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
							extra.Add(1)
							runtime.Gosched()
						}
					}
					go func() { _ = l.Close(context.Background()) }()
				}
			}
		})
	}
	wg.Wait()
	err := closeLog(t, l)
	var dropped int
	if _, scanErr := fmt.Sscanf(err.Error()[strings.LastIndex(err.Error(), "the audit log dropped"):], "the audit log dropped %d records", &dropped); scanErr != nil {
		t.Fatalf("Close() = %v: %v", err, scanErr)
	}
	envelopeSeqs, eventSeqs := envelopes.seqs(t), events.seqs(t)
	if written, offered := len(envelopeSeqs)+len(eventSeqs), producers*offers+int(extra.Load()); written+dropped != offered {
		t.Fatalf("%d written + %d dropped, want %d offered", written, dropped, offered)
	}
	for _, seqs := range [][]int{envelopeSeqs, eventSeqs} {
		if !slices.IsSorted(seqs) || len(slices.Compact(slices.Clone(seqs))) != len(seqs) {
			t.Fatalf("seq %v does not rise in write order", seqs)
		}
	}
	// The writer stalls until a quarter of the offers are made, so the queue
	// fills before the write failure, and Close waits for the failure; offers
	// after Close are not guaranteed.
	expected := []string{"audit log queue full", "audit log write failed"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		reportsMu.Lock()
		got := maps.Clone(reports)
		reportsMu.Unlock()
		missing := slices.ContainsFunc(expected, func(kind string) bool { return got[kind] == 0 })
		if !missing || time.Now().After(deadline) {
			for _, kind := range expected {
				if got[kind] != 1 {
					t.Fatalf("reports %v, want %v once each", got, expected)
				}
			}
			for kind, n := range got {
				if n != 1 {
					t.Fatalf("%q reported %d times, want once", kind, n)
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// A record dropped from a full queue keeps its number, so the written ones
// show the gap.
func TestJSONLAuditLogDropLeavesAGap(t *testing.T) {
	envelopes, events := newStalledAuditFile(), closedFile()
	size := smallRecordBytes
	l := newJSONLAuditLog([2]auditFile{envelopes, events}, JSONLQueue{MaxQueueBytes: 2 * size}, nil)
	for range 3 {
		l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
	}
	close(envelopes.proceed)
	<-envelopes.wrote
	<-envelopes.wrote
	// The writer released the first record before writing the second, so
	// one record's space is free; the event waits until the fourth envelope
	// is written, which frees the second's.
	l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
	<-envelopes.wrote
	l.Event(context.Background(), AuditEvent{Kind: EventFailure})
	_ = closeLog(t, l)
	if got := envelopes.seqs(t); !slices.Equal(got, []int{1, 2, 4}) {
		t.Fatalf("envelope seq %v, want [1 2 4]", got)
	}
	if got := events.seqs(t); !slices.Equal(got, []int{1}) {
		t.Fatalf("event seq %v, want [1]: each file numbers its own records", got)
	}
}

// Close returns when ctx expires and counts the records the writer still
// holds.
func TestJSONLAuditLogCloseHonorsContext(t *testing.T) {
	envelopes := newStalledAuditFile()
	defer close(envelopes.proceed)
	l := newJSONLAuditLog([2]auditFile{envelopes, closedFile()}, JSONLQueue{}, nil)
	l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(1, 32)})
	l.Envelope(context.Background(), EnvelopeRecord{Body: paddedBody(2, 32)})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := l.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "dropped 0 records and 2 were still queued") {
		t.Fatalf("Close() error = %v, want deadline exceeded and 2 records still queued", err)
	}
}

func TestJSONLAuditLogWriterFailureCallbackMayClose(t *testing.T) {
	diskFailure := errors.New("disk failed")
	callbackDone := make(chan error, 1)
	var l *JSONLAuditLog
	l = newJSONLAuditLog(
		[2]auditFile{failingAuditFile{err: diskFailure}, failingAuditFile{}},
		JSONLQueue{},
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
