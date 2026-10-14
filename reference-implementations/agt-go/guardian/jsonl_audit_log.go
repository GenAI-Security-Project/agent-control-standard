package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

// JSONLAuditLog is an AuditLog, cmd/guardian's: it appends envelopes to one JSON
// Lines file and audit events to another, from a background writer, so a
// slow disk never delays a decision.
//
// The envelope file has the TypeScript reference's line shape, {seq,
// recorded_at, direction, method, rpc_id, envelope} with direction request
// or response, so its Inspector reads it. Records beyond the queue's
// capacity are dropped and counted, and a write failure disables the log;
// both are reported through onError once, never to the caller.
type JSONLAuditLog struct {
	queue   chan line
	done    chan struct{}
	onError func(error)

	mu       sync.Mutex
	closed   bool
	dropped  int
	failure  error
	reported bool
}

// line is one record to write; exactly one of its fields is set. The writer
// numbers it from one per process run, so a reader detects gaps within a run;
// a restart appending to the same file repeats the numbers already in it.
type line struct {
	envelope *envelopeLine
	event    *eventLine
}

// JSONLQueueCapacity is how many records the writer holds before it drops.
const JSONLQueueCapacity = 4096

// JSONLRotation bounds each of the two files. When a record would take a
// file past MaxFileBytes, the file is renamed to <path>.1, earlier ones move
// up to <path>.2 and so on, and the one past MaxFiles is deleted, so a log
// keeps at most MaxFileBytes × (MaxFiles + 1) bytes, plus one record larger
// than MaxFileBytes. The zero value keeps every record: a deployment that
// rotates the files with its own tooling leaves it unset.
type JSONLRotation struct {
	MaxFileBytes int64
	MaxFiles     int
}

// Validate refuses a negative value, MaxFiles without MaxFileBytes, and
// MaxFileBytes without MaxFiles, which would delete the live log at each
// rotation.
func (r JSONLRotation) Validate() error {
	switch {
	case r.MaxFileBytes < 0 || r.MaxFiles < 0:
		return errors.New("max_file_bytes and max_files cannot be negative")
	case r.MaxFileBytes == 0 && r.MaxFiles != 0:
		return errors.New("max_files needs max_file_bytes")
	case r.MaxFileBytes > 0 && r.MaxFiles == 0:
		return errors.New("max_file_bytes needs max_files of at least 1, or each rotation deletes the live log")
	}
	return nil
}

// NewJSONLAuditLog opens (creating directories as needed) the two files and
// starts the writer. onError, which may be nil, receives the first failure
// asynchronously, so it may safely close the log.
func NewJSONLAuditLog(envelopePath, eventPath string, rotation JSONLRotation, onError func(error)) (*JSONLAuditLog, error) {
	if err := rotation.Validate(); err != nil {
		return nil, err
	}
	var files [2]auditFile
	for i, path := range []string{envelopePath, eventPath} {
		f, err := openRotatingFile(path, rotation)
		if err != nil {
			if files[0] != nil {
				_ = files[0].Close()
			}
			return nil, err
		}
		files[i] = f
	}
	return newJSONLAuditLog(files, onError), nil
}

// rotatingFile appends to path and rotates it as JSONLRotation describes.
// Only the writer goroutine uses it.
type rotatingFile struct {
	path     string
	rotation JSONLRotation
	f        *os.File
	size     int64
}

func openRotatingFile(path string, rotation JSONLRotation) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &rotatingFile{path: path, rotation: rotation}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|auditOpenFlags, 0o600)
	if err != nil {
		return auditOpenError(r.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	if err := checkAuditFileMode(r.path, info); err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, info.Size()
	return nil
}

// Write appends one record, rotating first when the record would take the
// file past MaxFileBytes; a record is never split across files.
func (r *rotatingFile) Write(b []byte) (int, error) {
	if r.rotation.MaxFileBytes > 0 && r.size > 0 && r.size+int64(len(b)) > r.rotation.MaxFileBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(b)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	numbered := func(i int) string { return fmt.Sprintf("%s.%d", r.path, i) }
	keep := r.rotation.MaxFiles
	last := r.path
	if keep > 0 {
		last = numbered(keep)
	}
	if err := os.Remove(last); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := keep - 1; i >= 1; i-- {
		if err := os.Rename(numbered(i), numbered(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if keep > 0 {
		if err := os.Rename(r.path, numbered(1)); err != nil {
			return err
		}
	}
	return r.open()
}

func (r *rotatingFile) Close() error { return r.f.Close() }

type auditFile interface {
	Write([]byte) (int, error)
	Close() error
}

func newJSONLAuditLog(files [2]auditFile, onError func(error)) *JSONLAuditLog {
	l := &JSONLAuditLog{queue: make(chan line, JSONLQueueCapacity), done: make(chan struct{}), onError: onError}
	go l.write(files)
	return l
}

type envelopeLine struct {
	Seq        int             `json:"seq"`
	RecordedAt string          `json:"recorded_at"`
	Direction  string          `json:"direction"`
	Method     *string         `json:"method"`
	RPCID      json.RawMessage `json:"rpc_id"`
	Envelope   json.RawMessage `json:"envelope"`
}

type eventLine struct {
	Seq        int            `json:"seq"`
	RecordedAt string         `json:"recorded_at"`
	Kind       AuditEventKind `json:"kind"`
	SessionID  string         `json:"session_id"`
	RequestID  string         `json:"request_id"`
	Method     string         `json:"method"`
	Message    string         `json:"message"`
}

// Envelope implements AuditLog.
func (l *JSONLAuditLog) Envelope(_ context.Context, r EnvelopeRecord) {
	direction := "request"
	if r.Direction == Outbound {
		direction = "response"
	}
	var method *string
	if r.Method != "" {
		method = &r.Method
	}
	var head struct {
		ID json.RawMessage `json:"id"`
	}
	_ = jsonv2.Unmarshal(r.Body, &head)
	id := json.RawMessage("null")
	if len(head.ID) > 0 && (head.ID[0] == '"' || head.ID[0] == '-' || (head.ID[0] >= '0' && head.ID[0] <= '9')) {
		id = head.ID
	}
	// The body is copied: the caller may reuse its buffer once Envelope
	// returns, and the writer reads it later.
	l.enqueue(line{envelope: &envelopeLine{RecordedAt: stamp(r.RecordedAt), Direction: direction, Method: method, RPCID: slices.Clone(id), Envelope: slices.Clone(r.Body)}})
}

// Event implements AuditLog.
func (l *JSONLAuditLog) Event(_ context.Context, e AuditEvent) {
	l.enqueue(line{event: &eventLine{RecordedAt: stamp(e.RecordedAt), Kind: e.Kind, SessionID: e.SessionID, RequestID: e.RequestID, Method: e.Method, Message: e.Message}})
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// enqueue queues a record, or drops and counts it when the queue is full
// or the log is closed. onError is called after the lock is released, so a
// slow or re-entrant callback cannot hold a governed request.
func (l *JSONLAuditLog) enqueue(ln line) {
	var failure error
	l.mu.Lock()
	switch {
	case l.closed:
		l.dropped++
		failure = errors.New("audit log closed; records are being dropped")
	default:
		select {
		case l.queue <- ln:
		default:
			l.dropped++
			failure = errors.New("audit log queue full; records are being dropped")
		}
	}
	l.mu.Unlock()
	if failure != nil {
		l.report(failure)
	}
}

func (l *JSONLAuditLog) write(files [2]auditFile) {
	defer close(l.done)
	var envelopes, events int
	failed := false
	for ln := range l.queue {
		if failed {
			continue
		}
		var (
			f      auditFile
			record any
		)
		if ln.envelope != nil {
			envelopes++
			ln.envelope.Seq, f, record = envelopes, files[0], ln.envelope
		} else {
			events++
			ln.event.Seq, f, record = events, files[1], ln.event
		}
		b, err := jsonv2.Marshal(record)
		if err == nil {
			_, err = f.Write(append(b, '\n'))
		}
		if err != nil {
			failed = true
			l.report(err)
		}
	}
	for _, f := range files {
		if err := f.Close(); err != nil && !failed {
			l.report(err)
		}
	}
}

// Close writes every queued record and closes the files until ctx expires.
// Records sent after Close are dropped and reported.
func (l *JSONLAuditLog) Close(ctx context.Context) error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	l.mu.Lock()
	dropped, failure := l.dropped, l.failure
	l.mu.Unlock()
	var droppedErr error
	if dropped > 0 {
		droppedErr = fmt.Errorf("the audit log dropped %d records", dropped)
	}
	return errors.Join(failure, droppedErr)
}

// report sends the first failure to onError outside l.mu. The callback runs
// asynchronously because a synchronous callback that closes the log would
// otherwise wait for the writer that called it.
func (l *JSONLAuditLog) report(err error) {
	l.mu.Lock()
	first := !l.reported
	if l.failure == nil {
		l.failure = err
	}
	l.reported = true
	l.mu.Unlock()
	if first && l.onError != nil {
		go l.onError(err)
	}
}
