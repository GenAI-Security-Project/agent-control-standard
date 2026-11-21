package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

// JSONLAuditLog is an AuditLog, cmd/guardian's: it appends envelopes to one JSON
// Lines file and audit events to another, from a background writer, so a
// slow disk delays only a step that needs a required event (RequiredEvent).
//
// The envelope file has the TypeScript reference's line shape, {seq,
// recorded_at, direction, method, rpc_id, envelope} with direction request
// or response, so its Inspector reads it.
//
// The queue holds the records JSONLQueue allows, the record being written
// included. A record that would exceed either limit is dropped and counted,
// and logging continues as space frees. An event file that holds all the
// rotated files it may keep drops and counts each event until the deployment
// archives them. Any other write failure turns the log off for the rest of
// the process: the failed record and every later one are dropped and counted.
// Each kind of failure
// reaches onError once, never the caller, and Close reports every dropped
// record.
type JSONLAuditLog struct {
	queue   chan line
	done    chan struct{}
	onError func(error)
	limits  JSONLQueue

	mu                sync.Mutex
	closed            bool
	failed            bool
	queued            int
	queuedBytes       int64
	envelopes, events int
	dropped           int
	queueFull         error
	writeFailure      error
	offeredAfterClose error
	requiredLate      error
	eventLogFull      error
}

// line is one record to write; exactly one of envelope and event is set.
// It is numbered when offered, from one per file and process run, so a
// record dropped from a full queue leaves a gap a reader detects; a restart
// appending to the same file repeats the numbers already in it.
type line struct {
	envelope *envelopeLine
	event    *eventLine
	size     int64
	// written, set for a required event, receives the outcome of its write.
	written chan error
	// state, set for a required event, is linePending until the writer takes
	// it (lineWriting) or its waiter gives up first (lineAbandoned), so an
	// event the Guardian did not act on is not written. A write already under
	// way when the waiter gives up may still land; the Guardian's failure
	// record for the same request follows it.
	state *atomic.Int32
}

const (
	linePending int32 = iota
	lineWriting
	lineAbandoned
)

// JSONLQueue bounds the records the writer holds. Zero means the default.
type JSONLQueue struct {
	MaxQueueRecords int
	MaxQueueBytes   int64
}

const (
	// DefaultMaxQueueRecords holds about 6.5 MiB at the 1.6 KB per step
	// docs/load.md measures.
	DefaultMaxQueueRecords = 4096
	// DefaultMaxQueueBytes holds a stalled disk to 64 MiB of records rather
	// than DefaultMaxQueueRecords requests of DefaultMaxBodyBytes, 4 GiB.
	DefaultMaxQueueBytes = 64 << 20
)

// Validate refuses a negative limit.
func (q JSONLQueue) Validate() error {
	if q.MaxQueueRecords < 0 || q.MaxQueueBytes < 0 {
		return errors.New("max_queue_records and max_queue_bytes cannot be negative")
	}
	return nil
}

func (q JSONLQueue) withDefaults() JSONLQueue {
	if q.MaxQueueRecords == 0 {
		q.MaxQueueRecords = DefaultMaxQueueRecords
	}
	if q.MaxQueueBytes == 0 {
		q.MaxQueueBytes = DefaultMaxQueueBytes
	}
	return q
}

// JSONLRecordBytes is the most that the record of a request of bodyBytes
// counts against MaxQueueBytes: the body, its method and JSON-RPC id, which
// are copied out of it, and the fixed part of a record. A MaxQueueBytes below
// it drops every such request.
func JSONLRecordBytes(bodyBytes int64) int64 {
	return lineOverheadBytes + 2*bodyBytes
}

// lineOverheadBytes is the memory a record holds beyond its variable-length
// fields: the structs, pointers and timestamp.
const lineOverheadBytes = 256

// JSONLRotation bounds one of the two files. When a record would take the
// file past MaxFileBytes, the file is renamed, so each file holds at most
// MaxFileBytes, or one record larger than that, and MaxFiles + 1 files are
// kept. The envelope file becomes <path>.1, earlier ones move up to
// <path>.2 and so on, and the one past MaxFiles is deleted. The event file
// holds events the standard requires, which are never deleted: it becomes
// <path>.<UTC time of the rotation>, kept for the deployment to archive, and
// while MaxFiles of them remain, each event is dropped and counted and a
// required one fails. The zero value keeps every record: a deployment that
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
		return errors.New("the file size and the file count cannot be negative")
	case r.MaxFileBytes == 0 && r.MaxFiles != 0:
		return errors.New("a file count needs a file size")
	case r.MaxFileBytes > 0 && r.MaxFiles == 0:
		return errors.New("a file size needs a file count of at least 1")
	}
	return nil
}

// NewJSONLAuditLog opens (creating directories as needed) the two files and
// starts the writer. onError, which may be nil, receives the first failure of
// each kind - queue full, write failure, full event file, offer after Close -
// asynchronously and possibly concurrently, so it may safely close the log.
func NewJSONLAuditLog(envelopePath, eventPath string, envelopes, events JSONLRotation, queue JSONLQueue, onError func(error)) (*JSONLAuditLog, error) {
	if err := envelopes.Validate(); err != nil {
		return nil, fmt.Errorf("envelope file rotation: %w", err)
	}
	if err := events.Validate(); err != nil {
		return nil, fmt.Errorf("event file rotation: %w", err)
	}
	if err := queue.Validate(); err != nil {
		return nil, err
	}
	var files [2]auditFile
	for i, path := range []string{envelopePath, eventPath} {
		rotation := envelopes
		if i == 1 {
			rotation = events
		}
		f, err := openRotatingFile(path, rotation, i == 1)
		if err != nil {
			if files[0] != nil {
				_ = files[0].Close()
			}
			return nil, err
		}
		files[i] = f
	}
	if err := separatePaths(envelopePath, eventPath); err != nil {
		_ = files[0].Close()
		_ = files[1].Close()
		return nil, err
	}
	return newJSONLAuditLog(files, queue, onError), nil
}

// separatePaths refuses two audit paths where one file, or a file one of them
// rotates to, is the other: the envelope file's rotation would then delete
// events the standard requires. It runs once both directories exist, so it
// compares them with symbolic links resolved.
func separatePaths(envelopePath, eventPath string) error {
	envelope, err := resolvedPath(envelopePath)
	if err != nil {
		return err
	}
	event, err := resolvedPath(eventPath)
	if err != nil {
		return err
	}
	if envelope == event || strings.HasPrefix(event, envelope+".") || strings.HasPrefix(envelope, event+".") {
		return fmt.Errorf("the envelope and event files must not share a path or rotate onto each other: %s, %s", envelopePath, eventPath)
	}
	return nil
}

func resolvedPath(path string) (string, error) {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}

// rotatingFile appends to path and rotates it as JSONLRotation describes.
// Only the writer goroutine uses it.
type rotatingFile struct {
	path     string
	rotation JSONLRotation
	// keepRotated renames a full file by its rotation time and deletes none.
	keepRotated bool
	now         func() time.Time
	f           *os.File
	size        int64
}

func openRotatingFile(path string, rotation JSONLRotation, keepRotated bool) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &rotatingFile{path: path, rotation: rotation, keepRotated: keepRotated, now: time.Now}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_RDWR|os.O_APPEND|auditOpenFlags, 0o600)
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
	if err := r.endUnfinishedLine(); err != nil {
		_ = f.Close()
		return err
	}
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
	if r.keepRotated {
		kept, err := r.rotatedFiles()
		if err != nil {
			return err
		}
		if kept >= r.rotation.MaxFiles {
			return errEventFileFull
		}
	}
	if err := r.f.Close(); err != nil {
		return err
	}
	if r.keepRotated {
		// A clock that is coarse or steps back can repeat a name, and a
		// rename would replace the file that holds it.
		stamped := r.path + "." + r.now().UTC().Format("20060102T150405.000000000Z")
		name := stamped
		for i := 1; ; i++ {
			_, err := os.Lstat(name)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return err
			}
			name = fmt.Sprintf("%s-%d", stamped, i)
		}
		if err := os.Rename(r.path, name); err != nil {
			return err
		}
		return r.open()
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

// endUnfinishedLine ends a last line that a crash left without its newline,
// so the next record starts a line of its own rather than joining that one.
func (r *rotatingFile) endUnfinishedLine() error {
	if r.size == 0 {
		return nil
	}
	last := make([]byte, 1)
	if _, err := r.f.ReadAt(last, r.size-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	n, err := r.f.Write([]byte{'\n'})
	r.size += int64(n)
	return err
}

// rotatedFiles counts the event files rotation renamed and the deployment
// has not yet moved away, matched by name rather than as a pattern, since a
// path may hold characters a pattern reads.
func (r *rotatingFile) rotatedFiles() (int, error) {
	entries, err := os.ReadDir(filepath.Dir(r.path))
	if err != nil {
		return 0, err
	}
	prefix := filepath.Base(r.path) + "."
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			n++
		}
	}
	return n, nil
}

func (r *rotatingFile) Close() error { return r.f.Close() }

type auditFile interface {
	Write([]byte) (int, error)
	Close() error
}

func newJSONLAuditLog(files [2]auditFile, queue JSONLQueue, onError func(error)) *JSONLAuditLog {
	limits := queue.withDefaults()
	l := &JSONLAuditLog{queue: make(chan line, limits.MaxQueueRecords), done: make(chan struct{}), onError: onError, limits: limits}
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
		// A pointer into r would keep r.Body, the caller's buffer, alive
		// beside the copy the queue counts.
		m := r.Method
		method = &m
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
	l.enqueue(line{
		envelope: &envelopeLine{RecordedAt: stamp(r.RecordedAt), Direction: direction, Method: method, RPCID: slices.Clone(id), Envelope: slices.Clone(r.Body)},
		size:     lineOverheadBytes + int64(len(r.Method)+len(id)+len(r.Body)),
	})
}

// Event implements AuditLog.
func (l *JSONLAuditLog) Event(_ context.Context, e AuditEvent) {
	_ = l.enqueue(eventLineOf(e))
}

// RequiredEvent implements AuditLog: it queues the event like any other and
// waits for the writer to write it.
func (l *JSONLAuditLog) RequiredEvent(ctx context.Context, e AuditEvent) error {
	ln := eventLineOf(e)
	ln.written, ln.state = make(chan error, 1), new(atomic.Int32)
	if err := l.enqueue(ln); err != nil {
		return err
	}
	select {
	case err := <-ln.written:
		return err
	case <-ctx.Done():
		ln.state.CompareAndSwap(linePending, lineAbandoned)
		l.mu.Lock()
		report := l.firstOf(&l.requiredLate, errors.New("audit log did not write a required event by its deadline"))
		l.mu.Unlock()
		report()
		return context.Cause(ctx)
	}
}

func eventLineOf(e AuditEvent) line {
	return line{
		event: &eventLine{RecordedAt: stamp(e.RecordedAt), Kind: e.Kind, SessionID: e.SessionID, RequestID: e.RequestID, Method: e.Method, Message: e.Message},
		size:  lineOverheadBytes + int64(len(e.Kind)+len(e.SessionID)+len(e.RequestID)+len(e.Method)+len(e.Message)),
	}
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// enqueue numbers a record and queues it, or drops and counts it when the
// queue is full, the log has failed or the log is closed, and says which.
// onError is called after the lock is released, so a slow or re-entrant
// callback cannot hold a governed request.
func (l *JSONLAuditLog) enqueue(ln line) (dropped error) {
	report := func() {}
	l.mu.Lock()
	if ln.envelope != nil {
		l.envelopes++
		ln.envelope.Seq = l.envelopes
	} else {
		l.events++
		ln.event.Seq = l.events
	}
	switch {
	case l.closed:
		l.dropped++
		dropped = errAuditLogClosed
		report = l.firstOf(&l.offeredAfterClose, errors.New("audit log closed; records are being dropped and counted"))
	case l.failed:
		l.dropped++
		dropped = errAuditLogFailed
	case l.queued == l.limits.MaxQueueRecords || l.queuedBytes+ln.size > l.limits.MaxQueueBytes:
		l.dropped++
		dropped = errAuditQueueFull
		report = l.firstOf(&l.queueFull, errors.New("audit log queue full; records are being dropped and counted"))
	default:
		l.queued++
		l.queuedBytes += ln.size
		// Never blocks: the channel holds at most queued records, and queued
		// falls only after the writer has received a record and written it.
		l.queue <- ln
	}
	l.mu.Unlock()
	report()
	return dropped
}

// errEventFileFull is the write error while the event file holds all the
// rotated files it may keep.
var errEventFileFull = errors.New("the audit event file is full until its rotated files are archived")

// The reasons enqueue drops a record.
var (
	errAuditLogClosed = errors.New("the audit log is closed")
	errAuditLogFailed = errors.New("the audit log failed and is off")
	errAuditQueueFull = errors.New("the audit log queue is full")
)

// write writes each queued record and releases its place in the queue only
// once its write returns, so the record in flight counts against the limits.
func (l *JSONLAuditLog) write(files [2]auditFile) {
	defer close(l.done)
	failed := false
	for ln := range l.queue {
		var err error
		abandoned := ln.state != nil && !ln.state.CompareAndSwap(linePending, lineWriting)
		if !failed && !abandoned {
			err = writeLine(files, ln)
		}
		l.mu.Lock()
		l.queued--
		l.queuedBytes -= ln.size
		report := func() {}
		if failed || err != nil || abandoned {
			l.dropped++
		}
		switch {
		case err == nil && ln.event != nil && !failed && !abandoned:
			// The event file takes events again; its next fill reports anew.
			l.eventLogFull = nil
		case errors.Is(err, errEventFileFull):
			report = l.firstOf(&l.eventLogFull, errors.New("audit event file holds all the rotated files it may keep; events are dropped and counted until they are archived"))
		case err != nil:
			failed, l.failed = true, true
			report = l.firstOf(&l.writeFailure, fmt.Errorf("audit log write failed; logging is off for the rest of the process: %w", err))
		}
		l.mu.Unlock()
		report()
		if ln.written != nil {
			if failed && err == nil {
				err = errAuditLogFailed
			}
			ln.written <- err
		}
	}
	for _, f := range files {
		if err := f.Close(); err != nil {
			l.mu.Lock()
			report := l.firstOf(&l.writeFailure, fmt.Errorf("audit log close failed: %w", err))
			l.mu.Unlock()
			report()
		}
	}
}

func writeLine(files [2]auditFile, ln line) error {
	f, record := files[0], any(ln.envelope)
	if ln.event != nil {
		f, record = files[1], ln.event
	}
	b, err := jsonv2.Marshal(record)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Close writes every queued record and closes the files until ctx expires.
// It returns the first error of each kind and the number of records that did
// not reach the files, counting those still queued when ctx expires. Records
// sent after Close are dropped and counted, and reported only through
// onError.
func (l *JSONLAuditLog) Close(ctx context.Context) error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	var timeout error
	select {
	case <-l.done:
	case <-ctx.Done():
		timeout = ctx.Err()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	errs := []error{timeout, l.writeFailure, l.queueFull, l.offeredAfterClose, l.requiredLate, l.eventLogFull}
	switch {
	case timeout != nil && l.queued > 0:
		errs = append(errs, fmt.Errorf("the audit log dropped %d records and %d were still queued", l.dropped, l.queued))
	case l.dropped > 0:
		errs = append(errs, fmt.Errorf("the audit log dropped %d records", l.dropped))
	}
	return errors.Join(errs...)
}

// firstOf keeps err in *slot when it is the first of its kind and returns the
// report to make after l.mu is released. The callback runs asynchronously
// because a synchronous callback that closes the log would otherwise wait for
// the writer that called it. Callers hold l.mu.
func (l *JSONLAuditLog) firstOf(slot *error, err error) func() {
	if *slot != nil {
		return func() {}
	}
	*slot = err
	if l.onError == nil {
		return func() {}
	}
	return func() { go l.onError(err) }
}
