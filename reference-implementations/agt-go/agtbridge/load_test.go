//go:build load

package agtbridge_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/tscases"
)

// TestLoad measures the Guardian over the evaluator ACS__POLICY__EVALUATOR
// names (agt, the default, or go): decisions per second (engine_saturated
// refusals not counted), latency of every step, the refusals, the opa
// processes alive at once and their memory (agt runs one per decision; go
// runs none), and the audit log's size on disk. It asserts only that the
// audit log lost, split and reordered no record it kept, and stayed within
// its rotation bound; `make load` runs it with the Makefile's EVALUATOR, and
// docs/load.md records the results the defaults rest on.
//
// ACS_LOAD_CLIENTS lists the concurrent clients per run (default
// 1,8,32,64,128,256), ACS_LOAD_STEPS the steps each client sends (default
// 20), ACS_LOAD_MAX_ENGINE_CALLS the Guardian's limit (default the library
// default), and ACS_LOAD_AUDIT_MAX_FILE_BYTES and ACS_LOAD_AUDIT_MAX_FILES
// the audit rotation (default none).
func TestLoad(t *testing.T) {
	clients := envInts(t, "ACS_LOAD_CLIENTS", []int{1, 8, 32, 64, 128, 256})
	steps := envInts(t, "ACS_LOAD_STEPS", []int{20})[0]
	maxEngineCalls := envInts(t, "ACS_LOAD_MAX_ENGINE_CALLS", []int{guardian.DefaultMaxEngineCalls})[0]
	rotation := guardian.JSONLRotation{
		MaxFileBytes: int64(envInts(t, "ACS_LOAD_AUDIT_MAX_FILE_BYTES", []int{0})[0]),
		MaxFiles:     envInts(t, "ACS_LOAD_AUDIT_MAX_FILES", []int{0})[0],
	}
	name := os.Getenv("ACS__POLICY__EVALUATOR")
	if name == "" {
		name = "agt"
	}
	evaluator, ok := recordedEvaluators[name]
	if !ok {
		t.Fatalf("evaluator %q is not built in; agt needs the agteval tag", name)
	}
	requests := loadRequests()
	signer := testSigner(t)
	t.Logf("evaluator=%s, max_engine_calls=%d, %d steps per client, audit rotation %d bytes x %d files", name, maxEngineCalls, steps, rotation.MaxFileBytes, rotation.MaxFiles)
	t.Logf("%8s %9s %8s %8s %8s %8s %10s %10s %12s", "clients", "decided/s", "p50", "p95", "p99", "max", "saturated", "opa_peak", "opa_rss_MiB")
	for _, n := range clients {
		dir := t.TempDir()
		audit, err := guardian.NewJSONLAuditLog(filepath.Join(dir, "envelopes.jsonl"), filepath.Join(dir, "events.jsonl"), rotation, guardian.JSONLQueue{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		g, err := guardian.New(guardian.Config{Engine: engineOver(t, evaluator(t)), Signer: signer, AuditLog: audit, MaxEngineCalls: maxEngineCalls})
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		peak := make(chan opaSample, 1)
		go sampleOPA(stop, peak)

		latencies := make([][]time.Duration, n)
		var saturated atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for c := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				latencies[c] = runClient(t, g, signer, requests, c, steps, &saturated)
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		close(stop)
		sample := <-peak
		if err := audit.Close(context.Background()); err != nil {
			t.Fatalf("audit log: %v", err)
		}

		all := slices.Concat(latencies...)
		slices.Sort(all)
		total := len(all)
		t.Logf("%8d %9.0f %8s %8s %8s %8s %10d %10d %12.0f", n, float64(int64(total)-saturated.Load())/elapsed.Seconds(),
			percentile(all, 50), percentile(all, 95), percentile(all, 99), all[total-1].Round(time.Millisecond), saturated.Load(), sample.processes, float64(sample.rssKiB)/1024)
		for _, log := range []string{"envelopes.jsonl", "events.jsonl"} {
			a := checkAuditLog(t, dir, log, rotation)
			t.Logf("%8s %s: %d records written, %d kept in %d files, %d bytes", "", log, a.written, a.kept, a.files, a.bytes)
		}
	}
}

// loadRequests is every toolCallRequest the parity corpus sends, allowed and
// denied alike, so the load exercises the same policy branches.
func loadRequests() []observedagent.Request {
	var requests []observedagent.Request
	for _, c := range tscases.Corpus() {
		for _, s := range c.Steps {
			if s.Method == acs.StepToolCallRequest {
				requests = append(requests, observedagent.Request{Method: s.Method, Payload: s.Payload})
			}
		}
	}
	return requests
}

func runClient(t *testing.T, g *guardian.Guardian, signer guardian.Signer, requests []observedagent.Request, client, steps int, saturated *atomic.Int64) []time.Duration {
	ctx := context.Background()
	c := &observedagent.Client{
		Transport: func(ctx context.Context, body []byte) ([]byte, error) { return g.Handle(ctx, body), nil },
		Signer:    signer, AgentID: "load", SessionID: observedagent.NewUUID(),
	}
	if o, err := c.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil {
		t.Errorf("client %d handshake: %v", client, err)
		return nil
	}
	latencies := make([]time.Duration, 0, steps)
	for i := range steps {
		start := time.Now()
		o, err := c.Send(ctx, requests[(client+i)%len(requests)])
		latencies = append(latencies, time.Since(start))
		if err != nil || o.Result == nil {
			t.Errorf("client %d step %d: %v", client, i, err)
			return latencies
		}
		if slices.Contains(o.Result.ReasonCodes, disposition.ReasonEngineSaturated) {
			saturated.Add(1)
		}
	}
	return latencies
}

type opaSample struct {
	processes int
	rssKiB    int
}

// sampleOPA reports the most opa processes this process had alive at once,
// and the most resident memory they held together, sampled every 5ms.
func sampleOPA(stop <-chan struct{}, peak chan<- opaSample) {
	var best opaSample
	self := strconv.Itoa(os.Getpid())
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			peak <- best
			return
		case <-ticker.C:
		}
		var now opaSample
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			status, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
			if err != nil {
				continue
			}
			fields := statusFields(string(status))
			if fields["Name"] == "opa" && fields["PPid"] == self {
				now.processes++
				rss, _ := strconv.Atoi(strings.TrimSuffix(fields["VmRSS"], " kB"))
				now.rssKiB += rss
			}
		}
		best.processes = max(best.processes, now.processes)
		best.rssKiB = max(best.rssKiB, now.rssKiB)
	}
}

func statusFields(status string) map[string]string {
	fields := map[string]string{}
	for line := range strings.SplitSeq(status, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

func percentile(sorted []time.Duration, p int) time.Duration {
	return sorted[(len(sorted)-1)*p/100].Round(time.Millisecond)
}

type auditLogSize struct {
	written, kept, files int
	bytes                int64
}

// checkAuditLog reads one audit log's files oldest first and requires that
// no record is split, that the kept records are the newest ones with
// consecutive seq numbers, and that the files stay within the rotation
// bound: max_file_bytes × (max_files + 1), each file past max_file_bytes by
// at most its one record. The writer numbers records from 1, so the last
// seq is the number written.
func checkAuditLog(t *testing.T, dir, name string, rotation guardian.JSONLRotation) auditLogSize {
	t.Helper()
	paths := []string{filepath.Join(dir, name)}
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%d", paths[0], i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		paths = append(paths, p)
	}
	slices.Reverse(paths)
	var size auditLogSize
	prev := 0
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		size.files++
		size.bytes += int64(len(content))
		if len(content) > 0 && content[len(content)-1] != '\n' {
			t.Errorf("%s ends inside a record", p)
		}
		lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		if rotation.MaxFileBytes > 0 && len(lines) > 1 && int64(len(content)-len(lines[len(lines)-1])-1) > rotation.MaxFileBytes {
			t.Errorf("%s holds %d bytes before its last record, past max_file_bytes %d", p, len(content), rotation.MaxFileBytes)
		}
		for _, line := range lines {
			var r struct {
				Seq int `json:"seq"`
			}
			if err := jsonv2.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("%s holds a line that is not one record: %v", p, err)
			}
			if prev != 0 && r.Seq != prev+1 {
				t.Errorf("%s: seq %d follows %d", p, r.Seq, prev)
			}
			prev = r.Seq
			size.kept++
		}
	}
	if rotation.MaxFileBytes > 0 && len(paths) > rotation.MaxFiles+1 {
		t.Errorf("%s has %d files, past max_files %d", name, len(paths), rotation.MaxFiles)
	}
	size.written = prev
	if rotation.MaxFileBytes == 0 && size.kept != size.written {
		t.Errorf("%s kept %d of %d records without rotation", name, size.kept, size.written)
	}
	return size
}

func envInts(t *testing.T, name string, fallback []int) []int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	var values []int
	for _, field := range strings.Split(raw, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || v <= 0 {
			t.Fatal(fmt.Errorf("%s: %q is not a positive integer", name, field))
		}
		values = append(values, v)
	}
	return values
}
