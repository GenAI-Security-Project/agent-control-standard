// Command record sends the parity corpus to a running TypeScript reference
// Guardian and writes its answers. Run it through scripts/record-ts-cases.sh,
// which starts that Guardian at a known commit.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/tscases"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8787/acs", "the TypeScript Guardian's endpoint")
	out := flag.String("out", "agtbridge/testdata/ts-cases.json", "where to write the recording")
	commit := flag.String("ts-commit", "", "commit of the TypeScript tree being recorded")
	version := flag.String("spec-version", "", "the repository's version.txt")
	flag.Parse()
	if err := run(*url, *out, *commit, *version); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func run(url, out, commit, version string) error {
	rec := tscases.Recording{TSCommit: commit, SpecVersion: version, Cases: tscases.Corpus()}
	for ci := range rec.Cases {
		session := observedagent.NewUUID()
		for si := range rec.Cases[ci].Steps {
			step := &rec.Cases[ci].Steps[si]
			id := observedagent.NewUUID()
			rawID, _ := json.Marshal(id)
			body, err := json.Marshal(acs.Request{JSONRPC: acs.JSONRPCVersion, Method: step.Method, ID: rawID, Params: acs.Params{
				ACSVersion: acs.Version, RequestID: id, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Metadata: acs.Metadata{AgentID: "parity", SessionID: session}, Payload: step.Payload,
			}})
			if err != nil {
				return err
			}
			resp, err := http.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			var r struct {
				Result *acs.Decision `json:"result"`
				Error  *acs.Error    `json:"error"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return fmt.Errorf("%s step %d: %w: %s", rec.Cases[ci].Name, si, err, raw)
			}
			step.Result, step.Error = r.Result, r.Error
		}
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(b, '\n'), 0o644)
}
