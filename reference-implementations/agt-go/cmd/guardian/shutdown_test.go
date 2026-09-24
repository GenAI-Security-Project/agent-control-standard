package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

type cancellationEngine struct {
	started chan struct{}
}

const shutdownTestSecret = "0123456789abcdef0123456789abcdef"

func (e *cancellationEngine) Policy() guardian.PolicyDescription {
	return guardian.PolicyDescription{}
}

func (e *cancellationEngine) Decide(ctx context.Context, _ guardian.PolicyInput) (guardian.PolicyDecision, error) {
	close(e.started)
	<-ctx.Done()
	return guardian.PolicyDecision{}, ctx.Err()
}

func TestShutdownDeliversCancellationDenial(t *testing.T) {
	for range 5 {
		engine := &cancellationEngine{started: make(chan struct{})}
		signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k1", Secret: []byte(shutdownTestSecret)})
		if err != nil {
			t.Fatal(err)
		}
		g, err := guardian.New(guardian.Config{Engine: engine, Signer: signer, DecisionTimeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: g}
		served := make(chan error, 1)
		go func() { served <- server.Serve(listener) }()
		client := &observedagent.Client{
			Signer: signer, AgentID: "agent", SessionID: observedagent.NewUUID(),
			Transport: func(ctx context.Context, body []byte) ([]byte, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listener.Addr().String(), bytes.NewReader(body))
				if err != nil {
					return nil, err
				}
				response, err := http.DefaultClient.Do(req)
				if err != nil {
					return nil, err
				}
				defer response.Body.Close()
				return io.ReadAll(response.Body)
			},
		}
		if outcome, err := client.Handshake(context.Background(), observedagent.DefaultHello(acs.StepToolCallRequest)); err != nil || outcome.Hello == nil {
			t.Fatalf("handshake: %v %s", err, outcome.Raw)
		}
		answer := make(chan observedagent.Outcome, 1)
		transportErr := make(chan error, 1)
		go func() {
			outcome, err := client.Send(context.Background(), observedagent.Request{Method: acs.StepToolCallRequest, Payload: acs.ToolCallRequestPayload{
				Tool: acs.Tool{Name: "Bash"}, Arguments: map[string]acs.ToolArgument{"command": {Value: []byte(`"ls"`)}},
			}})
			answer <- outcome
			transportErr <- err
		}()
		<-engine.started
		if err := shutdown(server, g, 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := <-transportErr; err != nil {
			t.Fatalf("request lost during shutdown: %v", err)
		}
		outcome := <-answer
		if outcome.Result == nil || !outcome.Verified || outcome.Result.Disposition != acs.Deny ||
			!slices.Contains(outcome.Result.ReasonCodes, disposition.ReasonShuttingDown) {
			t.Fatalf("shutdown answer: %s", outcome.Raw)
		}
		if err := <-served; err != nil && err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}
}
