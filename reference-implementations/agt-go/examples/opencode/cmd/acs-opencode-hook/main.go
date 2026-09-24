// Command acs-opencode-hook translates OpenCode tool events into signed ACS steps.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/hostadapter"
)

const (
	beforeEvent        = "execute.before"
	afterEvent         = "execute.after"
	defaultGuardianURL = "http://127.0.0.1:8787/acs"
	defaultAgentID     = "opencode"
	defaultTimeout     = 10 * time.Second
	defaultMaxInput    = 1 << 20
)

type options struct {
	guardianURL   string
	secretFile    string
	stateDir      string
	auditLog      string
	agentID       string
	timeout       time.Duration
	maxInputBytes int64
}

type hookInput struct {
	Event     string          `json:"event"`
	SessionID string          `json:"session_id"`
	MessageID string          `json:"message_id"`
	CallID    string          `json:"call_id"`
	Tool      string          `json:"tool"`
	Input     json.RawMessage `json:"input"`
	Status    string          `json:"status,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     json.RawMessage `json:"error,omitempty"`
}

type hookOutput struct {
	Decision      acs.Disposition `json:"decision"`
	Reasoning     string          `json:"reasoning,omitempty"`
	UpdatedInput  any             `json:"updated_input,omitempty"`
	UpdatedResult any             `json:"updated_result,omitempty"`
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func execute(args []string, input io.Reader, output, errOutput io.Writer) int {
	if err := run(args, input, output); err == nil {
		return 0
	} else {
		fmt.Fprintln(errOutput, "acs-opencode-hook:", err)
	}
	if err := writeOutput(output, hookOutput{Decision: acs.Deny, Reasoning: "the ACS policy adapter could not evaluate this tool event"}); err != nil {
		fmt.Fprintln(errOutput, "acs-opencode-hook: write denial:", err)
		return 2
	}
	return 0
}

func run(args []string, input io.Reader, output io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	event, err := readEvent(input, opts.maxInputBytes)
	if err != nil {
		return err
	}
	payload, method, err := payloadFor(event, opts.agentID)
	if err != nil {
		return err
	}
	client, err := hostadapter.New(hostadapter.Config{
		GuardianURL: opts.guardianURL, HMACSecretFile: opts.secretFile,
		StateDir: opts.stateDir, AuditLog: opts.auditLog, AgentID: opts.agentID,
		Methods: []string{acs.StepToolCallRequest, acs.StepToolCallResult},
		Timeout: opts.timeout, MaxBodyBytes: opts.maxInputBytes,
	})
	if err != nil {
		return err
	}
	evaluation, err := client.Evaluate(context.Background(), hostadapter.Step{
		SessionKey: event.SessionID,
		TurnID:     event.MessageID,
		CallID:     event.CallID,
		Method:     method,
		Payload:    payload,
	})
	if err != nil {
		return err
	}
	response := hookOutput{Decision: evaluation.Decision.Disposition, Reasoning: evaluation.Decision.Reasoning}
	if evaluation.Decision.Disposition == acs.Modify {
		switch method {
		case acs.StepToolCallRequest:
			response.UpdatedInput, err = hostadapter.ModifiedToolCallInput(evaluation.ModifiedPayload, payload.(acs.ToolCallRequestPayload))
		case acs.StepToolCallResult:
			response.UpdatedResult, err = hostadapter.ModifiedToolCallResult(evaluation.ModifiedPayload, payload.(acs.ToolCallResultPayload))
		}
		if err != nil {
			response = hookOutput{Decision: acs.Deny, Reasoning: "the OpenCode plugin cannot apply the Guardian modification"}
		}
	}
	return writeOutput(output, response)
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("acs-opencode-hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := options{}
	flags.StringVar(&options.guardianURL, "guardian-url", defaultGuardianURL, "ACS Guardian endpoint")
	flags.StringVar(&options.secretFile, "hmac-secret-file", "", "file holding shared HMAC keying material")
	flags.StringVar(&options.stateDir, "state-dir", ".acs/opencode", "directory for negotiated session state")
	flags.StringVar(&options.auditLog, "audit-log", ".acs/opencode-audit.jsonl", "file for fail-open decision audit events")
	flags.StringVar(&options.agentID, "agent-id", defaultAgentID, "ACS agent identity")
	flags.DurationVar(&options.timeout, "timeout", defaultTimeout, "maximum handshake round trip")
	flags.Int64Var(&options.maxInputBytes, "max-input-bytes", defaultMaxInput, "largest hook input accepted")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if options.secretFile == "" {
		return options, errors.New("--hmac-secret-file is required")
	}
	if options.guardianURL == "" || options.stateDir == "" || options.auditLog == "" || options.agentID == "" {
		return options, errors.New("--guardian-url, --state-dir, --audit-log and --agent-id must not be empty")
	}
	if options.timeout <= 0 || options.maxInputBytes <= 0 {
		return options, errors.New("--timeout and --max-input-bytes must be positive")
	}
	return options, nil
}

func readEvent(input io.Reader, maxBytes int64) (hookInput, error) {
	var event hookInput
	data, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return event, fmt.Errorf("read hook input: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return event, fmt.Errorf("hook input exceeds %d bytes", maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&event); err != nil {
		return event, fmt.Errorf("read hook input: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return event, errors.New("hook input must contain one JSON object")
	}
	if event.SessionID == "" || event.MessageID == "" || event.CallID == "" || event.Tool == "" || len(event.Input) == 0 {
		return event, errors.New("hook input requires session_id, message_id, call_id, tool and input")
	}
	if event.Event != beforeEvent && event.Event != afterEvent {
		return event, fmt.Errorf("unsupported OpenCode event %q", event.Event)
	}
	if event.Event == afterEvent && event.Status != "completed" && event.Status != "error" {
		return event, errors.New("execute.after requires status completed or error")
	}
	return event, nil
}

func payloadFor(event hookInput, agentID string) (any, string, error) {
	if event.Event == beforeEvent {
		payload, err := hostadapter.ToolCallRequest(event.Tool, event.Input)
		return payload, acs.StepToolCallRequest, err
	}
	exitStatus := "success"
	output := event.Result
	if event.Status == "error" {
		exitStatus = "failure"
		output = event.Error
	}
	if len(output) == 0 {
		output = json.RawMessage("null")
	}
	sessionID := hostadapter.SessionUUID(agentID, event.SessionID)
	requestID := hostadapter.RequestUUID(sessionID, acs.StepToolCallRequest, event.CallID)
	return hostadapter.ToolCallResult(event.Tool, requestID, exitStatus, output), acs.StepToolCallResult, nil
}

func writeOutput(output io.Writer, response hookOutput) error {
	return json.NewEncoder(output).Encode(response)
}
