// Command acs-codex-hook translates Codex PreToolUse input into a signed ACS step.
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
	defaultGuardianURL = "http://127.0.0.1:8787/acs"
	defaultAgentID     = "codex"
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
	SessionID string          `json:"session_id"`
	TurnID    string          `json:"turn_id"`
	ToolUseID string          `json:"tool_use_id"`
	Event     string          `json:"hook_event_name"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type hookOutput struct {
	HookSpecificOutput struct {
		Event    string `json:"hookEventName"`
		Decision string `json:"permissionDecision,omitempty"`
		Reason   string `json:"permissionDecisionReason,omitempty"`
		Updated  any    `json:"updatedInput,omitempty"`
	} `json:"hookSpecificOutput"`
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func execute(args []string, input io.Reader, output, errOutput io.Writer) int {
	if err := run(args, input, output); err == nil {
		return 0
	} else {
		fmt.Fprintln(errOutput, "acs-codex-hook:", err)
	}
	if err := writeDecision(output, acs.Decision{Disposition: acs.Deny, Reasoning: "the ACS policy adapter could not evaluate this tool call"}, "PreToolUse", nil); err != nil {
		fmt.Fprintln(errOutput, "acs-codex-hook: write denial:", err)
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
	payload, err := hostadapter.ToolCallRequest(event.ToolName, event.ToolInput)
	if err != nil {
		return err
	}
	client, err := hostadapter.New(hostadapter.Config{
		GuardianURL: opts.guardianURL, HMACSecretFile: opts.secretFile,
		StateDir: opts.stateDir, AuditLog: opts.auditLog, AgentID: opts.agentID,
		Methods: []string{acs.StepToolCallRequest}, Timeout: opts.timeout, MaxBodyBytes: opts.maxInputBytes,
	})
	if err != nil {
		return err
	}
	evaluation, err := client.Evaluate(context.Background(), hostadapter.Step{
		SessionKey: event.SessionID,
		TurnID:     event.TurnID,
		CallID:     event.ToolUseID,
		Method:     acs.StepToolCallRequest,
		Payload:    payload,
	})
	if err != nil {
		return err
	}
	var update any
	if evaluation.Decision.Disposition == acs.Modify {
		var modified map[string]any
		modified, err = hostadapter.ModifiedToolCallInput(evaluation.ModifiedPayload, payload)
		if err == nil {
			if _, ok := modified["command"].(string); !ok {
				err = errors.New("a Codex Bash update requires a string command")
			}
		}
		update = modified
		if err != nil {
			evaluation.Decision = acs.Decision{Disposition: acs.Deny, Reasoning: "the Codex hook cannot apply the Guardian modification"}
		}
	}
	return writeDecision(output, evaluation.Decision, event.Event, update)
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("acs-codex-hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := options{}
	guardianURL := os.Getenv("ACS_GUARDIAN_URL")
	if guardianURL == "" {
		guardianURL = defaultGuardianURL
	}
	flags.StringVar(&options.guardianURL, "guardian-url", guardianURL, "ACS Guardian endpoint")
	flags.StringVar(&options.secretFile, "hmac-secret-file", "", "file holding shared HMAC keying material")
	flags.StringVar(&options.stateDir, "state-dir", ".acs/codex", "directory for negotiated session state")
	flags.StringVar(&options.auditLog, "audit-log", ".acs/codex-audit.jsonl", "file for fail-open decision audit events")
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
	if event.SessionID == "" || event.TurnID == "" || event.ToolUseID == "" || event.Event != "PreToolUse" || event.ToolName == "" || len(event.ToolInput) == 0 {
		return event, errors.New("hook input requires session_id, turn_id, tool_use_id, hook_event_name PreToolUse, tool_name and tool_input")
	}
	return event, nil
}

func writeDecision(output io.Writer, decision acs.Decision, event string, updated any) error {
	response := hookOutput{}
	response.HookSpecificOutput.Event = event
	response.HookSpecificOutput.Reason = decision.Reasoning
	switch decision.Disposition {
	case acs.Allow:
		response.HookSpecificOutput.Reason = ""
	case acs.Modify:
		response.HookSpecificOutput.Decision = "allow"
		response.HookSpecificOutput.Updated = updated
	default:
		response.HookSpecificOutput.Decision = "deny"
	}
	return json.NewEncoder(output).Encode(response)
}
