// Package agtbridge is a guardian.PolicyEngine over Microsoft's Agent
// Governance Toolkit (AGT), the engine of the TypeScript reference
// implementation beside this module.
//
// AGT's ACS policy-engine runtime is a Rust core with no official Go binding.
// This package evaluates AGT's policy bundle, unchanged, with OPA's Go library in process,
// and reproduces in Go the part of AGT's runtime (policy-engine/core at the
// commit agt.lock pins) that the reference's manifest uses: assembling the
// policy input from a snapshot at the pre_tool_call and post_tool_call
// intervention points, the egress annotator, and normalising the Rego
// result into a verdict, including AGT's fail-closed runtime_error denials.
// A manifest feature outside that part is refused when the engine is built.
// The reference's mapping.yaml turns each verdict into an ACS decision.
//
// This is the only package that knows AGT exists.
package agtbridge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// reasonMCPCallPending is the reason code of a wrapped tools/call denied
// because its MCP id is already awaiting a response.
const reasonMCPCallPending = "mcp_call_pending"

// DefaultAskTimeout is the ask_details.timeout_seconds of an Ask when
// Options.AskTimeout is zero.
const DefaultAskTimeout = 5 * time.Minute

// Options are what a deployment chooses beyond the manifest and the mapping.
type Options struct {
	// Approver is who resolves AGT's escalate verdict, sent as an ACS Ask.
	// AGT's manifest names no approver for ACS, so without one an escalate
	// is answered DENY with reason code approver_unavailable.
	Approver *acs.Approver
	// AskTimeout is an Ask's timeout; zero means DefaultAskTimeout.
	AskTimeout time.Duration
	// ToolAliases maps host tool names to manifest tool names before policy
	// evaluation. The ACS request and audit chain retain the host's name.
	ToolAliases map[string]string
}

// Engine is AGT behind guardian.PolicyEngine.
type Engine struct {
	runtime *runtime
	mapping *mapping
	opts    Options
}

var _ guardian.PolicyEngine = (*Engine)(nil)

// New builds the engine from the manifest and mapping at the given paths in
// fsys, compiling the manifest's Rego bundle once. The bundle is found
// relative to the manifest's directory, as AGT resolves it.
func New(ctx context.Context, fsys fs.FS, manifestPath, mappingPath string, opts Options) (*Engine, error) {
	switch {
	case opts.AskTimeout != 0 && opts.AskTimeout < time.Second:
		return nil, errors.New("agtbridge: AskTimeout is at least one second, the smallest timeout_seconds ask-details.json admits")
	case opts.AskTimeout%time.Second != 0:
		return nil, errors.New("agtbridge: AskTimeout must be a whole number of seconds")
	case opts.Approver != nil && (opts.Approver.Type == "" || opts.Approver.ID == ""):
		return nil, errors.New("agtbridge: an Approver needs a type and an id")
	}
	for source, target := range opts.ToolAliases {
		if strings.TrimSpace(source) == "" || strings.TrimSpace(target) == "" {
			return nil, errors.New("agtbridge: ToolAliases must not contain empty names")
		}
	}
	if opts.AskTimeout == 0 {
		opts.AskTimeout = DefaultAskTimeout
	}
	if opts.Approver != nil {
		approver := *opts.Approver
		if approver.Endpoint != nil {
			endpoint := *approver.Endpoint
			approver.Endpoint = &endpoint
		}
		if approver.Auth != nil {
			auth := *approver.Auth
			if auth.Method != nil {
				method := *auth.Method
				auth.Method = &method
			}
			approver.Auth = &auth
		}
		opts.Approver = &approver
	}
	opts.ToolAliases = cloneMap(opts.ToolAliases)
	src, err := fs.ReadFile(fsys, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("agtbridge: %w", err)
	}
	m, err := parseManifest(src)
	if err != nil {
		return nil, fmt.Errorf("agtbridge: %s: %w", manifestPath, err)
	}
	src, err = fs.ReadFile(fsys, mappingPath)
	if err != nil {
		return nil, fmt.Errorf("agtbridge: %w", err)
	}
	mp, err := parseMapping(src)
	if err != nil {
		return nil, fmt.Errorf("agtbridge: %w", err)
	}
	rt, err := newRuntime(ctx, fsys, path.Dir(manifestPath), m)
	if err != nil {
		return nil, fmt.Errorf("agtbridge: %s: %w", manifestPath, err)
	}
	return &Engine{runtime: rt, mapping: mp, opts: opts}, nil
}

// Policy implements guardian.PolicyEngine.
func (e *Engine) Policy() guardian.PolicyDescription {
	var d guardian.PolicyDescription
	if e.opts.Approver != nil {
		d.ApproverTypes = []acs.ApproverType{e.opts.Approver.Type}
	}
	return d
}

// Decide implements guardian.PolicyEngine. A step whose method maps to no
// intervention point the manifest configures is not governed by AGT, and is
// allowed.
func (e *Engine) Decide(ctx context.Context, in guardian.PolicyInput) (guardian.PolicyDecision, error) {
	state, err := readState(in.Session.PolicyState)
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	before := len(state.MCPCalls)
	p, err := project(in.Request, &state)
	if errors.Is(err, errMCPCallPending) {
		return guardian.PolicyDecision{Decision: acs.Decision{
			Disposition: acs.Deny,
			Reasoning:   "Another tools/call with this MCP id is still awaiting its response, so their results could not be told apart.",
			ReasonCodes: []string{reasonMCPCallPending},
		}}, nil
	}
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	req := p.req
	point, ok := e.mapping.point(req.Method)
	if _, configured := e.runtime.points[point]; !ok || !configured {
		pd := guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}
		p.settle(&state, acs.Allow)
		if len(state.MCPCalls) != before || p.outputs != nil {
			pd.State, err = jsonv2.Marshal(state)
		}
		return pd, err
	}
	var head struct {
		Tool acs.Tool `json:"tool"`
	}
	if err := jsonv2.Unmarshal(req.Params.Payload, &head); err != nil {
		return guardian.PolicyDecision{}, err
	}
	policyToolName := head.Tool.Name
	if alias := e.opts.ToolAliases[policyToolName]; alias != "" {
		policyToolName = alias
	}
	argument, err := e.mapping.policyTargetArgument(point, policyToolName)
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	var snapshot map[string]any
	switch point {
	case pointPreToolCall:
		snapshot, err = preToolCallSnapshot(req, state.IFCLabels, argument, policyToolName)
	case pointPostToolCall:
		snapshot, err = postToolCallSnapshot(req, state.IFCLabels, policyToolName)
	}
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	v, err := e.runtime.evaluate(ctx, point, snapshot)
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	d, err := e.mapping.decision(v, point, argument)
	if err != nil {
		return guardian.PolicyDecision{}, err
	}
	if err := p.readdress(d.Modifications); err != nil {
		return guardian.PolicyDecision{}, err
	}
	pd := guardian.PolicyDecision{Decision: d}
	// An absent result_labels leaves the session unchanged. An explicit empty
	// array clears it, as the TypeScript Guardian's persistIfcLabels does.
	if v.ResultLabelsPresent {
		state.IFCLabels = v.ResultLabels
	}
	p.settle(&state, d.Disposition)
	if v.ResultLabelsPresent || len(state.MCPCalls) != before || p.outputs != nil {
		if pd.State, err = jsonv2.Marshal(state); err != nil {
			return guardian.PolicyDecision{}, err
		}
	}
	if d.Disposition == acs.Ask {
		pd.Decision = e.ask(d)
	}
	return pd, nil
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

// policyState is what the engine keeps with a session: the
// information-flow labels AGT's last verdict returned as result_labels,
// which the next step supplies back as source labels, since AGT's core
// stores nothing; and the tool name of each wrapped MCP tools/call awaiting
// its response, by MCP id.
type policyState struct {
	IFCLabels []string          `json:"ifc_labels"`
	MCPCalls  map[string]string `json:"mcp_calls,omitzero"`
}

// initialLabels are the labels a session starts with, the TypeScript
// reference's (packages/guardian/src/session-context.ts).
var initialLabels = []string{"public"}

func readState(raw []byte) (policyState, error) {
	if raw == nil {
		return policyState{IFCLabels: slices.Clone(initialLabels)}, nil
	}
	var s policyState
	if err := jsonv2.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("the session's policy state cannot be read: %w", err)
	}
	return s, nil
}

// ask completes an Ask with its details, or answers DENY when no approver is
// configured: an Ask nobody can resolve is a denial with its reason stated.
func (e *Engine) ask(d acs.Decision) acs.Decision {
	if e.opts.Approver == nil {
		d.Disposition = acs.Deny
		d.Reasoning = strings.TrimSpace(d.Reasoning + " No approver is configured for this Guardian, so the step is denied.")
		d.ReasonCodes = append(slices.Clip(d.ReasonCodes), "approver_unavailable")
		return d
	}
	d.AskDetails = &acs.AskDetails{
		Approver:       *e.opts.Approver,
		Question:       d.Reasoning,
		TimeoutSeconds: int64(e.opts.AskTimeout / time.Second),
	}
	return d
}
