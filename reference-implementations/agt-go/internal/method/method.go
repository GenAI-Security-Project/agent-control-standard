// Package method is the Guardian's method table: every method the standard
// defines, how the Guardian routes it, and which dispositions each hook
// permits (hooks.md, "Decision"). Wrapped protocols route through a registry
// of handlers, one per protocol name.
package method

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// Kind is how the Guardian routes a method.
type Kind int

// The routes of the method table.
const (
	// Undefined is a method the standard does not define: MethodNotFound.
	Undefined Kind = iota
	// Handshake is handshake/hello.
	Handshake
	// Ping is system/ping.
	Ping
	// Hook is a native steps/* hook.
	Hook
	// Wrapped is a protocols/<NAME>/<method> call.
	Wrapped
	// Unsupported is a method the standard defines and this Guardian never
	// negotiates, the Inspect profile's agbom/*: CapabilityNotNegotiated.
	Unsupported
)

// HookRule is the rule a native hook's decision follows.
type HookRule struct {
	// Permitted lists the dispositions the hook allows (hooks.md).
	Permitted []acs.Disposition
}

// Permits reports whether d is allowed at the hook.
func (r HookRule) Permits(d acs.Disposition) bool { return slices.Contains(r.Permitted, d) }

var (
	allowOnly      = []acs.Disposition{acs.Allow}
	allowDeny      = []acs.Disposition{acs.Allow, acs.Deny}
	allowDenyMod   = []acs.Disposition{acs.Allow, acs.Deny, acs.Modify}
	allowModify    = []acs.Disposition{acs.Allow, acs.Modify}
	allFive        = []acs.Disposition{acs.Allow, acs.Deny, acs.Modify, acs.Ask, acs.Defer}
	wrappedAllowed = allFive
)

// hooks is hooks.md's "Decision" line for every native hook. Audit-only and
// not decision-eligible hooks permit only ALLOW.
var hooks = map[string]HookRule{
	acs.StepSessionStart:           {allowDeny},
	acs.StepAgentTrigger:           {allowDenyMod},
	acs.StepTurnStart:              {allowDeny},
	acs.StepUserMessage:            {allowDenyMod},
	acs.StepAgentResponse:          {allowDenyMod},
	acs.StepKnowledgeRetrieval:     {allowDenyMod},
	acs.StepMemoryContextRetrieval: {allowDenyMod},
	acs.StepMemoryStore:            {allowDenyMod},
	acs.StepToolCallRequest:        {allFive},
	acs.StepToolCallResult:         {allowDenyMod},
	acs.StepPreCompact:             {allowDeny},
	acs.StepPostCompact:            {allowModify},
	acs.StepSubagentStart:          {allowDeny},
	acs.StepSubagentStop:           {allowOnly},
	acs.StepSkillRegister:          {allowDeny},
	acs.StepSkillLoad:              {allowDeny},
	acs.StepSkillUnload:            {allowOnly},
	acs.StepTurnEnd:                {allowOnly},
	acs.StepSessionEnd:             {allowOnly},
}

// Hooks lists every native hook, sorted.
func Hooks() []string {
	names := make([]string, 0, len(hooks))
	for name := range hooks {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// WrappedHandler reads a wrapped protocol's message for the policy engine.
// It is the only protocol-specific part of a wrapped call: authentication,
// validation of the envelope, the SessionContext append, the decision and
// the signature are the Guardian's, shared with the native hooks.
type WrappedHandler interface {
	// Protocol is the protocol name as it appears in
	// protocols/<NAME>/<method> and in the ClientHello's wrapped_protocols.
	Protocol() string
	// Supports reports whether the handler reads method, the part after
	// protocols/<NAME>/; negotiation evaluates only these.
	Supports(method string) bool
	// Check validates the wrapped message of method and returns an error
	// naming what is wrong.
	Check(method string, payload json.RawMessage) error
	// ParameterOverridePointer returns the JSON pointer an override of the
	// named argument addresses in this protocol's request payload.
	ParameterOverridePointer(argument string) string
}

// Table routes methods. It is built once and read concurrently.
type Table struct {
	wrapped map[string]WrappedHandler
}

// NewTable returns the method table with the given wrapped-protocol
// handlers registered.
func NewTable(handlers ...WrappedHandler) *Table {
	t := &Table{wrapped: map[string]WrappedHandler{}}
	for _, h := range handlers {
		t.wrapped[h.Protocol()] = h
	}
	return t
}

// Route returns how the Guardian answers name.
func (t *Table) Route(name string) Kind {
	switch {
	case name == acs.MethodHandshakeHello:
		return Handshake
	case name == acs.MethodSystemPing:
		return Ping
	case name == acs.MethodAgBOMSnapshot, name == acs.MethodAgBOMChanged:
		return Unsupported
	case strings.HasPrefix(name, acs.ProtocolsPrefix), strings.HasPrefix(name, wrappedPrefix):
		return Wrapped
	}
	if _, ok := hooks[name]; ok {
		return Hook
	}
	return Undefined
}

// HookRule returns the rule of a native hook or of a wrapped call.
func (t *Table) HookRule(name string) HookRule {
	if r, ok := hooks[name]; ok {
		return r
	}
	return HookRule{wrappedAllowed}
}

// WrappedHandler returns the handler registered for a wrapped call's
// protocol and the method within it, and false when no handler is
// registered or it does not read the method.
func (t *Table) WrappedHandler(name string) (WrappedHandler, string, bool) {
	protocol, _, method, ok := SplitWrapped(name)
	if !ok {
		return nil, "", false
	}
	for registered, h := range t.wrapped {
		if strings.EqualFold(registered, protocol) && h.Supports(method) {
			return h, method, true
		}
	}
	return nil, "", false
}

// Evaluates reports whether name is a wrapped call a registered handler
// reads.
func (t *Table) Evaluates(name string) bool {
	_, _, ok := t.WrappedHandler(name)
	return ok
}

// Protocols lists the registered wrapped protocols.
func (t *Table) Protocols() []string {
	names := make([]string, 0, len(t.wrapped))
	for name := range t.wrapped {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// wrappedPrefix starts the explicit-version wrapped form,
// wrapped:<protocol>-<version>/<method> (§3).
const wrappedPrefix = "wrapped:"

// SplitWrapped splits protocols/<NAME>/<method> and the explicit-version
// form wrapped:<name>-<version>/<method>. The protocol name is returned as
// written; version is empty for the protocols/ form, which pins none.
func SplitWrapped(name string) (protocol, version, method string, ok bool) {
	rest, explicit := strings.CutPrefix(name, wrappedPrefix)
	if !explicit {
		if rest, ok = strings.CutPrefix(name, acs.ProtocolsPrefix); !ok {
			return "", "", "", false
		}
	}
	protocol, method, ok = strings.Cut(rest, "/")
	if explicit {
		protocol, version, _ = strings.Cut(protocol, "-")
		ok = ok && version != ""
	}
	if !ok || protocol == "" || method == "" {
		return "", "", "", false
	}
	return protocol, version, method, true
}
