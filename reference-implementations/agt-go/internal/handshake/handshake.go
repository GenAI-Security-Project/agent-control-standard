// Package handshake negotiates a session (§4): it answers a ClientHello with
// the ServerHello the Guardian can honour, or with the refusal §17.1 names.
package handshake

import (
	"slices"
	"strconv"
	"strings"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
)

// Offer is everything the Guardian can do, before it reads the client's
// half.
type Offer struct {
	// Version is the ACS version the Guardian implements.
	Version string
	// Hooks lists the native hooks the Guardian evaluates.
	Hooks []string
	// Wrapped is the wrapped protocols the Guardian has handlers for.
	Wrapped Wrapped
	// Transport is the transport the Guardian is serving this session on.
	Transport                string
	SignatureAlgorithms      []string
	TimeoutConfig            acs.TimeoutConfig
	SkewWindowMS             int64
	OnDecisionFailure        acs.FailurePosture
	ApproverTypes            []acs.ApproverType
	PolicyRequiresProvenance bool
}

// Wrapped is what negotiation needs of the wrapped-protocol registry.
type Wrapped interface {
	// Evaluates reports whether a registered handler reads a wrapped
	// method, in either of its forms.
	Evaluates(method string) bool
}

// Refusal is a handshake the Guardian refuses, with the §17.1 code and data.
type Refusal struct {
	Code acs.ErrorCode
	Data acs.ErrorData
}

// CoreMethods returns the ACS-Core hooks a complete Observed Agent implements.
// A Guardian negotiates the subset each Observed Agent actually offers.
func CoreMethods() []string {
	return []string{
		acs.StepSessionStart,
		acs.StepToolCallRequest,
		acs.StepToolCallResult,
		acs.StepAgentResponse,
		acs.StepSessionEnd,
		acs.StepUserMessage,
	}
}

// Negotiate answers client with a ServerHello, or refuses it.
func Negotiate(client acs.ClientHello, o Offer) (acs.ServerHello, *Refusal) {
	version, ok := selectVersion(client.ACSVersionsSupported, o.Version)
	if !ok {
		return acs.ServerHello{}, &Refusal{Code: acs.UnsupportedVersion, Data: acs.ErrorData{
			Reason:            "unsupported_version",
			Message:           "none of the offered ACS versions shares this Guardian's major version",
			SupportedVersions: []string{o.Version},
		}}
	}
	if o.PolicyRequiresProvenance && client.ProvenanceProducer == acs.ProvenanceNone {
		return acs.ServerHello{}, &Refusal{Code: acs.ProvenanceRequired, Data: acs.ErrorData{
			Reason:  "provenance_required",
			Message: "the policy requires provenance and the client declared provenance_producer none",
		}}
	}
	if !slices.Contains(client.TransportsSupported, o.Transport) {
		return acs.ServerHello{}, &Refusal{Code: acs.SessionRefused, Data: acs.ErrorData{
			Reason:  "transport_unsupported",
			Message: "the Observed Agent does not support " + o.Transport + ", the transport this Guardian serves",
		}}
	}
	profiles := []string{}
	if slices.Contains(client.ProfilesSupported, acs.ProfileCore) {
		profiles = append(profiles, acs.ProfileCore)
	}
	return acs.ServerHello{
		NegotiatedVersion:            version,
		MethodsEvaluated:             evaluated(client, o),
		SelectedTransport:            o.Transport,
		SignatureAlgorithmsSupported: o.SignatureAlgorithms,
		TimeoutConfig:                o.TimeoutConfig,
		SkewWindowMS:                 o.SkewWindowMS,
		OnDecisionFailure:            o.OnDecisionFailure,
		ApproverTypesSupported:       o.ApproverTypes,
		PolicyRequiresProvenance:     o.PolicyRequiresProvenance,
		ProfilesAccepted:             profiles,
	}, nil
}

// evaluated is the client's methods_implemented narrowed to what the
// Guardian evaluates: its hooks, and the wrapped methods a handler reads, of
// a protocol the client declared in wrapped_protocols.
func evaluated(client acs.ClientHello, o Offer) []string {
	methods := []string{}
	for _, m := range client.MethodsImplemented {
		if slices.Contains(methods, m) {
			continue
		}
		if slices.Contains(o.Hooks, m) || (o.Wrapped != nil && o.Wrapped.Evaluates(m) && declares(client, m)) {
			methods = append(methods, m)
		}
	}
	return methods
}

// declares reports whether the client listed the protocol of wrapped
// method m in wrapped_protocols, at the version an explicit-version method
// pins.
func declares(client acs.ClientHello, m string) bool {
	protocol, version, _, _ := method.SplitWrapped(m)
	return slices.ContainsFunc(client.WrappedProtocols, func(w acs.WrappedProtocol) bool {
		return strings.EqualFold(string(w.Protocol), protocol) && (version == "" || w.Version == version)
	})
}

// SameMajor reports whether version shares ours's major version, the
// compatibility rule of §3.
func SameMajor(version, ours string) bool {
	a, okA := major(version)
	b, okB := major(ours)
	return okA && okB && a == b
}

// selectVersion picks the Guardian's own version when the client offers it,
// and otherwise the highest offered version that shares its major version.
func selectVersion(offered []string, ours string) (string, bool) {
	if slices.Contains(offered, ours) {
		return ours, true
	}
	var best string
	for _, v := range offered {
		if SameMajor(v, ours) && (best == "" || less(best, v)) {
			best = v
		}
	}
	return best, best != ""
}

func major(v string) (int, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[0])
	return n, err == nil
}

// less compares two X.Y.Z versions numerically.
func less(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range 3 {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}
