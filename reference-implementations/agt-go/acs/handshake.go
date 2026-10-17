package acs

// Transports of handshake.json.
const (
	TransportHTTP  = "http"
	TransportHTTPS = "https"
	TransportStdio = "stdio"
)

// ProvenanceProducer values of the ClientHello (§7).
const (
	ProvenanceDeterministic = "deterministic"
	ProvenanceNone          = "none"
)

// The conformance profile names of docs/spec/conformance.md.
const (
	ProfileCore           = "acs-core"
	ProfileTrace          = "acs-trace"
	ProfileInspect        = "acs-inspect"
	ProfileInspectDynamic = "acs-inspect-dynamic"
	ProfileProvenance     = "acs-provenance"
	ProfileCrypto         = "acs-crypto"
	ProfileAudit          = "acs-audit"
)

// FailurePosture is the on_decision_failure posture of §6.4.
type FailurePosture string

// The two failure postures of §6.4.
const (
	FailureProceed FailurePosture = "proceed"
	FailureDeny    FailurePosture = "deny"
)

// ClientHello is the Observed Agent's half of the handshake
// (handshake.json, ClientHello).
type ClientHello struct {
	ACSVersionsSupported []string          `json:"acs_versions_supported"`
	MethodsImplemented   []string          `json:"methods_implemented"`
	TransportsSupported  []string          `json:"transports_supported"`
	MaxPayloadSizeBytes  *int64            `json:"max_payload_size_bytes,omitzero"`
	ProvenanceProducer   string            `json:"provenance_producer"`
	WrappedProtocols     []WrappedProtocol `json:"wrapped_protocols,omitzero"`
	ProfilesSupported    []string          `json:"profiles_supported,omitzero"`
}

// WrappedProtocol is a sub-protocol an Observed Agent tunnels over ACS,
// pinned to a version.
type WrappedProtocol struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
}

// ServerHello is the Guardian's half of the handshake (handshake.json,
// ServerHello).
type ServerHello struct {
	NegotiatedVersion            string         `json:"negotiated_version"`
	MethodsEvaluated             []string       `json:"methods_evaluated"`
	SelectedTransport            string         `json:"selected_transport"`
	SignatureAlgorithmsSupported []string       `json:"signature_algorithms_supported"`
	TimeoutConfig                TimeoutConfig  `json:"timeout_config"`
	SkewWindowMS                 int64          `json:"skew_window_ms"`
	OnDecisionFailure            FailurePosture `json:"on_decision_failure"`
	ApproverTypesSupported       []ApproverType `json:"approver_types_supported,omitzero"`
	PolicyRequiresProvenance     bool           `json:"policy_requires_provenance"`
	AgBOMSerializationsSupported []string       `json:"agbom_serializations_supported,omitzero"`
	TraceEmission                *TraceEmission `json:"trace_emission,omitzero"`
	ProfilesAccepted             []string       `json:"profiles_accepted"`
	// Signature signs the handshake response. §10 and ACS-Core require a
	// signature on every response, and handshake.json gives the ServerHello
	// no member for it, so it sits where Result carries its own.
	Signature *Signature `json:"signature,omitzero"`
}

// TraceEmission declares which standard trace formats a deployment emits.
type TraceEmission struct {
	OTelEnabled           bool    `json:"otel_enabled,omitzero"`
	OCSFEnabled           bool    `json:"ocsf_enabled,omitzero"`
	OTelCollectorEndpoint *string `json:"otel_collector_endpoint,omitzero"`
}

// TimeoutConfig is the negotiated decision timeout, by default and per
// method.
type TimeoutConfig struct {
	DefaultMS   int64            `json:"default_ms"`
	PerMethodMS map[string]int64 `json:"per_method_ms,omitzero"`
}
