package acs

// ErrorCode is a JSON-RPC error code: the JSON-RPC 2.0 codes and the ACS
// registry of §17.1.
type ErrorCode int

// The JSON-RPC 2.0 error codes ACS uses (§17).
const (
	ParseError     ErrorCode = -32700
	InvalidRequest ErrorCode = -32600
	MethodNotFound ErrorCode = -32601
	InvalidParams  ErrorCode = -32602
	InternalError  ErrorCode = -32603
)

// The ACS error code registry (§17.1).
const (
	SessionRefused          ErrorCode = -32000
	UnsupportedVersion      ErrorCode = -32001
	ProvenanceRequired      ErrorCode = -32002
	CapabilityNotNegotiated ErrorCode = -32003
	SignatureInvalid        ErrorCode = -32004
	ReplayDetected          ErrorCode = -32005
	TimestampOutOfWindow    ErrorCode = -32006
	ChainMismatch           ErrorCode = -32007
)

// Error is the error member of a response envelope.
type Error struct {
	Code    ErrorCode  `json:"code"`
	Message string     `json:"message"`
	Data    *ErrorData `json:"data,omitzero"`
	// Signature signs an error that answers an authenticated request.
	// response-envelope.json names no member for it; the error object
	// admits one, and the member takes AcsResult's name and shape.
	Signature *Signature `json:"signature,omitzero"`
}

// ErrorData is the data object §17.1 describes: a machine-readable reason,
// a human-readable message, and the fields specific to some codes.
type ErrorData struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
	// SupportedVersions accompanies UnsupportedVersion.
	SupportedVersions []string `json:"supported_versions,omitzero"`
	// Method accompanies CapabilityNotNegotiated.
	Method string `json:"method,omitzero"`
	// SkewWindowMS accompanies TimestampOutOfWindow.
	SkewWindowMS *int64 `json:"skew_window_ms,omitzero"`
}
