package acs

import "encoding/json"

// Version is the ACS specification version this module implements.
const Version = "0.1.0"

// JSONRPCVersion is the value of the jsonrpc member of every envelope.
const JSONRPCVersion = "2.0"

// Request is the request envelope an Observed Agent sends
// (request-envelope.json).
type Request struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	// ID is the JSON-RPC correlation identifier, a string or a number, kept
	// as its JSON text so the response echoes it byte for byte.
	ID     json.RawMessage `json:"id"`
	Params Params          `json:"params"`
}

// Params is the ACS part of a request envelope (request-envelope.json,
// AcsParams).
type Params struct {
	ACSVersion string   `json:"acs_version"`
	RequestID  string   `json:"request_id"`
	Timestamp  string   `json:"timestamp"`
	Nonce      *string  `json:"nonce,omitzero"`
	TenantID   *string  `json:"tenant_id,omitzero"`
	Metadata   Metadata `json:"metadata"`
	// Payload is the hook-specific payload, whose schema depends on the
	// method.
	Payload   json.RawMessage `json:"payload"`
	Signature *Signature      `json:"signature,omitzero"`
}

// Metadata identifies the agent and the session a request belongs to.
type Metadata struct {
	AgentID         string        `json:"agent_id"`
	AgentName       *string       `json:"agent_name,omitzero"`
	SessionID       string        `json:"session_id"`
	TurnID          *string       `json:"turn_id,omitzero"`
	ParentTurnID    *string       `json:"parent_turn_id,omitzero"`
	SessionState    *SessionState `json:"session_state,omitzero"`
	Environment     *string       `json:"environment,omitzero"`
	Platform        *string       `json:"platform,omitzero"`
	PlatformVersion *string       `json:"platform_version,omitzero"`
	UserContext     *UserContext  `json:"user_context,omitzero"`
}

// SessionState carries the Observed Agent's view of the session, which the
// Guardian cross-checks against its own.
type SessionState struct {
	// ChainHash is the latest chain head the Observed Agent knows of.
	ChainHash *string `json:"chain_hash,omitzero"`
}

// UserContext describes the user on whose behalf the agent acts.
type UserContext struct {
	UserID               *string  `json:"user_id,omitzero"`
	Roles                []string `json:"roles,omitzero"`
	AuthenticationMethod *string  `json:"authentication_method,omitzero"`
}

// Signature is the signature envelope of §10: an algorithm from the
// registry, the base64 signature value and the identifier of the key.
type Signature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	KeyID     string `json:"key_id"`
}

// SignatureAlgorithmHMACSHA256 is the ACS-Core baseline signature algorithm.
const SignatureAlgorithmHMACSHA256 = "HMAC-SHA256"

// Response is the response envelope a Guardian sends
// (response-envelope.json). Exactly one of Result and Error is set.
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	// ID echoes the request's identifier, or is the JSON null when the
	// identifier could not be determined.
	ID json.RawMessage `json:"id"`
	// Result is a Result for every method except handshake/hello, whose
	// result is a ServerHello.
	Result json.RawMessage `json:"result,omitzero"`
	Error  *Error          `json:"error,omitzero"`
}

// ResultTypeFinal is the only Result type v0.1 emits.
const ResultTypeFinal = "final"

// Result is the result of every method other than handshake/hello
// (response-envelope.json, AcsResult).
type Result struct {
	Type       string `json:"type"`
	ACSVersion string `json:"acs_version"`
	RequestID  string `json:"request_id"`
	Decision
	// Payload is method-specific response data, used by system/ping.
	Payload json.RawMessage `json:"payload,omitzero"`
	// ChainHash is the SessionContext head after this step's ContextEntry
	// was appended (§8.6).
	ChainHash string     `json:"chain_hash,omitzero"`
	Signature *Signature `json:"signature,omitzero"`
}
