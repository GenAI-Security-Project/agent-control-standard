package acs

import "encoding/json"

// SessionStartPayload is the payload of steps/sessionStart
// (hooks/session-start.json).
type SessionStartPayload struct {
	UserIdentity    json.RawMessage `json:"user_identity,omitzero"`
	PolicyMode      *string         `json:"policy_mode,omitzero"`
	Intent          *Intent         `json:"intent,omitzero"`
	PlatformContext json.RawMessage `json:"platform_context,omitzero"`
}

// AgentTriggerPayload is the payload of steps/agentTrigger
// (hooks/agent-trigger.json).
type AgentTriggerPayload struct {
	TriggerType   string          `json:"trigger_type"`
	TriggerSource json.RawMessage `json:"trigger_source,omitzero"`
	Intent        *Intent         `json:"intent,omitzero"`
}

// SessionEndPayload is the payload of steps/sessionEnd
// (hooks/session-end.json).
type SessionEndPayload struct {
	Reason         string          `json:"reason"`
	Summary        json.RawMessage `json:"summary,omitzero"`
	FinalChainHash *string         `json:"final_chain_hash,omitzero"`
}

// SystemPingPayload is the payload of system/ping (hooks/system-ping.json).
type SystemPingPayload struct {
	Echo *string `json:"echo,omitzero"`
}

// PingStatusOK is the status system/ping reports (§13).
const PingStatusOK = "ok"

// SystemPingResponse is the payload of a system/ping result (§13).
type SystemPingResponse struct {
	Status          string  `json:"status"`
	Echo            *string `json:"echo,omitzero"`
	ServerTimestamp string  `json:"server_timestamp"`
}

// Tool identifies the tool a tool hook concerns.
type Tool struct {
	Name     string  `json:"name"`
	Version  *string `json:"version,omitzero"`
	Provider *string `json:"provider,omitzero"`
}

// ToolArgument is one argument of a tool call and its optional provenance.
type ToolArgument struct {
	Value      json.RawMessage `json:"value"`
	Provenance *Provenance     `json:"provenance,omitzero"`
}

// ToolCallIntent is the natural-language framing of a tool call.
type ToolCallIntent struct {
	Description *string `json:"description,omitzero"`
	Goal        *string `json:"goal,omitzero"`
}

// ToolCallRequestPayload is the payload of steps/toolCallRequest
// (hooks/tool-call-request.json).
type ToolCallRequestPayload struct {
	Tool       Tool                    `json:"tool"`
	Operation  *string                 `json:"operation,omitzero"`
	Capability *string                 `json:"capability,omitzero"`
	Arguments  map[string]ToolArgument `json:"arguments"`
	RawCommand *string                 `json:"raw_command,omitzero"`
	Intent     *ToolCallIntent         `json:"intent,omitzero"`
}

// ToolOutput is one output of a tool call and its optional provenance.
type ToolOutput struct {
	Value      json.RawMessage `json:"value"`
	Provenance *Provenance     `json:"provenance,omitzero"`
}

// ToolCallResultPayload is the payload of steps/toolCallResult
// (hooks/tool-call-result.json).
type ToolCallResultPayload struct {
	Tool         Tool         `json:"tool"`
	Operation    *string      `json:"operation,omitzero"`
	RequestIDRef *string      `json:"request_id_ref,omitzero"`
	ExitStatus   string       `json:"exit_status"`
	Outputs      []ToolOutput `json:"outputs"`
	DurationMS   *int64       `json:"duration_ms,omitzero"`
}

// Digest is an integrity digest over a skill's complete loadable artifact.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// SkillDefinition is the loadable artifact of a registered skill; the
// Guardian reads only its digest.
type SkillDefinition struct {
	Digest Digest `json:"digest"`
}

// SkillRegisterPayload is steps/skillRegister's payload
// (hooks/skill-register.json), its optional descriptors left to the engine.
type SkillRegisterPayload struct {
	SkillID              string          `json:"skill_id"`
	Definition           SkillDefinition `json:"definition"`
	DeclaredCapabilities json.RawMessage `json:"declared_capabilities"`
}

// SkillLoadPayload is steps/skillLoad's payload (hooks/skill-load.json),
// its optional members left to the engine.
type SkillLoadPayload struct {
	SkillID     string          `json:"skill_id"`
	Digest      Digest          `json:"digest"`
	LoadTrigger string          `json:"load_trigger"`
	LoadPath    json.RawMessage `json:"load_path"`
}

// CompactSummary is a postCompact summary and its lineage.
type CompactSummary struct {
	Value      string     `json:"value"`
	Provenance Provenance `json:"provenance"`
}

// PostCompactPayload is steps/postCompact's payload
// (hooks/post-compact.json).
type PostCompactPayload struct {
	Summary              CompactSummary `json:"summary"`
	EntriesCompacted     []string       `json:"entries_compacted"`
	PreCompactChainHash  string         `json:"pre_compact_chain_hash"`
	PostCompactChainHash string         `json:"post_compact_chain_hash"`
	LineageDepthAfter    *int64         `json:"lineage_depth_after,omitzero"`
}

// OriginAgentGenerated is the origin a postCompact summary must carry.
const OriginAgentGenerated = "agent_generated"
