package acs

// Methods outside the steps/* namespace.
const (
	MethodHandshakeHello = "handshake/hello"
	MethodSystemPing     = "system/ping"
	MethodAgBOMSnapshot  = "agbom/snapshot"
	MethodAgBOMChanged   = "agbom/changed"
)

// The native steps/* hooks of §5.
const (
	StepSessionStart           = "steps/sessionStart"
	StepAgentTrigger           = "steps/agentTrigger"
	StepTurnStart              = "steps/turnStart"
	StepUserMessage            = "steps/userMessage"
	StepAgentResponse          = "steps/agentResponse"
	StepKnowledgeRetrieval     = "steps/knowledgeRetrieval"
	StepMemoryContextRetrieval = "steps/memoryContextRetrieval"
	StepMemoryStore            = "steps/memoryStore"
	StepToolCallRequest        = "steps/toolCallRequest"
	StepToolCallResult         = "steps/toolCallResult"
	StepPreCompact             = "steps/preCompact"
	StepPostCompact            = "steps/postCompact"
	StepSubagentStart          = "steps/subagentStart"
	StepSubagentStop           = "steps/subagentStop"
	StepSkillRegister          = "steps/skillRegister"
	StepSkillLoad              = "steps/skillLoad"
	StepSkillUnload            = "steps/skillUnload"
	StepTurnEnd                = "steps/turnEnd"
	StepSessionEnd             = "steps/sessionEnd"
)

// Method namespace prefixes of §3.
const (
	StepsPrefix     = "steps/"
	ProtocolsPrefix = "protocols/"
)

// StepTypeIntentExtension is the step_type of the ContextEntry that records
// an approved intent extension (§9.1).
const StepTypeIntentExtension = "intent_extension"
