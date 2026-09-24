package acs

// ContextEntry is one entry of a SessionContext's append-only chain
// (context-entry.json, §8.1).
type ContextEntry struct {
	EntryID  string `json:"entry_id"`
	StepID   string `json:"step_id"`
	StepType string `json:"step_type"`
	// RequestHash is the lowercase-hex SHA-256 of the RFC 8785
	// canonicalization of the originating request's params.
	RequestHash       string             `json:"request_hash,omitzero"`
	ProvenanceSummary *ProvenanceSummary `json:"provenance_summary,omitzero"`
	Timestamp         string             `json:"timestamp,omitzero"`
	// TurnID is the envelope's metadata.turn_id, which turnStart requires
	// on every per-step entry of the turn. context-entry.json names no
	// member for it; the member takes the envelope field's name.
	TurnID string `json:"turn_id,omitzero"`
	// Approver and IntentExtension record an intent_extension entry's
	// grant (§9.1), which context-entry.json names no member for; the
	// members take ask-details.json's names.
	Approver        *Approver        `json:"approver,omitzero"`
	IntentExtension *IntentExtension `json:"intent_extension,omitzero"`
	// PreviousHash is null for the first entry of a session.
	PreviousHash *string `json:"previous_hash"`
	EntryHash    string  `json:"entry_hash"`
}

// ProvenanceSummary condenses provenance facts for an entry or a session
// (provenance-summary.json, §8.3).
type ProvenanceSummary struct {
	OriginsSeen            []string          `json:"origins_seen,omitzero"`
	EntryCount             *int64            `json:"entry_count,omitzero"`
	EntryCountByOrigin     map[string]int64  `json:"entry_count_by_origin,omitzero"`
	EarliestStepIDByOrigin map[string]string `json:"earliest_step_id_by_origin,omitzero"`
	MaxLineageDepth        *int64            `json:"max_lineage_depth,omitzero"`
}

// Provenance is the lineage label on a data-bearing field (provenance.json,
// §7).
type Provenance struct {
	ProvenanceID string   `json:"provenance_id"`
	Origin       string   `json:"origin"`
	SourceID     *string  `json:"source_id,omitzero"`
	DerivedFrom  []string `json:"derived_from,omitzero"`
}

// Intent is the session's declared purpose and capability set (§8.4).
type Intent struct {
	Raw              *string      `json:"raw,omitzero"`
	Parsed           []Capability `json:"parsed,omitzero"`
	ParserProvenance *Provenance  `json:"parser_provenance,omitzero"`
	ScopeMode        *string      `json:"scope_mode,omitzero"`
}

// ScopeModeStrict is the Intent scope mode under which a Guardian refuses
// intent extensions the deployment policy forbids (§9.1).
const ScopeModeStrict = "strict"

// Capability is one entry of Intent.parsed.
type Capability struct {
	Tool      string `json:"tool,omitzero"`
	Operation string `json:"operation,omitzero"`
	Resource  string `json:"resource,omitzero"`
}
