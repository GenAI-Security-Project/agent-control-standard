package chain

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// testdata/vectors.json was computed from §8.1 and §8.2 with Python's json
// and hashlib, independently of this package: json.dumps with sorted keys,
// compact separators and ensure_ascii=False is the RFC 8785 form for objects
// whose values are strings and integers, which is all the vectors hold.
type vectors struct {
	RequestHash struct {
		Params    jsontext.Value `json:"params"`
		Canonical string         `json:"canonical"`
		Hash      string         `json:"hash"`
	} `json:"request_hash"`
	Chain []struct {
		Entry            acs.ContextEntry `json:"entry"`
		PreviousHash     *string          `json:"previous_hash"`
		CanonicalContent string           `json:"canonical_content"`
		EntryHash        string           `json:"entry_hash"`
	} `json:"chain"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Chain) != 3 {
		t.Fatalf("read %d chain vectors, want 3", len(v.Chain))
	}
	return v
}

func TestRequestHashVector(t *testing.T) {
	v := loadVectors(t)
	got, err := RequestHash(v.RequestHash.Params)
	if err != nil {
		t.Fatal(err)
	}
	if got != v.RequestHash.Hash {
		t.Fatalf("got %s, want %s", got, v.RequestHash.Hash)
	}
}

func TestVector(t *testing.T) {
	v := loadVectors(t)
	previous := ""
	for i, vec := range v.Chain {
		if (vec.PreviousHash == nil) != (i == 0) {
			t.Fatalf("vector %d: only the first entry has no previous_hash", i)
		}
		content, err := contentBytes(vec.Entry)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != vec.CanonicalContent {
			t.Errorf("vector %d content:\n got %s\nwant %s", i, content, vec.CanonicalContent)
		}
		sealed, err := Seal(vec.Entry, previous)
		if err != nil {
			t.Fatal(err)
		}
		if sealed.EntryHash != vec.EntryHash {
			t.Errorf("vector %d: entry_hash %s, want %s", i, sealed.EntryHash, vec.EntryHash)
		}
		if i > 0 && *sealed.PreviousHash != *vec.PreviousHash {
			t.Errorf("vector %d: previous_hash %s, want %s", i, *sealed.PreviousHash, *vec.PreviousHash)
		}
		previous = sealed.EntryHash
	}
}

func TestEntryHashIgnoresItsOwnHash(t *testing.T) {
	e := acs.ContextEntry{EntryID: "1", StepID: "s", StepType: acs.StepSessionStart}
	a, err := EntryHash(e)
	if err != nil {
		t.Fatal(err)
	}
	e.EntryHash = strings.Repeat("f", 64)
	b, err := EntryHash(e)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("entry_hash changed the digest")
	}
}

// TestEntryHashCommitsToEveryMember changes one member at a time and expects
// a different digest, the tamper-evidence §8.2 exists for.
func TestEntryHashCommitsToEveryMember(t *testing.T) {
	prev := strings.Repeat("a", 64)
	count := int64(1)
	base := acs.ContextEntry{
		EntryID: "1", StepID: "s", StepType: acs.StepToolCallRequest,
		RequestHash: strings.Repeat("b", 64), Timestamp: "2026-09-19T10:00:00Z",
		ProvenanceSummary: &acs.ProvenanceSummary{EntryCount: &count},
		PreviousHash:      &prev,
	}
	want, err := EntryHash(base)
	if err != nil {
		t.Fatal(err)
	}
	otherPrev := strings.Repeat("c", 64)
	otherCount := int64(2)
	tests := []struct {
		name   string
		mutate func(*acs.ContextEntry)
	}{
		{"entry_id", func(e *acs.ContextEntry) { e.EntryID = "2" }},
		{"step_id", func(e *acs.ContextEntry) { e.StepID = "t" }},
		{"step_type", func(e *acs.ContextEntry) { e.StepType = acs.StepToolCallResult }},
		{"request_hash", func(e *acs.ContextEntry) { e.RequestHash = strings.Repeat("d", 64) }},
		{"timestamp", func(e *acs.ContextEntry) { e.Timestamp = "2026-09-19T10:00:01Z" }},
		{"provenance_summary", func(e *acs.ContextEntry) { e.ProvenanceSummary = &acs.ProvenanceSummary{EntryCount: &otherCount} }},
		{"turn_id", func(e *acs.ContextEntry) { e.TurnID = "turn-2" }},
		{"approver", func(e *acs.ContextEntry) {
			e.Approver = &acs.Approver{Type: acs.ApproverHuman, ID: "approver-1"}
		}},
		{"intent_extension", func(e *acs.ContextEntry) {
			e.IntentExtension = &acs.IntentExtension{
				Capabilities: []acs.Capability{{Tool: "Bash", Operation: "execute"}},
				Scope:        acs.ScopeSession,
			}
		}},
		{"previous_hash", func(e *acs.ContextEntry) { e.PreviousHash = &otherPrev }},
		{"first_entry", func(e *acs.ContextEntry) { e.PreviousHash = nil }},
	}
	changed := map[string]bool{}
	for _, tt := range tests {
		changed[tt.name] = true
	}
	entry := reflect.TypeFor[acs.ContextEntry]()
	for i := range entry.NumField() {
		member, _, _ := strings.Cut(entry.Field(i).Tag.Get("json"), ",")
		if member != "entry_hash" && !changed[member] {
			t.Errorf("%s is a member of acs.ContextEntry that no case changes", member)
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := base
			tt.mutate(&e)
			got, err := EntryHash(e)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("digest did not change")
			}
		})
	}
}

func TestEntryHashRefusesMalformedPrevious(t *testing.T) {
	for _, prev := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		e := acs.ContextEntry{EntryID: "1", PreviousHash: &prev}
		if _, err := EntryHash(e); err == nil {
			t.Errorf("accepted previous_hash %q", prev)
		}
	}
}
