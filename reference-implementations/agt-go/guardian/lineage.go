package guardian

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/disposition"
)

// provenanceIDs returns the provenance_id of every Provenance object in a
// payload, in document order: any object carrying a string provenance_id
// and a string origin, the two members provenance.json requires.
func provenanceIDs(payload json.RawMessage) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var tree any
	if err := jsonv2.Unmarshal(payload, &tree); err != nil {
		return nil, err
	}
	var ids []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			id, idOK := v["provenance_id"].(string)
			_, originOK := v["origin"].(string)
			if idOK && originOK && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(tree)
	slices.Sort(ids)
	return ids, nil
}

// checkLineage holds a postCompact step to post-compact.json: its
// pre_compact_chain_hash is the head before this step's entry, the
// summary's origin is agent_generated, and its derived_from is the union of
// the provenance_ids of every compacted entry. post_compact_chain_hash is
// not checked: it names the hash of the entry that carries it, which no
// sender can know, and the answer's chain_hash publishes the real one. The
// hook permits no DENY, since compaction has happened, so a mismatch is
// recorded and the engine's decision is sent with the mismatch's reason
// code added. Trust monotonicity over that lineage is policy, and stays
// with the engine.
func (g *Guardian) checkLineage(ctx context.Context, in *call, req acs.Request, sess Session, d acs.Decision) acs.Decision {
	var p acs.PostCompactPayload
	if err := jsonv2.Unmarshal(req.Params.Payload, &p); err != nil {
		return d
	}
	var problem string
	before := ""
	if n := len(sess.Entries); n > 0 && sess.Entries[n-1].PreviousHash != nil {
		before = *sess.Entries[n-1].PreviousHash
	}
	if p.PreCompactChainHash != before {
		problem = fmt.Sprintf("pre_compact_chain_hash %s is not the head %s this step was appended to", p.PreCompactChainHash, before)
	} else if p.Summary.Provenance.Origin != acs.OriginAgentGenerated {
		problem = fmt.Sprintf("the summary's origin is %q, not %q", p.Summary.Provenance.Origin, acs.OriginAgentGenerated)
	} else {
		var want []string
		for _, step := range p.EntriesCompacted {
			ids, ok := sess.Lineage[step]
			if !ok {
				problem = "entries_compacted names step " + step + ", which is not in this session's chain"
				break
			}
			for _, id := range ids {
				if !slices.Contains(want, id) {
					want = append(want, id)
				}
			}
		}
		got := slices.Clone(p.Summary.Provenance.DerivedFrom)
		slices.Sort(want)
		slices.Sort(got)
		got = slices.Compact(got)
		if problem == "" && !slices.Equal(got, want) {
			problem = fmt.Sprintf("the summary's derived_from %v is not the union %v of the compacted entries' provenance_ids", got, want)
		}
	}
	if problem == "" {
		return d
	}
	g.event(ctx, EventLineageMismatch, req.Method, in.SessionID, in.RequestID, problem)
	d.ReasonCodes = append(slices.Clip(d.ReasonCodes), disposition.ReasonLineageMismatch)
	if d.Reasoning == "" {
		d.Reasoning = problem
	}
	return d
}
