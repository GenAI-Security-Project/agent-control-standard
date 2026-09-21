package agtbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"go.yaml.in/yaml/v3"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// mapping is the TypeScript reference's mapping.yaml, the single source of
// truth for how an AGT verdict becomes an ACS decision. This file reads it
// and implements it as packages/guardian/src/map-verdict.ts does; it
// declares nothing of its own.
type mapping struct {
	ACSVersion         string                  `yaml:"acs_version"`
	AGTVersion         string                  `yaml:"agt_version"`
	InterventionPoints map[string]mappingPoint `yaml:"intervention_points"`
	Verdicts           map[string]verdictRule  `yaml:"verdicts"`
	FieldSynthesis     fieldSynthesis          `yaml:"field_synthesis"`

	detail *regexp.Regexp
}

type mappingPoint struct {
	ACSMethod            *string               `yaml:"acs_method"`
	Note                 string                `yaml:"note"`
	PolicyTargetArgument *policyTargetArgument `yaml:"policy_target_argument"`
	Modifications        *modificationsRule    `yaml:"modifications"`
}

type policyTargetArgument struct {
	Default string            `yaml:"default"`
	ByTool  map[string]string `yaml:"by_tool"`
}

type modificationsRule struct {
	From     string `yaml:"from"`
	WhenPath string `yaml:"when_path"`
	Into     string `yaml:"into"`
	IntoPath string `yaml:"into_path"`
}

type verdictRule struct {
	Decision                acs.Disposition `yaml:"decision"`
	RequirePolicyReferences bool            `yaml:"require_policy_references"`
}

type fieldSynthesis struct {
	Reasoning struct {
		Source    string         `yaml:"source"`
		Template  *string        `yaml:"template"`
		Summaries map[string]any `yaml:"summaries"`
		Detail    *struct {
			WhenMatches string `yaml:"when_matches"`
			Render      string `yaml:"render"`
			Otherwise   string `yaml:"otherwise"`
		} `yaml:"detail"`
	} `yaml:"reasoning"`
	ReasonCodes struct {
		Source string `yaml:"source"`
		Wrap   string `yaml:"wrap"`
	} `yaml:"reason_codes"`
	PolicyReferences struct {
		RuleID struct {
			Source string `yaml:"source"`
		} `yaml:"rule_id"`
		PolicyID struct {
			Literal string `yaml:"literal"`
		} `yaml:"policy_id"`
	} `yaml:"policy_references"`
}

var verdictFields = []string{"verdict.decision", "verdict.reason", "verdict.message", "verdict.transform", "verdict.result_labels"}

// parseMapping reads mapping.yaml and checks every rule the translation
// reads, so a broken table stops the Guardian at start rather than denying
// at the first step that reaches it.
func parseMapping(src []byte) (*mapping, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	var m mapping
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("mapping.yaml: %w", err)
	}
	fs := m.FieldSynthesis
	for _, source := range []string{fs.Reasoning.Source, fs.ReasonCodes.Source, fs.PolicyReferences.RuleID.Source} {
		if !slices.Contains(verdictFields, source) {
			return nil, fmt.Errorf("mapping.yaml: field_synthesis reads %q, which is not a verdict field", source)
		}
	}
	if fs.ReasonCodes.Wrap != "array" {
		return nil, fmt.Errorf("mapping.yaml: field_synthesis.reason_codes.wrap is %q; only array is expressible", fs.ReasonCodes.Wrap)
	}
	if d := fs.Reasoning.Detail; d != nil {
		re, err := regexp.Compile(d.WhenMatches)
		if err != nil {
			return nil, fmt.Errorf("mapping.yaml: field_synthesis.reasoning.detail.when_matches: %w", err)
		}
		m.detail = re
	}
	for name, rule := range m.Verdicts {
		switch rule.Decision {
		case acs.Allow, acs.Deny, acs.Modify, acs.Ask, acs.Defer:
		default:
			return nil, fmt.Errorf("mapping.yaml: verdict %s maps to %q, which is not an ACS disposition", name, rule.Decision)
		}
	}
	methods := map[string]string{}
	for point, row := range m.InterventionPoints {
		if row.ACSMethod != nil {
			if other, dup := methods[*row.ACSMethod]; dup {
				return nil, fmt.Errorf("mapping.yaml: %s maps to both %s and %s", *row.ACSMethod, other, point)
			}
			methods[*row.ACSMethod] = point
		}
		if r := row.Modifications; r != nil {
			if !slices.Contains(verdictFields, r.From) || (r.Into != "parameter_overrides" && r.Into != "redactions") {
				return nil, fmt.Errorf("mapping.yaml: intervention_points.%s.modifications is not expressible", point)
			}
		}
	}
	return &m, nil
}

// point returns the AGT intervention point an ACS method maps to.
func (m *mapping) point(method string) (string, bool) {
	for point, row := range m.InterventionPoints {
		if row.ACSMethod != nil && *row.ACSMethod == method {
			return point, true
		}
	}
	return "", false
}

// policyTargetArgument is the tool argument a point's policy target is read
// from and an override is written to; empty when the point declares none.
func (m *mapping) policyTargetArgument(point, tool string) (string, error) {
	table := m.InterventionPoints[point].PolicyTargetArgument
	if table == nil {
		return "", nil
	}
	if named, ok := table.ByTool[tool]; ok {
		return named, nil
	}
	if table.Default == "" {
		return "", fmt.Errorf("mapping.yaml's intervention_points.%s.policy_target_argument names no argument for tool %q and declares no default", point, tool)
	}
	return table.Default, nil
}

// decision translates a verdict at a point, as mapVerdict does.
func (m *mapping) decision(v verdict, point, argument string) (acs.Decision, error) {
	rule, ok := m.Verdicts[v.Decision]
	if !ok {
		return acs.Decision{}, fmt.Errorf("mapping.yaml has no verdict rule for AGT decision %q", v.Decision)
	}
	fs := m.FieldSynthesis
	d := acs.Decision{Disposition: rule.Decision}
	ruleID := v.field(fs.PolicyReferences.RuleID.Source)
	if reasoning := m.reasoning(ruleID, v.field(fs.Reasoning.Source), fs.PolicyReferences.PolicyID.Literal, point); reasoning != nil {
		d.Reasoning = *reasoning
	}
	if code := v.field(fs.ReasonCodes.Source); code != nil {
		d.ReasonCodes = []string{*code}
	}
	if ruleID != nil {
		d.PolicyReferences = []acs.PolicyReference{{PolicyID: fs.PolicyReferences.PolicyID.Literal, RuleID: *ruleID}}
	}
	if rule.RequirePolicyReferences && len(d.PolicyReferences) == 0 {
		return acs.Decision{}, fmt.Errorf("mapping.yaml declares require_policy_references for AGT decision %q, but no policy_references could be synthesized (verdict.reason was empty)", v.Decision)
	}
	if rule.Decision == acs.Modify {
		mods, err := m.modifications(v, point, argument)
		if err != nil {
			return acs.Decision{}, err
		}
		d.Modifications = mods
	}
	return d, nil
}

// field reads a string verdict field a mapping source names.
func (v verdict) field(source string) *string {
	switch source {
	case "verdict.reason":
		return v.Reason
	case "verdict.message":
		return v.Message
	case "verdict.decision":
		return &v.Decision
	}
	return nil
}

// reasoning is composeReasoning: the template filled in order, each
// placeholder replaced across the text the previous ones produced.
func (m *mapping) reasoning(ruleID, message *string, policyID, point string) *string {
	rule := m.FieldSynthesis.Reasoning
	if rule.Template == nil {
		return message
	}
	if ruleID == nil || *ruleID == "" {
		return nil
	}
	detail := ""
	if rule.Detail != nil && message != nil && *message != "" {
		if hit := m.detail.FindStringSubmatch(*message); hit != nil {
			group := ""
			if len(hit) > 1 {
				group = hit[1]
			}
			detail = strings.ReplaceAll(rule.Detail.Render, "{1}", group)
		} else {
			detail = strings.ReplaceAll(rule.Detail.Otherwise, "{message}", *message)
		}
	}
	out := *rule.Template
	out = strings.ReplaceAll(out, "{summary}", m.summary(*ruleID, point))
	out = strings.ReplaceAll(out, "{rule_id}", *ruleID)
	out = strings.ReplaceAll(out, "{policy_id}", policyID)
	out = strings.ReplaceAll(out, "{detail}", detail)
	return &out
}

func (m *mapping) summary(ruleID, point string) string {
	summaries := m.FieldSynthesis.Reasoning.Summaries
	switch entry := summaries[ruleID].(type) {
	case string:
		return entry
	case map[string]any:
		if perPoint, ok := entry[point].(string); ok {
			return perPoint
		}
	}
	fallback, _ := summaries["default"].(string)
	return fallback
}

var errModificationUnexpressible = errors.New("the rewrite cannot be expressed as an ACS modification")

// modifications is synthesizeModifications.
func (m *mapping) modifications(v verdict, point, argument string) (*acs.Modifications, error) {
	rule := m.InterventionPoints[point].Modifications
	if rule == nil {
		return nil, fmt.Errorf("%w: mapping.yaml maps AGT decision %q to ACS modify, but its intervention_points row for %q declares no modifications rule", errModificationUnexpressible, v.Decision, point)
	}
	if v.Transform == nil {
		return nil, fmt.Errorf("%w: %s is absent", errModificationUnexpressible, rule.From)
	}
	if v.Transform.Path != rule.WhenPath {
		return nil, fmt.Errorf("%w: mapping.yaml can express a transform of %q only, but the verdict rewrote %q", errModificationUnexpressible, rule.WhenPath, v.Transform.Path)
	}
	value, err := jsonv2.Marshal(v.Transform.Value)
	if err != nil {
		return nil, err
	}
	switch rule.Into {
	case "parameter_overrides":
		if argument == "" {
			return nil, fmt.Errorf("%w: intervention point %q declares no policy_target_argument for the override to land on", errModificationUnexpressible, point)
		}
		return &acs.Modifications{ParameterOverrides: map[string]json.RawMessage{argument: value}}, nil
	default:
		replacement, ok := v.Transform.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: a redaction's replacement is a string, and %s.value is not", errModificationUnexpressible, rule.From)
		}
		return &acs.Modifications{Redactions: []acs.Redaction{{Path: rule.IntoPath, Replacement: &replacement}}}, nil
	}
}
