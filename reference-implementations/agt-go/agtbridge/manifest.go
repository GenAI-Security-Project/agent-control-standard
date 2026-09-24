package agtbridge

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"go.yaml.in/yaml/v3"
)

// The two intervention points whose snapshot this bridge assembles, the
// ones the TypeScript reference assembles.
const (
	pointPreToolCall  = "pre_tool_call"
	pointPostToolCall = "post_tool_call"
)

// supportedManifestVersions is AGT's manifest_version::SUPPORTED at the
// agt.lock commit (policy-engine/core/src/constants.rs).
var supportedManifestVersions = []string{"0.3.1-beta", "0.3.1-beta-agt", "0.3.0-alpha", "0.3.0-alpha-agt"}

// knownPoints are AGT's eight intervention points.
var knownPoints = []string{"agent_startup", "input", "pre_model_call", "post_model_call", pointPreToolCall, pointPostToolCall, "output", "agent_shutdown"}

// manifest is the part of AGT's manifest grammar
// (policy-engine/core/src/manifest.rs) this bridge reproduces. Every other
// feature is refused when the manifest loads.
type manifest struct {
	Version            string                    `yaml:"agent_control_specification_version"`
	Metadata           any                       `yaml:"metadata"`
	Extends            []any                     `yaml:"extends"`
	Policies           map[string]regoPolicy     `yaml:"policies"`
	InterventionPoints map[string]pointConfig    `yaml:"intervention_points"`
	Tools              map[string]map[string]any `yaml:"tools"`
	Annotators         map[string]map[string]any `yaml:"annotators"`
	Approval           any                       `yaml:"approval"`
}

type regoPolicy struct {
	Type   string         `yaml:"type"`
	Query  string         `yaml:"query"`
	Bundle string         `yaml:"bundle"`
	Other  map[string]any `yaml:",inline"`
}

type pointConfig struct {
	PolicyTarget     string                    `yaml:"policy_target"`
	PolicyTargetKind *string                   `yaml:"policy_target_kind"`
	ToolNameFrom     *string                   `yaml:"tool_name_from"`
	Annotations      map[string]map[string]any `yaml:"annotations"`
	Policy           struct {
		ID    string         `yaml:"id"`
		Query string         `yaml:"query"`
		Other map[string]any `yaml:",inline"`
	} `yaml:"policy"`
}

// compiledPoint is an intervention point with its paths parsed.
type compiledPoint struct {
	name         string
	target       jsonPath
	targetRaw    string
	targetKind   *string
	toolNameFrom *jsonPath
	annotations  []compiledAnnotation // sorted by annotator name, as AGT iterates them
	policyID     string
	query        string
}

type compiledAnnotation struct {
	name string
	from jsonPath
	// config is what the dispatcher receives: the annotator's type and
	// fields, then from, then the annotation's own fields.
	config map[string]any
}

// errManifestInvalid is AGT's runtime_error:manifest_invalid.
var errManifestInvalid = errors.New("runtime_error:manifest_invalid")

func parseManifest(src []byte) (*manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	var m manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", errManifestInvalid, err)
	}
	return &m, nil
}

// compile validates the manifest as AGT's validate_point_config does, and
// refuses every feature outside what this bridge reproduces.
func (m *manifest) compile() (map[string]*compiledPoint, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{errManifestInvalid}, args...)...)
	}
	unsupported := func(what string) error {
		return fmt.Errorf("the manifest uses %s, which agtbridge does not implement", what)
	}
	if !slices.Contains(supportedManifestVersions, m.Version) {
		return nil, invalid("agent_control_specification_version %q is not supported", m.Version)
	}
	switch {
	case len(m.Extends) > 0:
		return nil, unsupported("extends")
	case m.Approval != nil:
		return nil, unsupported("an approval section")
	case len(m.InterventionPoints) == 0:
		return nil, invalid("at least one intervention point config is required")
	}
	for id, p := range m.Policies {
		switch {
		case p.Type != "rego":
			return nil, unsupported(fmt.Sprintf("policy %q of type %q", id, p.Type))
		case len(p.Other) > 0:
			return nil, unsupported(fmt.Sprintf("policy %q with fields beyond query and bundle", id))
		case p.Bundle == "":
			return nil, unsupported(fmt.Sprintf("policy %q without a local bundle", id))
		}
	}
	for name, a := range m.Annotators {
		if a["type"] != "classifier" {
			return nil, unsupported(fmt.Sprintf("annotator %q of type %v", name, a["type"]))
		}
		if name != egressAnnotator {
			return nil, unsupported(fmt.Sprintf("annotator %q, for which this Guardian has no dispatcher", name))
		}
	}
	points := map[string]*compiledPoint{}
	for name, cfg := range m.InterventionPoints {
		if !slices.Contains(knownPoints, name) {
			return nil, invalid("unknown intervention point %q", name)
		}
		if name != pointPreToolCall && name != pointPostToolCall {
			return nil, unsupported(fmt.Sprintf("intervention point %q, whose snapshot this bridge does not assemble", name))
		}
		cp, err := m.compilePoint(name, cfg)
		if err != nil {
			return nil, err
		}
		points[name] = cp
	}
	return points, nil
}

func (m *manifest) compilePoint(name string, cfg pointConfig) (*compiledPoint, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: intervention point %s: "+format, append([]any{errManifestInvalid, name}, args...)...)
	}
	cp := &compiledPoint{name: name, targetRaw: cfg.PolicyTarget, targetKind: cfg.PolicyTargetKind, policyID: cfg.Policy.ID}
	if strings.TrimSpace(cfg.PolicyTarget) == "" {
		return nil, invalid("policy_target is required")
	}
	target, err := parseSnapshotPath(cfg.PolicyTarget)
	if err != nil || target.root != rootSnap {
		return nil, invalid("policy_target %q must be a snapshot path", cfg.PolicyTarget)
	}
	cp.target = target
	if cfg.PolicyTargetKind != nil && strings.TrimSpace(*cfg.PolicyTargetKind) == "" {
		return nil, invalid("policy_target_kind is empty")
	}
	if cfg.ToolNameFrom != nil {
		p, err := parseSnapshotPath(*cfg.ToolNameFrom)
		if err != nil || p.root != rootSnap {
			return nil, invalid("tool_name_from %q must be a snapshot path", *cfg.ToolNameFrom)
		}
		cp.toolNameFrom = &p
	}
	for _, annotator := range sortedKeys(cfg.Annotations) {
		fields := cfg.Annotations[annotator]
		global, ok := m.Annotators[annotator]
		if !ok {
			return nil, invalid("annotation %q names no declared annotator", annotator)
		}
		if _, shadow := fields["annotator"]; shadow {
			return nil, invalid("annotation %q carries an annotator field", annotator)
		}
		from, _ := fields["from"].(string)
		if strings.TrimSpace(from) == "" {
			return nil, invalid("annotation %q requires from", annotator)
		}
		p, err := parseSnapshotPath(from)
		if err != nil || p.referencesPIAnnotations() {
			return nil, invalid("annotation %q has an invalid from %q", annotator, from)
		}
		config := map[string]any{}
		for k, v := range global {
			config[k] = v
		}
		config["from"] = from
		for k, v := range fields {
			config[k] = v
		}
		cp.annotations = append(cp.annotations, compiledAnnotation{name: annotator, from: p, config: config})
	}
	policy, ok := m.Policies[cfg.Policy.ID]
	switch {
	case strings.TrimSpace(cfg.Policy.ID) == "" || !ok:
		return nil, invalid("references unknown policy %q", cfg.Policy.ID)
	case len(cfg.Policy.Other) > 0:
		return nil, fmt.Errorf("intervention point %s binds adapter fields, which agtbridge does not implement", name)
	}
	cp.query = cfg.Policy.Query
	if cp.query == "" {
		cp.query = policy.Query
	}
	if cp.query == "" {
		return nil, invalid("the rego policy %q has no query", cfg.Policy.ID)
	}
	return cp, nil
}

// projectedTool is AGT's ToolConfig::to_projected_value: the entry's fields
// with name set to the registry key.
func (m *manifest) projectedTool(name string) (map[string]any, bool) {
	fields, ok := m.Tools[name]
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for k, v := range fields {
		out[k] = v
	}
	out["name"] = name
	return out, true
}

// asJSON converts a YAML-decoded value to the shapes a JSON decoder yields.
func asJSON(v any) (any, error) {
	b, err := jsonv2.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	return out, jsonv2.Unmarshal(b, &out)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
