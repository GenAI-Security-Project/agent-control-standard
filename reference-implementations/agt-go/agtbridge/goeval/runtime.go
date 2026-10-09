package goeval

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
)

// AGT's resource limits (policy-engine/core/src/limits.rs, Limits::default).
const (
	maxDepth                = 64
	maxSnapshotBytes        = 1 << 20
	maxAnnotatorsPerPoint   = 16
	maxAnnotatorOutputBytes = 256 << 10
	maxPolicyOutputBytes    = 256 << 10
)

// AGT's runtime_error reasons (policy-engine/core/src/error.rs) this path
// can produce.
const (
	reasonInterventionPointUnknown = "runtime_error:intervention_point_unknown"
	reasonToolUnknown              = "runtime_error:tool_unknown"
	reasonAnnotationFailed         = "runtime_error:annotation_failed"
	reasonPolicyInvocationFailed   = "runtime_error:policy_invocation_failed"
	reasonPolicyOutputInvalid      = "runtime_error:policy_output_invalid"
	reasonResourceLimitExceeded    = "runtime_error:resource_limit_exceeded"
	reasonTransformTargetForbidden = "runtime_error:transform_target_forbidden"
	reasonTransformInvalid         = "runtime_error:transform_invalid"
	runtimeErrorPrefix             = "runtime_error:"
)

// runtimeErrorMessage is the message of every verdict AGT builds from a
// runtime error (policy-engine/core/src/verdict.rs, Verdict::runtime_error).
const runtimeErrorMessage = "Request blocked by Agent Control Specification."

// failure is a runtime error on the evaluation path: AGT answers it with a
// fail-closed deny, never an exception.
type failure struct {
	reason string
	detail string
}

func (f *failure) Error() string { return f.reason + ": " + f.detail }

func fail(reason, format string, args ...any) *failure {
	return &failure{reason: reason, detail: fmt.Sprintf(format, args...)}
}

func (f *failure) verdict() agtbridge.Verdict {
	message := runtimeErrorMessage
	if f.reason == reasonAnnotationFailed && f.detail != "" {
		message += " " + f.detail
	}
	reason := f.reason
	return agtbridge.Verdict{Decision: "deny", Reason: &reason, Message: &message}
}

// prepare prepares one OPA query per intervention point over the bundle
// each binds. manifestDir is the manifest's directory within fsys; AGT
// resolves a bundle relative to it.
func (r *Evaluator) prepare(ctx context.Context, fsys fs.FS, manifestDir string) error {
	m := r.manifest
	bundles := map[string]*bundle.Bundle{}
	for name, p := range r.points {
		dir := joinFS(manifestDir, m.Policies[p.policyID].Bundle)
		b, ok := bundles[dir]
		if !ok {
			var err error
			b, err = readBundle(fsys, dir)
			if err != nil {
				return err
			}
			bundles[dir] = b
		}
		q, err := rego.New(rego.Query(p.query), rego.ParsedBundle(dir, b)).PrepareForEval(ctx)
		if err != nil {
			return fmt.Errorf("prepare %s at %s: %w", p.query, name, err)
		}
		r.queries[name] = q
	}
	return nil
}

// joinFS joins a manifest-relative bundle path the way AGT's
// resolve_relative_string does, without cleaning it: a "./" segment stays,
// as AGT's Path::join keeps it.
func joinFS(dir, bundle string) string {
	if dir == "." || dir == "" {
		return bundle
	}
	return dir + "/" + bundle
}

func readBundle(fsys fs.FS, dir string) (*bundle.Bundle, error) {
	if strings.Contains("/"+dir+"/", "/./") {
		return nil, fmt.Errorf("bundle path %q contains a ./ segment, which makes OPA drop the bundle's data document and so disables every rule", dir)
	}
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil, err
	}
	loader, err := bundle.NewFSLoader(sub)
	if err != nil {
		return nil, err
	}
	b, err := bundle.NewCustomReader(loader).Read()
	if err != nil {
		return nil, fmt.Errorf("read bundle %s: %w", dir, err)
	}
	return &b, nil
}

// Evaluate implements agtbridge.Evaluator: every failure is a fail-closed
// verdict, never an error. An error is returned only for a cancelled or
// expired context.
func (r *Evaluator) Evaluate(ctx context.Context, point string, snapshot map[string]any) (agtbridge.Verdict, error) {
	v, f := r.evaluate(ctx, point, snapshot)
	if ctx.Err() != nil {
		return agtbridge.Verdict{}, ctx.Err()
	}
	if f != nil {
		return f.verdict(), nil
	}
	return v, nil
}

func (r *Evaluator) evaluate(ctx context.Context, point string, snapshot map[string]any) (agtbridge.Verdict, *failure) {
	p, ok := r.points[point]
	if !ok {
		return agtbridge.Verdict{}, fail(reasonInterventionPointUnknown, "%s", point)
	}
	if f := checkSize(snapshot, maxSnapshotBytes, reasonResourceLimitExceeded, "snapshot"); f != nil {
		return agtbridge.Verdict{}, f
	}
	env := pathEnv{snap: snapshot}
	target, err := p.target.resolve(env)
	if err != nil {
		return agtbridge.Verdict{}, pathFailure(err)
	}
	tool, f := r.projectTool(p, env)
	if f != nil {
		return agtbridge.Verdict{}, f
	}
	pi := policyInput(p, target, snapshot, map[string]any{}, tool)
	if f := checkDepth(pi, reasonResourceLimitExceeded, "policy input"); f != nil {
		return agtbridge.Verdict{}, f
	}
	annotations, f := r.annotate(p, pi, snapshot)
	if f != nil {
		return agtbridge.Verdict{}, f
	}
	pi = policyInput(p, target, snapshot, annotations, tool)
	if f := checkDepth(pi, reasonResourceLimitExceeded, "policy input"); f != nil {
		return agtbridge.Verdict{}, f
	}

	output, f := r.query(ctx, point, pi)
	if f != nil {
		return agtbridge.Verdict{}, f
	}
	if f := checkSize(output, maxPolicyOutputBytes, reasonResourceLimitExceeded, "policy output"); f != nil {
		return agtbridge.Verdict{}, f
	}
	v, f := normalize(output)
	if f != nil {
		return agtbridge.Verdict{}, f
	}
	if v.Transform != nil {
		if f := applyTransform(p, snapshot, target, *v.Transform); f != nil {
			return agtbridge.Verdict{}, f
		}
	}
	return v, nil
}

// policyInput is AGT's five-member policy input document
// (policy-engine/core/src/policy_input.rs).
func policyInput(p *compiledPoint, target any, snapshot map[string]any, annotations map[string]any, tool any) map[string]any {
	var kind any
	if p.targetKind != nil {
		kind = *p.targetKind
	}
	return map[string]any{
		"intervention_point": p.name,
		"policy_target":      map[string]any{"kind": kind, "path": p.targetRaw, "value": target},
		"snapshot":           snapshot,
		"annotations":        annotations,
		"tool":               tool,
	}
}

func (r *Evaluator) projectTool(p *compiledPoint, env pathEnv) (any, *failure) {
	if p.toolNameFrom == nil {
		return nil, nil
	}
	v, err := p.toolNameFrom.resolve(env)
	if err != nil {
		return nil, pathFailure(err)
	}
	name, ok := v.(string)
	if !ok {
		return nil, fail(errPathTypeMismatch.Error(), "tool_name_from '%s' did not resolve to a string", p.toolNameFrom.original)
	}
	tool, ok := r.manifest.projectedTool(name)
	if !ok {
		return nil, fail(reasonToolUnknown, "%s", name)
	}
	projected, err := asJSON(tool)
	if err != nil {
		return nil, fail(errManifestInvalid.Error(), "tool %s: %v", name, err)
	}
	return projected, nil
}

// annotate runs each annotator of the point in name order. Its from path is
// a precondition that must resolve; the dispatcher receives the whole
// preliminary policy input and its answer lands at annotations.<name>.
func (r *Evaluator) annotate(p *compiledPoint, preliminary, snapshot map[string]any) (map[string]any, *failure) {
	out := map[string]any{}
	if len(p.annotations) > maxAnnotatorsPerPoint {
		return nil, fail(reasonResourceLimitExceeded, "%d annotators exceed the limit %d", len(p.annotations), maxAnnotatorsPerPoint)
	}
	for _, a := range p.annotations {
		if _, err := a.from.resolve(pathEnv{snap: snapshot, pi: preliminary}); err != nil {
			return nil, pathFailure(err)
		}
		// compile admits the egress annotator only.
		value := any(agtbridge.AnnotateEgress(preliminary))
		if f := checkAnnotatorOutput(a.name, value); f != nil {
			return nil, f
		}
		out[a.name] = value
	}
	return out, nil
}

func (r *Evaluator) query(ctx context.Context, point string, pi map[string]any) (any, *failure) {
	input, err := asJSON(pi)
	if err != nil {
		return nil, fail(reasonPolicyInvocationFailed, "encode policy input: %v", err)
	}
	rs, err := r.queries[point].Eval(ctx, rego.EvalInput(input))
	switch {
	case err != nil:
		return nil, fail(reasonPolicyInvocationFailed, "opa eval failed: %v", err)
	case len(rs) == 0:
		return nil, fail(reasonPolicyInvocationFailed, "opa eval returned no result")
	case len(rs) > 1:
		return nil, fail(reasonPolicyInvocationFailed, "opa eval returned multiple results")
	case len(rs[0].Expressions) != 1:
		return nil, fail(reasonPolicyInvocationFailed, "opa eval returned %d expressions", len(rs[0].Expressions))
	}
	value, err := asJSON(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fail(reasonPolicyInvocationFailed, "decode opa result: %v", err)
	}
	return value, nil
}

// normalize is AGT's normalize_policy_output
// (policy-engine/core/src/verdict.rs). An empty result_labels is left out,
// as AGT's C ABI serializes it.
func normalize(output any) (agtbridge.Verdict, *failure) {
	invalid := func(message string) *failure { return fail(reasonPolicyOutputInvalid, "%s", message) }
	obj, ok := output.(map[string]any)
	if !ok {
		return agtbridge.Verdict{}, invalid("policy output decision is required")
	}
	decision, ok := obj["decision"].(string)
	if !ok {
		return agtbridge.Verdict{}, invalid("policy output decision is required")
	}
	switch decision {
	case "allow", "deny", "warn", "escalate", "transform":
	default:
		return agtbridge.Verdict{}, invalid(fmt.Sprintf("unsupported decision '%s'", decision))
	}
	v := agtbridge.Verdict{Decision: decision}
	switch reason := obj["reason"].(type) {
	case nil:
	case string:
		if strings.HasPrefix(reason, runtimeErrorPrefix) {
			return agtbridge.Verdict{}, invalid("policy reasons must not use reserved runtime_error:* prefix")
		}
		v.Reason = &reason
	default:
		return agtbridge.Verdict{}, invalid("policy output reason must be a string")
	}
	switch message := obj["message"].(type) {
	case nil:
	case string:
		v.Message = &message
	default:
		return agtbridge.Verdict{}, invalid("policy output message must be a string")
	}
	if _, present := obj["effects"]; present {
		return agtbridge.Verdict{}, invalid("verdict 'effects' is no longer supported; remove the effects key and use the transform decision per SPECIFICATION.md §14. Migrate multi-step rewriting to an annotator")
	}
	if labels, present := obj["result_labels"]; present {
		values, ok := labels.([]any)
		if !ok {
			return agtbridge.Verdict{}, invalid("policy output result_labels must be an array")
		}
		for _, l := range values {
			s, ok := l.(string)
			if !ok {
				return agtbridge.Verdict{}, invalid("policy output result_labels must be an array of strings")
			}
			v.ResultLabels = append(v.ResultLabels, s)
		}
	}
	t := obj["transform"]
	switch {
	case decision == "transform" && t == nil:
		return agtbridge.Verdict{}, invalid("transform decision requires a transform object")
	case decision != "transform" && t != nil:
		return agtbridge.Verdict{}, invalid("transform is only permitted on the transform decision")
	case decision == "transform":
		tm, ok := t.(map[string]any)
		if !ok {
			return agtbridge.Verdict{}, invalid("transform must be an object")
		}
		pathText, ok := tm["path"].(string)
		if !ok {
			return agtbridge.Verdict{}, invalid("transform.path must be a string")
		}
		p, err := parsePath(pathText)
		if err != nil {
			return agtbridge.Verdict{}, invalid(err.Error())
		}
		if p.root != rootPolicyTarget {
			return agtbridge.Verdict{}, fail(reasonTransformTargetForbidden, "%s", pathText)
		}
		value, ok := tm["value"]
		if !ok {
			return agtbridge.Verdict{}, invalid("transform.value is required when decision is transform")
		}
		v.Transform = &agtbridge.Transform{Path: pathText, Value: value}
	}
	if f := checkEvidence(obj["evidence"]); f != nil {
		return agtbridge.Verdict{}, f
	}
	return v, nil
}

// checkEvidence applies AGT's evidence checks; the Guardian does not carry
// evidence onto the wire, as the TypeScript reference does not.
func checkEvidence(e any) *failure {
	if e == nil {
		return nil
	}
	invalid := func(message string) *failure { return fail(reasonPolicyOutputInvalid, "%s", message) }
	obj, ok := e.(map[string]any)
	if !ok {
		return invalid("evidence must be an object")
	}
	if b, err := jsonv2.Marshal(obj); err != nil || len(b) > 4096 {
		return invalid("evidence exceeds 4096 bytes")
	}
	switch obj["artefact"].(type) {
	case nil, string:
	default:
		return invalid("evidence.artefact must be a string")
	}
	switch pointers := obj["verification_pointers"].(type) {
	case nil:
	case map[string]any:
		for key, value := range pointers {
			if _, ok := value.(string); !ok {
				return invalid("evidence.verification_pointers." + key + " must be a string")
			}
		}
	default:
		return invalid("evidence.verification_pointers must be an object of strings")
	}
	return nil
}

// applyTransform checks that a transform lands inside the policy target, and
// that the snapshot rebuilt with it stays within the snapshot limits, as
// AGT does in enforce mode before it surfaces the rewrite.
func applyTransform(p *compiledPoint, snapshot map[string]any, target any, t agtbridge.Transform) *failure {
	tp, err := parsePath(t.Path)
	if err != nil || tp.root != rootPolicyTarget {
		return fail(reasonTransformTargetForbidden, "%s", t.Path)
	}
	transformed, err := setIn(target, tp.segments, t.Value)
	if err != nil {
		return fail(reasonTransformInvalid, "transform could not be applied: %v", err)
	}
	rebuilt, err := setIn(any(snapshot), p.target.segments, transformed)
	if err != nil {
		return fail(reasonTransformInvalid, "transform could not be applied: %v", err)
	}
	if f := checkSize(rebuilt, maxSnapshotBytes, reasonResourceLimitExceeded, "snapshot"); f != nil {
		return f
	}
	return nil
}

// setIn returns a copy of node with the value at segments replaced; every
// segment must already exist.
func setIn(node any, segments []segment, value any) (any, error) {
	if len(segments) == 0 {
		return value, nil
	}
	s := segments[0]
	switch n := node.(type) {
	case map[string]any:
		if s.isIdx {
			return nil, errPathTypeMismatch
		}
		child, ok := n[s.field]
		if !ok {
			return nil, errPathMissing
		}
		replaced, err := setIn(child, segments[1:], value)
		if err != nil {
			return nil, err
		}
		out := make(map[string]any, len(n))
		for k, v := range n {
			out[k] = v
		}
		out[s.field] = replaced
		return out, nil
	case []any:
		if !s.isIdx {
			return nil, errPathTypeMismatch
		}
		if s.index >= len(n) {
			return nil, errPathMissing
		}
		replaced, err := setIn(n[s.index], segments[1:], value)
		if err != nil {
			return nil, err
		}
		out := append([]any(nil), n...)
		out[s.index] = replaced
		return out, nil
	default:
		return nil, errPathTypeMismatch
	}
}

func pathFailure(err error) *failure {
	reason := errPathMissing.Error()
	if errors.Is(err, errPathTypeMismatch) {
		reason = errPathTypeMismatch.Error()
	}
	return &failure{reason: reason, detail: err.Error()}
}

func checkAnnotatorOutput(name string, value any) *failure {
	if f := checkDepth(value, reasonAnnotationFailed, "annotator output"); f != nil {
		f.detail = name + ": " + f.detail
		return f
	}
	if reservedReason(value) {
		return fail(reasonAnnotationFailed, "%s: annotator output reason must not use reserved runtime_error prefix", name)
	}
	if f := checkSize(value, maxAnnotatorOutputBytes, reasonAnnotationFailed, "annotator output"); f != nil {
		f.detail = name + ": " + f.detail
		return f
	}
	return nil
}

func reservedReason(v any) bool {
	switch n := v.(type) {
	case []any:
		for _, e := range n {
			if reservedReason(e) {
				return true
			}
		}
	case map[string]any:
		if r, ok := n["reason"].(string); ok && strings.HasPrefix(r, runtimeErrorPrefix) {
			return true
		}
		for _, e := range n {
			if reservedReason(e) {
				return true
			}
		}
	}
	return false
}

// checkSize checks depth and the serialized size, as AGT's validators do.
func checkSize(v any, limit int, reason, what string) *failure {
	if f := checkDepth(v, reason, what); f != nil {
		return f
	}
	b, err := jsonv2.Marshal(v)
	if err != nil {
		return fail(reason, "failed to serialize %s: %v", what, err)
	}
	if len(b) > limit {
		return fail(reason, "%s serialized size %d exceeds limit %d", what, len(b), limit)
	}
	return nil
}

func checkDepth(v any, reason, what string) *failure {
	if depth(v) > maxDepth {
		return fail(reason, "%s JSON nesting depth exceeds limit %d", what, maxDepth)
	}
	return nil
}

// depth counts nested objects and arrays; a scalar has depth 0.
func depth(v any) int {
	deepest := 0
	switch n := v.(type) {
	case map[string]any:
		for _, e := range n {
			deepest = max(deepest, depth(e))
		}
		return deepest + 1
	case []any:
		for _, e := range n {
			deepest = max(deepest, depth(e))
		}
		return deepest + 1
	}
	return 0
}
