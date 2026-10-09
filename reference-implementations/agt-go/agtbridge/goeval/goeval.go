// Package goeval is the Go evaluator: it executes AGT's policy for agtbridge
// without AGT's runtime library, so the Guardian builds and runs without cgo.
//
// It evaluates AGT's policy bundle, unchanged, with OPA's Go library in
// process, and reproduces in Go the part of AGT's runtime
// (policy-engine/core at AGTVersion) that the reference's manifest uses:
// assembling the policy input from a snapshot at the pre_tool_call and
// post_tool_call intervention points, the annotator dispatch, and
// normalising the Rego result into a verdict, including AGT's fail-closed
// runtime_error denials. A manifest feature outside that part is refused
// when the evaluator is built. AGT's runtime library, which the AGT
// evaluator calls, is the authority; the comparison test in agtbridge
// reports every case where the two disagree.
package goeval

import (
	"context"
	"fmt"
	"io/fs"
	"path"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
)

// AGTVersion is the AGT commit whose runtime this package reproduces, the
// commit the TypeScript reference's agt.lock pins.
const AGTVersion = "81955d48025c6b11deb3fc9dabf89f74f4145775"

// Evaluator is the Go evaluator.
type Evaluator struct {
	manifest *manifest
	points   map[string]*compiledPoint
	queries  map[string]rego.PreparedEvalQuery // by intervention point
}

var _ agtbridge.Evaluator = (*Evaluator)(nil)

// New builds the evaluator from the manifest at manifestPath in fsys,
// compiling the manifest's Rego bundle once. The bundle is found relative
// to the manifest's directory, as AGT resolves it.
func New(ctx context.Context, fsys fs.FS, manifestPath string) (*Evaluator, error) {
	src, err := fs.ReadFile(fsys, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("goeval: %w", err)
	}
	m, err := parseManifest(src)
	if err != nil {
		return nil, fmt.Errorf("goeval: %s: %w", manifestPath, err)
	}
	points, err := m.compile()
	if err != nil {
		return nil, fmt.Errorf("goeval: %s: %w", manifestPath, err)
	}
	e := &Evaluator{manifest: m, points: points, queries: map[string]rego.PreparedEvalQuery{}}
	if err := e.prepare(ctx, fsys, path.Dir(manifestPath)); err != nil {
		return nil, fmt.Errorf("goeval: %s: %w", manifestPath, err)
	}
	return e, nil
}

// Governs implements agtbridge.Evaluator.
func (e *Evaluator) Governs(point string) bool {
	_, ok := e.points[point]
	return ok
}

// AGTVersion implements agtbridge.Evaluator.
func (e *Evaluator) AGTVersion() string { return AGTVersion }
