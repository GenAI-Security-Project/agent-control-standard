//go:build agteval

// Package agteval is the AGT evaluator: it executes AGT's policy for
// agtbridge by calling AGT's own runtime library, the Rust crate
// agent_control_specification_core, in the Guardian's process through its
// C ABI. It compiles only with the agteval build tag and cgo, so a program
// that imports guardian or agtbridge links no native library unless it
// imports this package.
//
// One runtime handle is built at startup and serves every call: AGT's
// evaluate takes it read-only and keeps no state between calls, so session
// state stays in agtbridge's policy state and the snapshot. The handle is
// never freed, since a call the Guardian stopped waiting for may still be
// running in it. At the pinned AGT version Rego runs in the opa program, one
// process per decision.
package agteval

/*
#cgo LDFLAGS: -lagent_control_specification_core
#cgo linux LDFLAGS: -ldl
#cgo darwin,amd64 LDFLAGS: -Wl,-rpath,${SRCDIR}/../../.acs/agt/darwin-amd64/lib
#cgo darwin,arm64 LDFLAGS: -Wl,-rpath,${SRCDIR}/../../.acs/agt/darwin-arm64/lib
#include <stdlib.h>
#include "acs.h"

int32_t agteval_register_annotator(AcsBuilder *b, char **err);
char *agteval_library_path(void);
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
)

// BuildRecord is the file scripts/build-agt-native.sh writes beside the
// library it builds: the AGT commit it built and the library's SHA-256.
const BuildRecord = "agt-native.json"

// The environment AGT's default policy dispatcher reads its opa executable
// and timeout from when the runtime is built (policy-engine/core/src/opa.rs).
const (
	opaPathEnv    = "ACS_OPA_PATH"
	opaTimeoutEnv = "ACS_OPA_TIMEOUT_MS"
)

// annotationFailed is the string a host annotator returns to make AGT fail
// the annotation closed (policy-engine/core/src/constants.rs).
const annotationFailed = "runtime_error:annotation_failed"

// Config is what the AGT evaluator needs beyond the library.
type Config struct {
	// ManifestPath is the manifest's file path; AGT resolves its bundle
	// relative to the manifest's directory.
	ManifestPath string
	// OPAPath is the opa executable AGT runs for each Rego decision.
	OPAPath string
	// OPATimeout bounds each opa run, in whole milliseconds; AGT denies a
	// decision whose run exceeds it.
	OPATimeout time.Duration
}

// Evaluator is the AGT evaluator.
type Evaluator struct {
	runtime *C.AcsRuntime
	points  map[string]bool
	version string
	calls   atomic.Uint64
}

var _ agtbridge.Evaluator = (*Evaluator)(nil)

// buildLock serializes builds, since each publishes its opa settings
// through the process environment for the moment AGT reads them.
var buildLock sync.Mutex

// New verifies the loaded library against its build record and builds one
// runtime from the manifest, with this Guardian's egress annotator and
// AGT's own opa policy dispatcher. AGT reads the opa settings only from the
// process environment, so New sets them for the moment of the build: build
// every evaluator before any of them serves, since another evaluator's opa
// launch would read the environment while New changes it.
func New(c Config) (*Evaluator, error) {
	if c.ManifestPath == "" {
		return nil, errors.New("agteval: the manifest path is empty")
	}
	if c.OPATimeout <= 0 || c.OPATimeout%time.Millisecond != 0 {
		return nil, errors.New("agteval: the opa timeout must be a positive whole number of milliseconds")
	}
	if info, err := os.Stat(c.OPAPath); err == nil && info.IsDir() {
		name := "opa"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		c.OPAPath = filepath.Join(c.OPAPath, name)
	}
	path, err := exec.LookPath(c.OPAPath)
	if err != nil {
		return nil, fmt.Errorf("agteval: %q is not an opa executable (make agt-native fetches the pinned one)", c.OPAPath)
	}
	c.OPAPath = path
	version, err := libraryVersion()
	if err != nil {
		return nil, err
	}
	runtime, err := build(c)
	if err != nil {
		return nil, err
	}
	points, err := governedPoints(runtime)
	if err != nil {
		C.acs_runtime_free(runtime)
		return nil, err
	}
	return &Evaluator{runtime: runtime, points: points, version: version}, nil
}

func build(c Config) (*C.AcsRuntime, error) {
	buildLock.Lock()
	defer buildLock.Unlock()
	restore, err := setenv(map[string]string{
		opaPathEnv:    c.OPAPath,
		opaTimeoutEnv: strconv.FormatInt(c.OPATimeout.Milliseconds(), 10),
	})
	if err != nil {
		return nil, fmt.Errorf("agteval: %w", err)
	}
	defer restore()
	path := C.CString(c.ManifestPath)
	defer C.free(unsafe.Pointer(path))
	var cErr *C.char
	builder := C.acs_builder_from_path(path, &cErr)
	if builder == nil {
		return nil, abiError("load the manifest "+c.ManifestPath, cErr)
	}
	if C.agteval_register_annotator(builder, &cErr) != 0 {
		C.acs_builder_free(builder)
		return nil, abiError("register the annotator dispatcher", cErr)
	}
	if C.acs_builder_enable_default_policy_dispatcher(builder, &cErr) != 0 {
		C.acs_builder_free(builder)
		return nil, abiError("enable the opa policy dispatcher", cErr)
	}
	runtime := C.acs_builder_build(builder, &cErr)
	if runtime == nil {
		return nil, abiError("build the runtime from "+c.ManifestPath, cErr)
	}
	return runtime, nil
}

// setenv sets each variable and returns what puts the previous values back.
func setenv(values map[string]string) (func(), error) {
	type previous struct {
		value string
		set   bool
	}
	saved := map[string]previous{}
	restore := func() {
		for name, p := range saved {
			if p.set {
				_ = os.Setenv(name, p.value)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}
	for name, value := range values {
		old, set := os.LookupEnv(name)
		saved[name] = previous{old, set}
		if err := os.Setenv(name, value); err != nil {
			restore()
			return nil, err
		}
	}
	return restore, nil
}

// governedPoints reads the intervention points the manifest configures,
// and refuses one that wires an annotator this Guardian does not dispatch.
func governedPoints(runtime *C.AcsRuntime) (map[string]bool, error) {
	var cErr *C.char
	out := C.acs_runtime_policy_labels(runtime, &cErr)
	if out == nil {
		return nil, abiError("read the manifest's intervention points", cErr)
	}
	defer C.acs_free_string(out)
	var labels map[string]struct {
		Annotators []string `json:"annotators"`
	}
	if err := jsonv2.Unmarshal([]byte(C.GoString(out)), &labels); err != nil {
		return nil, fmt.Errorf("agteval: read the manifest's intervention points: %w", err)
	}
	points := map[string]bool{}
	for point, label := range labels {
		for _, annotator := range label.Annotators {
			if annotator != agtbridge.EgressAnnotator {
				return nil, fmt.Errorf("agteval: intervention point %s wires annotator %q, for which this Guardian has no dispatcher", point, annotator)
			}
		}
		points[point] = true
	}
	return points, nil
}

// libraryVersion finds the file the loader mapped for AGT's runtime
// library and returns the AGT commit its build record names.
func libraryVersion() (string, error) {
	cPath := C.agteval_library_path()
	if cPath == nil {
		return "", errors.New("agteval: the loaded AGT runtime library cannot be located")
	}
	defer C.free(unsafe.Pointer(cPath))
	return verifyBuildRecord(C.GoString(cPath))
}

// verifyBuildRecord checks a library against the build record beside it
// and returns the AGT commit the record names.
func verifyBuildRecord(library string) (string, error) {
	recordPath := filepath.Join(filepath.Dir(library), BuildRecord)
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return "", fmt.Errorf("agteval: the AGT runtime library %s has no build record (make agt-native): %w", library, err)
	}
	var record struct {
		AGTRef string `json:"agt_ref"`
		SHA256 string `json:"sha256"`
	}
	if err := jsonv2.Unmarshal(raw, &record); err != nil || record.AGTRef == "" || record.SHA256 == "" {
		return "", fmt.Errorf("agteval: the build record %s does not name an AGT commit and a SHA-256 (make agt-native)", recordPath)
	}
	f, err := os.Open(library)
	if err != nil {
		return "", fmt.Errorf("agteval: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("agteval: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != record.SHA256 {
		return "", fmt.Errorf("agteval: the AGT runtime library %s has SHA-256 %s, and its build record names %s (make agt-native)", library, got, record.SHA256)
	}
	return record.AGTRef, nil
}

// Governs implements agtbridge.Evaluator.
func (e *Evaluator) Governs(point string) bool { return e.points[point] }

// AGTVersion implements agtbridge.Evaluator: the AGT commit the loaded
// library was built from.
func (e *Evaluator) AGTVersion() string { return e.version }

// Calls is the number of evaluations made in AGT's runtime library.
func (e *Evaluator) Calls() uint64 { return e.calls.Load() }

type request struct {
	InterventionPoint string         `json:"intervention_point"`
	Mode              string         `json:"mode"`
	Snapshot          map[string]any `json:"snapshot"`
}

// Evaluate implements agtbridge.Evaluator. A call into AGT cannot be
// interrupted: when ctx ends during it, the call runs to completion and its
// verdict is discarded, while the Guardian keeps the call's engine slot.
func (e *Evaluator) Evaluate(ctx context.Context, point string, snapshot map[string]any) (agtbridge.Verdict, error) {
	if err := ctx.Err(); err != nil {
		return agtbridge.Verdict{}, err
	}
	body, err := jsonv2.Marshal(request{InterventionPoint: point, Mode: "enforce", Snapshot: snapshot})
	if err != nil {
		return agtbridge.Verdict{}, fmt.Errorf("agteval: encode the request: %w", err)
	}
	cRequest := C.CString(string(body))
	defer C.free(unsafe.Pointer(cRequest))
	var cErr *C.char
	e.calls.Add(1)
	out := C.acs_runtime_evaluate(e.runtime, cRequest, &cErr)
	if out == nil {
		return agtbridge.Verdict{}, abiError("evaluate", cErr)
	}
	defer C.acs_free_string(out)
	if err := ctx.Err(); err != nil {
		return agtbridge.Verdict{}, err
	}
	var result struct {
		Verdict *agtbridge.Verdict `json:"verdict"`
	}
	if err := jsonv2.Unmarshal([]byte(C.GoString(out)), &result); err != nil || result.Verdict == nil {
		return agtbridge.Verdict{}, fmt.Errorf("agteval: AGT answered without a verdict: %v", err)
	}
	return *result.Verdict, nil
}

func abiError(what string, cErr *C.char) error {
	if cErr == nil {
		return fmt.Errorf("agteval: %s failed without an error message", what)
	}
	defer C.acs_free_string(cErr)
	return fmt.Errorf("agteval: %s: %s", what, C.GoString(cErr))
}

// agtevalAnnotate is the host annotator AGT calls for each annotation of a
// step. It dispatches the egress annotator, the one this Guardian supplies,
// and fails any other closed. A panic must not unwind into AGT's frames.
//
//export agtevalAnnotate
func agtevalAnnotate(name, preliminary *C.char) (out *C.char) {
	defer func() {
		if recover() != nil {
			out = C.CString(annotationFailed)
		}
	}()
	if C.GoString(name) != agtbridge.EgressAnnotator {
		return C.CString(annotationFailed)
	}
	var input map[string]any
	if err := jsonv2.Unmarshal([]byte(C.GoString(preliminary)), &input); err != nil {
		return C.CString(annotationFailed)
	}
	answer, err := jsonv2.Marshal(agtbridge.AnnotateEgress(input))
	if err != nil {
		return C.CString(annotationFailed)
	}
	return C.CString(string(answer))
}
