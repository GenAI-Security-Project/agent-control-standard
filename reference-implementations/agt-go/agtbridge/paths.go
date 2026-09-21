package agtbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The path dialect of AGT's manifest (policy-engine/core/src/paths.rs): a
// root, then a flat sequence of .field, ["field"] and [index] segments. No
// wildcard, recursive descent, slice, filter or negative index exists.

type pathRoot int

const (
	rootSnap pathRoot = iota
	rootPI
	rootPolicyTarget
	rootTool
)

var rootNames = []struct {
	name string
	root pathRoot
}{
	// Longest first, so $policy_target is not read as $pi.
	{"$policy_target", rootPolicyTarget},
	{"$snap", rootSnap},
	{"$tool", rootTool},
	{"$pi", rootPI},
}

type segment struct {
	field string
	index int
	isIdx bool
}

type jsonPath struct {
	original string
	root     pathRoot
	segments []segment
}

// parseSnapshotPath parses a path in which $ and $. stand for $snap, as
// policy_target, tool_name_from and an annotation's from are written.
func parseSnapshotPath(s string) (jsonPath, error) {
	aliased := s
	switch {
	case s == "$":
		aliased = "$snap"
	case strings.HasPrefix(s, "$."):
		aliased = "$snap." + s[2:]
	}
	p, err := parsePath(aliased)
	p.original = s
	return p, err
}

// parsePath parses a path with an explicit root, as a transform's path is
// written.
func parsePath(s string) (jsonPath, error) {
	p := jsonPath{original: s}
	rest := ""
	found := false
	for _, r := range rootNames {
		if after, ok := strings.CutPrefix(s, r.name); ok && (after == "" || after[0] == '.' || after[0] == '[') {
			p.root, rest, found = r.root, after, true
			break
		}
	}
	if !found {
		return p, fmt.Errorf("path %q has an unknown root", s)
	}
	for rest != "" {
		switch rest[0] {
		case '.':
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			field := rest[:end]
			if field == "" || strings.Contains(field, "]") {
				return p, fmt.Errorf("path %q has an invalid field segment", s)
			}
			p.segments = append(p.segments, segment{field: field})
			rest = rest[end:]
		case '[':
			end := strings.IndexByte(rest, ']')
			if len(rest) > 1 && rest[1] == '"' {
				end = closingQuote(rest)
			}
			if end < 0 {
				return p, fmt.Errorf("path %q has an unclosed bracket", s)
			}
			inner := rest[1:end]
			rest = rest[end+1:]
			if strings.HasPrefix(inner, `"`) {
				var field string
				if err := json.Unmarshal([]byte(inner), &field); err != nil {
					return p, fmt.Errorf("path %q has an invalid quoted field", s)
				}
				p.segments = append(p.segments, segment{field: field})
				continue
			}
			if strings.HasPrefix(inner, "-") {
				return p, fmt.Errorf("path %q has a negative index", s)
			}
			n, err := strconv.Atoi(inner)
			if err != nil || n < 0 {
				return p, fmt.Errorf("path %q has an invalid index", s)
			}
			p.segments = append(p.segments, segment{index: n, isIdx: true})
		default:
			return p, fmt.Errorf("path %q is malformed", s)
		}
	}
	return p, nil
}

// closingQuote returns the index of the ] that closes a ["..."] segment
// starting at s[0], honouring escapes inside the quoted field.
func closingQuote(s string) int {
	for i := 2; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			if i+1 < len(s) && s[i+1] == ']' {
				return i + 1
			}
			return -1
		}
	}
	return -1
}

// pathEnv holds the documents a path may start from.
type pathEnv struct {
	snap any
	pi   map[string]any
}

// Errors of resolving a path, each an AGT runtime_error reason.
var (
	errPathMissing      = errors.New("runtime_error:path_missing")
	errPathTypeMismatch = errors.New("runtime_error:path_type_mismatch")
)

// resolve reads the value p addresses.
func (p jsonPath) resolve(env pathEnv) (any, error) {
	var node any
	switch p.root {
	case rootSnap:
		node = env.snap
	case rootPI:
		if env.pi == nil {
			return nil, fmt.Errorf("%w: root not available for %s", errPathMissing, p.original)
		}
		node = env.pi
	case rootPolicyTarget:
		target, _ := env.pi["policy_target"].(map[string]any)
		if target == nil {
			return nil, fmt.Errorf("%w: root not available for %s", errPathMissing, p.original)
		}
		node = target["value"]
	case rootTool:
		tool, ok := env.pi["tool"]
		if !ok {
			return nil, fmt.Errorf("%w: root not available for %s", errPathMissing, p.original)
		}
		node = tool
	}
	for _, s := range p.segments {
		switch n := node.(type) {
		case map[string]any:
			if s.isIdx {
				return nil, fmt.Errorf("%w: %s", errPathTypeMismatch, p.original)
			}
			v, ok := n[s.field]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errPathMissing, p.original)
			}
			node = v
		case []any:
			if !s.isIdx {
				return nil, fmt.Errorf("%w: %s", errPathTypeMismatch, p.original)
			}
			if s.index >= len(n) {
				return nil, fmt.Errorf("%w: %s", errPathMissing, p.original)
			}
			node = n[s.index]
		default:
			return nil, fmt.Errorf("%w: %s", errPathTypeMismatch, p.original)
		}
	}
	return node, nil
}

// referencesPIAnnotations reports whether p reads the annotations member of
// the policy input, which does not exist when an annotation's from is
// checked.
func (p jsonPath) referencesPIAnnotations() bool {
	return p.root == rootPI && len(p.segments) > 0 && !p.segments[0].isIdx && p.segments[0].field == "annotations"
}
