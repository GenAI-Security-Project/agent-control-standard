package schema

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// specificationDir is the repository's own specification, relative to this
// package.
const specificationDir = "../../../../specification/v0.1.0"

func TestSchemasMatchSpecification(t *testing.T) {
	want := readTree(t, os.DirFS(specificationDir), ".")
	got := readTree(t, files, root)
	for name, b := range want {
		c, ok := got[name]
		switch {
		case !ok:
			t.Errorf("%s is in specification/v0.1.0/ but not in the embedded copy", name)
		case !bytes.Equal(b, c):
			t.Errorf("%s differs from specification/v0.1.0/%s", name, name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s is in the embedded copy but not in specification/v0.1.0/", name)
		}
	}
	if t.Failed() {
		t.Log("run go generate ./internal/schema to refresh the copy")
	}
}

func readTree(t *testing.T, fsys fs.FS, dir string) map[string][]byte {
	t.Helper()
	tree := map[string][]byte{}
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		tree[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) == 0 {
		t.Fatalf("no files under %s", dir)
	}
	return tree
}

func TestEveryHookSchemaHasAMethod(t *testing.T) {
	entries, err := fs.ReadDir(files, root+"/hooks")
	if err != nil {
		t.Fatal(err)
	}
	mapped := map[string]bool{}
	for _, ref := range payloadSchemas {
		mapped[ref] = true
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".acs-provenance.json") {
			continue
		}
		if !mapped["hooks/"+name] {
			t.Errorf("hooks/%s is not the payload schema of any method", name)
		}
	}
}

func TestLoad(t *testing.T) {
	r := mustLoad(t)
	if got := len(r.payloads); got != len(payloadSchemas) {
		t.Fatalf("compiled %d payload schemas, want %d", got, len(payloadSchemas))
	}
}

func mustLoad(t *testing.T) *Registry {
	t.Helper()
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const validRequest = `{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "8d0b6b0e-4d6b-4f7a-9d1c-1f1c7f0e2a10",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "8d0b6b0e-4d6b-4f7a-9d1c-1f1c7f0e2a10",
    "timestamp": "2026-09-19T10:00:00Z",
    "metadata": {"agent_id": "agent", "session_id": "5c3f1b8e-9a0d-4c2e-8f4b-2d6a7e9c1b30"},
    "payload": {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}}
  }
}`

func TestValidateRequest(t *testing.T) {
	r := mustLoad(t)
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		pointer string
	}{
		{"valid", func(map[string]any) {}, ""},
		{"missing_request_id", func(m map[string]any) { delete(params(m), "request_id") }, "/params"},
		{"request_id_not_uuid", func(m map[string]any) { params(m)["request_id"] = "not-a-uuid" }, "/params/request_id"},
		{"timestamp_not_date_time", func(m map[string]any) { params(m)["timestamp"] = "yesterday" }, "/params/timestamp"},
		{"session_id_not_uuid", func(m map[string]any) {
			params(m)["metadata"].(map[string]any)["session_id"] = "demo"
		}, "/params/metadata/session_id"},
		{"unknown_top_level_member", func(m map[string]any) { m["Method"] = "x" }, ""},
		{"method_outside_namespaces", func(m map[string]any) { m["method"] = "tools/call" }, "/method"},
		{"nonce_too_short", func(m map[string]any) { params(m)["nonce"] = "short" }, "/params/nonce"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(validRequest), &m); err != nil {
				t.Fatal(err)
			}
			tt.mutate(m)
			err := r.Validate(RequestEnvelope, m)
			if tt.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("got %v, want a schema error", err)
			}
			if se.Pointer != tt.pointer {
				t.Fatalf("pointer %q, want %q (%s)", se.Pointer, tt.pointer, se.Message)
			}
		})
	}
}

func params(m map[string]any) map[string]any { return m["params"].(map[string]any) }

func TestValidatePayload(t *testing.T) {
	r := mustLoad(t)
	var ok, missing any
	if err := json.Unmarshal([]byte(`{"tool":{"name":"Bash"},"arguments":{}}`), &ok); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"tool":{"name":"Bash"}}`), &missing); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidatePayload(acs.StepToolCallRequest, ok); err != nil {
		t.Fatal(err)
	}
	var se *Error
	if err := r.ValidatePayload(acs.StepToolCallRequest, missing); !errors.As(err, &se) {
		t.Fatalf("got %v, want a schema error", err)
	}
	if err := r.ValidatePayload("steps/undefined", ok); !errors.Is(err, ErrNoPayloadSchema) {
		t.Fatalf("got %v, want ErrNoPayloadSchema", err)
	}
}

// TestWireTypesMatchSchemas checks every JSON member name of the acs types
// against the properties the schema declares for that object, and every
// required property against the type, so a mistyped tag cannot pass as an
// unknown member the schema tolerates.
func TestWireTypesMatchSchemas(t *testing.T) {
	tests := []struct {
		value   any
		ref     string
		extra   []string // members the type carries beyond the schema, each declared in the type's doc
		missing []string // schema properties the type leaves to raw JSON or omits on purpose
	}{
		{acs.Request{}, "request-envelope.json#", nil, nil},
		{acs.Params{}, "request-envelope.json#/$defs/AcsParams", nil, nil},
		{acs.Metadata{}, "request-envelope.json#/$defs/Metadata", nil, nil},
		{acs.SessionState{}, "request-envelope.json#/$defs/Metadata/properties/session_state", nil, nil},
		{acs.UserContext{}, "request-envelope.json#/$defs/Metadata/properties/user_context", nil, nil},
		{acs.Signature{}, "request-envelope.json#/$defs/Signature", nil, nil},
		{acs.Response{}, "response-envelope.json#", nil, nil},
		{acs.Result{}, "response-envelope.json#/$defs/AcsResult", nil, nil},
		{acs.Error{}, "response-envelope.json#/$defs/JsonRpcError", []string{"signature"}, nil},
		{acs.PolicyReference{}, "response-envelope.json#/$defs/AcsResult/properties/policy_references/items", nil, nil},
		{acs.EvaluationMetadata{}, "response-envelope.json#/$defs/AcsResult/properties/metadata", nil, nil},
		{acs.Modifications{}, "modifications.json#", nil, nil},
		{acs.Redaction{}, "modifications.json#/properties/redactions/items", nil, nil},
		{acs.AskDetails{}, "ask-details.json#", nil, nil},
		{acs.Approver{}, "ask-details.json#/properties/approver", nil, nil},
		{acs.ApproverAuth{}, "ask-details.json#/properties/approver/properties/auth", nil, nil},
		{acs.IntentExtension{}, "ask-details.json#/properties/intent_extension", nil, nil},
		{acs.Capability{}, "ask-details.json#/properties/intent_extension/properties/capabilities/items", nil, nil},
		{acs.DeferDetails{}, "defer-details.json#", nil, nil},
		{acs.ClientHello{}, "handshake.json#/$defs/ClientHello", nil, nil},
		{acs.WrappedProtocol{}, "handshake.json#/$defs/ClientHello/properties/wrapped_protocols/items", nil, nil},
		{acs.ServerHello{}, "handshake.json#/$defs/ServerHello", []string{"signature"}, []string{"agbom_serializations_supported", "trace_emission"}},
		{acs.TimeoutConfig{}, "handshake.json#/$defs/ServerHello/properties/timeout_config", nil, nil},
		{acs.ContextEntry{}, "context-entry.json#", []string{"turn_id", "approver", "intent_extension"}, nil},
		{acs.ProvenanceSummary{}, "provenance-summary.json#", nil, nil},
		{acs.Provenance{}, "provenance.json#", nil, nil},
		{acs.Intent{}, "hooks/session-start.json#/properties/intent", nil, nil},
		{acs.SessionStartPayload{}, "hooks/session-start.json#", nil, nil},
		{acs.AgentTriggerPayload{}, "hooks/agent-trigger.json#", nil, nil},
		{acs.SessionEndPayload{}, "hooks/session-end.json#", nil, nil},
		{acs.SystemPingPayload{}, "hooks/system-ping.json#", nil, nil},
		{acs.ToolCallRequestPayload{}, "hooks/tool-call-request.json#", nil, nil},
		{acs.Tool{}, "hooks/tool-call-request.json#/properties/tool", nil, nil},
		{acs.ToolArgument{}, "hooks/tool-call-request.json#/properties/arguments/additionalProperties", nil, nil},
		{acs.ToolCallIntent{}, "hooks/tool-call-request.json#/properties/intent", nil, nil},
		{acs.ToolCallResultPayload{}, "hooks/tool-call-result.json#", nil, nil},
		{acs.ToolOutput{}, "hooks/tool-call-result.json#/properties/outputs/items", nil, nil},
		{acs.SkillRegisterPayload{}, "hooks/skill-register.json#", nil, []string{"skill", "composition", "registration_provenance"}},
		{acs.SkillDefinition{}, "hooks/skill-register.json#/properties/definition", nil, []string{"ref", "body"}},
		{acs.Digest{}, "hooks/skill-load.json#/properties/digest", nil, nil},
		{acs.SkillLoadPayload{}, "hooks/skill-load.json#", nil, []string{"registration_ref", "parent_step_id", "digest_verified", "declared_capabilities"}},
		{acs.PostCompactPayload{}, "hooks/post-compact.json#", nil, nil},
		{acs.CompactSummary{}, "hooks/post-compact.json#/properties/summary", nil, nil},
	}
	for _, tt := range tests {
		name := reflect.TypeOf(tt.value).Name()
		t.Run(name, func(t *testing.T) {
			node := resolve(t, tt.ref)
			props, _ := node["properties"].(map[string]any)
			fields := jsonNames(reflect.TypeOf(tt.value))
			for _, f := range fields {
				if _, ok := props[f]; !ok && !slices.Contains(tt.extra, f) {
					t.Errorf("member %q is not a property of %s", f, tt.ref)
				}
			}
			for p := range props {
				if !slices.Contains(fields, p) && !slices.Contains(tt.missing, p) {
					t.Errorf("property %q of %s has no member in %s", p, tt.ref, name)
				}
			}
			required, _ := node["required"].([]any)
			for _, r := range required {
				if !slices.Contains(fields, r.(string)) {
					t.Errorf("required property %q of %s has no member in %s", r, tt.ref, name)
				}
			}
		})
	}
}

// resolve returns the schema object ref names, following a JSON pointer
// fragment within one file.
func resolve(t *testing.T, ref string) map[string]any {
	t.Helper()
	file, fragment, _ := strings.Cut(ref, "#")
	b, err := files.ReadFile(root + "/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var node any
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	for _, token := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
		if token == "" {
			continue
		}
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s: %q does not address an object", ref, token)
		}
		node = m[token]
	}
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s does not address a schema object", ref)
	}
	return m
}

// jsonNames lists the JSON member names of a struct type, embedded structs
// inlined.
func jsonNames(typ reflect.Type) []string {
	var names []string
	for f := range typ.Fields() {
		if f.Anonymous {
			names = append(names, jsonNames(f.Type)...)
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}
