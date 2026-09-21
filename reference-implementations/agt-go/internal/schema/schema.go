// Package schema validates ACS messages against the specification's own JSON
// Schemas.
//
// specification/v0.1.0/ in this package is a byte-identical copy of the
// repository's specification/v0.1.0/, embedded so the Guardian carries its
// schemas wherever the module is built. TestSchemasMatchSpecification fails
// when the two differ; go generate ./internal/schema refreshes the copy.
package schema

//go:generate go run gen.go

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

//go:embed specification/v0.1.0
var files embed.FS

const root = "specification/v0.1.0"

// Base is the namespace every schema $id in the package sits under.
const Base = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/"

// References of the schemas the Guardian validates against, relative to
// Base.
const (
	RequestEnvelope  = "request-envelope.json"
	ResponseEnvelope = "response-envelope.json"
	ContextEntry     = "context-entry.json"
	ServerHello      = "handshake.json#/$defs/ServerHello"
)

// payloadSchemas maps each method to the schema its params.payload is
// validated against. ACS-Core validates the base hook schemas; the
// *.acs-provenance.json variants belong to the ACS-Provenance profile.
var payloadSchemas = map[string]string{
	acs.MethodHandshakeHello:       "handshake.json#/$defs/ClientHello",
	acs.MethodSystemPing:           "hooks/system-ping.json",
	acs.MethodAgBOMSnapshot:        "hooks/agbom-snapshot.json",
	acs.MethodAgBOMChanged:         "hooks/agbom-changed.json",
	acs.StepSessionStart:           "hooks/session-start.json",
	acs.StepAgentTrigger:           "hooks/agent-trigger.json",
	acs.StepTurnStart:              "hooks/turn-start.json",
	acs.StepUserMessage:            "hooks/user-message.json",
	acs.StepAgentResponse:          "hooks/agent-response.json",
	acs.StepKnowledgeRetrieval:     "hooks/knowledge-retrieval.json",
	acs.StepMemoryContextRetrieval: "hooks/memory-context-retrieval.json",
	acs.StepMemoryStore:            "hooks/memory-store.json",
	acs.StepToolCallRequest:        "hooks/tool-call-request.json",
	acs.StepToolCallResult:         "hooks/tool-call-result.json",
	acs.StepPreCompact:             "hooks/pre-compact.json",
	acs.StepPostCompact:            "hooks/post-compact.json",
	acs.StepSubagentStart:          "hooks/subagent-start.json",
	acs.StepSubagentStop:           "hooks/subagent-stop.json",
	acs.StepSkillRegister:          "hooks/skill-register.json",
	acs.StepSkillLoad:              "hooks/skill-load.json",
	acs.StepSkillUnload:            "hooks/skill-unload.json",
	acs.StepTurnEnd:                "hooks/turn-end.json",
	acs.StepSessionEnd:             "hooks/session-end.json",
}

// Registry holds every schema the Guardian validates against, compiled once.
type Registry struct {
	byRef    map[string]*jsonschema.Schema
	payloads map[string]*jsonschema.Schema
}

// Error reports the first place an instance fails its schema.
type Error struct {
	// Pointer is the JSON pointer of the failing value within the instance.
	Pointer string
	Message string
}

func (e *Error) Error() string {
	if e.Pointer == "" {
		return "schema validation failed at the root: " + e.Message
	}
	return fmt.Sprintf("schema validation failed at %s: %s", e.Pointer, e.Message)
}

// ErrNoPayloadSchema is returned for a method the specification defines no
// payload schema for.
var ErrNoPayloadSchema = errors.New("no payload schema for method")

// Load compiles every schema of the embedded specification.
func Load() (*Registry, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseLoader(jsonschema.SchemeURLLoader{})
	err := fs.WalkDir(files, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		want := Base + strings.TrimPrefix(p, root+"/")
		obj, _ := doc.(map[string]any)
		if id, _ := obj["$id"].(string); id != want {
			return fmt.Errorf("%s: $id is %q, want %q", p, id, want)
		}
		return c.AddResource(want, doc)
	})
	if err != nil {
		return nil, fmt.Errorf("load schemas: %w", err)
	}
	r := &Registry{byRef: map[string]*jsonschema.Schema{}, payloads: map[string]*jsonschema.Schema{}}
	compile := func(ref string) (*jsonschema.Schema, error) {
		if s, ok := r.byRef[ref]; ok {
			return s, nil
		}
		s, err := c.Compile(Base + ref)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", ref, err)
		}
		r.byRef[ref] = s
		return s, nil
	}
	for _, ref := range []string{RequestEnvelope, ResponseEnvelope, ContextEntry, ServerHello} {
		if _, err := compile(ref); err != nil {
			return nil, err
		}
	}
	for method, ref := range payloadSchemas {
		s, err := compile(ref)
		if err != nil {
			return nil, err
		}
		r.payloads[method] = s
	}
	return r, nil
}

// Validate checks a decoded JSON instance against the schema ref names, one
// of the references declared in this package.
func (r *Registry) Validate(ref string, instance any) error {
	s, ok := r.byRef[ref]
	if !ok {
		return fmt.Errorf("schema %s is not registered", ref)
	}
	return check(s, instance)
}

// ValidatePayload checks a decoded params.payload against the payload schema
// of method.
func (r *Registry) ValidatePayload(method string, payload any) error {
	s, ok := r.payloads[method]
	if !ok {
		return fmt.Errorf("%w %s", ErrNoPayloadSchema, method)
	}
	return check(s, payload)
}

// ValidateJSON decodes b and checks it against the schema ref names.
func (r *Registry) ValidateJSON(ref string, b []byte) error {
	var instance any
	if err := json.Unmarshal(b, &instance); err != nil {
		return err
	}
	return r.Validate(ref, instance)
}

func check(s *jsonschema.Schema, instance any) error {
	err := s.Validate(instance)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	leaf := firstLeaf(ve)
	return &Error{Pointer: pointer(leaf.InstanceLocation), Message: leaf.ErrorKind.LocalizedString(printer)}
}

var printer = message.NewPrinter(language.English)

// firstLeaf descends to the first innermost cause, which names the specific
// keyword that failed rather than the enclosing schema.
func firstLeaf(e *jsonschema.ValidationError) *jsonschema.ValidationError {
	for len(e.Causes) > 0 {
		e = e.Causes[0]
	}
	return e
}

// pointer renders an instance location as an RFC 6901 JSON pointer; the
// root is the empty pointer.
func pointer(location []string) string {
	var b strings.Builder
	for _, token := range location {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(token))
	}
	return b.String()
}
