package guardian

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/method"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

// echoProtocol is a test-only handler registered under the name MCP, the
// only wrapped protocol handshake.json lets a client declare with wrapping
// semantics. It reads its message and nothing else, which is all a handler
// contributes; it implements none of MCP.
type echoProtocol struct{ checked []string }

func (*echoProtocol) Protocol() string { return "MCP" }

func (*echoProtocol) Supports(m string) bool { return m == "say" }

func (p *echoProtocol) Check(m string, payload json.RawMessage) error {
	p.checked = append(p.checked, m)
	var msg struct {
		Text *string `json:"text"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil || msg.Text == nil {
		return errors.New("the test message carries text")
	}
	return nil
}

func (*echoProtocol) ParameterOverridePointer(argument string) string {
	return "/arguments/" + argument
}

type allowEngine struct{ methods []string }

func (*allowEngine) Policy() PolicyDescription { return PolicyDescription{} }

func (e *allowEngine) Decide(_ context.Context, in PolicyInput) (PolicyDecision, error) {
	e.methods = append(e.methods, in.Request.Method)
	return PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}, nil
}

func TestWrappedProtocolRouting(t *testing.T) {
	const (
		call        = "protocols/MCP/say"
		explicit    = "wrapped:mcp-2025-06-18/say"
		unsupported = "protocols/MCP/shout"
	)
	hello := observedagent.DefaultHello(append(method.Hooks(), call, explicit, unsupported)...)
	hello.WrappedProtocols = []acs.WrappedProtocol{{Protocol: "MCP", Version: "2025-06-18"}}
	signer, err := NewHMACSigner(HMACKey{ID: "k", Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, table *method.Table) (*observedagent.Client, *allowEngine, acs.ServerHello) {
		engine := &allowEngine{}
		g, err := newGuardian(Config{Engine: engine, Signer: signer}, table)
		if err != nil {
			t.Fatal(err)
		}
		c := &observedagent.Client{
			Transport: func(ctx context.Context, body []byte) ([]byte, error) { return g.Handle(ctx, body), nil },
			Signer:    signer, AgentID: "a", SessionID: observedagent.NewUUID(),
		}
		o, err := c.Handshake(context.Background(), hello)
		if err != nil || o.Hello == nil {
			t.Fatalf("handshake: %v %s", err, o.Raw)
		}
		return c, engine, *o.Hello
	}

	t.Run("registered", func(t *testing.T) {
		handler := &echoProtocol{}
		c, engine, server := start(t, method.NewTable(handler))
		if !slices.Contains(server.MethodsEvaluated, call) || !slices.Contains(server.MethodsEvaluated, explicit) || slices.Contains(server.MethodsEvaluated, unsupported) {
			t.Fatalf("methods_evaluated %v: want %s and %s, not %s", server.MethodsEvaluated, call, explicit, unsupported)
		}
		for _, m := range []string{call, explicit} {
			o, err := c.Send(context.Background(), observedagent.Request{Method: m, Payload: map[string]any{"text": "hi"}})
			if err != nil {
				t.Fatal(err)
			}
			if o.Result == nil || !o.Verified || o.Result.Disposition != acs.Allow || o.Result.ChainHash == "" {
				t.Fatalf("%s got %s", m, o.Raw)
			}
		}
		if !slices.Equal(engine.methods, []string{call, explicit}) || !slices.Equal(handler.checked, []string{"say", "say"}) {
			t.Fatalf("engine saw %v, handler checked %v", engine.methods, handler.checked)
		}
		o, err := c.Send(context.Background(), observedagent.Request{Method: call, Payload: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		if o.Error == nil || o.Error.Code != acs.InvalidParams {
			t.Fatalf("an invalid wrapped message got %s, want -32602", o.Raw)
		}
		o, err = c.Send(context.Background(), observedagent.Request{Method: unsupported, Payload: map[string]any{"text": "hi"}})
		if err != nil {
			t.Fatal(err)
		}
		if o.Error == nil || o.Error.Code != acs.CapabilityNotNegotiated {
			t.Fatalf("a method the handler does not read got %s, want -32003", o.Raw)
		}
	})

	t.Run("unregistered", func(t *testing.T) {
		c, engine, server := start(t, method.NewTable())
		if slices.Contains(server.MethodsEvaluated, call) {
			t.Fatalf("methods_evaluated %v lists an unregistered protocol", server.MethodsEvaluated)
		}
		o, err := c.Send(context.Background(), observedagent.Request{Method: call, Payload: map[string]any{"text": "hi"}})
		if err != nil {
			t.Fatal(err)
		}
		if o.Error == nil || o.Error.Code != acs.CapabilityNotNegotiated {
			t.Fatalf("got %s, want -32003", o.Raw)
		}
		if len(engine.methods) != 0 {
			t.Fatal("the engine was called")
		}
	})
}
