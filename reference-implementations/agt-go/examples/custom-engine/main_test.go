package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-json-experiment/json/jsontext"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian/guardiantest"
)

const secret = "0123456789abcdef0123456789abcdef"

// send signs a request with the host's own Signer and posts it.
func send(t *testing.T, url string, signer guardian.Signer, method, session string, payload any) acs.Response {
	t.Helper()
	p, _ := json.Marshal(payload)
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	req := acs.Request{JSONRPC: acs.JSONRPCVersion, Method: method, ID: json.RawMessage(`"` + requestID + `"`), Params: acs.Params{
		ACSVersion: acs.Version, RequestID: requestID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Metadata: acs.Metadata{AgentID: "example", SessionID: session}, Payload: p,
	}}
	body, _ := json.Marshal(req)
	canonical := jsontext.Value(body)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(context.Background(), session, "default", canonical)
	if err != nil {
		t.Fatal(err)
	}
	req.Params.Signature = &sig
	body, _ = json.Marshal(req)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out acs.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestServesAGovernedStep(t *testing.T) {
	g, store, err := newGuardian([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	defer server.Close()
	signer := vaultSigner{vault: map[string][]byte{"default": []byte(secret)}}
	session := "5c3f1b8e-9a0d-4c2e-8f4b-2d6a7e9c1b30"
	hello := acs.ClientHello{
		ACSVersionsSupported: []string{acs.Version},
		MethodsImplemented:   []string{acs.StepSessionStart, acs.StepUserMessage, acs.StepToolCallRequest, acs.StepToolCallResult, acs.StepAgentResponse, acs.StepSessionEnd},
		TransportsSupported:  []string{acs.TransportHTTP},
		ProvenanceProducer:   acs.ProvenanceNone,
		ProfilesSupported:    []string{acs.ProfileCore},
	}
	if r := send(t, server.URL, signer, acs.MethodHandshakeHello, session, hello); r.Error != nil {
		t.Fatalf("handshake: %+v", r.Error)
	}
	command := "rm -rf /tmp/x"
	r := send(t, server.URL, signer, acs.StepToolCallRequest, session, acs.ToolCallRequestPayload{
		Tool: acs.Tool{Name: "shell"}, Arguments: map[string]acs.ToolArgument{"command": {Value: json.RawMessage(`"` + command + `"`)}}, RawCommand: &command,
	})
	var result acs.Result
	if r.Error != nil || json.Unmarshal(r.Result, &result) != nil || result.Disposition != acs.Deny || result.ChainHash == "" || result.Signature == nil {
		t.Fatalf("got %+v %s", r.Error, r.Result)
	}
	if store.appends.Load() != 1 {
		t.Fatalf("the host's store saw %d appends, want 1", store.appends.Load())
	}
}

// TestStoreContract holds the host's store to the contract every
// SessionContextStore meets.
func TestStoreContract(t *testing.T) {
	guardiantest.TestSessionContextStore(t, func(t *testing.T) guardian.SessionContextStore {
		memory, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{MaxSessions: 8, MaxEntries: 64, MaxReservations: 128, MaxSkillApprovals: 8, Retention: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return &countingStore{MemorySessionContextStore: memory}
	})
}
