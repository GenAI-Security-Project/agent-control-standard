// Command custom-engine runs the Guardian with a host's own implementation
// of each of the four interfaces, and no AGT in its build: a policy engine
// that denies listed commands, a Signer over keys the host holds, a
// SessionContextStore that counts what it keeps, and an AuditLog that
// prints to standard error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// denyListEngine denies a tool call whose raw command contains a listed
// fragment, and allows every other step.
type denyListEngine struct{ fragments []string }

func (denyListEngine) Policy() guardian.PolicyDescription { return guardian.PolicyDescription{} }

func (e denyListEngine) Decide(_ context.Context, in guardian.PolicyInput) (guardian.PolicyDecision, error) {
	allow := guardian.PolicyDecision{Decision: acs.Decision{Disposition: acs.Allow}}
	if in.Request.Method != acs.StepToolCallRequest {
		return allow, nil
	}
	var call acs.ToolCallRequestPayload
	if err := json.Unmarshal(in.Request.Params.Payload, &call); err != nil {
		return guardian.PolicyDecision{}, err
	}
	if call.RawCommand == nil {
		return allow, nil
	}
	for _, f := range e.fragments {
		if strings.Contains(*call.RawCommand, f) {
			return guardian.PolicyDecision{Decision: acs.Decision{
				Disposition: acs.Deny,
				Reasoning:   fmt.Sprintf("the command contains %q, which this deployment forbids", f),
				ReasonCodes: []string{"deny_listed_command"},
			}}, nil
		}
	}
	return allow, nil
}

// vaultSigner stands for a host's key custody: it looks the secret up by
// key_id at each call and never hands it out.
type vaultSigner struct{ vault map[string][]byte }

func (vaultSigner) Algorithms() []string { return []string{acs.SignatureAlgorithmHMACSHA256} }

func (v vaultSigner) signer(keyID string) (*guardian.HMACSigner, error) {
	secret, ok := v.vault[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: no key %q in the vault", guardian.ErrSignatureInvalid, keyID)
	}
	return guardian.NewHMACSigner(guardian.HMACKey{ID: keyID, Secret: secret})
}

func (v vaultSigner) Verify(ctx context.Context, sessionID string, input []byte, sig acs.Signature) error {
	s, err := v.signer(sig.KeyID)
	if err != nil {
		return err
	}
	return s.Verify(ctx, sessionID, input, sig)
}

func (v vaultSigner) Sign(ctx context.Context, sessionID, keyID string, input []byte) (acs.Signature, error) {
	if keyID == "" {
		keyID = "default"
	}
	s, err := v.signer(keyID)
	if err != nil {
		return acs.Signature{}, err
	}
	return s.Sign(ctx, sessionID, keyID, input)
}

// countingStore keeps sessions in the default store and counts appends; a
// host's database store implements the same methods.
type countingStore struct {
	*guardian.MemorySessionContextStore
	appends atomic.Int64
}

func (s *countingStore) Append(ctx context.Context, sessionID string, a guardian.Append) error {
	err := s.MemorySessionContextStore.Append(ctx, sessionID, a)
	if err == nil {
		s.appends.Add(1)
	}
	return err
}

// stderrAuditLog prints each audit event.
type stderrAuditLog struct{}

func (stderrAuditLog) Envelope(context.Context, guardian.EnvelopeRecord) {}

func (stderrAuditLog) Event(_ context.Context, e guardian.AuditEvent) {
	fmt.Fprintf(os.Stderr, "audit %s session=%s request=%s: %s\n", e.Kind, e.SessionID, e.RequestID, e.Message)
}

func newGuardian(secret []byte) (*guardian.Guardian, *countingStore, error) {
	if len(secret) < guardian.MinHMACSecretBytes {
		return nil, nil, errors.New("the secret must be at least 32 bytes")
	}
	memory, err := guardian.NewMemorySessionContextStore(guardian.MemoryStoreLimits{
		MaxSessions:       guardian.DefaultMaxSessions,
		MaxEntries:        guardian.DefaultMaxEntries,
		MaxReservations:   guardian.DefaultMaxReservations,
		MaxSkillApprovals: guardian.DefaultMaxSkillApprovals,
		Retention:         guardian.DefaultSessionRetention,
	})
	if err != nil {
		return nil, nil, err
	}
	store := &countingStore{MemorySessionContextStore: memory}
	g, err := guardian.New(guardian.Config{
		Engine:   denyListEngine{fragments: []string{"rm -rf", "mkfs"}},
		Signer:   vaultSigner{vault: map[string][]byte{"default": secret}},
		Store:    store,
		AuditLog: stderrAuditLog{},
	})
	return g, store, err
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8788", "address to serve POST /acs on")
	flag.Parse()
	g, _, err := newGuardian([]byte(os.Getenv("ACS_HMAC_SECRET")))
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/acs", g)
	log.Printf("Guardian with a custom engine listening at http://%s/acs", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
