package guardian_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

// signatureVectors reads the vectors computed in Python, independently of
// this module, for the §10 HMAC baseline.
type signatureVectors struct {
	IKMHex    string `json:"ikm_hex"`
	KeyID     string `json:"key_id"`
	SessionID string `json:"session_id"`
	Request   struct {
		Signed struct {
			Params struct {
				Signature acs.Signature `json:"signature"`
			} `json:"params"`
		} `json:"signed"`
		SigningInput string `json:"signing_input"`
	} `json:"request"`
	Response struct {
		Signed struct {
			Result struct {
				Signature acs.Signature `json:"signature"`
			} `json:"result"`
		} `json:"signed"`
		SigningInput string `json:"signing_input"`
	} `json:"response"`
}

func loadSignatureVectors(t *testing.T) (signatureVectors, *guardian.HMACSigner) {
	t.Helper()
	b, err := os.ReadFile("../internal/envelope/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v signatureVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	ikm, err := hex.DecodeString(v.IKMHex)
	if err != nil {
		t.Fatal(err)
	}
	s, err := guardian.NewHMACSigner(guardian.HMACKey{ID: v.KeyID, Secret: ikm})
	if err != nil {
		t.Fatal(err)
	}
	return v, s
}

func TestHMACSignerVectors(t *testing.T) {
	v, s := loadSignatureVectors(t)
	ctx := context.Background()
	if err := s.Verify(ctx, v.SessionID, []byte(v.Request.SigningInput), v.Request.Signed.Params.Signature); err != nil {
		t.Fatalf("request vector does not verify: %v", err)
	}
	got, err := s.Sign(ctx, v.SessionID, v.KeyID, []byte(v.Response.SigningInput))
	if err != nil {
		t.Fatal(err)
	}
	if got != v.Response.Signed.Result.Signature {
		t.Fatalf("signed %+v, want %+v", got, v.Response.Signed.Result.Signature)
	}
}

func TestHMACSignerRefuses(t *testing.T) {
	v, s := loadSignatureVectors(t)
	ctx := context.Background()
	input := []byte(v.Request.SigningInput)
	good := v.Request.Signed.Params.Signature
	tests := []struct {
		name      string
		sessionID string
		input     []byte
		sig       func(acs.Signature) acs.Signature
	}{
		{"other_session", "00000000-0000-4000-8000-000000000000", input, func(s acs.Signature) acs.Signature { return s }},
		{"changed_input", v.SessionID, append([]byte(" "), input...), func(s acs.Signature) acs.Signature { return s }},
		{"unknown_key_id", v.SessionID, input, func(s acs.Signature) acs.Signature { s.KeyID = "k9"; return s }},
		{"other_algorithm", v.SessionID, input, func(s acs.Signature) acs.Signature { s.Algorithm = "ECDSA-P256"; return s }},
		{"not_base64", v.SessionID, input, func(s acs.Signature) acs.Signature { s.Value = "***"; return s }},
		{"unpadded_base64", v.SessionID, input, func(s acs.Signature) acs.Signature { s.Value = strings.TrimRight(s.Value, "="); return s }},
		{"truncated", v.SessionID, input, func(s acs.Signature) acs.Signature { s.Value = s.Value[:8]; return s }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Verify(ctx, tt.sessionID, tt.input, tt.sig(good))
			if !errors.Is(err, guardian.ErrSignatureInvalid) {
				t.Fatalf("%v, want ErrSignatureInvalid", err)
			}
		})
	}
}

func TestHMACSignerRotation(t *testing.T) {
	ctx := context.Background()
	oldKey := guardian.HMACKey{ID: "old", Secret: []byte(strings.Repeat("o", 32))}
	newKey := guardian.HMACKey{ID: "new", Secret: []byte(strings.Repeat("n", 32))}
	before, err := guardian.NewHMACSigner(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	after, err := guardian.NewHMACSigner(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := before.Sign(ctx, "s", "", []byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	if err := after.Verify(ctx, "s", []byte("input"), sig); err != nil {
		t.Fatalf("a retired key no longer verifies: %v", err)
	}
	answer, err := after.Sign(ctx, "s", sig.KeyID, []byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	if answer.KeyID != "old" {
		t.Fatalf("answered with %q, want the key the request used", answer.KeyID)
	}
	unsigned, err := after.Sign(ctx, "s", "", []byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	if unsigned.KeyID != "new" {
		t.Fatalf("answered an unsigned request with %q, want the first key", unsigned.KeyID)
	}
	if _, err := after.Sign(ctx, "s", "gone", []byte("input")); err == nil {
		t.Fatal("signed with a key_id the signer does not hold")
	}
}

func TestNewHMACSignerRefuses(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	tests := []struct {
		name string
		keys []guardian.HMACKey
	}{
		{"no_key", nil},
		{"no_key_id", []guardian.HMACKey{{Secret: secret}}},
		{"short_secret", []guardian.HMACKey{{ID: "k", Secret: secret[:31]}}},
		{"duplicate_key_id", []guardian.HMACKey{{ID: "k", Secret: secret}, {ID: "k", Secret: secret}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := guardian.NewHMACSigner(tt.keys...); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestHMACSignerCopiesTheSecret(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	s, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "k", Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := s.Sign(context.Background(), "x", "", []byte("in"))
	secret[0] = 'z'
	again, _ := s.Sign(context.Background(), "x", "", []byte("in"))
	if sig != again {
		t.Fatal("changing the caller's slice changed the key")
	}
}
