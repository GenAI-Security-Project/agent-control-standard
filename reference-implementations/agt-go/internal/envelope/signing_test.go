package envelope

import (
	"errors"
	"os"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// testdata/vectors.json was computed with Python's json, hmac and hashlib,
// independently of this module; its HKDF matches RFC 5869 test case 3.
type vectors struct {
	Request  vector `json:"request"`
	Response vector `json:"response"`
}

type vector struct {
	Signed       jsontext.Value `json:"signed"`
	SigningInput string         `json:"signing_input"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSigningInputVectors(t *testing.T) {
	v := loadVectors(t)
	tests := []struct {
		name  string
		input func([]byte) ([]byte, error)
		vec   vector
	}{
		{"request", func(b []byte) ([]byte, error) { in, _, err := RequestSigningInput(b); return in, err }, v.Request},
		{"response", func(b []byte) ([]byte, error) { in, _, err := ResponseSigningInput(b); return in, err }, v.Response},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input(tt.vec.Signed)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.vec.SigningInput {
				t.Fatalf("got  %s\nwant %s", got, tt.vec.SigningInput)
			}
		})
	}
}

func TestRequestSigningInputReturnsTheSignature(t *testing.T) {
	v := loadVectors(t)
	_, sig, err := RequestSigningInput(v.Request.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil || sig.Algorithm != "HMAC-SHA256" || sig.KeyID != "k1" || sig.Value == "" {
		t.Fatalf("signature %+v", sig)
	}
}

// TestSigningInputCoversEverythingButTheSignature: the signature itself is
// the only member that may change without changing the input.
func TestSigningInputCoversEverythingButTheSignature(t *testing.T) {
	base := `{"jsonrpc":"2.0","method":"steps/userMessage","id":1,"params":{"request_id":"r","metadata":{"session_id":"s"},"signature":{"algorithm":"HMAC-SHA256","value":"AAAA","key_id":"k"}}}`
	want, _, err := RequestSigningInput([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	same := `{"params":{"signature":{"algorithm":"HMAC-SHA256","value":"BBBB","key_id":"k2"},"metadata":{"session_id":"s"},"request_id":"r"},"id":1,"method":"steps/userMessage","jsonrpc":"2.0"}`
	got, _, err := RequestSigningInput([]byte(same))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("the signature value or member order changed the signed input")
	}
	for _, changed := range []string{
		`{"jsonrpc":"2.0","method":"steps/userMessage","id":1,"params":{"request_id":"r","metadata":{"session_id":"t"},"signature":{"algorithm":"HMAC-SHA256","value":"AAAA","key_id":"k"}}}`,
		`{"jsonrpc":"2.0","method":"steps/agentResponse","id":1,"params":{"request_id":"r","metadata":{"session_id":"s"},"signature":{"algorithm":"HMAC-SHA256","value":"AAAA","key_id":"k"}}}`,
		`{"jsonrpc":"2.0","method":"steps/userMessage","id":2,"params":{"request_id":"r","metadata":{"session_id":"s"},"signature":{"algorithm":"HMAC-SHA256","value":"AAAA","key_id":"k"}}}`,
		`{"jsonrpc":"2.0","method":"steps/userMessage","id":1,"params":{"request_id":"q","metadata":{"session_id":"s"},"signature":{"algorithm":"HMAC-SHA256","value":"AAAA","key_id":"k"}}}`,
	} {
		got, _, err := RequestSigningInput([]byte(changed))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) == string(want) {
			t.Errorf("%s signs the same input as the original", changed)
		}
	}
}

func TestMalformedSignature(t *testing.T) {
	for _, raw := range []string{
		`{"params":{"signature":"abc"}}`,
		`{"params":{"signature":{"algorithm":"HMAC-SHA256","value":"x"}}}`,
		`{"params":{"signature":{"algorithm":"HMAC-SHA256","value":"","key_id":"k"}}}`,
		`{"params":{"signature":{"algorithm":1,"value":"x","key_id":"k"}}}`,
	} {
		if _, _, err := RequestSigningInput([]byte(raw)); !errors.Is(err, ErrMalformedSignature) {
			t.Errorf("%s: %v, want ErrMalformedSignature", raw, err)
		}
	}
}

func TestUnsignedRequest(t *testing.T) {
	_, sig, err := RequestSigningInput([]byte(`{"params":{"request_id":"r"}}`))
	if err != nil || sig != nil {
		t.Fatalf("signature %v, error %v", sig, err)
	}
}

func TestRefusesDuplicateMembers(t *testing.T) {
	if _, _, err := RequestSigningInput([]byte(`{"params":{"a":1},"params":{"a":2}}`)); err == nil {
		t.Fatal("accepted an envelope two parsers would read differently")
	}
}

// An error's signature is removed from error, not result, and a result's
// from result.
func TestResponseSigningInputHolder(t *testing.T) {
	sig := `{"algorithm":"HMAC-SHA256","value":"AA==","key_id":"k"}`
	for name, tt := range map[string]struct{ raw, want string }{
		"error":  {`{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"m","signature":` + sig + `}}`, `{"error":{"code":-32005,"message":"m"},"id":1,"jsonrpc":"2.0"}`},
		"result": {`{"jsonrpc":"2.0","id":1,"result":{"decision":"allow","signature":` + sig + `}}`, `{"id":1,"jsonrpc":"2.0","result":{"decision":"allow"}}`},
	} {
		input, got, err := ResponseSigningInput([]byte(tt.raw))
		if err != nil || got == nil || got.KeyID != "k" || string(input) != tt.want {
			t.Errorf("%s: input %s, signature %+v, %v", name, input, got, err)
		}
	}
}
