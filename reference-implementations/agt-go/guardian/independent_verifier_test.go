package guardian_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// verifyResponse checks the signature of a response envelope from §10 alone,
// with its own RFC 8785 canonicalizer and the standard library's HKDF and
// HMAC. It shares no code with the Guardian's signing path, so a defect
// there cannot hide behind the same defect here. Its canonicalizer handles
// integers only, which is all a Guardian response in these tests carries,
// and refuses anything else rather than guess.
func verifyResponse(raw, ikm []byte, sessionID string) error {
	dec := stdjson.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		return err
	}
	holder, ok := envelope["result"].(map[string]any)
	if !ok {
		if holder, ok = envelope["error"].(map[string]any); !ok {
			return errors.New("no result or error to verify")
		}
	}
	sig, ok := holder["signature"].(map[string]any)
	if !ok {
		return errors.New("the answer carries no signature")
	}
	delete(holder, "signature")
	if sig["algorithm"] != "HMAC-SHA256" {
		return fmt.Errorf("algorithm %v", sig["algorithm"])
	}
	var input strings.Builder
	if err := canonical(&input, envelope); err != nil {
		return err
	}
	key, err := hkdf.Key(sha256.New, ikm, nil, sessionID, 32)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input.String()))
	value, _ := sig["value"].(string)
	got, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("signature does not verify")
	}
	return nil
}

func canonical(b *strings.Builder, v any) error {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		fmt.Fprint(b, v)
	case string:
		canonicalString(b, v)
	case stdjson.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return fmt.Errorf("the independent verifier handles integers only, got %s", v)
		}
		if v == "-0" {
			v = "0"
		}
		b.WriteString(string(v))
	case []any:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// RFC 8785 §3.2.3: members sorted by their UTF-16 code units.
		slices.SortFunc(keys, func(x, y string) int {
			return slices.Compare(utf16.Encode([]rune(x)), utf16.Encode([]rune(y)))
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonicalString(b, k)
			b.WriteByte(':')
			if err := canonical(b, v[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unexpected %T", v)
	}
	return nil
}

// canonicalString follows RFC 8785 §3.2.2.2: only the quotation mark, the
// reverse solidus and the controls are escaped.
func canonicalString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func TestIndependentVerifier(t *testing.T) {
	b, err := os.ReadFile("../internal/envelope/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		IKMHex    string `json:"ikm_hex"`
		SessionID string `json:"session_id"`
		Response  struct {
			Signed stdjson.RawMessage `json:"signed"`
		} `json:"response"`
	}
	if err := stdjson.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	ikm, _ := hex.DecodeString(v.IKMHex)
	if err := verifyResponse(v.Response.Signed, ikm, v.SessionID); err != nil {
		t.Fatalf("the recorded response does not verify: %v", err)
	}
	tampered := bytes.Replace(v.Response.Signed, []byte(`"deny"`), []byte(`"allow"`), 1)
	if err := verifyResponse(tampered, ikm, v.SessionID); err == nil {
		t.Fatal("a response changed from deny to allow still verifies")
	}
	if err := verifyResponse(v.Response.Signed, ikm, "another-session"); err == nil {
		t.Fatal("a response verifies under another session's key")
	}
}
