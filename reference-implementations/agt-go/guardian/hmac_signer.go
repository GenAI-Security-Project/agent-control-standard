package guardian

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// MinHMACSecretBytes is the shortest input keying material NewHMACSigner
// accepts: the output length of SHA-256, below which a guessed secret costs
// less than a guessed HMAC key (RFC 2104 §3).
const MinHMACSecretBytes = sha256.Size

// HMACKey is deployment-provided input keying material and the key_id that
// names it on the wire.
type HMACKey struct {
	ID     string
	Secret []byte
}

// HMACSigner is the ACS-Core baseline Signer: HMAC-SHA256 under a
// per-session key derived with HKDF-SHA256 (RFC 5869) from the input keying
// material and the session identifier, as §10 prescribes.
//
// §10 leaves the HKDF parameters open. This signer uses no salt, the UTF-8
// session_id as info and a 32-byte output; the signature value is standard
// base64 with padding (RFC 4648 §4).
type HMACSigner struct {
	signing HMACKey // answers unsigned requests
	byID    map[string][]byte
}

// NewHMACSigner returns a signer that verifies with any of its keys and
// answers with the key the request used, so a retired secret keeps working
// for the sessions that use it while its successor opens new ones. Sign uses
// the first key when keyID is empty.
func NewHMACSigner(keys ...HMACKey) (*HMACSigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("an HMAC signer needs at least one key")
	}
	s := &HMACSigner{signing: keys[0], byID: map[string][]byte{}}
	for _, k := range keys {
		switch {
		case k.ID == "":
			return nil, errors.New("an HMAC key needs a key_id")
		case len(k.Secret) < MinHMACSecretBytes:
			return nil, fmt.Errorf("HMAC key %q has %d bytes of secret, fewer than %d", k.ID, len(k.Secret), MinHMACSecretBytes)
		}
		if _, dup := s.byID[k.ID]; dup {
			return nil, fmt.Errorf("HMAC key_id %q is given twice", k.ID)
		}
		s.byID[k.ID] = append([]byte(nil), k.Secret...)
	}
	s.signing.Secret = s.byID[s.signing.ID]
	return s, nil
}

// Algorithms implements Signer.
func (s *HMACSigner) Algorithms() []string {
	return []string{acs.SignatureAlgorithmHMACSHA256}
}

// Verify implements Signer.
func (s *HMACSigner) Verify(_ context.Context, sessionID string, input []byte, sig acs.Signature) error {
	if sig.Algorithm != acs.SignatureAlgorithmHMACSHA256 {
		return fmt.Errorf("%w: algorithm %q is not supported", ErrSignatureInvalid, sig.Algorithm)
	}
	secret, ok := s.byID[sig.KeyID]
	if !ok {
		return fmt.Errorf("%w: unknown key_id %q", ErrSignatureInvalid, sig.KeyID)
	}
	got, err := base64.StdEncoding.Strict().DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("%w: value is not base64", ErrSignatureInvalid)
	}
	want, err := mac(secret, sessionID, input)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, want) {
		return fmt.Errorf("%w: HMAC does not match", ErrSignatureInvalid)
	}
	return nil
}

// Sign implements Signer.
func (s *HMACSigner) Sign(_ context.Context, sessionID, keyID string, input []byte) (acs.Signature, error) {
	if keyID == "" {
		keyID = s.signing.ID
	}
	secret, ok := s.byID[keyID]
	if !ok {
		return acs.Signature{}, fmt.Errorf("unknown key_id %q", keyID)
	}
	m, err := mac(secret, sessionID, input)
	if err != nil {
		return acs.Signature{}, err
	}
	return acs.Signature{
		Algorithm: acs.SignatureAlgorithmHMACSHA256,
		Value:     base64.StdEncoding.EncodeToString(m),
		KeyID:     keyID,
	}, nil
}

func mac(secret []byte, sessionID string, input []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, sessionID, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(input)
	return h.Sum(nil), nil
}
