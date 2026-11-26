// Package jcs produces the RFC 8785 JSON Canonicalization Scheme form that
// ACS hashes and signs: the §8.2 chain digest, the §10 signed input and
// ContextEntry.request_hash.
//
// The canonicalizer is the one in the upstream of Go's encoding/json/v2,
// which implements RFC 8785 directly. Go's encoding/json v1 is not used for
// canonical bytes: it escapes <, > and & and U+2028 and U+2029, and it
// formats numbers its own way.
package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/go-json-experiment/json/jsontext"
)

// Canonicalize returns the RFC 8785 canonical form of the JSON text b.
//
// The input must be I-JSON (RFC 7493), as RFC 8785 requires: a text with a
// duplicate member name, invalid UTF-8 or an unpaired surrogate is refused,
// because two parsers would disagree about what it says and a signature over
// it would then cover two different messages.
func Canonicalize(b []byte) ([]byte, error) {
	v := jsontext.Value(append([]byte(nil), b...))
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return v, nil
}

// SHA256Hex returns the lowercase-hex SHA-256 of the canonical form of b,
// the digest §8.1 prescribes for request_hash.
func SHA256Hex(b []byte) (string, error) {
	c, err := Canonicalize(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}
