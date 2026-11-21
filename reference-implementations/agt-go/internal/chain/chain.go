// Package chain computes the SessionContext digests of §8: request_hash
// (§8.1) and entry_hash (§8.2).
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/jcs"
)

// RequestHash is the lowercase-hex SHA-256 of the RFC 8785 canonicalization
// of a request envelope's params.
func RequestHash(params []byte) (string, error) {
	return jcs.SHA256Hex(params)
}

// EntryHash computes the §8.2 digest of e:
//
//	lowercase-hex(SHA-256(content_bytes || prev_hash_bytes))
//
// where content_bytes is the RFC 8785 canonicalization of e with entry_hash
// and previous_hash removed, and prev_hash_bytes is the raw 32 bytes of
// e.PreviousHash, or nothing when e is the first entry of its session. The
// EntryHash field of e is ignored.
func EntryHash(e acs.ContextEntry) (string, error) {
	prev, err := previousBytes(e.PreviousHash)
	if err != nil {
		return "", err
	}
	content, err := contentBytes(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(content)
	h.Write(prev)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Seal returns e with PreviousHash set to previous and EntryHash computed.
// previous is empty for the first entry of a session.
func Seal(e acs.ContextEntry, previous string) (acs.ContextEntry, error) {
	e.PreviousHash = nil
	if previous != "" {
		e.PreviousHash = &previous
	}
	hash, err := EntryHash(e)
	if err != nil {
		return acs.ContextEntry{}, err
	}
	e.EntryHash = hash
	return e, nil
}

// contentBytes removes the two members through a generic object, so a member
// added to acs.ContextEntry later is committed to without a change here.
func contentBytes(e acs.ContextEntry) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode context entry: %w", err)
	}
	var object map[string]any
	if err := json.Unmarshal(b, &object); err != nil {
		return nil, fmt.Errorf("decode context entry: %w", err)
	}
	delete(object, "entry_hash")
	delete(object, "previous_hash")
	b, err = json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("encode context entry content: %w", err)
	}
	return jcs.Canonicalize(b)
}

var errBadPreviousHash = errors.New("previous_hash is not 64 lowercase hex digits")

func previousBytes(previous *string) ([]byte, error) {
	if previous == nil {
		return nil, nil
	}
	if !IsDigest(*previous) {
		return nil, fmt.Errorf("%w: %q", errBadPreviousHash, *previous)
	}
	return hex.DecodeString(*previous)
}

// IsDigest reports whether s has the shape of a chain digest: 64 lowercase
// hexadecimal digits.
func IsDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
