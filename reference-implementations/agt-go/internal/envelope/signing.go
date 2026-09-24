// Package envelope reads the parts of an ACS envelope the Guardian needs
// before it trusts the envelope, and builds the §10 signed input.
package envelope

import (
	"errors"
	"fmt"

	"github.com/go-json-experiment/json"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/jcs"
)

// ErrMalformedSignature reports a signature member that is not a signature
// envelope of §10.
var ErrMalformedSignature = errors.New("malformed signature")

// RequestSigningInput returns the §10 signed input of a request, the RFC 8785
// canonicalization of the envelope with params.signature removed, and the
// signature the request carried, nil when it carried none.
func RequestSigningInput(raw []byte) ([]byte, *acs.Signature, error) {
	return signingInput(raw, "params")
}

// ResponseSigningInput returns the §10 signed input of a response, the
// envelope with its signature removed - result.signature, or
// error.signature for an error - and the signature it carried.
func ResponseSigningInput(raw []byte) ([]byte, *acs.Signature, error) {
	return signingInput(raw, "")
}

// signingInput removes the signature from holder; an empty holder means a
// response's, error when it has one and result otherwise.
func signingInput(raw []byte, holder string) ([]byte, *acs.Signature, error) {
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, nil, fmt.Errorf("decode envelope: %w", err)
	}
	if holder == "" {
		holder = "result"
		if _, isError := envelope["error"]; isError {
			holder = "error"
		}
	}
	var sig *acs.Signature
	if member, ok := envelope[holder].(map[string]any); ok {
		if value, present := member["signature"]; present {
			s, err := decodeSignature(value)
			if err != nil {
				return nil, nil, err
			}
			sig = s
			delete(member, "signature")
		}
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("encode envelope: %w", err)
	}
	input, err := jcs.Canonicalize(b)
	if err != nil {
		return nil, nil, err
	}
	return input, sig, nil
}

func decodeSignature(value any) (*acs.Signature, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", ErrMalformedSignature)
	}
	var s acs.Signature
	for name, dst := range map[string]*string{"algorithm": &s.Algorithm, "value": &s.Value, "key_id": &s.KeyID} {
		v, ok := object[name].(string)
		if !ok || v == "" {
			return nil, fmt.Errorf("%w: %s must be a non-empty string", ErrMalformedSignature, name)
		}
		*dst = v
	}
	return &s, nil
}
