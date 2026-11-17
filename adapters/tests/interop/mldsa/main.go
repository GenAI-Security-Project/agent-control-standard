// Independent ML-DSA-65 implementation for the acs.core interop tests (issue #574).
//
// Go's standard library crypto/mldsa (Go 1.26 or later) shares no code with pyca/cryptography
// or OpenSSL, so agreement between the two is evidence that acs.core signs plain FIPS 204
// ML-DSA-65 in pure mode with the context it claims.
//
// It reads one JSON object on stdin and writes one JSON object on stdout. Byte fields are
// standard base64. Context is a string, empty by default, as in mldsa.Options.
//
//	{"op": "keygen", "seed": ...}                                       -> {"public_key": ...}
//	{"op": "sign", "seed": ..., "message": ..., "context": ...}          -> {"signature": ...}
//	{"op": "verify", "public_key": ..., "message": ..., "signature": ..., "context": ...}
//	                                                                     -> {"valid": true|false}
package main

import (
	"crypto/mldsa"
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	Op        string `json:"op"`
	Seed      []byte `json:"seed"`
	PublicKey []byte `json:"public_key"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
	Context   string `json:"context"`
}

func run() (map[string]any, error) {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	params := mldsa.MLDSA65()
	opts := &mldsa.Options{Context: req.Context}
	switch req.Op {
	case "keygen":
		sk, err := mldsa.NewPrivateKey(params, req.Seed)
		if err != nil {
			return nil, err
		}
		return map[string]any{"public_key": sk.PublicKey().Bytes()}, nil
	case "sign":
		sk, err := mldsa.NewPrivateKey(params, req.Seed)
		if err != nil {
			return nil, err
		}
		sig, err := sk.Sign(nil, req.Message, opts)
		if err != nil {
			return nil, err
		}
		return map[string]any{"signature": sig}, nil
	case "verify":
		pk, err := mldsa.NewPublicKey(params, req.PublicKey)
		if err != nil {
			return nil, err
		}
		// A bad signature is an answer, not an error, so the caller can tell the two apart.
		return map[string]any{"valid": mldsa.Verify(pk, req.Message, req.Signature, opts) == nil}, nil
	}
	return nil, fmt.Errorf("unknown op %q", req.Op)
}

func main() {
	out, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mldsa:", err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "mldsa:", err)
		os.Exit(2)
	}
}
