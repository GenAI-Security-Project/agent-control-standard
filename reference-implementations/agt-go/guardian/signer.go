package guardian

import (
	"context"
	"errors"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// Signer verifies signed requests and signs responses to authenticated
// requests (§10). system/ping may be unsigned; responses produced before
// authentication are not signed. Unlike crypto.Signer, this interface verifies
// as well as signs; whoever implements it holds the keys, and the keys never
// leave it.
//
// The Guardian computes the signed input, the RFC 8785 canonicalization of
// the envelope with its signature removed, and a Signer only signs or checks
// those bytes, so no implementation can change what a signature covers. The
// Guardian may call Verify and Sign concurrently. Verify and Sign must return
// when ctx ends. Algorithms is read once by New; the Guardian owns its copy of
// the returned slice.
type Signer interface {
	// Algorithms lists the signature algorithms Verify accepts, declared in
	// the ServerHello as signature_algorithms_supported.
	Algorithms() []string

	// Verify checks sig over input, the signed input of a request in the
	// session sessionID. It returns an error wrapping ErrSignatureInvalid
	// when the signature does not verify; any other error means the Signer
	// could not decide, and the request is refused all the same.
	Verify(ctx context.Context, sessionID string, input []byte, sig acs.Signature) error

	// Sign signs input, the signed input of a response in sessionID.
	// verifiedKeyID names the key that verified the request. A symmetric
	// signer may answer with that key; an asymmetric signer chooses its own
	// response key. The returned Signature.KeyID identifies the actual key.
	// verifiedKeyID is empty for an unsigned system/ping request.
	Sign(ctx context.Context, sessionID, verifiedKeyID string, input []byte) (acs.Signature, error)
}

// ErrSignatureInvalid reports a signature that does not verify.
var ErrSignatureInvalid = errors.New("signature invalid")
