package guardian

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// ServeHTTP answers ACS requests sent as the body of an HTTP POST, at
// whatever route the host mounts it on. Every answer is 200 with a JSON-RPC
// response, as JSON-RPC over HTTP is; a body larger than MaxBodyBytes is
// refused with Invalid Request, never buffered.
func (g *Guardian) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "ACS requests are sent with POST", http.StatusMethodNotAllowed)
		return
	}
	// Counted in flight from here, before the body arrives, so a request that
	// is still arriving when Shutdown begins is answered.
	if !g.begin() {
		writeJSON(w, http.StatusOK, g.shuttingDown(r.Context()))
		return
	}
	defer g.inflight.Done()
	stopReading := context.AfterFunc(g.stop, func() { _ = r.Body.Close() })
	defer stopReading()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		message := fmt.Sprintf("the request body exceeds %d bytes", g.cfg.MaxBodyBytes)
		writeJSON(w, http.StatusOK, g.encode(r.Context(), errorReply(nullID, acs.InvalidRequest, "body_too_large", message), ""))
		return
	case err != nil:
		writeJSON(w, http.StatusOK, g.encode(r.Context(), errorReply(nullID, acs.InvalidRequest, "body_unreadable", "the request body cannot be read"), ""))
		return
	}
	writeJSON(w, http.StatusOK, g.handle(r.Context(), body))
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Paths the Endpoints serve.
const (
	PathACS     = "/acs"
	PathHealthz = "/healthz"
	PathReadyz  = "/readyz"
)

// Endpoints serves a Guardian that may still be loading its engine: POST
// /acs answers once Ready is called, GET /healthz answers while the process
// runs, and GET /readyz answers 200 only once Ready is called. A supervisor
// routes traffic on /readyz, so no agent reaches a Guardian that is not
// ready and falls back on its failure posture.
type Endpoints struct {
	guardian atomic.Pointer[Guardian]
}

// Ready makes g the Guardian the endpoints serve.
func (e *Endpoints) Ready(g *Guardian) { e.guardian.Store(g) }

// ServeHTTP implements http.Handler.
func (e *Endpoints) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g := e.guardian.Load()
	switch r.URL.Path {
	case PathHealthz:
		w.WriteHeader(http.StatusOK)
	case PathReadyz:
		if g == nil {
			http.Error(w, "loading", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	case PathACS:
		if g == nil {
			http.Error(w, "the Guardian is loading", http.StatusServiceUnavailable)
			return
		}
		g.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}
