package guardian_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

func TestEndpointsGateOnReadiness(t *testing.T) {
	endpoints := &guardian.Endpoints{}
	server := httptest.NewServer(endpoints)
	defer server.Close()
	status := func(method, path string) int {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader("{}"))
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status(http.MethodGet, guardian.PathHealthz) != 200 || status(http.MethodGet, guardian.PathReadyz) != 503 || status(http.MethodPost, guardian.PathACS) != 503 {
		t.Fatal("a loading Guardian must be live and not ready")
	}
	endpoints.Ready(newHarness(t).g)
	if status(http.MethodGet, guardian.PathReadyz) != 200 || status(http.MethodPost, guardian.PathACS) != 200 || status(http.MethodGet, guardian.PathACS) != 405 {
		t.Fatal("a ready Guardian must answer")
	}
}
