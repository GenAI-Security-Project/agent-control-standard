package guardian

import (
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

func TestNegotiatedTimeout(t *testing.T) {
	server := acs.ServerHello{TimeoutConfig: acs.TimeoutConfig{
		DefaultMS: 5000,
		PerMethodMS: map[string]int64{
			acs.StepToolCallRequest: 75,
		},
	}}
	if got := negotiatedTimeout(server, acs.StepToolCallRequest); got != 75*time.Millisecond {
		t.Fatalf("method timeout %s", got)
	}
	if got := negotiatedTimeout(server, acs.StepUserMessage); got != 5*time.Second {
		t.Fatalf("default timeout %s", got)
	}
}
