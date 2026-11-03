package main

import (
	"fmt"
	"os"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/docscheck"
)

func main() {
	if err := docscheck.Check("."); err != nil {
		fmt.Fprintln(os.Stderr, "docs-check:", err)
		os.Exit(1)
	}
}
