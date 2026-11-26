//go:build !agteval

package main

import (
	"context"
	"strings"
	"testing"
)

func agtSelection(t *testing.T, c config) {
	if _, err := newEvaluator(context.Background(), c); err == nil || !strings.Contains(err.Error(), "built without the AGT evaluator") {
		t.Fatalf("error %v, want a refusal naming the missing AGT evaluator", err)
	}
}
