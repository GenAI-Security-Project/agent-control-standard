package guardian

import (
	"testing"
	"time"
)

func TestWithinSkew(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		timestamp string
		window    time.Duration
		want      bool
	}{
		{"now", "2026-09-19T10:00:00Z", DefaultSkewWindow, true},
		{"past_edge", "2026-09-19T09:55:00Z", DefaultSkewWindow, true},
		{"future_edge", "2026-09-19T10:05:00Z", DefaultSkewWindow, true},
		{"past_beyond", "2026-09-19T09:54:59.999Z", DefaultSkewWindow, false},
		{"future_beyond", "2026-09-19T10:05:00.001Z", DefaultSkewWindow, false},
		{"offset_zone", "2026-09-19T05:00:00-05:00", DefaultSkewWindow, true},
		{"zero_window_exact", "2026-09-19T10:00:00Z", 0, true},
		{"zero_window_late", "2026-09-19T10:00:00.001Z", 0, false},
		// Far enough that now.Sub saturates at the minimum duration, whose
		// negation overflows back to a negative skew.
		{"year_9999", "9999-12-31T23:59:59Z", DefaultSkewWindow, false},
		{"year_0001", "0001-01-01T00:00:00Z", DefaultSkewWindow, false},
		{"unreadable", "19 Sep 2026", DefaultSkewWindow, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withinSkew(tt.timestamp, now, tt.window); got != tt.want {
				t.Fatalf("withinSkew = %v, want %v", got, tt.want)
			}
		})
	}
}
