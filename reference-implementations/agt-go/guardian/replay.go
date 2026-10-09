package guardian

import "time"

// DefaultSkewWindow is the skew window §10.3 recommends and the ServerHello
// declares when the deployment sets none.
const DefaultSkewWindow = 300 * time.Second

// withinSkew reports whether a request timestamp lies within window of now,
// in the past or the future (§10.3). It compares instants, never a
// difference: the difference of two far-apart times saturates, and its
// negation overflows.
func withinSkew(timestamp string, now time.Time, window time.Duration) bool {
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return false
	}
	return !t.Before(now.Add(-window)) && !t.After(now.Add(window))
}
