package workloadapi

import (
	"math"
	"time"
)

// BackoffStrategy provides backoff facilities.
type BackoffStrategy interface {
	// NewBackoff returns a new backoff for the strategy. The returned
	// Backoff is in the same state that it would be in after a call to
	// Reset().
	NewBackoff() Backoff
}

// Backoff provides backoff for a workload API operation.
type Backoff interface {
	// Next returns the next backoff period.
	Next() time.Duration

	// Reset() resets the backoff.
	Reset()
}

type defaultBackoffStrategy struct{}

func (defaultBackoffStrategy) NewBackoff() Backoff {
	return newLinearBackoff()
}

// linearBackoff defines an linear backoff policy.
type linearBackoff struct {
	initialDelay time.Duration
	maxDelay     time.Duration
	n            int
}

func newLinearBackoff() *linearBackoff {
	return &linearBackoff{
		initialDelay: time.Second,
		maxDelay:     30 * time.Second,
		n:            0,
	}
}

func (b *linearBackoff) Next() time.Duration {
	backoff := float64(b.n) + 1
	d := math.Min(b.initialDelay.Seconds()*backoff, b.maxDelay.Seconds())
	b.n++
	return time.Duration(d) * time.Second
}

func (b *linearBackoff) Reset() {
	b.n = 0
}
