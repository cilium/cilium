package workloadapi

import (
	"math"
	"time"
)

// backoff defines an linear backoff policy.
type backoff struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	n            int
}

func newBackoff() *backoff {
	return &backoff{
		InitialDelay: time.Second,
		MaxDelay:     30 * time.Second,
		n:            0,
	}
}

// Duration returns the next wait period for the backoff. Not goroutine-safe.
func (b *backoff) Duration() time.Duration {
	backoff := float64(b.n) + 1
	d := math.Min(b.InitialDelay.Seconds()*backoff, b.MaxDelay.Seconds())
	b.n++
	return time.Duration(d) * time.Second
}

// Reset resets the backoff's state.
func (b *backoff) Reset() {
	b.n = 0
}
