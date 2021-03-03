package bgp

import "time"

const (
	backoffMax    = 2 * time.Minute
	backoffFactor = 2
)

// backoff implements multiplicative backoff for retrying failing
// operations.
type backoff struct {
	nextDelay time.Duration
}

// Duration returns how long to wait before the next retry.
func (b *backoff) Duration() time.Duration {
	ret := b.nextDelay
	if b.nextDelay == 0 {
		b.nextDelay = time.Second
	} else {
		b.nextDelay *= backoffFactor
		if b.nextDelay > backoffMax {
			b.nextDelay = backoffMax
		}
	}
	return ret
}

// Reset removes any existing backoff, so the next Duration() will
// return 0.
func (b *backoff) Reset() {
	b.nextDelay = 0
}
