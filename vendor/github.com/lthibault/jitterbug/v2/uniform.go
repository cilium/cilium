package jitterbug

import (
	"math/rand"
	"time"
)

// Uniform distribution.
type Uniform struct {
	Source *rand.Rand
	Min    time.Duration
}

// Jitter the duration uniformly over the range [Min, d).
// The zero-value is ready to use.  Panics if d <= Min.
func (u Uniform) Jitter(d time.Duration) time.Duration {
	drawUniform := rand.Int63n
	if u.Source != nil {
		drawUniform = u.Source.Int63n
	}

	delta := d - u.Min
	if delta <= 0 {
		panic("duration must exceed min")
	}
	return u.Min + time.Duration(drawUniform(int64(delta)))
}
