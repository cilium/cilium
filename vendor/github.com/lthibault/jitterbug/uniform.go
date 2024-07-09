package jitterbug

import (
	"math/rand"
	"time"
)

// Uniform distribution
type Uniform struct {
	Source *rand.Rand
	Min    time.Duration
}

// Jitter the duration by drawing from a uniform distribution
func (u Uniform) Jitter(d time.Duration) time.Duration {
	drawUniform := rand.Int63n
	if u.Source != nil {
		drawUniform = u.Source.Int63n
	}

	d = time.Duration(drawUniform(int64(d)))
	return max(d, u.Min)
}
