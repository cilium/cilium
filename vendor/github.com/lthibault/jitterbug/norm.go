package jitterbug

import (
	"math/rand"
	"time"
)

// Norm is a normal distribution
type Norm struct {
	Source      *rand.Rand
	Mean, Stdev time.Duration
}

// Jitter the duration by drawing form a normal distribution
func (n Norm) Jitter(d time.Duration) time.Duration {
	f := rand.NormFloat64
	if n.Source != nil {
		f = n.Source.NormFloat64
	}

	samp := f()*float64(n.Stdev) + float64(n.Mean)
	return d + time.Duration(samp)
}
