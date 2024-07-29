package jitterbug

import "time"

// Sampler can sample from any univariate distribution.  It is used in conjunction
// with the Univariate type and is compatible with GoNum:
// https://godoc.org/gonum.org/v1/gonum/stat/distuv.
type Sampler interface {
	Rand() float64
}

// Univariate distribution
type Univariate struct {
	Sampler
}

// Jitter the duration by adding a delay that has been drawn
// from the supplied univariate distribution.
func (u Univariate) Jitter(d time.Duration) time.Duration {
	return d + time.Duration(u.Rand())
}
