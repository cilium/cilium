package jitterbug

import (
	"time"
)

// Jitter can compute a jitter
type Jitter interface {
	// Jitter consumes an interval from a ticker and returns the final, jittered
	// duration.
	Jitter(time.Duration) time.Duration
}

// Ticker behaves like time.Ticker
type Ticker struct {
	C  <-chan time.Time
	cq chan struct{}
	Jitter
	Interval time.Duration
}

// New Ticker with the base interval d and the jitter source j.
func New(d time.Duration, j Jitter) (t *Ticker) {
	c := make(chan time.Time)
	t = &Ticker{
		C:        c,
		cq:       make(chan struct{}),
		Interval: d,
		Jitter:   j,
	}
	go t.loop(c)
	return
}

// Stop the Ticker
func (t *Ticker) Stop() { close(t.cq) }

func (t *Ticker) loop(c chan<- time.Time) {
	defer close(c)

	for {
		time.Sleep(t.calcDelay())

		select {
		case <-t.cq:
			return
		case c <- time.Now():
		default: // there may be nobody ready to recv
		}
	}
}

func (t *Ticker) calcDelay() time.Duration { return t.Jitter.Jitter(t.Interval) }

func min(a, b time.Duration) time.Duration {
	if a > b {
		return b
	}
	return a
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
