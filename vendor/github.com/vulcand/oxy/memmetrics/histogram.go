package memmetrics

import (
	"fmt"
	"time"

	"github.com/codahale/hdrhistogram"
	"github.com/mailgun/timetools"
)

// HDRHistogram is a tiny wrapper around github.com/codahale/hdrhistogram that provides convenience functions for measuring http latencies
type HDRHistogram struct {
	// lowest trackable value
	low int64
	// highest trackable value
	high int64
	// significant figures
	sigfigs int

	h *hdrhistogram.Histogram
}

func NewHDRHistogram(low, high int64, sigfigs int) (h *HDRHistogram, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			err = fmt.Errorf("%s", msg)
		}
	}()
	return &HDRHistogram{
		low:     low,
		high:    high,
		sigfigs: sigfigs,
		h:       hdrhistogram.New(low, high, sigfigs),
	}, nil
}

// Returns latency at quantile with microsecond precision
func (h *HDRHistogram) LatencyAtQuantile(q float64) time.Duration {
	return time.Duration(h.ValueAtQuantile(q)) * time.Microsecond
}

// Records latencies with microsecond precision
func (h *HDRHistogram) RecordLatencies(d time.Duration, n int64) error {
	return h.RecordValues(int64(d/time.Microsecond), n)
}

func (h *HDRHistogram) Reset() {
	h.h.Reset()
}

func (h *HDRHistogram) ValueAtQuantile(q float64) int64 {
	return h.h.ValueAtQuantile(q)
}

func (h *HDRHistogram) RecordValues(v, n int64) error {
	return h.h.RecordValues(v, n)
}

func (h *HDRHistogram) Merge(other *HDRHistogram) error {
	if other == nil {
		return fmt.Errorf("other is nil")
	}
	h.h.Merge(other.h)
	return nil
}

type rhOptSetter func(r *RollingHDRHistogram) error

func RollingClock(clock timetools.TimeProvider) rhOptSetter {
	return func(r *RollingHDRHistogram) error {
		r.clock = clock
		return nil
	}
}

// RollingHistogram holds multiple histograms and rotates every period.
// It provides resulting histogram as a result of a call of 'Merged' function.
type RollingHDRHistogram struct {
	idx         int
	lastRoll    time.Time
	period      time.Duration
	bucketCount int
	low         int64
	high        int64
	sigfigs     int
	buckets     []*HDRHistogram
	clock       timetools.TimeProvider
}

func NewRollingHDRHistogram(low, high int64, sigfigs int, period time.Duration, bucketCount int, options ...rhOptSetter) (*RollingHDRHistogram, error) {
	rh := &RollingHDRHistogram{
		bucketCount: bucketCount,
		period:      period,
		low:         low,
		high:        high,
		sigfigs:     sigfigs,
	}

	for _, o := range options {
		if err := o(rh); err != nil {
			return nil, err
		}
	}

	if rh.clock == nil {
		rh.clock = &timetools.RealTime{}
	}

	buckets := make([]*HDRHistogram, rh.bucketCount)
	for i := range buckets {
		h, err := NewHDRHistogram(low, high, sigfigs)
		if err != nil {
			return nil, err
		}
		buckets[i] = h
	}
	rh.buckets = buckets
	return rh, nil
}

func (r *RollingHDRHistogram) Append(o *RollingHDRHistogram) error {
	if r.bucketCount != o.bucketCount || r.period != o.period || r.low != o.low || r.high != o.high || r.sigfigs != o.sigfigs {
		return fmt.Errorf("can't merge")
	}

	for i := range r.buckets {
		if err := r.buckets[i].Merge(o.buckets[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *RollingHDRHistogram) Reset() {
	r.idx = 0
	r.lastRoll = r.clock.UtcNow()
	for _, b := range r.buckets {
		b.Reset()
	}
}

func (r *RollingHDRHistogram) rotate() {
	r.idx = (r.idx + 1) % len(r.buckets)
	r.buckets[r.idx].Reset()
}

func (r *RollingHDRHistogram) Merged() (*HDRHistogram, error) {
	m, err := NewHDRHistogram(r.low, r.high, r.sigfigs)
	if err != nil {
		return m, err
	}
	for _, h := range r.buckets {
		if m.Merge(h); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (r *RollingHDRHistogram) getHist() *HDRHistogram {
	if r.clock.UtcNow().Sub(r.lastRoll) >= r.period {
		r.rotate()
		r.lastRoll = r.clock.UtcNow()
	}
	return r.buckets[r.idx]
}

func (r *RollingHDRHistogram) RecordLatencies(v time.Duration, n int64) error {
	return r.getHist().RecordLatencies(v, n)
}

func (r *RollingHDRHistogram) RecordValues(v, n int64) error {
	return r.getHist().RecordValues(v, n)
}
