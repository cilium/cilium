// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"github.com/cilium/cilium/pkg/time"
)

// RangeCount represents a monotonically increasing count along with the first and last time it was
// incremented.
type RangeCount struct {
	Count uint64
	First time.Time
	Last  time.Time
}

// RangeCounter is a simple counter that tracks a count and a time interval.
type RangeCounter struct {
	count RangeCount
}

// NewRangeCounter creates a new RangeCounter.
func NewRangeCounter() *RangeCounter {
	return &RangeCounter{}
}

// Increment increments the counter and updates the time range.
func (c *RangeCounter) Increment(now time.Time) {
	if c.count.Count == 0 || c.count.First.After(now) {
		c.count.First = now
	}
	if c.count.Count == 0 || c.count.Last.Before(now) {
		c.count.Last = now
	}
	c.count.Count++
}

// Peek returns the current count.
func (c *RangeCounter) Peek() RangeCount {
	return c.count
}

// Clear clears the counter and returns the existing count.
func (c *RangeCounter) Clear() RangeCount {
	count := c.count
	c.count = RangeCount{}
	return count
}

// IntervalRangeCounter is a specialized RangeCounter that provides a IsElapsed() method to check if
// the time interval has elapsed since the first increment.
type IntervalRangeCounter struct {
	RangeCounter
	interval time.Duration
}

// NewIntervalRangeCounter creates a new IntervalRangeCounter with the specified interval.
func NewIntervalRangeCounter(interval time.Duration) *IntervalRangeCounter {
	return &IntervalRangeCounter{
		RangeCounter: RangeCounter{},
		interval:     interval,
	}
}

// IsElapsed checks if the duration since the first increment until now exceeds the configured
// interval. It always returns false when the counter is empty as a "start time" is required as base
// to compute the interval.
func (c *IntervalRangeCounter) IsElapsed(now time.Time) bool {
	if c.count.Count == 0 {
		return false
	}
	return now.Sub(c.count.First) >= c.interval
}
