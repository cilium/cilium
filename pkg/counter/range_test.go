// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRangeCounter(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-1 * time.Second)
	later := now.Add(1 * time.Second)

	counter := NewRangeCounter()
	require.NotNil(t, counter, "Expected counter to be initialized")

	counter.Increment(now)
	require.Equal(t, uint64(1), counter.count.Count, "Expected count to be 1")
	require.Equal(t, now, counter.count.First, "Expected first time to be now")
	require.Equal(t, now, counter.count.Last, "Expected last time to be now")

	counter.Increment(later)
	require.Equal(t, uint64(2), counter.count.Count, "Expected count to be 2")
	require.Equal(t, now, counter.count.First, "Expected first time to be now")
	require.Equal(t, later, counter.count.Last, "Expected last time to be now + 1s")

	count := counter.Clear()
	require.Equal(t, uint64(2), count.Count, "Expected cleared count to be 2")
	require.Equal(t, now, count.First, "Expected cleared first time to be now")
	require.Equal(t, now.Add(1*time.Second), count.Last, "Expected cleared last time to be now + 1s")

	count = counter.Clear()
	require.Equal(t, uint64(0), count.Count, "Expected second cleared count to be 0")
	require.Equal(t, time.Time{}, count.First, "Expected second cleared first time to be zero")
	require.Equal(t, time.Time{}, count.Last, "Expected second cleared last time to be zero")

	counter.Increment(now)
	counter.Increment(earlier)
	counter.Increment(later)
	require.Equal(t, uint64(3), counter.count.Count, "Expected count to be 3 after increments")
	require.Equal(t, earlier, counter.count.First, "Expected first time to be earlier")
	require.Equal(t, later, counter.count.Last, "Expected last time to be later")
}

func TestIntervalRangeCounter(t *testing.T) {
	interval := 2 * time.Second
	now := time.Now()

	counter := NewIntervalRangeCounter(interval)
	require.NotNil(t, counter, "Expected counter to be initialized")

	require.False(t, counter.IsElapsed(now.Add(-2*interval)), "Expected IsElapsed to return false when count is not incremented")
	require.False(t, counter.IsElapsed(now), "Expected IsElapsed to return false when count is not incremented")
	require.False(t, counter.IsElapsed(now.Add(2*interval)), "Expected IsElapsed to return false when count is not incremented")

	counter.Increment(now)
	require.False(t, counter.IsElapsed(now.Add(-2*interval)), "Expected IsElapsed to return false when first time is in the future")
	require.False(t, counter.IsElapsed(now), "Expected IsElapsed to return false when first time is now")
	require.True(t, counter.IsElapsed(now.Add(2*interval)), "Expected IsElapsed to return true when first time is past the interval")
}
