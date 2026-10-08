// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLimiter(t *testing.T) {
	// Set up a limiter that allows one event every half second with the burts of 3.
	// The underlying token bucket has the capacity of three and fill rate of
	// 2 per second.
	limiter := NewLimiter(500*time.Millisecond, 3)

	// Initially tree events should be allowed and the rest denied.
	require.True(t, limiter.Allow())
	require.True(t, limiter.Allow())
	require.True(t, limiter.Allow())
	require.False(t, limiter.Allow())
	require.False(t, limiter.Allow())
	require.False(t, limiter.Allow())

	// After half second one more event should be allowed, the rest denied
	time.Sleep(500 * time.Millisecond)
	require.True(t, limiter.Allow())
	require.False(t, limiter.Allow())
	require.False(t, limiter.Allow())

	// After one more second two events should be allowed, the rest denied
	time.Sleep(1 * time.Second)
	require.True(t, limiter.Allow())
	require.True(t, limiter.Allow())
	require.False(t, limiter.Allow())
	require.False(t, limiter.Allow())

	// After two more seconds three events should be allowed, the rest denied
	time.Sleep(2 * time.Second)
	require.True(t, limiter.Allow())
	require.True(t, limiter.Allow())
	require.True(t, limiter.Allow())
	require.False(t, limiter.Allow())
	require.False(t, limiter.Allow())
}
