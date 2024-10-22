// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLimiter(t *testing.T) {
	l := NewLimiter(1*time.Second, 100)

	require.True(t, l.AllowN(100), "Limiter should have 100 available tokens")
	require.False(t, l.Allow(), "Limiter should not have any available tokens")

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	require.NoError(t, l.WaitN(ctx, 100), "Limiter should have 100 available tokens within 1.5 seconds")
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	require.Error(t, l.Wait(ctx), "Limiter should not have any available tokens within 100 milliseconds")
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	require.Error(t, l.WaitN(ctx, 101), "Limiter should not allow tokens to exceed the burst rate")
	cancel()

	l.Stop()

	require.PanicsWithValue(t, "limiter misuse: Allow / Wait / WaitN called concurrently after Stop", func() { l.Allow() }, "Using a stopped limiter should panic")
}
