// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/api/metrics/mock"
)

func TestRateLimitBurst(t *testing.T) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewAPILimiter(metricsAPI, 1, 10)
	require.NotNil(t, limiter)

	// Exhaust bucket (rate limit should not kick in)
	for range 10 {
		limiter.Limit(context.TODO(), "test")
	}
	require.Equal(t, time.Duration(0), metricsAPI.RateLimit("test"))

	// Rate limit should now kick in (use an expired context to avoid waiting 1sec)
	ctx, cancel := context.WithTimeout(context.TODO(), time.Microsecond)
	defer cancel()
	limiter.Limit(ctx, "test")
	require.NotEqual(t, time.Duration(0), metricsAPI.RateLimit("test"))
}

func TestRateLimitWait(t *testing.T) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewAPILimiter(metricsAPI, 100, 1)
	require.NotNil(t, limiter)

	// Exhaust bucket
	limiter.Limit(context.TODO(), "test")
	require.Equal(t, time.Duration(0), metricsAPI.RateLimit("test"))

	// Hit rate limit 15 times. The bucket refill rate is 100 per second,
	// meaning we expect this to take around 15 * 10 = 150 milliseconds
	start := time.Now()
	for range 15 {
		limiter.Limit(context.TODO(), "test")
	}
	measured := time.Since(start)

	// Measured duration should be approximately the accounted duration
	accounted := metricsAPI.RateLimit("test")
	if measured > 2*accounted {
		// We allow the wait to be up to 2x larger than the expected wait time
		// to avoid flaky tests. If you are reading this because this test has
		// been flaky despite the 100% margin of error, my recommendation
		// is to disable this check by replacing the c.Errorf below with c.Logf
		t.Errorf("waited longer than expected (expected %s (+/-100%%), measured %s)", accounted, measured)
	}
}
