// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"testing"
	"time"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/api/metrics/mock"
	"github.com/cilium/cilium/pkg/checker"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type HelpersSuite struct{}

var _ = check.Suite(&HelpersSuite{})

func (e *HelpersSuite) TestRateLimitBurst(c *check.C) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewAPILimiter(metricsAPI, 1, 10)
	c.Assert(limiter, check.Not(check.IsNil))

	// Exhaust bucket (rate limit should not kick in)
	for i := 0; i < 10; i++ {
		limiter.Limit(context.TODO(), "test")
	}
	c.Assert(metricsAPI.RateLimit("test"), check.Equals, time.Duration(0))

	// Rate limit should now kick in (use an expired context to avoid waiting 1sec)
	ctx, cancel := context.WithTimeout(context.TODO(), time.Microsecond)
	defer cancel()
	limiter.Limit(ctx, "test")
	c.Assert(metricsAPI.RateLimit("test"), check.Not(checker.Equals), time.Duration(0))
}

func (e *HelpersSuite) TestRateLimitWait(c *check.C) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewAPILimiter(metricsAPI, 100, 1)
	c.Assert(limiter, check.Not(check.IsNil))

	// Exhaust bucket
	limiter.Limit(context.TODO(), "test")
	c.Assert(metricsAPI.RateLimit("test"), checker.Equals, time.Duration(0))

	// Hit rate limit 15 times. The bucket refill rate is 100 per second,
	// meaning we expect this to take around 15 * 10 = 150 milliseconds
	start := time.Now()
	for i := 0; i < 15; i++ {
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
		c.Errorf("waited longer than expected (expected %s (+/-100%%), measured %s)", accounted, measured)
	}
}
