// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package helpers

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/api/metrics/mock"
	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type HelpersSuite struct{}

var _ = check.Suite(&HelpersSuite{})

func (e *HelpersSuite) TestRateLimitBurst(c *check.C) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewApiLimiter(metricsAPI, 1, 10)
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
	limiter := NewApiLimiter(metricsAPI, 100, 1)
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
