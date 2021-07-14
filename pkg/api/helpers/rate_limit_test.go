// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

// +build !privileged_tests

package helpers

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/api/metrics/mock"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type HelpersSuite struct{}

var _ = check.Suite(&HelpersSuite{})

func (e *HelpersSuite) TestRateLimit(c *check.C) {
	metricsAPI := mock.NewMockMetrics()
	limiter := NewApiLimiter(metricsAPI, 10.0, 4)
	c.Assert(limiter, check.Not(check.IsNil))

	for i := 0; i < 10; i++ {
		limiter.Limit(context.TODO(), "test")
	}

	c.Assert(metricsAPI.RateLimit("test"), check.Not(check.DeepEquals), time.Duration(0))
}
