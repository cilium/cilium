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
