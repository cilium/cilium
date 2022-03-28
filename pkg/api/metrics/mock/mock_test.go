// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package mock

import (
	"testing"
	"time"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewMockMetrics()
	api.ObserveAPICall("DescribeNetworkInterfaces", "success", 2.0)
	c.Assert(api.APICall("DescribeNetworkInterfaces", "success"), check.Equals, 2.0)
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	c.Assert(api.RateLimit("DescribeNetworkInterfaces"), check.Equals, 2*time.Second)
}
