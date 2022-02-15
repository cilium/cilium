// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package mock

import (
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewMockMetrics()
	api.IncAllocationAttempt("foo", "s-1")
	c.Assert(api.AllocationAttempts("foo", "s-1"), check.Equals, int64(1))
	api.AddIPAllocation("s-1", 10)
	api.AddIPAllocation("s-1", 20)
	c.Assert(api.IPAllocations("s-1"), check.Equals, int64(30))
	api.SetAllocatedIPs("used", 200)
	c.Assert(api.AllocatedIPs("used"), check.Equals, 200)
	api.SetAvailableInterfaces(10)
	c.Assert(api.AvailableInterfaces(), check.Equals, 10)
	api.SetNodes("at-capacity", 5)
	c.Assert(api.Nodes("at-capacity"), check.Equals, 5)
	api.IncResyncCount()
	c.Assert(api.ResyncCount(), check.Equals, int64(1))
}
