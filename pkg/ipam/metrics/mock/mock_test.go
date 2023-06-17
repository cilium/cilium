// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"testing"

	check "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewMockMetrics()
	api.AllocationAttempt("createInterfaceAndAllocateIP", "foo", "s-1", 0)
	c.Assert(api.GetAllocationAttempts("createInterfaceAndAllocateIP", "foo", "s-1"), check.Equals, int64(1))
	api.AddIPAllocation("s-1", 10)
	api.AddIPAllocation("s-1", 20)
	c.Assert(api.IPAllocations("s-1"), check.Equals, int64(30))
	api.SetAllocatedIPs("used", 200)
	c.Assert(api.AllocatedIPs("used"), check.Equals, 200)
	api.SetAvailableInterfaces(10)
	c.Assert(api.AvailableInterfaces(), check.Equals, 10)
	api.SetInterfaceCandidates(10)
	c.Assert(api.InterfaceCandidates(), check.Equals, 10)
	api.SetEmptyInterfaceSlots(10)
	c.Assert(api.EmptyInterfaceSlots(), check.Equals, 10)
	api.SetNodes("at-capacity", 5)
	c.Assert(api.Nodes("at-capacity"), check.Equals, 5)
	api.IncResyncCount()
	c.Assert(api.ResyncCount(), check.Equals, int64(1))
}
