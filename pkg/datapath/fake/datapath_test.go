// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	check "github.com/cilium/checkmate"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type fakeTestSuite struct{}

var _ = check.Suite(&fakeTestSuite{})

func (s *fakeTestSuite) TestNewDatapath(c *check.C) {
	dp := NewDatapath()
	c.Assert(dp, check.Not(check.IsNil))

	c.Assert(dp.Node().NodeAdd(nodeTypes.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeUpdate(nodeTypes.Node{}, nodeTypes.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeDelete(nodeTypes.Node{}), check.IsNil)
	c.Assert(dp.Node().NodeConfigurationChanged(datapath.LocalNodeConfiguration{}), check.IsNil)

	c.Assert(dp.LocalNodeAddressing().IPv6().Router(), check.Not(check.IsNil))
	c.Assert(dp.LocalNodeAddressing().IPv4().Router(), check.Not(check.IsNil))
	c.Assert(dp.LocalNodeAddressing().IPv4().AllocationCIDR(), check.Not(check.IsNil))

	list, err := dp.LocalNodeAddressing().IPv4().LocalAddresses()
	c.Assert(len(list), check.Not(check.Equals), 0)
	c.Assert(err, check.IsNil)
	list, err = dp.LocalNodeAddressing().IPv6().LocalAddresses()
	c.Assert(len(list), check.Not(check.Equals), 0)
	c.Assert(err, check.IsNil)
}
