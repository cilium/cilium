// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type NodeMapTestSuite struct{}

var _ = Suite(&NodeMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *NodeMapTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *NodeMapTestSuite) TestNodeMap(c *C) {
	nodeMap := newMap()
	err := nodeMap.init()
	c.Assert(err, IsNil)
	defer nodeMap.bpfMap.Unpin()

	bpfNodeIDMap := map[uint16]string{}
	toMap := func(key *NodeKey, val *NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		bpfNodeIDMap[val.NodeID] = address
	}

	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 0)

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10)
	c.Assert(err, IsNil)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20)
	c.Assert(err, IsNil)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 2)

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	c.Assert(err, IsNil)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 1)
}
