// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type NodeMapV2TestSuite struct{}

var _ = Suite(&NodeMapV2TestSuite{})

func (k *NodeMapV2TestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *NodeMapV2TestSuite) TestNodeMap(c *C) {
	nodeMap := newMapV2("test_cilium_node_map_v2", "test_cilium_node_map", Config{
		NodeMapMax: 1024,
	})
	err := nodeMap.init()
	c.Assert(err, IsNil)
	defer nodeMap.bpfMap.Unpin()

	bpfNodeIDMap := map[uint16]string{}
	bpfNodeSPI := []uint8{}
	toMap := func(key *NodeKey, val *NodeValueV2) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		bpfNodeIDMap[val.NodeID] = address
		bpfNodeSPI = append(bpfNodeSPI, uint8(val.SPI))
	}

	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 0)
	c.Assert(bpfNodeSPI, HasLen, 0)

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10, 3)
	c.Assert(err, IsNil)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20, 3)
	c.Assert(err, IsNil)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 2)
	c.Assert(bpfNodeSPI, HasLen, 2)

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	c.Assert(err, IsNil)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	c.Assert(err, IsNil)
	c.Assert(bpfNodeIDMap, HasLen, 1)
	c.Assert(bpfNodeSPI, HasLen, 1)

	// ensure we see mirrored writes in MapV1
	_, err = ciliumebpf.LoadPinnedMap(bpf.MapPath("test_cilium_node_map"), nil)
	c.Assert(err, IsNil)

	toMapV1 := func(key *NodeKey, val *NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		c.Assert(bpfNodeIDMap[val.NodeID], Equals, address)
	}

	err = nodeMap.v1Map.IterateWithCallback(toMapV1)
	c.Assert(err, IsNil)
}
