// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"errors"
	"net"
	"syscall"

	. "github.com/cilium/checkmate"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/encrypt"
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
	nodeMap := newMapV2("test_cilium_node_map_v2", Config{
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
}

func (k *NodeMapV2TestSuite) TestNodeMapMigration(c *C) {
	name1 := "test_cilium_node_map"
	name2 := "test_cilium_node_map_v2"
	emName := "test_cilium_encrypt_state"

	IP1 := net.ParseIP("10.1.0.0")
	IP2 := net.ParseIP("10.1.0.1")

	var ID1 uint16 = 10
	var ID2 uint16 = 20

	nodeMapV1 := newMap(name1, Config{
		NodeMapMax: 1024,
	})
	err := nodeMapV1.init()
	c.Assert(err, IsNil)

	nodeMapV2 := newMapV2(name2, Config{
		NodeMapMax: 1024,
	})
	err = nodeMapV2.init()
	c.Assert(err, IsNil)
	defer nodeMapV2.bpfMap.Unpin()

	encryptMap := encrypt.NewMap(emName)
	err = encryptMap.OpenOrCreate()
	c.Assert(err, IsNil)

	encrypt.MapUpdateContextWithMap(encryptMap, 0, 3)

	err = nodeMapV1.Update(IP1, ID1)
	c.Assert(err, IsNil)
	err = nodeMapV1.Update(IP2, ID2)
	c.Assert(err, IsNil)

	// done with nodeMapV2 so we can close the FD.
	nodeMapV2.close()

	// do migration
	err = nodeMapV2.migrateV1(name1, emName)
	c.Assert(err, IsNil)

	// confirm we see the correct migrated values
	parse := func(k *NodeKey, v *NodeValueV2) {
		// family must be IPv4
		if k.Family != bpf.EndpointKeyIPv4 {
			c.Fatalf("want: %v, got: %v", bpf.EndpointKeyIPv4, k.Family)
		}
		ipv4 := net.IP(k.IP[:4])

		// IP must equal one of our two test IPs
		if !ipv4.Equal(IP1) && !ipv4.Equal(IP2) {
			c.Fatalf("migrated NodeValue2 did not match any IP under test: %v", ipv4)
		}

		// SPI must equal 3
		if v.SPI != 3 {
			c.Fatalf("wanted: 3, got: %v", v.SPI)
		}
	}
	MapV2(nodeMapV2).IterateWithCallback(parse)

	// confirm that the map was removed.
	m, err := ciliumebpf.LoadPinnedMap(bpf.MapPath(name1), nil)
	c.Assert(m, IsNil)
	if !errors.Is(err, syscall.ENOENT) {
		c.Fatalf("Expected ENOENT, got: %v", err)
	}
}
