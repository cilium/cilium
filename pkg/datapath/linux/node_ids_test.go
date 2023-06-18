// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2021 Authors of Cilium

package linux

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"gopkg.in/check.v1"
)

const (
	dummyHostDeviceName = "dummy_host"
)

var (
	testIP1 = net.ParseIP("192.88.99.1")
	testIP2 = net.ParseIP("192.88.99.2")

	testNode            = &nodeTypes.Node{
		Name:    "newTestNode",
		Cluster: "testCluster",
		IPAddresses: []nodeTypes.Address{
			nodeTypes.Address{
				Type: addressing.NodeInternalIP,
				IP:   testIP1,
			},
			nodeTypes.Address{
				Type: addressing.NodeCiliumInternalIP,
				IP:   testIP2,
			},
		},
	}
)

type linuxNodeIDTestSuite struct {
	nodeAddressing datapath.NodeAddressing
	enableIPv4     bool
	enableIPv6     bool
}

func (n *linuxNodeHandler) checkNodeIdsExist(c *check.C, node *nodeTypes.Node) {
	for _, addr := range node.IPAddresses {
		_, exists := n.nodeIDsByIPs[addr.IP.String()]
		c.Assert(exists, check.Equals, true)
	}
}

func (n *linuxNodeHandler) checkNodeIdsRemoved(c *check.C, node *nodeTypes.Node) {
	for _, addr := range node.IPAddresses {
		_, exists := n.nodeIDsByIPs[addr.IP.String()]
		c.Assert(exists, check.Equals, false)
	}
}

func (n *linuxNodeHandler) checkIPExists(c *check.C, ip net.IP) {
	_, exists := n.nodeIDsByIPs[ip.String()]
	c.Assert(exists, check.Equals, true)
}

func (n *linuxNodeHandler) checkIPRemoved(c *check.C, ip net.IP) {
	_, exists := n.nodeIDsByIPs[ip.String()]
	c.Assert(exists, check.Equals, false)
}


func (s *linuxTestSuite) TestNodeIDAddDelete(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id := lnh.allocateIDForNode(testNode)
	c.Assert(id, check.Not(check.Equals), 0)
	lnh.checkNodeIdsExist(c, testNode)
	lnh.deallocateIDForNode(testNode)
	lnh.checkNodeIdsRemoved(c, testNode)
}

func (s *linuxTestSuite) TestIPCacheAddDelete(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id := lnh.AllocateNodeID(testIP1)
	c.Assert(id, check.Not(check.Equals), 0)
	lnh.checkIPExists(c, testIP1)
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPRemoved(c, testIP1)
}

// IPCache entries get promoted to Node source if the Node Add events
// duplicates the entry. The reason for this is so that instead of
// using the IPCache delete logic we can hook the node delete logic
// to remove it. I guess we trust the node delete more?
func (s *linuxTestSuite) TestIPCachePromote1(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id1 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Not(check.Equals), 0)
	lnh.checkIPExists(c, testIP1)
	id2 := lnh.allocateIDForNode(testNode)
	c.Assert(id1, check.Equals, id2)
	lnh.checkIPExists(c, testIP1)

	// Now id1<->TestIP1 should be promoted to node source
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPExists(c, testIP1)
	lnh.deallocateIDForNode(testNode)
	lnh.checkNodeIdsRemoved(c, testNode)
}

// Same test as above, but lets promote an entry with refcnt gt 1
func (s *linuxTestSuite) TestIPCachePromote2(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id1 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Not(check.Equals), 0)
	id2 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Equals, id2)
	lnh.checkIPExists(c, testIP1)
	id3 := lnh.allocateIDForNode(testNode)
	c.Assert(id1, check.Equals, id3)
	lnh.checkIPExists(c, testIP1)

	// Now id1<->TestIP1 should be promoted to node source
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPExists(c, testIP1)
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPExists(c, testIP1)
	lnh.deallocateIDForNode(testNode)
	lnh.checkNodeIdsRemoved(c, testNode)
}

func (s *linuxTestSuite) TestIPCacheRef(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id1 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Not(check.Equals), 0)
	lnh.checkIPExists(c, testIP1)
	id2 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Equals, id2)
	lnh.checkIPExists(c, testIP1)

	// Now id1==id2 and refcnt=2 so do two Deallocates
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPExists(c, testIP1)
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPRemoved(c, testIP1)
}

// Ensure if we get an IPcache allocate after a node Allocate that we
// continue to correctly manage that IP<->ID mapping. Ensure delete
// order Node than IPcache correctly removes mapping.
func (s *linuxTestSuite) TestNodeIPCacheDelete1(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id1 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Not(check.Equals), 0)
	id2 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Equals, id2)
	lnh.checkIPExists(c, testIP1)

	// Now id1<->IP1 is still owned by Node so node delete
	// shoudl remove it
	lnh.deallocateIDForNode(testNode)
	lnh.checkIPRemoved(c, testIP1)
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPRemoved(c, testIP1)
}

// Ensure if we get an IPcache allocate after a node Allocate that we
// continue to correctly manage that IP<->ID mapping. Ensure delete
// order IPCache than Node correctly removes mapping.
func (s *linuxTestSuite) TestNodeIPCacheDelete2(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	fakeNodeAddressing := fake.NewNodeAddressing()
	lnh := NewNodeHandler(dpConfig, fakeNodeAddressing)
	c.Assert(lnh, check.Not(check.IsNil))

	id1 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Not(check.Equals), 0)
	id2 := lnh.AllocateNodeID(testIP1)
	c.Assert(id1, check.Equals, id2)
	lnh.checkIPExists(c, testIP1)

	// Now id1<->IP1 is still owned by Node so node delete
	// shoudl remove it
	lnh.DeallocateNodeID(testIP1)
	lnh.checkIPExists(c, testIP1)
	lnh.deallocateIDForNode(testNode)
	lnh.checkIPRemoved(c, testIP1)
}
