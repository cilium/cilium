// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package manager

import (
	"net"
	"strings"
	"time"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
)

type managerPrivilegedTestSuite struct{}

var _ = check.Suite(&managerPrivilegedTestSuite{})

func (s *managerPrivilegedTestSuite) SetUpSuite(c *check.C) {
	testutils.PrivilegedCheck(c)
}

func (c *configMock) NodeIpsetNeeded() bool {
	return !c.Tunneling && (c.EnableIPv4Masquerade || c.EnableIPv6Masquerade)
}

// TestNodeIpset tests that the ipset entries on the node are updated correctly
// when a node is updated or removed.
// It is inspired from TestNode() in manager_test.go.
func (s *managerPrivilegedTestSuite) TestNodeIpset(c *check.C) {
	ipcacheMock := newIPcacheMock()
	ipsetExpect := func(ip string, expected bool) {
		setName := iptables.CiliumNodeIpsetV6
		if v4 := net.ParseIP(ip).To4(); v4 != nil {
			setName = iptables.CiliumNodeIpsetV4
		}
		found := iptables.IpsetContains(setName, strings.ToLower(ip))
		if found && !expected {
			c.Errorf("ipset %s contains IP %s but it should not", setName, ip)
		}
		if !found && expected {
			c.Errorf("ipset %s does not contain expected IP %s", setName, ip)
		}
	}

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := NewManager("test", dp, &configMock{
		// Tunneling and EnableIPv4Masquerade are disabled and enabled,
		// respectively, to make sure we update the ipset in the
		// manager (see NodeIpsetNeeded()).
		Tunneling:            false,
		EnableIPv4Masquerade: true,
		// RemoteNodeIdentity is enabled to make sure we don't skip the
		// ipcache update in NodeUpdated(), and in particular, the
		// update to ipsAdded.
		//
		// Note: If we don't updated ipsAdded, NodeUpdated() will
		// remove the ipset entry it just added. I'm not sure whether
		// this is intended or not, if the ipset entry is not needed in
		// that case we should check before adding it; if it is needed
		// even without the ipcache update, then we might have a bug.
		// Bug this has changed and works differently on the "main'
		// branch, so I didn't want to change the code too much here.
		// So we just enable RemoteNodeIdentity for our test.
		RemoteNodeIdentity: true,
	}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()
	defer iptables.RemoveIpset(iptables.CiliumNodeIpsetV4)
	defer iptables.RemoveIpset(iptables.CiliumNodeIpsetV6)

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("192.0.2.1"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("2001:DB8::1"),
			},
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("2001:ABCD::1"),
			},
		},
		IPv4HealthIP: net.ParseIP("192.0.2.2"),
		IPv6HealthIP: net.ParseIP("2001:DB8::2"),
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event")
	}

	ipsetExpect("192.0.2.1", false)
	ipsetExpect("2001:DB8::1", false)
	ipsetExpect("10.0.0.1", true)
	ipsetExpect("2001:ABCD::1", true)

	n1.IPv4HealthIP = net.ParseIP("192.0.2.20")
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event")
	}

	ipsetExpect("192.0.2.1", false)
	ipsetExpect("2001:DB8::1", false)
	ipsetExpect("10.0.0.1", true)
	ipsetExpect("2001:ABCD::1", true)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event")
	}

	ipsetExpect("192.0.2.1", false)
	ipsetExpect("2001:DB8::1", false)
	ipsetExpect("10.0.0.1", false)
	ipsetExpect("2001:ABCD::1", false)
}
