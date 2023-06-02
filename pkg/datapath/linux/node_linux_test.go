// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	check "github.com/cilium/checkmate"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/testutils"
)

type linuxPrivilegedBaseTestSuite struct {
	nodeAddressing datapath.NodeAddressing
	mtuConfig      mtu.Configuration
	enableIPv4     bool
	enableIPv6     bool
}

type linuxPrivilegedIPv6OnlyTestSuite struct {
	linuxPrivilegedBaseTestSuite
}

var _ = check.Suite(&linuxPrivilegedIPv6OnlyTestSuite{})

func (s *linuxPrivilegedIPv6OnlyTestSuite) SetUpSuite(c *check.C) {
	testutils.PrivilegedTest(c)
}

type linuxPrivilegedIPv4OnlyTestSuite struct {
	linuxPrivilegedBaseTestSuite
}

var _ = check.Suite(&linuxPrivilegedIPv4OnlyTestSuite{})

func (s *linuxPrivilegedIPv4OnlyTestSuite) SetUpSuite(c *check.C) {
	testutils.PrivilegedTest(c)
}

type linuxPrivilegedIPv4AndIPv6TestSuite struct {
	linuxPrivilegedBaseTestSuite
}

var _ = check.Suite(&linuxPrivilegedIPv4AndIPv6TestSuite{})

func (s *linuxPrivilegedIPv4AndIPv6TestSuite) SetUpSuite(c *check.C) {
	testutils.PrivilegedTest(c)
}

const (
	dummyHostDeviceName     = "dummy_host"
	dummyExternalDeviceName = "dummy_external"

	baseIPv4Time = "net.ipv4.neigh.default.base_reachable_time_ms"
	baseIPv6Time = "net.ipv6.neigh.default.base_reachable_time_ms"
)

func (s *linuxPrivilegedBaseTestSuite) SetUpTest(c *check.C, addressing datapath.NodeAddressing, enableIPv6, enableIPv4 bool) {
	rlimit.RemoveMemlock()
	s.nodeAddressing = addressing
	s.mtuConfig = mtu.NewConfiguration(0, false, false, false, 1500, nil)
	s.enableIPv6 = enableIPv6
	s.enableIPv4 = enableIPv4

	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)

	ips := make([]net.IP, 0)
	if enableIPv6 {
		ips = append(ips, s.nodeAddressing.IPv6().PrimaryExternal())
	}
	if enableIPv4 {
		ips = append(ips, s.nodeAddressing.IPv4().PrimaryExternal())
	}
	err := setupDummyDevice(dummyExternalDeviceName, ips...)
	c.Assert(err, check.IsNil)

	ips = []net.IP{}
	if enableIPv4 {
		ips = append(ips, s.nodeAddressing.IPv4().Router())
	}
	if enableIPv6 {
		ips = append(ips, s.nodeAddressing.IPv6().Router())
	}
	err = setupDummyDevice(dummyHostDeviceName, ips...)
	c.Assert(err, check.IsNil)

	tunnel.SetTunnelMap(tunnel.NewTunnelMap("test_cilium_tunnel_map"))
	err = tunnel.TunnelMap().OpenOrCreate()
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedIPv6OnlyTestSuite) SetUpTest(c *check.C) {
	addressing := fake.NewIPv6OnlyNodeAddressing()
	s.linuxPrivilegedBaseTestSuite.SetUpTest(c, addressing, true, false)
}

func (s *linuxPrivilegedIPv4OnlyTestSuite) SetUpTest(c *check.C) {
	addressing := fake.NewIPv4OnlyNodeAddressing()
	s.linuxPrivilegedBaseTestSuite.SetUpTest(c, addressing, false, true)
}

func (s *linuxPrivilegedIPv4AndIPv6TestSuite) SetUpTest(c *check.C) {
	addressing := fake.NewNodeAddressing()
	s.linuxPrivilegedBaseTestSuite.SetUpTest(c, addressing, true, true)
}

func tearDownTest(c *check.C) {
	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)
	err := tunnel.TunnelMap().Unpin()
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedIPv6OnlyTestSuite) TearDownTest(c *check.C) {
	tearDownTest(c)
}

func (s *linuxPrivilegedIPv4OnlyTestSuite) TearDownTest(c *check.C) {
	tearDownTest(c)
}

func (s *linuxPrivilegedIPv4AndIPv6TestSuite) TearDownTest(c *check.C) {
	tearDownTest(c)
}

func setupDummyDevice(name string, ips ...net.IP) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(dummy); err != nil {
		removeDevice(name)
		return err
	}

	for _, ip := range ips {
		var ipnet *net.IPNet
		if ip.To4() != nil {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}

		addr := &netlink.Addr{IPNet: ipnet}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			removeDevice(name)
			return err
		}
	}

	return nil
}

func removeDevice(name string) {
	l, err := netlink.LinkByName(name)
	if err == nil {
		netlink.LinkDel(l)
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestUpdateNodeRoute(c *check.C) {
	ip4CIDR := cidr.MustParseCIDR("254.254.254.0/24")
	c.Assert(ip4CIDR, check.Not(check.IsNil))

	ip6CIDR := cidr.MustParseCIDR("cafe:cafe:cafe:cafe::/96")
	c.Assert(ip6CIDR, check.Not(check.IsNil))

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		// add & remove IPv4 node route
		err = linuxNodeHandler.updateNodeRoute(ip4CIDR, true, false)
		c.Assert(err, check.IsNil)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4CIDR, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))

		err = linuxNodeHandler.deleteNodeRoute(ip4CIDR, false)
		c.Assert(err, check.IsNil)

		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4CIDR, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	if s.enableIPv6 {
		// add & remove IPv6 node route
		err = linuxNodeHandler.updateNodeRoute(ip6CIDR, true, false)
		c.Assert(err, check.IsNil)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6CIDR, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))

		err = linuxNodeHandler.deleteNodeRoute(ip6CIDR, false)
		c.Assert(err, check.IsNil)

		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6CIDR, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestSingleClusterPrefix(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	// enable as per test definition
	err := linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv4:            s.enableIPv4,
		EnableIPv6:            s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR(), false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR(), false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// disable ipv4, enable ipv6. addressing may not be available for IPv6
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv6:            true,
	})
	c.Assert(err, check.IsNil)

	foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR(), false)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR(), false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// enable ipv4, enable ipv6, addressing may not be available
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv6:            true,
		EnableIPv4:            true,
	})
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR(), false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR(), false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestAuxiliaryPrefixes(c *check.C) {
	net1 := cidr.MustParseCIDR("30.30.0.0/24")
	net2 := cidr.MustParseCIDR("cafe:f00d::/112")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:        s.enableIPv4,
		EnableIPv6:        s.enableIPv6,
		AuxiliaryPrefixes: []*cidr.CIDR{net1, net2},
	}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// remove aux prefix net2
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv4:        s.enableIPv4,
		EnableIPv6:        s.enableIPv6,
		AuxiliaryPrefixes: []*cidr.CIDR{net1},
	})
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	// remove aux prefix net1, re-add net2
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv4:        s.enableIPv4,
		EnableIPv6:        s.enableIPv6,
		AuxiliaryPrefixes: []*cidr.CIDR{net2},
	})
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateEncapsulation(c *check.C) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("6.6.6.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	ip6Alloc2 := cidr.MustParseCIDR("2001:bbbb::/96")

	externalNodeIP1 := net.ParseIP("4.4.4.4")
	externalNodeIP2 := net.ParseIP("8.8.8.8")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nodemapfake.NewFakeNodeMap())
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	// nodev1: ip4Alloc1, ip6alloc1 => externalNodeIP1
	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}
	if s.enableIPv6 {
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// nodev2: ip4Alloc1, ip6alloc1 => externalNodeIP2
	nodev2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP2, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev2.IPv4AllocCIDR = ip4Alloc1
	}
	if s.enableIPv6 {
		nodev2.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	c.Assert(err, check.IsNil)

	// alloc range v1 should map to underlay2
	if s.enableIPv4 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP2), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP2), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// nodev3: ip4Alloc2, ip6alloc2 => externalNodeIP1
	nodev3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev3.IPv4AllocCIDR = ip4Alloc2
	}
	if s.enableIPv6 {
		nodev3.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	c.Assert(err, check.IsNil)

	// alloc range v1 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))

	if s.enableIPv4 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		// node routes for alloc1 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		// node routes for alloc1 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// nodev4: stop announcing CIDRs
	nodev4 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	c.Assert(err, check.IsNil)

	// alloc range v2 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
	c.Assert(err, check.Not(check.IsNil))

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
	c.Assert(err, check.Not(check.IsNil))

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	// nodev5: re-announce CIDRs
	nodev5 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev5.IPv4AllocCIDR = ip4Alloc2
	}
	if s.enableIPv6 {
		nodev5.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeUpdate(nodev4, nodev5)
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	c.Assert(err, check.IsNil)

	// alloc range v1 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))

	// alloc range v2 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
	c.Assert(err, check.Not(check.IsNil))

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
	c.Assert(err, check.Not(check.IsNil))

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.IsNil)
	}
}

func lookupDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) ([]netlink.Route, error) {
	routeSpec, err := createDirectRouteSpec(CIDR, nodeIP)
	if err != nil {
		return nil, err
	}

	family := netlink.FAMILY_V4
	if nodeIP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	return netlink.RouteListFiltered(family, routeSpec, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF)
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateDirectRouting(c *check.C) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("5.5.5.0/26")

	ipv4SecondaryAlloc1 := cidr.MustParseCIDR("5.5.6.0/24")
	ipv4SecondaryAlloc2 := cidr.MustParseCIDR("5.5.7.0/24")
	ipv4SecondaryAlloc3 := cidr.MustParseCIDR("5.5.8.0/24")

	externalNode1IP4v1 := net.ParseIP("4.4.4.4")
	externalNode1IP4v2 := net.ParseIP("4.4.4.5")

	externalNode1Device := "dummy_node1"
	removeDevice(externalNode1Device)
	err := setupDummyDevice(externalNode1Device, externalNode1IP4v1, net.ParseIP("face::1"))
	c.Assert(err, check.IsNil)
	defer removeDevice(externalNode1Device)

	externalNode2Device := "dummy_node2"
	removeDevice(externalNode2Device)
	err = setupDummyDevice(externalNode2Device, externalNode1IP4v2, net.ParseIP("face::2"))
	c.Assert(err, check.IsNil)
	defer removeDevice(externalNode2Device)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	}

	expectedIPv4Routes := 0
	if s.enableIPv4 {
		expectedIPv4Routes = 1
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	// nodev1: ip4Alloc1 => externalNodeIP1
	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	foundRoutes, err := lookupDirectRoute(ip4Alloc1, externalNode1IP4v1)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)

	// nodev2: ip4Alloc1 => externalNodeIP2
	nodev2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}

	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	c.Assert(err, check.IsNil)

	foundRoutes, err = lookupDirectRoute(ip4Alloc1, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)

	// nodev3: ip4Alloc2 => externalNodeIP2
	nodev3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	c.Assert(err, check.IsNil)

	// node routes for alloc1 ranges should be gone
	foundRoutes, err = lookupDirectRoute(ip4Alloc1, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0) // route should not exist regardless whether ipv4 is enabled or not

	// node routes for alloc2 ranges should have been installed
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)

	// nodev4: no longer announce CIDR
	nodev4 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)

	// nodev5: Re-announce CIDR
	nodev5 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev4, nodev5)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should be gone
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0) // route should not exist regardless whether ipv4 is enabled or not

	// nodev6: Re-introduce node with secondary CIDRs
	nodev6 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc2},
	}
	err = linuxNodeHandler.NodeAdd(nodev6)
	c.Assert(err, check.IsNil)

	// expecting both primary and secondary routes to exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		foundRoutes, err = lookupDirectRoute(ip4Alloc, externalNode1IP4v1)
		c.Assert(err, check.IsNil)
		c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)
	}

	// nodev7: Replace a secondary route
	nodev7 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc3},
	}
	err = linuxNodeHandler.NodeUpdate(nodev6, nodev7)
	c.Assert(err, check.IsNil)

	// Checks all three required routes exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(ip4Alloc, externalNode1IP4v1)
		c.Assert(err, check.IsNil)
		c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)
	}
	// Checks route for removed CIDR has been deleted
	foundRoutes, err = lookupDirectRoute(ipv4SecondaryAlloc2, externalNode1IP4v1)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)

	// nodev8: Change node IP to externalNode1IP4v2
	nodev8 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc3},
	}
	err = linuxNodeHandler.NodeUpdate(nodev7, nodev8)
	c.Assert(err, check.IsNil)

	// Checks all routes with the new node IP exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(ip4Alloc, externalNode1IP4v2)
		c.Assert(err, check.IsNil)
		c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)
	}
	// Checks all routes with the old node IP have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(ip4Alloc, externalNode1IP4v1)
		c.Assert(err, check.IsNil)
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

	// nodev9: replacement of primary route, removal of secondary CIDRs
	nodev9 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc2,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{},
	}
	err = linuxNodeHandler.NodeUpdate(nodev8, nodev9)
	c.Assert(err, check.IsNil)

	// Checks primary route has been created
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, expectedIPv4Routes)

	// Checks all old routes have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(ip4Alloc, externalNode1IP4v2)
		c.Assert(err, check.IsNil)
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

	// delete nodev9
	err = linuxNodeHandler.NodeDelete(nodev9)
	c.Assert(err, check.IsNil)

	// remaining primary node route must have been deleted
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)
}

func (s *linuxPrivilegedBaseTestSuite) TestAgentRestartOptionChanges(c *check.C) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	underlayIP := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nodemapfake.NewFakeNodeMap())
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: underlayIP, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv6 {
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	if s.enableIPv4 {
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	// tunnel map entries must exist
	if s.enableIPv4 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		c.Assert(err, check.IsNil)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		c.Assert(err, check.IsNil)
	}

	// Simulate agent restart with address families disables
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv6:          false,
		EnableIPv4:          false,
		EnableEncapsulation: true,
	})
	c.Assert(err, check.IsNil)

	// Simulate initial node addition
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	// tunnel map entries should have been removed
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	c.Assert(err, check.Not(check.IsNil))

	// Simulate agent restart with address families enabled again
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
	c.Assert(err, check.IsNil)

	// Simulate initial node addition
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	// tunnel map entries must exist
	if s.enableIPv4 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		c.Assert(err, check.IsNil)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		c.Assert(err, check.IsNil)
	}

	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
}

func insertFakeRoute(c *check.C, n *linuxNodeHandler, prefix *cidr.CIDR) {
	nodeRoute, err := n.createNodeRouteSpec(prefix, false)
	c.Assert(err, check.IsNil)

	nodeRoute.Device = dummyExternalDeviceName

	err = route.Upsert(nodeRoute)
	c.Assert(err, check.IsNil)
}

func lookupFakeRoute(c *check.C, n *linuxNodeHandler, prefix *cidr.CIDR) bool {
	routeSpec, err := n.createNodeRouteSpec(prefix, false)
	c.Assert(err, check.IsNil)

	routeSpec.Device = dummyExternalDeviceName
	rt, err := route.Lookup(routeSpec)
	c.Assert(err, check.IsNil)
	return rt != nil
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeValidationDirectRouting(c *check.C) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	if s.enableIPv4 {
		insertFakeRoute(c, linuxNodeHandler, ip4Alloc1)
	}

	if s.enableIPv6 {
		insertFakeRoute(c, linuxNodeHandler, ip6Alloc1)
	}

	err := linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv4().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv6().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	err = linuxNodeHandler.NodeValidateImplementation(nodev1)
	c.Assert(err, check.IsNil)

	if s.enableIPv4 {
		c.Assert(lookupFakeRoute(c, linuxNodeHandler, ip4Alloc1), check.Equals, true)
	}

	if s.enableIPv6 {
		c.Assert(lookupFakeRoute(c, linuxNodeHandler, ip6Alloc1), check.Equals, true)
	}
}

func neighStateOk(n netlink.Neigh) (bool, bool) {
	retry := false
	good := false
	switch {
	case (n.State & netlink.NUD_REACHABLE) > 0:
		fallthrough
	case (n.State & netlink.NUD_STALE) > 0:
		// Current final state
		good = true
	case (n.State & netlink.NUD_DELAY) > 0:
		fallthrough
	case (n.State & netlink.NUD_PROBE) > 0:
		fallthrough
	case (n.State & netlink.NUD_FAILED) > 0:
		fallthrough
	case (n.State & netlink.NUD_INCOMPLETE) > 0:
		// Still potential ongoing resolution
		retry = true
	}
	return good, retry
}

func (s *linuxPrivilegedIPv6OnlyTestSuite) TestArpPingHandling(c *check.C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := c.MkDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := sysctl.Read(baseIPv6Time)
	c.Assert(err, check.IsNil)
	err = sysctl.Write(baseIPv6Time, fmt.Sprintf("%d", 2500))
	c.Assert(err, check.IsNil)
	defer func() { sysctl.Write(baseIPv6Time, baseTimeOld) }()

	// 1. Test whether another node in the same L2 subnet can be arpinged.
	//    The other node is in the different netns reachable via the veth pair.
	//
	//      +--------------+     +--------------+
	//      |  host netns  |     |    netns0    |
	//      |              |     |    nodev1    |
	//      |         veth0+-----+veth1         |
	//      | f00d::249/96 |     | f00d::250/96 |
	//      +--------------+     +--------------+

	// Setup
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(veth)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(veth)
	veth0, err := netlink.LinkByName("veth0")
	c.Assert(err, check.IsNil)
	veth1, err := netlink.LinkByName("veth1")
	c.Assert(err, check.IsNil)
	_, ipnet, _ := net.ParseCIDR("f00d::/96")
	ip0 := net.ParseIP("f00d::249")
	ip1 := net.ParseIP("f00d::250")
	ipG := net.ParseIP("f00d::251")
	ipnet.IP = ip0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth0)
	c.Assert(err, check.IsNil)

	netns0, err := netns.ReplaceNetNSWithName("test-arping-netns0")
	c.Assert(err, check.IsNil)
	defer netns0.Close()
	err = netlink.LinkSetNsFd(veth1, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		ipnet.IP = ip1
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = ipG
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth1)
		c.Assert(err, check.IsNil)
		return nil
	})

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = time.Duration(1 * time.Nanosecond)

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode6[nodeID]
			if !found {
				return waitForDelete
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return waitForDelete
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			if waitForDelete {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   ip1,
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
refetch1:
	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found := false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch1
			}
		}
	}
	c.Assert(found, check.Equals, true)

	// Swap MAC addresses of veth0 and veth1 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		c.Assert(err, check.IsNil)
		return nil
	})

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	c.Assert(err, check.IsNil)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1)
	wait(nodev1.Identity(), "veth0", &now, false)
refetch2:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch2
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth0HwAddr.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	// Create multiple goroutines which call insertNeighbor and check whether
	// MAC changes of veth1 are properly handled. This is a basic randomized
	// testing of insertNeighbor() fine-grained locking.
	now = time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	wait(nodev1.Identity(), "veth0", &now, false)

	rndHWAddr := func() net.HardwareAddr {
		mac := make([]byte, 6)
		_, err := rand.Read(mac)
		c.Assert(err, check.IsNil)
		mac[0] = (mac[0] | 2) & 0xfe
		return net.HardwareAddr(mac)
	}
	neighRefCount := func(nextHopStr string) int {
		linuxNodeHandler.neighLock.Lock()
		defer linuxNodeHandler.neighLock.Unlock()
		return linuxNodeHandler.neighNextHopRefCount[nextHopStr]
	}

	done := make(chan struct{})
	count := 30
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(100 * time.Millisecond)
			for {
				linuxNodeHandler.insertNeighbor(context.Background(), &nodev1, true)
				select {
				case <-ticker.C:
				case <-done:
					return
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		mac := rndHWAddr()
		// Change MAC
		netns0.Do(func(ns.NetNS) error {
			veth1, err := netlink.LinkByName("veth1")
			c.Assert(err, check.IsNil)
			err = netlink.LinkSetHardwareAddr(veth1, mac)
			c.Assert(err, check.IsNil)
			return nil
		})

		// Check that MAC has been changed in the neigh table
		var found bool
		err := testutils.WaitUntilWithSleep(func() bool {
			neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
			c.Assert(err, check.IsNil)
			found = false
			for _, n := range neighs {
				if n.IP.Equal(ip1) && (n.State&netlink.NUD_REACHABLE) > 0 &&
					n.HardwareAddr.String() == mac.String() &&
					neighRefCount(ip1.String()) == 1 {
					found = true
					return true
				}
			}
			return false
		}, 25*time.Second, 200*time.Millisecond)
		c.Assert(err, check.IsNil)
		c.Assert(found, check.Equals, true)
	}

	// Cleanup
	close(done)
	wg.Wait()
	now = time.Now()
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	wait(nodev1.Identity(), "veth0", nil, true)

	// Setup routine for the 2. test
	setupRemoteNode := func(vethName, vethPeerName, netnsName, vethCIDR, vethIPAddr,
		vethPeerIPAddr string) (cleanup func(), errRet error) {

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: vethName},
			PeerName:  vethPeerName,
		}
		errRet = netlink.LinkAdd(veth)
		if errRet != nil {
			return nil, err
		}
		cleanup1 := func() { netlink.LinkDel(veth) }
		cleanup = cleanup1

		veth2, err := netlink.LinkByName(vethName)
		if err != nil {
			errRet = err
			return
		}
		veth3, err := netlink.LinkByName(vethPeerName)
		if err != nil {
			errRet = err
			return
		}
		netns1, err := netns.ReplaceNetNSWithName(netnsName)
		if err != nil {
			errRet = err
			return
		}
		cleanup = func() {
			cleanup1()
			netns1.Close()
		}
		if errRet = netlink.LinkSetNsFd(veth2, int(netns0.Fd())); errRet != nil {
			return
		}
		if errRet = netlink.LinkSetNsFd(veth3, int(netns1.Fd())); errRet != nil {
			return
		}

		ip, ipnet, err := net.ParseCIDR(vethCIDR)
		if err != nil {
			errRet = err
			return
		}
		ip2 := net.ParseIP(vethIPAddr)
		ip3 := net.ParseIP(vethPeerIPAddr)
		ipnet.IP = ip2

		if errRet = netns0.Do(func(ns.NetNS) error {
			addr = &netlink.Addr{IPNet: ipnet}
			if err := netlink.AddrAdd(veth2, addr); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth2); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth2); err != nil {
				return err
			}
			return nil
		}); errRet != nil {
			return
		}

		ipnet.IP = ip
		route := &netlink.Route{
			Dst: ipnet,
			Gw:  ip1,
		}
		if errRet = netlink.RouteAdd(route); errRet != nil {
			return
		}

		if errRet = netns1.Do(func(ns.NetNS) error {
			veth3, err := netlink.LinkByName(vethPeerName)
			if err != nil {
				return err
			}
			ipnet.IP = ip3
			addr = &netlink.Addr{IPNet: ipnet}
			if err := netlink.AddrAdd(veth3, addr); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth3); err != nil {
				return err
			}

			_, ipnet, err := net.ParseCIDR("f00d::/96")
			if err != nil {
				return err
			}
			route := &netlink.Route{
				Dst: ipnet,
				Gw:  ip2,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return err
			}
			return nil
		}); errRet != nil {
			return
		}

		return
	}

	// 2. Add two nodes which are reachable from the host only via nodev1 (gw).
	//    Arping should ping veth1 IP addr instead of veth3 or veth5.
	//
	//      +--------------+     +--------------+     +--------------+
	//      |  host netns  |     |    netns0    |     |    netns1    |
	//      |              |     |    nodev1    |     |    nodev2    |
	//      |              |     |  f00a::249/96|     |              |
	//      |              |     |           |  |     |              |
	//      |         veth0+-----+veth1    veth2+-----+veth3         |
	//      |          |   |     |   |          |     | |            |
	//      | f00d::249/96 |     |f00d::250/96  |     | f00a::250/96 |
	//      +--------------+     |         veth4+-+   +--------------+
	//                           |           |  | |   +--------------+
	//                           | f00b::249/96 | |   |    netns2    |
	//                           +--------------+ |   |    nodev3    |
	//                                            |   |              |
	//                                            +---+veth5         |
	//                                                | |            |
	//                                                | f00b::250/96 |
	//                                                +--------------+

	cleanup1, err := setupRemoteNode("veth2", "veth3", "test-arping-netns1",
		"f00a::/96", "f00a::249", "f00a::250")
	c.Assert(err, check.IsNil)
	defer cleanup1()
	cleanup2, err := setupRemoteNode("veth4", "veth5", "test-arping-netns2",
		"f00b::/96", "f00b::249", "f00b::250")
	c.Assert(err, check.IsNil)
	defer cleanup2()

	node2IP := net.ParseIP("f00a::250")
	nodev2 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node2IP}},
	}
	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", &now, false)

	node3IP := net.ParseIP("f00b::250")
	nodev3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node3IP,
		}},
	}
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop := net.ParseIP("f00d::250")
refetch3:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch3
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Check that removing node2 will not remove nextHop, as it is still used by node3
	c.Assert(linuxNodeHandler.NodeDelete(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", nil, true)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	// However, removing node3 should remove the neigh entry for nextHop
	c.Assert(linuxNodeHandler.NodeDelete(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", nil, true)

	found = false
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("f00d::250")
refetch4:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch4
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// We have stored the devices in NodeConfigurationChanged
	linuxNodeHandler.NodeCleanNeighbors(false)
refetch5:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch5
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, false)

	// Setup routine for the 3. test
	setupNewGateway := func(vethCIDR, gwIP string) (errRet error) {
		ipGw := net.ParseIP(gwIP)
		ip, ipnet, err := net.ParseCIDR(vethCIDR)
		if err != nil {
			errRet = err
			return
		}
		ipnet.IP = ip
		route := &netlink.Route{
			Dst: ipnet,
			Gw:  ipGw,
		}
		errRet = netlink.RouteReplace(route)
		return
	}

	// In the next test, we add node 2,3 again, and then change the nextHop
	// address to check the refcount behavior, and that the old one was
	// deleted from the neighbor table as well as the new one added.
	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", &now, false)

	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("f00d::250")
refetch6:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch6
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Switch to new nextHop address for node2
	err = setupNewGateway("f00a::/96", "f00d::251")
	c.Assert(err, check.IsNil)

	// waitGw waits for the nextHop to appear in the agent's nextHop table
	waitGw := func(nextHopNew string, nodeID nodeTypes.Identity, link string, before *time.Time) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode6[nodeID]
			if !found {
				return false
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return false
			}
			if nextHop != nextHopNew {
				return false
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3)
	waitGw("f00d::251", nodev2.Identity(), "veth0", &now)
	waitGw("f00d::250", nodev3.Identity(), "veth0", &now)

	// Both nextHops now need to be present
	nextHop = net.ParseIP("f00d::250")
refetch7:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch7
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	nextHop = net.ParseIP("f00d::251")
refetch8:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch8
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Now also switch over the other node.
	err = setupNewGateway("f00b::/96", "f00d::251")
	c.Assert(err, check.IsNil)

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3)
	waitGw("f00d::251", nodev2.Identity(), "veth0", &now)
	waitGw("f00d::251", nodev3.Identity(), "veth0", &now)

	nextHop = net.ParseIP("f00d::250")
refetch9:
	// Check that old nextHop address got removed
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch9
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, false)

	nextHop = net.ParseIP("f00d::251")
refetch10:
	// Check that new nextHop address got added
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch10
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	c.Assert(linuxNodeHandler.NodeDelete(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", nil, true)

	// In the next test, we have node2 left in the neighbor table, and
	// we add an unrelated externally learned neighbor entry. Check that
	// NodeCleanNeighbors() removes the unrelated one. This is to simulate
	// the agent after kubeapi-server resync that it cleans up stale node
	// entries from previous runs.

	nextHop = net.ParseIP("f00d::1")
	neigh := netlink.Neigh{
		LinkIndex: veth0.Attrs().Index,
		IP:        nextHop,
		State:     netlink.NUD_NONE,
		Flags:     netlink.NTF_EXT_LEARNED,
	}
	err = netlink.NeighSet(&neigh)
	c.Assert(err, check.IsNil)

	// Check that new nextHop address got added, we don't care about its NUD_* state
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	// Clean unrelated externally learned entries
	linuxNodeHandler.NodeCleanNeighborsLink(veth0, true)

	// Check that new nextHop address got removed
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	// Check that node2 nextHop address is still there
	nextHop = net.ParseIP("f00d::251")
refetch11:
	// Check that new nextHop address got added
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch11
			}
		} else if n.IP.Equal(node2IP) {
			c.ExpectFailure("node2 should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	c.Assert(linuxNodeHandler.NodeDelete(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", nil, true)

	linuxNodeHandler.NodeCleanNeighborsLink(veth0, false)
}

func (s *linuxPrivilegedIPv6OnlyTestSuite) TestArpPingHandlingForMultiDevice(c *check.C) {
	c.Skip("Skipping due flakiness. See https://github.com/cilium/cilium/issues/22373 for more info")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := c.MkDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := sysctl.Read(baseIPv6Time)
	c.Assert(err, check.IsNil)
	err = sysctl.Write(baseIPv6Time, fmt.Sprintf("%d", 2500))
	c.Assert(err, check.IsNil)
	defer func() { sysctl.Write(baseIPv6Time, baseTimeOld) }()

	// 1. Test whether another node in the same L2 subnet can be arpinged.
	//    Each node has two devices and the other node in the different netns
	//    is reachable via either pair.
	//
	//      +--------------+     +--------------+
	//      |  host netns  |     |    netns1    |
	//      |              |     |    nodev1    |
	//      |              |     |  fe80::1/128 |
	//      |         veth0+-----+veth1         |
	//      |          |   |     |   |          |
	//      | f00d::249/96 |     | f00d::250/96 |
	//      |              |     |              |
	//      |         veth2+-----+veth3         |
	//      |          |   |     | |            |
	//      | f00a::249/96 |     | f00a::250/96 |
	//      +--------------+     +--------------+

	// Setup
	vethPair01 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(vethPair01)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(vethPair01)
	veth0, err := netlink.LinkByName("veth0")
	c.Assert(err, check.IsNil)
	veth1, err := netlink.LinkByName("veth1")
	c.Assert(err, check.IsNil)
	_, ipnet, _ := net.ParseCIDR("f00d::/96")
	v1IP0 := net.ParseIP("f00d::249")
	v1IP1 := net.ParseIP("f00d::250")
	v1IPG := net.ParseIP("f00d::251")
	ipnet.IP = v1IP0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth0)
	c.Assert(err, check.IsNil)

	netns0, err := netns.ReplaceNetNSWithName("test-arping-netns0")
	c.Assert(err, check.IsNil)
	defer netns0.Close()
	err = netlink.LinkSetNsFd(veth1, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	netns0.Do(func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(lo)
		c.Assert(err, check.IsNil)
		addr, err := netlink.ParseAddr("fe80::1/128")
		c.Assert(err, check.IsNil)
		err = netlink.AddrAdd(lo, addr)
		c.Assert(err, check.IsNil)

		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		ipnet.IP = v1IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = v1IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth1)
		c.Assert(err, check.IsNil)
		return nil
	})

	vethPair23 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth2"},
		PeerName:  "veth3",
	}
	err = netlink.LinkAdd(vethPair23)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(vethPair23)
	veth2, err := netlink.LinkByName("veth2")
	c.Assert(err, check.IsNil)
	veth3, err := netlink.LinkByName("veth3")
	c.Assert(err, check.IsNil)
	_, ipnet, _ = net.ParseCIDR("f00a::/96")
	v2IP0 := net.ParseIP("f00a::249")
	v2IP1 := net.ParseIP("f00a::250")
	v2IPG := net.ParseIP("f00a::251")
	ipnet.IP = v2IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth2, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth2)
	c.Assert(err, check.IsNil)

	err = netlink.LinkSetNsFd(veth3, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	err = netns0.Do(func(ns.NetNS) error {
		veth3, err := netlink.LinkByName("veth3")
		c.Assert(err, check.IsNil)
		ipnet.IP = v2IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = v2IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth3)
		c.Assert(err, check.IsNil)
		return nil
	})
	c.Assert(err, check.IsNil)

	r := &netlink.Route{
		Dst: netlink.NewIPNet(net.ParseIP("fe80::1")),
		MultiPath: []*netlink.NexthopInfo{
			{
				LinkIndex: veth0.Attrs().Index,
				Gw:        v1IP1,
			},
			{
				LinkIndex: veth2.Attrs().Index,
				Gw:        v2IP1,
			},
		}}

	err = netlink.RouteAdd(r)
	c.Assert(err, check.IsNil)
	defer netlink.RouteDel(r)

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevDevices := option.Config.GetDevices()
	defer func() { option.Config.SetDevices(prevDevices) }()
	option.Config.SetDevices([]string{"veth0", "veth2"})
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = 1 * time.Nanosecond

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode6[nodeID]
			if !found {
				return waitForDelete
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return waitForDelete
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			if waitForDelete {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   net.ParseIP("fe80::1"),
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)
refetch1:
	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found := false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch1
			}
		}
	}
	c.Assert(found, check.Equals, true)

refetch2:
	// Check whether an arp entry for nodev1 IP addr (=veth3) was added
	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch2
			}
		}
	}
	c.Assert(found, check.Equals, true)

	// Swap MAC addresses of veth0 and veth1, veth2 and veth3 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, veth2HwAddr, veth3HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	veth2HwAddr = veth2.Attrs().HardwareAddr
	err = netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		c.Assert(err, check.IsNil)

		veth3, err := netlink.LinkByName("veth3")
		c.Assert(err, check.IsNil)
		veth3HwAddr = veth3.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth3, veth2HwAddr)
		c.Assert(err, check.IsNil)
		return nil
	})
	c.Assert(err, check.IsNil)

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetHardwareAddr(veth2, veth3HwAddr)
	c.Assert(err, check.IsNil)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1)
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)
refetch3:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch3
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth0HwAddr.String())

refetch4:
	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch4
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth2HwAddr.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)
	wait(nodev1.Identity(), "veth2", nil, true)

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V6)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)
}

func (s *linuxPrivilegedIPv4OnlyTestSuite) TestArpPingHandling(c *check.C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := c.MkDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := sysctl.Read(baseIPv4Time)
	c.Assert(err, check.IsNil)
	err = sysctl.Write(baseIPv4Time, fmt.Sprintf("%d", 2500))
	c.Assert(err, check.IsNil)
	defer func() { sysctl.Write(baseIPv4Time, baseTimeOld) }()

	// 1. Test whether another node in the same L2 subnet can be arpinged.
	//    The other node is in the different netns reachable via the veth pair.
	//
	//      +--------------+     +--------------+
	//      |  host netns  |     |    netns0    |
	//      |              |     |    nodev1    |
	//      |         veth0+-----+veth1         |
	//      | 9.9.9.249/29 |     | 9.9.9.250/29 |
	//      +--------------+     +--------------+

	// Setup
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(veth)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(veth)
	veth0, err := netlink.LinkByName("veth0")
	c.Assert(err, check.IsNil)
	veth1, err := netlink.LinkByName("veth1")
	c.Assert(err, check.IsNil)
	_, ipnet, _ := net.ParseCIDR("9.9.9.252/29")
	ip0 := net.ParseIP("9.9.9.249")
	ip1 := net.ParseIP("9.9.9.250")
	ipG := net.ParseIP("9.9.9.251")
	ipnet.IP = ip0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth0)
	c.Assert(err, check.IsNil)

	netns0, err := netns.ReplaceNetNSWithName("test-arping-netns0")
	c.Assert(err, check.IsNil)
	defer netns0.Close()
	err = netlink.LinkSetNsFd(veth1, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		ipnet.IP = ip1
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = ipG
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth1)
		c.Assert(err, check.IsNil)
		return nil
	})

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = time.Duration(1 * time.Nanosecond)

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode4[nodeID]
			if !found {
				return waitForDelete
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return waitForDelete
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			if waitForDelete {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   ip1,
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
refetch1:
	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found := false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch1
			}
		}
	}
	c.Assert(found, check.Equals, true)

	// Swap MAC addresses of veth0 and veth1 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		c.Assert(err, check.IsNil)
		return nil
	})

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	c.Assert(err, check.IsNil)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1)
	wait(nodev1.Identity(), "veth0", &now, false)
refetch2:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch2
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth0HwAddr.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	// Create multiple goroutines which call insertNeighbor and check whether
	// MAC changes of veth1 are properly handled. This is a basic randomized
	// testing of insertNeighbor() fine-grained locking.
	now = time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	wait(nodev1.Identity(), "veth0", &now, false)

	rndHWAddr := func() net.HardwareAddr {
		mac := make([]byte, 6)
		_, err := rand.Read(mac)
		c.Assert(err, check.IsNil)
		mac[0] = (mac[0] | 2) & 0xfe
		return net.HardwareAddr(mac)
	}
	neighRefCount := func(nextHopStr string) int {
		linuxNodeHandler.neighLock.Lock()
		defer linuxNodeHandler.neighLock.Unlock()
		return linuxNodeHandler.neighNextHopRefCount[nextHopStr]
	}

	done := make(chan struct{})
	count := 30
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(100 * time.Millisecond)
			for {
				linuxNodeHandler.insertNeighbor(context.Background(), &nodev1, true)
				select {
				case <-ticker.C:
				case <-done:
					return
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		mac := rndHWAddr()
		// Change MAC
		netns0.Do(func(ns.NetNS) error {
			veth1, err := netlink.LinkByName("veth1")
			c.Assert(err, check.IsNil)
			err = netlink.LinkSetHardwareAddr(veth1, mac)
			c.Assert(err, check.IsNil)
			return nil
		})

		// Check that MAC has been changed in the neigh table
		var found bool
		err := testutils.WaitUntilWithSleep(func() bool {
			neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
			c.Assert(err, check.IsNil)
			found = false
			for _, n := range neighs {
				if n.IP.Equal(ip1) && (n.State&netlink.NUD_REACHABLE) > 0 &&
					n.HardwareAddr.String() == mac.String() &&
					neighRefCount(ip1.String()) == 1 {
					found = true
					return true
				}
			}
			return false
		}, 25*time.Second, 200*time.Millisecond)
		c.Assert(err, check.IsNil)
		c.Assert(found, check.Equals, true)
	}

	// Cleanup
	close(done)
	wg.Wait()
	now = time.Now()
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	wait(nodev1.Identity(), "veth0", nil, true)

	// Setup routine for the 2. test
	setupRemoteNode := func(vethName, vethPeerName, netnsName, vethCIDR, vethIPAddr,
		vethPeerIPAddr string) (cleanup func(), errRet error) {

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: vethName},
			PeerName:  vethPeerName,
		}
		errRet = netlink.LinkAdd(veth)
		if errRet != nil {
			return nil, err
		}
		cleanup1 := func() { netlink.LinkDel(veth) }
		cleanup = cleanup1

		veth2, err := netlink.LinkByName(vethName)
		if err != nil {
			errRet = err
			return
		}
		veth3, err := netlink.LinkByName(vethPeerName)
		if err != nil {
			errRet = err
			return
		}
		netns1, err := netns.ReplaceNetNSWithName(netnsName)
		if err != nil {
			errRet = err
			return
		}
		cleanup = func() {
			cleanup1()
			netns1.Close()
		}
		if errRet = netlink.LinkSetNsFd(veth2, int(netns0.Fd())); errRet != nil {
			return
		}
		if errRet = netlink.LinkSetNsFd(veth3, int(netns1.Fd())); errRet != nil {
			return
		}

		ip, ipnet, err := net.ParseCIDR(vethCIDR)
		if err != nil {
			errRet = err
			return
		}
		ip2 := net.ParseIP(vethIPAddr)
		ip3 := net.ParseIP(vethPeerIPAddr)
		ipnet.IP = ip2

		if errRet = netns0.Do(func(ns.NetNS) error {
			addr = &netlink.Addr{IPNet: ipnet}
			if err := netlink.AddrAdd(veth2, addr); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth2); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth2); err != nil {
				return err
			}
			return nil
		}); errRet != nil {
			return
		}

		ipnet.IP = ip
		route := &netlink.Route{
			Dst: ipnet,
			Gw:  ip1,
		}
		if errRet = netlink.RouteAdd(route); errRet != nil {
			return
		}

		if errRet = netns1.Do(func(ns.NetNS) error {
			veth3, err := netlink.LinkByName(vethPeerName)
			if err != nil {
				return err
			}
			ipnet.IP = ip3
			addr = &netlink.Addr{IPNet: ipnet}
			if err := netlink.AddrAdd(veth3, addr); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(veth3); err != nil {
				return err
			}

			_, ipnet, err := net.ParseCIDR("9.9.9.248/29")
			if err != nil {
				return err
			}
			route := &netlink.Route{
				Dst: ipnet,
				Gw:  ip2,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return err
			}
			return nil
		}); errRet != nil {
			return
		}

		return
	}

	// 2. Add two nodes which are reachable from the host only via nodev1 (gw).
	//    Arping should ping veth1 IP addr instead of veth3 or veth5.
	//
	//      +--------------+     +--------------+     +--------------+
	//      |  host netns  |     |    netns0    |     |    netns1    |
	//      |              |     |    nodev1    |     |    nodev2    |
	//      |              |     |  8.8.8.249/29|     |              |
	//      |              |     |           |  |     |              |
	//      |         veth0+-----+veth1    veth2+-----+veth3         |
	//      |          |   |     |   |          |     | |            |
	//      | 9.9.9.249/29 |     |9.9.9.250/29  |     | 8.8.8.250/29 |
	//      +--------------+     |         veth4+-+   +--------------+
	//                           |           |  | |   +--------------+
	//                           | 7.7.7.249/29 | |   |    netns2    |
	//                           +--------------+ |   |    nodev3    |
	//                                            |   |              |
	//                                            +---+veth5         |
	//                                                | |            |
	//                                                | 7.7.7.250/29 |
	//                                                +--------------+

	cleanup1, err := setupRemoteNode("veth2", "veth3", "test-arping-netns1",
		"8.8.8.248/29", "8.8.8.249", "8.8.8.250")
	c.Assert(err, check.IsNil)
	defer cleanup1()
	cleanup2, err := setupRemoteNode("veth4", "veth5", "test-arping-netns2",
		"7.7.7.248/29", "7.7.7.249", "7.7.7.250")
	c.Assert(err, check.IsNil)
	defer cleanup2()

	node2IP := net.ParseIP("8.8.8.250")
	nodev2 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node2IP,
		}},
	}
	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", &now, false)

	node3IP := net.ParseIP("7.7.7.250")
	nodev3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node3IP,
		}},
	}
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop := net.ParseIP("9.9.9.250")
refetch3:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch3
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Check that removing node2 will not remove nextHop, as it is still used by node3
	c.Assert(linuxNodeHandler.NodeDelete(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", nil, true)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	// However, removing node3 should remove the neigh entry for nextHop
	c.Assert(linuxNodeHandler.NodeDelete(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", nil, true)

	found = false
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("9.9.9.250")
refetch4:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch4
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// We have stored the devices in NodeConfigurationChanged
	linuxNodeHandler.NodeCleanNeighbors(false)
refetch5:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch5
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, false)

	// Setup routine for the 3. test
	setupNewGateway := func(vethCIDR, gwIP string) (errRet error) {
		ipGw := net.ParseIP(gwIP)
		ip, ipnet, err := net.ParseCIDR(vethCIDR)
		if err != nil {
			errRet = err
			return
		}
		ipnet.IP = ip
		route := &netlink.Route{
			Dst: ipnet,
			Gw:  ipGw,
		}
		errRet = netlink.RouteReplace(route)
		return
	}

	// In the next test, we add node 2,3 again, and then change the nextHop
	// address to check the refcount behavior, and that the old one was
	// deleted from the neighbor table as well as the new one added.
	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", &now, false)

	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("9.9.9.250")
refetch6:
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch6
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Switch to new nextHop address for node2
	err = setupNewGateway("8.8.8.248/29", "9.9.9.251")
	c.Assert(err, check.IsNil)

	// waitGw waits for the nextHop to appear in the agent's nextHop table
	waitGw := func(nextHopNew string, nodeID nodeTypes.Identity, link string, before *time.Time) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode4[nodeID]
			if !found {
				return false
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return false
			}
			if nextHop != nextHopNew {
				return false
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3)
	waitGw("9.9.9.251", nodev2.Identity(), "veth0", &now)
	waitGw("9.9.9.250", nodev3.Identity(), "veth0", &now)

	// Both nextHops now need to be present
	nextHop = net.ParseIP("9.9.9.250")
refetch7:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch7
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	nextHop = net.ParseIP("9.9.9.251")
refetch8:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch8
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Now also switch over the other node.
	err = setupNewGateway("7.7.7.248/29", "9.9.9.251")
	c.Assert(err, check.IsNil)

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3)
	waitGw("9.9.9.251", nodev2.Identity(), "veth0", &now)
	waitGw("9.9.9.251", nodev3.Identity(), "veth0", &now)

	nextHop = net.ParseIP("9.9.9.250")
refetch9:
	// Check that old nextHop address got removed
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch9
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, false)

	nextHop = net.ParseIP("9.9.9.251")
refetch10:
	// Check that new nextHop address got added
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch10
			}
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	c.Assert(linuxNodeHandler.NodeDelete(nodev3), check.IsNil)
	wait(nodev3.Identity(), "veth0", nil, true)

	// In the next test, we have node2 left in the neighbor table, and
	// we add an unrelated externally learned neighbor entry. Check that
	// NodeCleanNeighbors() removes the unrelated one. This is to simulate
	// the agent after kubeapi-server resync that it cleans up stale node
	// entries from previous runs.

	nextHop = net.ParseIP("9.9.9.1")
	neigh := netlink.Neigh{
		LinkIndex: veth0.Attrs().Index,
		IP:        nextHop,
		State:     netlink.NUD_NONE,
		Flags:     netlink.NTF_EXT_LEARNED,
	}
	err = netlink.NeighSet(&neigh)
	c.Assert(err, check.IsNil)

	// Check that new nextHop address got added, we don't care about its NUD_* state
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	// Clean unrelated externally learned entries
	linuxNodeHandler.NodeCleanNeighborsLink(veth0, true)

	// Check that new nextHop address got removed
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	// Check that node2 nextHop address is still there
	nextHop = net.ParseIP("9.9.9.251")
refetch11:
	// Check that new nextHop address got added
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch11
			}
		} else if n.IP.Equal(node2IP) {
			c.ExpectFailure("node2 should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	c.Assert(linuxNodeHandler.NodeDelete(nodev2), check.IsNil)
	wait(nodev2.Identity(), "veth0", nil, true)

	linuxNodeHandler.NodeCleanNeighborsLink(veth0, false)
}

func (s *linuxPrivilegedIPv4OnlyTestSuite) TestArpPingHandlingForMultiDevice(c *check.C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := c.MkDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := sysctl.Read(baseIPv4Time)
	c.Assert(err, check.IsNil)
	err = sysctl.Write(baseIPv4Time, fmt.Sprintf("%d", 2500))
	c.Assert(err, check.IsNil)
	defer func() { sysctl.Write(baseIPv4Time, baseTimeOld) }()

	// 1. Test whether another node in the same L2 subnet can be arpinged.
	//    Each node has two devices and the other node in the different netns
	//    is reachable via either pair.
	//
	//      +--------------+     +--------------+
	//      |  host netns  |     |    netns1    |
	//      |              |     |    nodev1    |
	//      |              |     |  10.0.0.1/32 |
	//      |         veth0+-----+veth1         |
	//      |          |   |     |   |          |
	//      | 9.9.9.249/29 |     |9.9.9.250/29  |
	//      |              |     |              |
	//      |         veth2+-----+veth3         |
	//      |          |   |     | |            |
	//      | 8.8.8.249/29 |     | 8.8.8.250/29 |
	//      +--------------+     +--------------+

	// Setup
	vethPair01 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(vethPair01)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(vethPair01)
	veth0, err := netlink.LinkByName("veth0")
	c.Assert(err, check.IsNil)
	veth1, err := netlink.LinkByName("veth1")
	c.Assert(err, check.IsNil)
	_, ipnet, _ := net.ParseCIDR("9.9.9.252/29")
	v1IP0 := net.ParseIP("9.9.9.249")
	v1IP1 := net.ParseIP("9.9.9.250")
	v1IPG := net.ParseIP("9.9.9.251")
	ipnet.IP = v1IP0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth0)
	c.Assert(err, check.IsNil)

	netns0, err := netns.ReplaceNetNSWithName("test-arping-netns0")
	c.Assert(err, check.IsNil)
	defer netns0.Close()
	err = netlink.LinkSetNsFd(veth1, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	err = netns0.Do(func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(lo)
		c.Assert(err, check.IsNil)
		addr, err := netlink.ParseAddr("10.0.0.1/32")
		c.Assert(err, check.IsNil)
		err = netlink.AddrAdd(lo, addr)
		c.Assert(err, check.IsNil)

		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		ipnet.IP = v1IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = v1IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth1)
		c.Assert(err, check.IsNil)
		return nil
	})
	c.Assert(err, check.IsNil)

	vethPair23 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth2"},
		PeerName:  "veth3",
	}
	err = netlink.LinkAdd(vethPair23)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(vethPair23)
	veth2, err := netlink.LinkByName("veth2")
	c.Assert(err, check.IsNil)
	veth3, err := netlink.LinkByName("veth3")
	c.Assert(err, check.IsNil)
	_, ipnet, _ = net.ParseCIDR("8.8.8.252/29")
	v2IP0 := net.ParseIP("8.8.8.249")
	v2IP1 := net.ParseIP("8.8.8.250")
	v2IPG := net.ParseIP("8.8.8.251")
	ipnet.IP = v2IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth2, addr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetUp(veth2)
	c.Assert(err, check.IsNil)

	err = netlink.LinkSetNsFd(veth3, int(netns0.Fd()))
	c.Assert(err, check.IsNil)
	err = netns0.Do(func(ns.NetNS) error {
		veth3, err := netlink.LinkByName("veth3")
		c.Assert(err, check.IsNil)
		ipnet.IP = v2IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		c.Assert(err, check.IsNil)
		ipnet.IP = v2IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		c.Assert(err, check.IsNil)
		err = netlink.LinkSetUp(veth3)
		c.Assert(err, check.IsNil)
		return nil
	})
	c.Assert(err, check.IsNil)

	r := &netlink.Route{
		Dst: netlink.NewIPNet(net.ParseIP("10.0.0.1")),
		MultiPath: []*netlink.NexthopInfo{
			{
				LinkIndex: veth0.Attrs().Index,
				Gw:        v1IP1,
			},
			{
				LinkIndex: veth2.Attrs().Index,
				Gw:        v2IP1,
			},
		}}
	err = netlink.RouteAdd(r)
	c.Assert(err, check.IsNil)
	defer netlink.RouteDel(r)

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevDevices := option.Config.GetDevices()
	defer func() { option.Config.SetDevices(prevDevices) }()
	option.Config.SetDevices([]string{"veth0", "veth2"})
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = 1 * time.Nanosecond

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHopByLink, found := linuxNodeHandler.neighNextHopByNode4[nodeID]
			if !found {
				return waitForDelete
			}
			nextHop, found := nextHopByLink[link]
			if !found {
				return waitForDelete
			}
			lastPing, found := linuxNodeHandler.neighLastPingByNextHop[nextHop]
			if !found {
				return false
			}
			if waitForDelete {
				return false
			}
			return before.Before(lastPing)
		}, 5*time.Second)
		c.Assert(err, check.IsNil)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)
refetch1:
	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found := false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch1
			}
		}
	}
	c.Assert(found, check.Equals, true)

refetch2:
	// Check whether an arp entry for nodev1 IP addr (=veth3) was added
	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				break
			}
			if retry {
				goto refetch2
			}
		}
	}
	c.Assert(found, check.Equals, true)

	// Swap MAC addresses of veth0 and veth1, veth2 and veth3 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, veth2HwAddr, veth3HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	veth2HwAddr = veth2.Attrs().HardwareAddr
	err = netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		c.Assert(err, check.IsNil)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		c.Assert(err, check.IsNil)

		veth3, err := netlink.LinkByName("veth3")
		c.Assert(err, check.IsNil)
		veth3HwAddr = veth3.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth3, veth2HwAddr)
		c.Assert(err, check.IsNil)
		return nil
	})
	c.Assert(err, check.IsNil)

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	c.Assert(err, check.IsNil)
	err = netlink.LinkSetHardwareAddr(veth2, veth3HwAddr)
	c.Assert(err, check.IsNil)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1)
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)
refetch3:
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch3
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth0HwAddr.String())

refetch4:
	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			good, retry := neighStateOk(n)
			if good {
				found = true
				updatedHwAddrFromArpEntry = n.HardwareAddr
				break
			}
			if retry {
				goto refetch4
			}
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth2HwAddr.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)
	wait(nodev1.Identity(), "veth2", nil, true)

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v1IP1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	neighs, err = netlink.NeighList(veth2.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(v2IP1) {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeUpdate(c *check.C, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("6.6.6.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	ip6Alloc2 := cidr.MustParseCIDR("2001:bbbb::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv4().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv6().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	nodev2 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev2.IPAddresses = append(nodev2.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv4().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev2.IPv4AllocCIDR = ip4Alloc2
	}

	if s.enableIPv6 {
		nodev2.IPAddresses = append(nodev2.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv6().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev2.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	oldNode := nodev1
	newNode := nodev2

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		err = linuxNodeHandler.NodeUpdate(oldNode, newNode)
		c.Assert(err, check.IsNil)

		tmp := oldNode
		oldNode = newNode
		newNode = tmp
	}
	c.StopTimer()

	err = linuxNodeHandler.NodeDelete(oldNode)
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdate(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdateEncap(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdateEncapSingleClusterRoute(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:            s.enableIPv4,
		EnableIPv6:            s.enableIPv6,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdateDirectRoute(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeUpdateNOP(c *check.C, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv4().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv6().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		err = linuxNodeHandler.NodeUpdate(nodev1, nodev1)
		c.Assert(err, check.IsNil)
	}
	c.StopTimer()

	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdate(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdateEncapAll(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdateDirectRouteAll(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeValidateImplementation(c *check.C, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv4().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   s.nodeAddressing.IPv6().PrimaryExternal(),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		err = linuxNodeHandler.NodeValidateImplementation(nodev1)
		c.Assert(err, check.IsNil)
	}
	c.StopTimer()

	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementation(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementationEncap(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementationEncapSingleCluster(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:            s.enableIPv4,
		EnableIPv6:            s.enableIPv6,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementationDirectRoute(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	})
}
