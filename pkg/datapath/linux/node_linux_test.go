// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build privileged_tests

package linux

import (
	"context"
	"crypto/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

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

type linuxPrivilegedIPv4OnlyTestSuite struct {
	linuxPrivilegedBaseTestSuite
}

var _ = check.Suite(&linuxPrivilegedIPv4OnlyTestSuite{})

type linuxPrivilegedIPv4AndIPv6TestSuite struct {
	linuxPrivilegedBaseTestSuite
}

var _ = check.Suite(&linuxPrivilegedIPv4AndIPv6TestSuite{})

const (
	dummyHostDeviceName     = "dummy_host"
	dummyExternalDeviceName = "dummy_external"
)

func (s *linuxPrivilegedBaseTestSuite) SetUpTest(c *check.C, addressing datapath.NodeAddressing, enableIPv6, enableIPv4 bool) {
	bpf.ConfigureResourceLimits()
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

	if enableIPv4 {
		err = setupDummyDevice(dummyHostDeviceName, s.nodeAddressing.IPv4().Router())
	} else {
		err = setupDummyDevice(dummyHostDeviceName)
	}
	c.Assert(err, check.IsNil)

	tunnel.TunnelMap = tunnel.NewTunnelMap("test_cilium_tunnel_map")
	_, err = tunnel.TunnelMap.OpenOrCreate()
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
	err := tunnel.TunnelMap.Unpin()
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

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
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
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP2), check.Equals, true)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
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
	underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	if s.enableIPv4 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
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
		underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
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
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
	c.Assert(err, check.Not(check.IsNil))

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
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
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
		c.Assert(err, check.IsNil)
		c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		c.Assert(err, check.IsNil)
		c.Assert(foundRoute, check.Not(check.IsNil))
	}

	if s.enableIPv6 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
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
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	// alloc range v2 should fail
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
	c.Assert(err, check.Not(check.IsNil))

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
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
	if s.enableIPv4 {
		c.Assert(len(foundRoutes), check.Equals, 1)
	} else {
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

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
	if s.enableIPv4 {
		c.Assert(len(foundRoutes), check.Equals, 1)
	} else {
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

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
	if s.enableIPv4 {
		c.Assert(len(foundRoutes), check.Equals, 1)
	} else {
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

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
	if s.enableIPv4 {
		c.Assert(len(foundRoutes), check.Equals, 1)
	} else {
		c.Assert(len(foundRoutes), check.Equals, 0)
	}

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should be gone
	foundRoutes, err = lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0) // route should not exist regardless whether ipv4 is enabled or not
}

func (s *linuxPrivilegedBaseTestSuite) TestAgentRestartOptionChanges(c *check.C) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	underlayIP := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
		_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
		c.Assert(err, check.IsNil)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
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
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
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
		_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
		c.Assert(err, check.IsNil)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
		c.Assert(err, check.IsNil)
	}

	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
}

func insertFakeRoute(c *check.C, n *linuxNodeHandler, prefix *cidr.CIDR) {
	nodeRoute, err := n.createNodeRouteSpec(prefix, false)
	c.Assert(err, check.IsNil)

	nodeRoute.Device = dummyExternalDeviceName

	_, err = route.Upsert(nodeRoute)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
	err := netlink.LinkAdd(veth)
	c.Assert(err, check.IsNil)
	defer netlink.LinkDel(veth)
	veth0, err := netlink.LinkByName("veth0")
	c.Assert(err, check.IsNil)
	veth1, err := netlink.LinkByName("veth1")
	c.Assert(err, check.IsNil)
	_, ipnet, err := net.ParseCIDR("9.9.9.252/29")
	ip0 := net.ParseIP("9.9.9.249")
	ip1 := net.ParseIP("9.9.9.250")
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
		err = netlink.LinkSetUp(veth1)
		c.Assert(err, check.IsNil)
		return nil
	})

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

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableEncapsulation: false,
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
	})
	c.Assert(err, check.IsNil)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, before *time.Time, waitForDelete bool) {
		err := testutils.WaitUntil(func() bool {
			linuxNodeHandler.neighLock.Lock()
			defer linuxNodeHandler.neighLock.Unlock()
			nextHop, found := linuxNodeHandler.neighNextHopByNode[nodeID]
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
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{{nodeaddressing.NodeInternalIP, ip1}},
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
	wait(nodev1.Identity(), &now, false)

	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found := false
	for _, n := range neighs {
		if n.IP.Equal(ip1) && n.State == netlink.NUD_PERMANENT {
			found = true
			break
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
	wait(nodev1.Identity(), &now, false)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) && n.State == netlink.NUD_PERMANENT {
			found = true
			updatedHwAddrFromArpEntry = n.HardwareAddr
			break
		}
	}
	c.Assert(found, check.Equals, true)
	c.Assert(updatedHwAddrFromArpEntry.String(), check.Equals, veth0HwAddr.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), nil, true)

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(ip1) && n.State == netlink.NUD_PERMANENT {
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
	wait(nodev1.Identity(), &now, false)

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
	neighHwAddr := func(nextHopStr string) string {
		linuxNodeHandler.neighLock.Lock()
		defer linuxNodeHandler.neighLock.Unlock()
		if neigh, found := linuxNodeHandler.neighByNextHop[nextHopStr]; found {
			return neigh.HardwareAddr.String()
		}
		return ""
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
				if n.IP.Equal(ip1) && n.State == netlink.NUD_PERMANENT &&
					n.HardwareAddr.String() == mac.String() &&
					neighHwAddr(ip1.String()) == mac.String() &&
					neighRefCount(ip1.String()) == 1 {
					found = true
					return true
				}
			}
			return false
		}, 5*time.Second, 200*time.Millisecond)
		c.Assert(err, check.IsNil)
		c.Assert(found, check.Equals, true)
	}

	// Cleanup
	close(done)
	wg.Wait()
	now = time.Now()
	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
	wait(nodev1.Identity(), nil, true)

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
		Name:        "node2",
		IPAddresses: []nodeTypes.Address{{nodeaddressing.NodeInternalIP, node2IP}},
	}
	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev2), check.IsNil)
	wait(nodev2.Identity(), &now, false)

	node3IP := net.ParseIP("7.7.7.250")
	nodev3 := nodeTypes.Node{
		Name:        "node3",
		IPAddresses: []nodeTypes.Address{{nodeaddressing.NodeInternalIP, node3IP}},
	}
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), &now, false)

	nextHop := net.ParseIP("9.9.9.250")
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && n.State == netlink.NUD_PERMANENT {
			found = true
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// Check that removing node2 will not remove nextHop, as it is still used by node3
	c.Assert(linuxNodeHandler.NodeDelete(nodev2), check.IsNil)
	wait(nodev2.Identity(), nil, true)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && n.State == netlink.NUD_PERMANENT {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	// However, removing node3 should remove the neigh entry for nextHop
	c.Assert(linuxNodeHandler.NodeDelete(nodev3), check.IsNil)
	wait(nodev3.Identity(), nil, true)

	found = false
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && n.State == netlink.NUD_PERMANENT {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, false)

	now = time.Now()
	c.Assert(linuxNodeHandler.NodeAdd(nodev3), check.IsNil)
	wait(nodev3.Identity(), &now, false)

	nextHop = net.ParseIP("9.9.9.250")
	// Check that both node{2,3} are via nextHop (gw)
	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && n.State == netlink.NUD_PERMANENT {
			found = true
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
		}
	}
	c.Assert(found, check.Equals, true)

	// We have stored the devices in NodeConfigurationChanged
	linuxNodeHandler.NodeCleanNeighbors()

	neighs, err = netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
	c.Assert(err, check.IsNil)
	found = false
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && n.State == netlink.NUD_PERMANENT {
			found = true
		} else if n.IP.Equal(node2IP) || n.IP.Equal(node3IP) {
			c.ExpectFailure("node{2,3} should not be in the same L2")
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing, nil).(*linuxNodeHandler)
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
