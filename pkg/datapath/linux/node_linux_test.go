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
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"

	"github.com/vishvananda/netlink"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type linuxPrivilegedTestSuite struct {
	nodeAddressing datapath.NodeAddressing
	mtuConfig      mtu.Configuration
}

var _ = check.Suite(&linuxPrivilegedTestSuite{})

const (
	dummyHostDeviceName     = "dummy_host"
	dummyExternalDeviceName = "dummy_external"
)

func (s *linuxPrivilegedTestSuite) SetUpTest(c *check.C) {
	s.nodeAddressing = fake.NewNodeAddressing()
	s.mtuConfig = mtu.NewConfiguration(false, 1500)

	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)

	err := setupDummyDevice(dummyExternalDeviceName, s.nodeAddressing.IPv4().PrimaryExternal(), s.nodeAddressing.IPv6().PrimaryExternal())
	c.Assert(err, check.IsNil)

	err = setupDummyDevice(dummyHostDeviceName, s.nodeAddressing.IPv4().Router())
	c.Assert(err, check.IsNil)

}

func (s *linuxPrivilegedTestSuite) TearDownTest(c *check.C) {
	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)
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

func (s *linuxPrivilegedTestSuite) TestUpdateNodeRoute(c *check.C) {
	_, ip4Net, err := net.ParseCIDR("254.254.254.0/24")
	c.Assert(ip4Net, check.Not(check.IsNil))
	c.Assert(err, check.IsNil)

	_, ip6Net, err := net.ParseCIDR("cafe:cafe:cafe:cafe::/96")
	c.Assert(ip4Net, check.Not(check.IsNil))
	c.Assert(err, check.IsNil)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4: true,
		EnableIPv6: true,
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	// add & remove IPv4 node route
	err = linuxNodeHandler.updateNodeRoute(ip4Net, true)
	c.Assert(err, check.IsNil)

	foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Net)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	err = linuxNodeHandler.deleteNodeRoute(ip4Net)
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Net)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	// add & remove IPv6 node route
	err = linuxNodeHandler.updateNodeRoute(ip6Net, true)
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Net)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	err = linuxNodeHandler.deleteNodeRoute(ip6Net)
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Net)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)
}

func (s *linuxPrivilegedTestSuite) TestSingleClusterPrefixIPv4(c *check.C) {
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}

	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	// enable ipv4
	err := linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv4:            true,
	})
	c.Assert(err, check.IsNil)

	foundRoute, err := linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	// disable ipv4, enable ipv6
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv6:            true,
	})
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	// enable ipv4, enable ipv6
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		UseSingleClusterRoute: true,
		EnableIPv6:            true,
		EnableIPv4:            true,
	})
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv4().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(s.nodeAddressing.IPv6().AllocationCIDR())
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))
}

func (s *linuxPrivilegedTestSuite) TestAuxiliaryPrefixes(c *check.C) {
	_, net1, err := net.ParseCIDR("30.30.0.0/24")
	c.Assert(err, check.IsNil)
	_, net2, err := net.ParseCIDR("cafe:f00d::/112")
	c.Assert(err, check.IsNil)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv6:        true,
		EnableIPv4:        true,
		AuxiliaryPrefixes: []*net.IPNet{net1, net2},
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(net2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	// remove aux prefix net2
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv6:        true,
		EnableIPv4:        true,
		AuxiliaryPrefixes: []*net.IPNet{net1},
	})
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(net1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(net2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	// remove aux prefix net1, re-add net2
	err = linuxNodeHandler.NodeConfigurationChanged(datapath.LocalNodeConfiguration{
		EnableIPv6:        true,
		EnableIPv4:        true,
		AuxiliaryPrefixes: []*net.IPNet{net2},
	})
	c.Assert(err, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(net1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(net2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))
}

func (s *linuxPrivilegedTestSuite) TestNodeUpdateEncapsulation(c *check.C) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip4Alloc2, err := net.ParseCIDR("6.6.6.0/24")
	c.Assert(err, check.IsNil)
	_, ip6Alloc1, err := net.ParseCIDR("2001:aaaa::/96")
	c.Assert(err, check.IsNil)
	_, ip6Alloc2, err := net.ParseCIDR("2001:bbbb::/96")
	c.Assert(err, check.IsNil)

	externalNodeIP1 := net.ParseIP("4.4.4.4")
	externalNodeIP2 := net.ParseIP("8.8.8.8")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	// nodev1: ip4Alloc1, ip6alloc1 => externalNodeIP1
	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
	}
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	underlayIP, err := tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	// nodev2: ip4Alloc1, ip6alloc1 => externalNodeIP2
	nodev2 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNodeIP2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
	}
	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	c.Assert(err, check.IsNil)

	// alloc range v1 should map to underlay2
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP2), check.Equals, true)

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP2), check.Equals, true)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	// nodev3: ip4Alloc2, ip6alloc2 => externalNodeIP1
	nodev3 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
		IPv6AllocCIDR: ip6Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	c.Assert(err, check.IsNil)

	// alloc range v1 should fail
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.Not(check.IsNil))

	// alloc range v2 should map to underlay1
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	// node routes for alloc1 ranges should be gone
	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc1)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	// node routes for alloc2 ranges should have been installed
	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	// nodev4: stop announcing CIDRs
	nodev4 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
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

	// node routes for alloc2 ranges should be gone
	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	// nodev5: re-announce CIDRs
	nodev5 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
		IPv6AllocCIDR: ip6Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev4, nodev5)
	c.Assert(err, check.IsNil)

	// alloc range v2 should map to underlay1
	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc2.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	underlayIP, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc2.IP)
	c.Assert(err, check.IsNil)
	c.Assert(underlayIP.Equal(externalNodeIP1), check.Equals, true)

	// node routes for alloc2 ranges should have been installed
	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.Not(check.IsNil))

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

	// node routes for alloc2 ranges should be gone
	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)

	foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2)
	c.Assert(err, check.IsNil)
	c.Assert(foundRoute, check.IsNil)
}

func (s *linuxPrivilegedTestSuite) TestNodeUpdateDirectRouting(c *check.C) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip4Alloc2, err := net.ParseCIDR("6.6.6.0/24")
	c.Assert(err, check.IsNil)

	externalNode1IP4v1 := net.ParseIP("4.4.4.4")
	externalNode1IP4v2 := net.ParseIP("4.4.4.5")

	externalNode1Device := "dummy_node1"
	removeDevice(externalNode1Device)
	err = setupDummyDevice(externalNode1Device, externalNode1IP4v1, net.ParseIP("face::1"))
	c.Assert(err, check.IsNil)
	defer removeDevice(externalNode1Device)

	externalNode2Device := "dummy_node2"
	removeDevice(externalNode2Device)
	err = setupDummyDevice(externalNode2Device, externalNode1IP4v2, net.ParseIP("face::2"))
	c.Assert(err, check.IsNil)
	defer removeDevice(externalNode2Device)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	// nodev1: ip4Alloc1 => externalNodeIP1
	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	foundRoutes, err := linuxNodeHandler.lookupDirectRoute(ip4Alloc1, externalNode1IP4v1)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 1)

	// nodev2: ip4Alloc1 => externalNodeIP2
	nodev2 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}
	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	c.Assert(err, check.IsNil)

	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc1, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 1)

	// nodev3: ip4Alloc2 => externalNodeIP2
	nodev3 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	c.Assert(err, check.IsNil)

	// node routes for alloc1 ranges should be gone
	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc1, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)

	// node routes for alloc2 ranges should have been installed
	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 1)

	// nodev4: no longer announce CIDR
	nodev4 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)

	// nodev5: Re-announce CIDR
	nodev5 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev4, nodev5)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 1)

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	c.Assert(err, check.IsNil)

	// node routes for alloc2 ranges should be gone
	foundRoutes, err = linuxNodeHandler.lookupDirectRoute(ip4Alloc2, externalNode1IP4v2)
	c.Assert(err, check.IsNil)
	c.Assert(len(foundRoutes), check.Equals, 0)
}

func (s *linuxPrivilegedTestSuite) TestAgentRestartOptionChanges(c *check.C) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip6Alloc1, err := net.ParseCIDR("2001:aaaa::/96")
	c.Assert(err, check.IsNil)
	underlayIP := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))
	nodeConfig := datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	c.Assert(err, check.IsNil)

	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: underlayIP, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
	}
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	// tunnel map entries must exist
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.IsNil)
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.IsNil)

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
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
	c.Assert(err, check.IsNil)

	// Simulate initial node addition
	err = linuxNodeHandler.NodeAdd(nodev1)
	c.Assert(err, check.IsNil)

	// tunnel map entries must exist
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip4Alloc1.IP)
	c.Assert(err, check.IsNil)
	_, err = tunnel.TunnelMap.GetTunnelEndpoint(ip6Alloc1.IP)
	c.Assert(err, check.IsNil)

	err = linuxNodeHandler.NodeDelete(nodev1)
	c.Assert(err, check.IsNil)
}

func (s *linuxPrivilegedTestSuite) benchmarkNodeUpdate(c *check.C, config datapath.LocalNodeConfiguration) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip4Alloc2, err := net.ParseCIDR("6.6.6.0/24")
	c.Assert(err, check.IsNil)
	_, ip6Alloc1, err := net.ParseCIDR("2001:aaaa::/96")
	c.Assert(err, check.IsNil)
	_, ip6Alloc2, err := net.ParseCIDR("2001:bbbb::/96")
	c.Assert(err, check.IsNil)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: s.nodeAddressing.IPv4().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
			{IP: s.nodeAddressing.IPv6().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
	}
	nodev2 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: s.nodeAddressing.IPv4().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
			{IP: s.nodeAddressing.IPv6().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
		IPv6AllocCIDR: ip6Alloc2,
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

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateAll(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateIPv4(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateIPv6(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapAll(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapIPv4(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapIPv6(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapSingleClusterRouteAll(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:            true,
		EnableIPv4:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapSingleClusterRouteIPv4(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateEncapSingleClusterRouteIPv6(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateDirectRouteAll(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:              true,
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateDirectRouteIPv4(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeUpdateDirectRouteIPv6(c *check.C) {
	s.benchmarkNodeUpdate(c, datapath.LocalNodeConfiguration{
		EnableIPv6:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) benchmarkNodeUpdateNOP(c *check.C, config datapath.LocalNodeConfiguration) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip6Alloc1, err := net.ParseCIDR("2001:aaaa::/96")
	c.Assert(err, check.IsNil)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: s.nodeAddressing.IPv4().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
			{IP: s.nodeAddressing.IPv6().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
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

func (s *linuxPrivilegedTestSuite) BenchmarkNoChangeNodeUpdate(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNoChangeNodeUpdateEncapAll(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNoChangeNodeUpdateDirectRouteAll(c *check.C) {
	s.benchmarkNodeUpdateNOP(c, datapath.LocalNodeConfiguration{
		EnableIPv6:              true,
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) benchmarkNodeValidateImplementation(c *check.C, config datapath.LocalNodeConfiguration) {
	_, ip4Alloc1, err := net.ParseCIDR("5.5.5.0/24")
	c.Assert(err, check.IsNil)
	_, ip6Alloc1, err := net.ParseCIDR("2001:aaaa::/96")
	c.Assert(err, check.IsNil)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := NewNodeHandler(dpConfig, s.nodeAddressing).(*linuxNodeHandler)
	c.Assert(linuxNodeHandler, check.Not(check.IsNil))

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	c.Assert(err, check.IsNil)

	nodev1 := node.Node{
		Name: "node1",
		IPAddresses: []node.Address{
			{IP: s.nodeAddressing.IPv4().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
			{IP: s.nodeAddressing.IPv6().PrimaryExternal(), Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
		IPv6AllocCIDR: ip6Alloc1,
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

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationAll(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationIPv4(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationIPv6(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6: true,
		EnableIPv4: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapAll(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapIPv4(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapIPv6(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:          true,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapSingleClusterxAll(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:            true,
		EnableIPv4:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapSingleClusterxIPv4(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationEncapSingleClusterxIPv6(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:            true,
		EnableEncapsulation:   true,
		UseSingleClusterRoute: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationDirectRouteAll(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:              true,
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationDirectRouteIPv4(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv4:              true,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedTestSuite) BenchmarkNodeValidateImplementationDirectRouteIPv6(c *check.C) {
	s.benchmarkNodeValidateImplementation(c, datapath.LocalNodeConfiguration{
		EnableIPv6:              true,
		EnableAutoDirectRouting: true,
	})
}
