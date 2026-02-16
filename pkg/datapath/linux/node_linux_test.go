//go:build unparallel

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/kpr"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type linuxPrivilegedBaseTestSuite struct {
	sysctl     sysctl.Sysctl
	mtuCalc    mtu.RouteMTU
	enableIPv4 bool
	enableIPv6 bool

	// nodeConfigTemplate is the partially filled template for local node configuration.
	// copy it, don't mutate it.
	nodeConfigTemplate datapath.LocalNodeConfiguration
}

type linuxPrivilegedIPv6OnlyTestSuite struct {
	linuxPrivilegedBaseTestSuite
}

type linuxPrivilegedIPv4OnlyTestSuite struct {
	linuxPrivilegedBaseTestSuite
}

type linuxPrivilegedIPv4AndIPv6TestSuite struct {
	linuxPrivilegedBaseTestSuite
}

func setup(tb testing.TB, family string) *linuxPrivilegedBaseTestSuite {
	switch family {
	case "IPv4":
		return &setupLinuxPrivilegedIPv4OnlyTestSuite(tb).linuxPrivilegedBaseTestSuite
	case "IPv6":
		return &setupLinuxPrivilegedIPv6OnlyTestSuite(tb).linuxPrivilegedBaseTestSuite
	case "dual":
		return &setupLinuxPrivilegedIPv4AndIPv6TestSuite(tb).linuxPrivilegedBaseTestSuite
	default:
		return nil
	}
}

const (
	dummyHostDeviceName     = "dummy_host"
	dummyExternalDeviceName = "dummy_external"
)

func setupLinuxPrivilegedBaseTestSuite(tb testing.TB, addressing datapath.NodeAddressing, enableIPv6, enableIPv4 bool) *linuxPrivilegedBaseTestSuite {
	testutils.PrivilegedTest(tb)
	s := &linuxPrivilegedBaseTestSuite{}

	s.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	rlimit.RemoveMemlock()
	mtuConfig := mtu.NewConfiguration(0, false, false, false, false)
	s.mtuCalc = mtuConfig.Calculate(1500)
	s.enableIPv6 = enableIPv6
	s.enableIPv4 = enableIPv4

	node.SetTestLocalNodeStore()

	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)

	ips := make([]net.IP, 0)
	if enableIPv6 {
		ips = append(ips, addressing.IPv6().PrimaryExternal())
	}
	if enableIPv4 {
		ips = append(ips, addressing.IPv4().PrimaryExternal())
	}
	devExt, err := setupDummyDevice(dummyExternalDeviceName, ips...)
	require.NoError(tb, err)

	ips = []net.IP{}
	if enableIPv4 {
		ips = append(ips, addressing.IPv4().Router())
	}
	if enableIPv6 {
		ips = append(ips, addressing.IPv6().Router())
	}
	devHost, err := setupDummyDevice(dummyHostDeviceName, ips...)
	require.NoError(tb, err)

	s.nodeConfigTemplate = datapath.LocalNodeConfiguration{
		Devices:             []*tables.Device{devExt, devHost},
		DirectRoutingDevice: devHost,
		NodeIPv4:            addressing.IPv4().PrimaryExternal(),
		NodeIPv6:            addressing.IPv6().PrimaryExternal(),
		CiliumInternalIPv4:  netip.MustParseAddr(addressing.IPv4().Router().String()),
		CiliumInternalIPv6:  netip.MustParseAddr(addressing.IPv6().Router().String()),
		AllocCIDRIPv4:       addressing.IPv4().AllocationCIDR(),
		AllocCIDRIPv6:       addressing.IPv6().AllocationCIDR(),
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		DeviceMTU:           s.mtuCalc.DeviceMTU,
		RouteMTU:            s.mtuCalc.RouteMTU,
		RoutePostEncryptMTU: s.mtuCalc.RoutePostEncryptMTU,
	}

	return s
}

func setupLinuxPrivilegedIPv6OnlyTestSuite(tb testing.TB) *linuxPrivilegedIPv6OnlyTestSuite {
	testutils.PrivilegedTest(tb)

	addressing := fakeTypes.NewIPv6OnlyNodeAddressing()
	s := &linuxPrivilegedIPv6OnlyTestSuite{
		linuxPrivilegedBaseTestSuite: *setupLinuxPrivilegedBaseTestSuite(tb, addressing, true, false),
	}

	tb.Cleanup(func() {
		tearDownTest(tb)
	})

	return s
}

func setupLinuxPrivilegedIPv4OnlyTestSuite(tb testing.TB) *linuxPrivilegedIPv4OnlyTestSuite {
	testutils.PrivilegedTest(tb)

	addressing := fakeTypes.NewIPv4OnlyNodeAddressing()
	s := &linuxPrivilegedIPv4OnlyTestSuite{
		linuxPrivilegedBaseTestSuite: *setupLinuxPrivilegedBaseTestSuite(tb, addressing, false, true),
	}

	tb.Cleanup(func() {
		tearDownTest(tb)
	})

	return s
}

func setupLinuxPrivilegedIPv4AndIPv6TestSuite(tb testing.TB) *linuxPrivilegedIPv4AndIPv6TestSuite {
	testutils.PrivilegedTest(tb)

	addressing := fakeTypes.NewNodeAddressing()
	s := &linuxPrivilegedIPv4AndIPv6TestSuite{
		linuxPrivilegedBaseTestSuite: *setupLinuxPrivilegedBaseTestSuite(tb, addressing, true, true),
	}

	tb.Cleanup(func() {
		tearDownTest(tb)
	})
	return s
}

func tearDownTest(_ testing.TB) {
	node.UnsetTestLocalNodeStore()
	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)
}

func setupDummyDevice(name string, ips ...net.IP) (*tables.Device, error) {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(dummy); err != nil {
		removeDevice(name)
		return nil, err
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
			return nil, err
		}
	}

	link, err := safenetlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return &tables.Device{
		Index:        link.Attrs().Index,
		MTU:          link.Attrs().MTU,
		Name:         name,
		HardwareAddr: tables.HardwareAddr(link.Attrs().HardwareAddr),
		Type:         "dummy",
		Selected:     true,
	}, nil
}

func removeDevice(name string) {
	l, err := safenetlink.LinkByName(name)
	if err == nil {
		netlink.LinkDel(l)
	}
}

func TestPrivilegedAll(t *testing.T) {
	for _, tt := range []string{"IPv4", "IPv6", "dual"} {
		t.Run(tt, func(t *testing.T) {
			t.Run("TestUpdateNodeRoute", func(t *testing.T) {
				s := setup(t, tt)
				s.TestUpdateNodeRoute(t)
			})
			t.Run("TestAuxiliaryPrefixes", func(t *testing.T) {
				s := setup(t, tt)
				s.TestAuxiliaryPrefixes(t)
			})
			t.Run("TestNodeUpdateEncapsulation", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeUpdateEncapsulation(t)
			})
			t.Run("TestNodeUpdateEncapsulationWithOverride", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeUpdateEncapsulationWithOverride(t)
			})
			t.Run("TestNodeUpdateIDs", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeUpdateIDs(t)
			})
			t.Run("TestNodeChurnXFRMLeaks", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeChurnXFRMLeaks(t)
			})
			t.Run("TestNodeChurnXFRMLeaksEncryptedOverlay", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeChurnXFRMLeaksEncryptedOverlay(t)
			})
			t.Run("TestNodeChurnXFRMLeaksSubnetMode", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeChurnXFRMLeaksSubnetMode(t)
			})
			t.Run("TestNodeUpdateDirectRouting", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeUpdateDirectRouting(t)
			})
			t.Run("TestNodeValidationDirectRouting", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeValidationDirectRouting(t)
			})
			t.Run("TestNodePodCIDRsChurnIPSec", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodePodCIDRsChurnIPSec(t)
			})
		})
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestUpdateNodeRoute(t *testing.T) {
	ip4CIDR := cidr.MustParseCIDR("254.254.254.0/24")
	require.NotNil(t, ip4CIDR)

	ip6CIDR := cidr.MustParseCIDR("cafe:cafe:cafe:cafe::/96")
	require.NotNil(t, ip6CIDR)

	var linuxNodeHandler *linuxNodeHandler
	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler = newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)

	require.NotNil(t, linuxNodeHandler)
	nodeConfig := s.nodeConfigTemplate

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	if s.enableIPv4 {
		// add & remove IPv4 node route
		err = linuxNodeHandler.updateNodeRoute(ip4CIDR, true, false)
		require.NoError(t, err)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4CIDR, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)

		err = linuxNodeHandler.deleteNodeRoute(ip4CIDR, false)
		require.NoError(t, err)

		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4CIDR, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// add & remove IPv6 node route
		err = linuxNodeHandler.updateNodeRoute(ip6CIDR, true, false)
		require.NoError(t, err)

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6CIDR, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)

		err = linuxNodeHandler.deleteNodeRoute(ip6CIDR, false)
		require.NoError(t, err)

		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6CIDR, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestAuxiliaryPrefixes(t *testing.T) {
	net1 := cidr.MustParseCIDR("30.30.0.0/24")
	net2 := cidr.MustParseCIDR("cafe:f00d::/112")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)

	require.NotNil(t, linuxNodeHandler)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net1, net2}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// remove aux prefix net2
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net1}
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	// remove aux prefix net1, re-add net2
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net2}
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net1, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(net2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateEncapsulation(t *testing.T) {
	s.commonNodeUpdateEncapsulation(t, true, nil)
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateEncapsulationWithOverride(t *testing.T) {
	s.commonNodeUpdateEncapsulation(t, false, func(*nodeTypes.Node) bool { return true })
}

func (s *linuxPrivilegedBaseTestSuite) commonNodeUpdateEncapsulation(t *testing.T, encap bool, override func(*nodeTypes.Node) bool) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("6.6.6.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	ip6Alloc2 := cidr.MustParseCIDR("2001:bbbb::/96")

	externalNodeIP1 := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)

	require.NotNil(t, linuxNodeHandler)
	linuxNodeHandler.OverrideEnableEncapsulation(override)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = encap
	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// nodev1: ip4Alloc1, ip6alloc1 => externalNodeIP1
	nodev1 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
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
	require.NoError(t, err)

	if s.enableIPv4 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// nodev2: ip4Alloc2, ip6alloc2 => externalNodeIP1
	nodev2 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev2.IPv4AllocCIDR = ip4Alloc2
	}
	if s.enableIPv6 {
		nodev2.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	require.NoError(t, err)

	if s.enableIPv4 {
		// node routes for alloc1 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc1 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// nodev3: stop announcing CIDRs
	nodev3 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	require.NoError(t, err)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	// nodev4: re-announce CIDRs
	nodev4 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}

	if s.enableIPv4 {
		nodev4.IPv4AllocCIDR = ip4Alloc2
	}
	if s.enableIPv6 {
		nodev4.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	require.NoError(t, err)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev4)
	require.NoError(t, err)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)
	}
}

// Tests that the node ID BPF map is correctly updated during the lifecycle of
// nodes and that the mapping nodeID:node remains 1:1.
func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateIDs(t *testing.T) {
	nodeIP1 := netip.MustParseAddr("4.4.4.4")
	nodeIP2 := netip.MustParseAddr("8.8.8.8")
	nodeIP3 := netip.MustParseAddr("1.1.1.1")

	nodeMap := nodemapfake.NewFakeNodeMapV2()

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodeMap, kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)

	nodeConfig := s.nodeConfigTemplate
	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// New node receives a node ID.
	node1v1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1.AsSlice(), Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node1v1)
	require.NoError(t, err)

	nodeValue1, err := nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	require.NotEqual(t, 0, nodeValue1.NodeID)

	// When the node is updated, the new IPs are mapped to the existing node ID.
	node1v2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1.AsSlice(), Type: nodeaddressing.NodeInternalIP},
			{IP: nodeIP2.AsSlice(), Type: nodeaddressing.NodeExternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(node1v1, node1v2)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	nodeValue2, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	require.Equal(t, nodeValue1.NodeID, nodeValue2.NodeID)

	// When the node is updated, the old IPs are unmapped from the node ID.
	node1v3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP2.AsSlice(), Type: nodeaddressing.NodeExternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(node1v2, node1v3)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP1)
	require.ErrorContains(t, err, "IP not found in node ID map")
	nodeValue3, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	require.Equal(t, nodeValue2.NodeID, nodeValue3.NodeID)

	// If a second node is created, it receives a different node ID.
	node2 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1.AsSlice(), Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node2)
	require.NoError(t, err)

	nodeValue4, err := nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	require.NotEqual(t, nodeValue3.NodeID, nodeValue4.NodeID)

	// When the node is deleted, all references to its ID are also removed.
	err = linuxNodeHandler.NodeDelete(node1v3)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP2)
	require.ErrorContains(t, err, "IP not found in node ID map")

	// When a node is created with multiple IP addresses, they all have the same ID.
	node3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP2.AsSlice(), Type: nodeaddressing.NodeInternalIP},
			{IP: nodeIP3.AsSlice(), Type: nodeaddressing.NodeCiliumInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node3)
	require.NoError(t, err)

	nodeValue5, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	nodeValue6, err := nodeMap.Lookup(nodeIP3)
	require.NoError(t, err)
	require.Equal(t, nodeValue6.NodeID, nodeValue5.NodeID)
}

// Tests that we don't leak XFRM policies and states as nodes come and go.
func (s *linuxPrivilegedBaseTestSuite) TestNodeChurnXFRMLeaks(t *testing.T) {
	// Cover the XFRM configuration for IPAM modes cluster-pool, kubernetes, etc.
	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"
	s.testNodeChurnXFRMLeaksWithConfig(t, config)
}

// Tests the same as TestNodeChurnXFRMLeaks, but in tunneling mode. As a
// consequence, encrypted overlay will kick in.
func (s *linuxPrivilegedBaseTestSuite) TestNodeChurnXFRMLeaksEncryptedOverlay(t *testing.T) {
	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	config.EnableEncapsulation = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"
	s.testNodeChurnXFRMLeaksWithConfig(t, config)
}

// Tests the same as linuxPrivilegedBaseTestSuite.TestNodeChurnXFRMLeaks just
// for the subnet encryption.
func (s *linuxPrivilegedBaseTestSuite) TestNodeChurnXFRMLeaksSubnetMode(t *testing.T) {
	externalNodeDevice := "ipsec_interface"
	config := s.nodeConfigTemplate
	config.EnableIPSec = true

	// In the case of subnet encryption, the IPsec logic retrieves the IP
	// address of the encryption interface directly so we need a dummy
	// interface.
	removeDevice(externalNodeDevice)
	_, err := setupDummyDevice(externalNodeDevice, net.ParseIP("1.1.1.1"), net.ParseIP("face::1"))
	require.NoError(t, err)
	defer removeDevice(externalNodeDevice)
	option.Config.UnsafeDaemonConfigOption.EncryptInterface = []string{externalNodeDevice}
	option.Config.RoutingMode = option.RoutingModeNative

	// Cover the XFRM configuration for subnet encryption: IPAM modes AKS and EKS.
	ipv4PodSubnets, err := cidr.ParseCIDR("4.4.0.0/16")
	require.NoError(t, err)
	require.NotNil(t, ipv4PodSubnets)
	config.IPv4PodSubnets = []*cidr.CIDR{ipv4PodSubnets}
	ipv6PodSubnets, err := cidr.ParseCIDR("2001:aaaa::/64")
	require.NoError(t, err)
	require.NotNil(t, ipv6PodSubnets)
	config.IPv6PodSubnets = []*cidr.CIDR{ipv6PodSubnets}
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"
	s.testNodeChurnXFRMLeaksWithConfig(t, config)
}

func (s *linuxPrivilegedBaseTestSuite) testNodeChurnXFRMLeaksWithConfig(t *testing.T, config datapath.LocalNodeConfiguration) {
	log := hivetest.Logger(t)
	keys := bytes.NewReader([]byte("6+ rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"))

	a := ipsec.NewTestIPsecAgent(t)
	_, _, err := a.LoadIPSecKeys(keys)
	require.NoError(t, err)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, a, fakeTypes.IPsecConfig{}, lns)

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(t, err)

	// Adding a node adds some XFRM states and policies.
	node := nodeTypes.Node{
		Name: "node",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("4.4.4.4"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: net.ParseIP("3.3.3.3"), Type: nodeaddressing.NodeInternalIP},
			{IP: net.ParseIP("2001:aaaa::1"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: net.ParseIP("2001:bbbb::1"), Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: cidr.MustParseCIDR("4.4.4.0/24"),
		IPv6AllocCIDR: cidr.MustParseCIDR("2001:aaaa::/96"),
		BootID:        "b892866c-26cb-4018-8a55-c0330551a2be",
	}
	err = linuxNodeHandler.NodeAdd(node)
	require.NoError(t, err)

	states, err := safenetlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.NotEmpty(t, states)
	policies, err := safenetlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.NotEqual(t, 0, countXFRMPolicies(policies))

	// Removing the node removes those XFRM states and policies.
	err = linuxNodeHandler.NodeDelete(node)
	require.NoError(t, err)

	states, err = safenetlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Empty(t, states)
	policies, err = safenetlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 0, countXFRMPolicies(policies))
}

// Counts the number of XFRM OUT policies excluding the catch-all default-drop
// one. The default-drop is always installed and shouldn't be removed. The IN
// and FWD policies are installed once and for all in reaction to new nodes;
// contrary to XFRM IN states, they don't need to be unique per remote node.
func countXFRMPolicies(policies []netlink.XfrmPolicy) int {
	nbPolicies := 0
	for _, policy := range policies {
		if policy.Action != netlink.XFRM_POLICY_BLOCK &&
			policy.Dir == netlink.XFRM_DIR_OUT {
			nbPolicies++
		}
	}
	return nbPolicies
}

func lookupDirectRoute(log *slog.Logger, CIDR *cidr.CIDR, nodeIP net.IP) ([]netlink.Route, error) {
	routeSpec, _, err := createDirectRouteSpec(log, CIDR, nodeIP, false)
	if err != nil {
		return nil, err
	}

	family := netlink.FAMILY_V4
	if nodeIP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	return safenetlink.RouteListFiltered(family, routeSpec, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF)
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeUpdateDirectRouting(t *testing.T) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("5.5.5.0/26")

	ipv4SecondaryAlloc1 := cidr.MustParseCIDR("5.5.6.0/24")
	ipv4SecondaryAlloc2 := cidr.MustParseCIDR("5.5.7.0/24")
	ipv4SecondaryAlloc3 := cidr.MustParseCIDR("5.5.8.0/24")

	externalNode1IP4v1 := net.ParseIP("4.4.4.4")
	externalNode1IP4v2 := net.ParseIP("4.4.4.5")

	externalNode1Device := "dummy_node1"
	removeDevice(externalNode1Device)
	dev1, err := setupDummyDevice(externalNode1Device, externalNode1IP4v1, net.ParseIP("face::1"))
	require.NoError(t, err)
	defer removeDevice(externalNode1Device)

	externalNode2Device := "dummy_node2"
	removeDevice(externalNode2Device)
	dev2, err := setupDummyDevice(externalNode2Device, externalNode1IP4v2, net.ParseIP("face::2"))
	require.NoError(t, err)
	defer removeDevice(externalNode2Device)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)

	require.NotNil(t, linuxNodeHandler)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices), dev1, dev2)
	nodeConfig.EnableAutoDirectRouting = true

	expectedIPv4Routes := 0
	if s.enableIPv4 {
		expectedIPv4Routes = 1
	}

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// nodev1: ip4Alloc1 => externalNodeIP1
	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)

	foundRoutes, err := lookupDirectRoute(log, ip4Alloc1, externalNode1IP4v1)
	require.NoError(t, err)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// nodev2: ip4Alloc1 => externalNodeIP2
	nodev2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}

	err = linuxNodeHandler.NodeUpdate(nodev1, nodev2)
	require.NoError(t, err)

	foundRoutes, err = lookupDirectRoute(log, ip4Alloc1, externalNode1IP4v2)
	require.NoError(t, err)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// nodev3: ip4Alloc2 => externalNodeIP2
	nodev3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev2, nodev3)
	require.NoError(t, err)

	// node routes for alloc1 ranges should be gone
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc1, externalNode1IP4v2)
	require.NoError(t, err)
	require.Empty(t, foundRoutes) // route should not exist regardless whether ipv4 is enabled or not

	// node routes for alloc2 ranges should have been installed
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// nodev4: no longer announce CIDR
	nodev4 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	require.NoError(t, err)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Empty(t, foundRoutes)

	// nodev5: Re-announce CIDR
	nodev5 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	err = linuxNodeHandler.NodeUpdate(nodev4, nodev5)
	require.NoError(t, err)

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	require.NoError(t, err)

	// node routes for alloc2 ranges should be gone
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Empty(t, foundRoutes) // route should not exist regardless whether ipv4 is enabled or not

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
	require.NoError(t, err)

	// expecting both primary and secondary routes to exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Len(t, foundRoutes, expectedIPv4Routes)
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
	require.NoError(t, err)

	// Checks all three required routes exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Len(t, foundRoutes, expectedIPv4Routes)
	}
	// Checks route for removed CIDR has been deleted
	foundRoutes, err = lookupDirectRoute(log, ipv4SecondaryAlloc2, externalNode1IP4v1)
	require.NoError(t, err)
	require.Empty(t, foundRoutes)

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
	require.NoError(t, err)

	// Checks all routes with the new node IP exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v2)
		require.NoError(t, err)
		require.Len(t, foundRoutes, expectedIPv4Routes)
	}
	// Checks all routes with the old node IP have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Empty(t, foundRoutes)
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
	require.NoError(t, err)

	// Checks primary route has been created
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// Checks all old routes have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v2)
		require.NoError(t, err)
		require.Empty(t, foundRoutes)
	}

	// nodev10: Re-introduce node with secondary CIDRs
	nodev10 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc2},
	}
	err = linuxNodeHandler.NodeUpdate(nodev9, nodev10)
	require.NoError(t, err)

	// expecting both primary and secondary routes to exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Len(t, foundRoutes, expectedIPv4Routes)
	}

	// node routes for alloc2 ranges should have been removed
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Empty(t, foundRoutes)

	// delete nodev10
	err = linuxNodeHandler.NodeDelete(nodev10)
	require.NoError(t, err)

	// all node routes must have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Empty(t, foundRoutes)
	}
}

func insertFakeRoute(t *testing.T, n *linuxNodeHandler, prefix *cidr.CIDR) {
	nodeRoute, err := n.createNodeRouteSpec(prefix, false)
	require.NoError(t, err)

	nodeRoute.Device = dummyExternalDeviceName

	err = route.Upsert(hivetest.Logger(t), nodeRoute)
	require.NoError(t, err)
}

func lookupFakeRoute(t *testing.T, n *linuxNodeHandler, prefix *cidr.CIDR) bool {
	routeSpec, err := n.createNodeRouteSpec(prefix, false)
	require.NoError(t, err)

	routeSpec.Device = dummyExternalDeviceName
	rt, err := route.Lookup(routeSpec)
	require.NoError(t, err)
	return rt != nil
}

func (s *linuxPrivilegedBaseTestSuite) TestNodeValidationDirectRouting(t *testing.T) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(t), fakeTypes.IPsecConfig{}, lns)
	require.NotNil(t, linuxNodeHandler)

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
	linuxNodeHandler.nodeConfig = nodeConfig

	if s.enableIPv4 {
		insertFakeRoute(t, linuxNodeHandler, ip4Alloc1)
	}

	if s.enableIPv6 {
		insertFakeRoute(t, linuxNodeHandler, ip6Alloc1)
	}

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   nodeConfig.NodeIPv4,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   nodeConfig.NodeIPv6,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)

	err = linuxNodeHandler.NodeValidateImplementation(nodev1)
	require.NoError(t, err)

	if s.enableIPv4 {
		require.True(t, lookupFakeRoute(t, linuxNodeHandler, ip4Alloc1))
	}

	if s.enableIPv6 {
		require.True(t, lookupFakeRoute(t, linuxNodeHandler, ip6Alloc1))
	}
}

func lookupIPSecInRoutes(t *testing.T, family int, extDev string, prefixes []*cidr.CIDR) {
	link, err := safenetlink.LinkByName(extDev)
	require.NoError(t, err)

	routes, err := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return safenetlink.RouteListFiltered(
			family,
			&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Table:     linux_defaults.RouteTableIPSec,
				Protocol:  linux_defaults.RTProto,
				Type:      route.RTN_LOCAL,
			},
			netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TYPE,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, len(prefixes))
	dests := make([]*cidr.CIDR, 0, len(routes))
	for _, route := range routes {
		dests = append(dests, &cidr.CIDR{IPNet: route.Dst})
	}
	require.ElementsMatch(t, dests, prefixes)
}

func lookupIPSecXFRMPoliciesOut(t *testing.T, family int, prefixes []*cidr.CIDR) {
	policies, err := safenetlink.XfrmPolicyList(family)
	require.NoError(t, err)

	var zero *cidr.CIDR
	if family == netlink.FAMILY_V4 {
		zero = cidr.MustParseCIDR("0.0.0.0/0")
	} else {
		zero = cidr.MustParseCIDR("::/0")
	}

	dests := make([]*cidr.CIDR, 0, len(prefixes))
	for _, policy := range policies {
		var policyIP net.IP
		if family == netlink.FAMILY_V4 {
			policyIP = policy.Dst.IP.To4()
		} else {
			policyIP = policy.Dst.IP.To16()
		}
		dst := cidr.CIDR{IPNet: &net.IPNet{
			IP:   policyIP,
			Mask: policy.Dst.Mask,
		}}

		if dst.Equal(zero) {
			continue
		}

		dests = append(dests, &dst)
	}
	require.ElementsMatch(t, dests, prefixes)
}

func lookupIPSecOutRoutes(t *testing.T, family int, extDev string, prefixes []*cidr.CIDR) {
	link, err := safenetlink.LinkByName(extDev)
	require.NoError(t, err)

	routes, err := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return safenetlink.RouteListFiltered(
			family,
			&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Table:     linux_defaults.RouteTableIPSec,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})

	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, len(prefixes))
	dests := make([]*cidr.CIDR, 0, len(routes))
	for _, route := range routes {
		dests = append(dests, &cidr.CIDR{IPNet: route.Dst})
	}
	require.ElementsMatch(t, dests, prefixes)
}

func (s *linuxPrivilegedBaseTestSuite) TestNodePodCIDRsChurnIPSec(t *testing.T) {
	remoteNode1IPv4, remoteNode1IPv6 := net.ParseIP("4.4.4.4"), net.ParseIP("face::1")
	remoteNode1Device := "remote_node_1"
	removeDevice(remoteNode1Device)
	dev1, err := setupDummyDevice(remoteNode1Device, remoteNode1IPv4, remoteNode1IPv6)
	require.NoError(t, err)
	defer removeDevice(remoteNode1Device)

	remoteNode2IPv4, remoteNode2IPv6 := net.ParseIP("4.4.4.5"), net.ParseIP("face::2")
	remoteNode2Device := "remote_node_2"
	removeDevice(remoteNode2Device)
	dev2, err := setupDummyDevice(remoteNode2Device, remoteNode2IPv4, remoteNode2IPv6)
	require.NoError(t, err)
	defer removeDevice(remoteNode2Device)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	a := ipsec.NewTestIPsecAgent(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, a, fakeTypes.IPsecConfig{}, lns)

	require.NotNil(t, linuxNodeHandler)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices), dev1, dev2)

	option.Config.RoutingMode = option.RoutingModeNative
	nodeConfig.EnableIPSec = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"

	keys := bytes.NewReader([]byte("6+ rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"))
	_, _, err = a.LoadIPSecKeys(keys)
	require.NoError(t, err)

	// set "local_node" as the local node name
	nodeTypes.SetName("local_node")

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// Add local node with multiple pod CIDRs
	localIPv4AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("5.5.5.0/24"),
		cidr.MustParseCIDR("6.6.6.0/24"),
		cidr.MustParseCIDR("7.7.7.0/24"),
	}
	localIPv6AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("2001:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2002:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2003:aaaa:bbbb::/96"),
	}
	localNodeV1 := nodeTypes.Node{
		Name:                    "local_node",
		IPv4AllocCIDR:           localIPv4AllocCIDRsV1[0],
		IPv4SecondaryAllocCIDRs: localIPv4AllocCIDRsV1[1:],
		IPv6AllocCIDR:           localIPv6AllocCIDRsV1[0],
		IPv6SecondaryAllocCIDRs: localIPv6AllocCIDRsV1[1:],
	}
	err = linuxNodeHandler.NodeAdd(localNodeV1)
	require.NoError(t, err)
	if s.enableIPv4 {
		lookupIPSecInRoutes(t, netlink.FAMILY_V4, dummyExternalDeviceName, localIPv4AllocCIDRsV1)
	}
	if s.enableIPv6 {
		lookupIPSecInRoutes(t, netlink.FAMILY_V6, dummyExternalDeviceName, localIPv6AllocCIDRsV1)
	}

	// Update local node and change the podCIDRs
	localIPv4AllocCIDRsV2 := []*cidr.CIDR{
		cidr.MustParseCIDR("6.6.6.0/24"),
		cidr.MustParseCIDR("7.7.7.0/24"),
		cidr.MustParseCIDR("8.8.8.0/24"),
	}
	localIPv6AllocCIDRsV2 := []*cidr.CIDR{
		cidr.MustParseCIDR("2002:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2003:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2004:aaaa:bbbb::/96"),
	}
	localNodeV2 := localNodeV1
	localNodeV2.IPv4AllocCIDR = localIPv4AllocCIDRsV2[0]
	localNodeV2.IPv4SecondaryAllocCIDRs = localIPv4AllocCIDRsV2[1:]
	localNodeV2.IPv6AllocCIDR = localIPv6AllocCIDRsV2[0]
	localNodeV2.IPv6SecondaryAllocCIDRs = localIPv6AllocCIDRsV2[1:]
	err = linuxNodeHandler.NodeUpdate(localNodeV1, localNodeV2)
	require.NoError(t, err)
	if s.enableIPv4 {
		lookupIPSecInRoutes(t, netlink.FAMILY_V4, dummyExternalDeviceName, localIPv4AllocCIDRsV2)
	}
	if s.enableIPv6 {
		lookupIPSecInRoutes(t, netlink.FAMILY_V6, dummyExternalDeviceName, localIPv6AllocCIDRsV2)
	}

	// Add first remote node
	remoteNode1IPv4AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("9.9.9.0/24"),
		cidr.MustParseCIDR("10.10.10.0/24"),
		cidr.MustParseCIDR("11.11.11.0/24"),
	}
	remoteNode1IPv6AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("2005:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2006:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2007:aaaa:bbbb::/96"),
	}
	remoteNode1V1 := nodeTypes.Node{
		Name: "remote_node_1",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("1.1.1.1"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: remoteNode1IPv4, Type: nodeaddressing.NodeInternalIP},
			{IP: net.ParseIP("face::3"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: remoteNode1IPv6, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           remoteNode1IPv4AllocCIDRsV1[0],
		IPv4SecondaryAllocCIDRs: remoteNode1IPv4AllocCIDRsV1[1:],
		IPv6AllocCIDR:           remoteNode1IPv6AllocCIDRsV1[0],
		IPv6SecondaryAllocCIDRs: remoteNode1IPv6AllocCIDRsV1[1:],
		BootID:                  "b892866c-26cb-4018-8a55-c0330551a2be",
	}
	err = linuxNodeHandler.NodeAdd(remoteNode1V1)
	require.NoError(t, err)
	if s.enableIPv4 {
		lookupIPSecOutRoutes(t, netlink.FAMILY_V4, dummyHostDeviceName, remoteNode1IPv4AllocCIDRsV1)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V4, remoteNode1IPv4AllocCIDRsV1)
	}
	if s.enableIPv6 {
		lookupIPSecOutRoutes(t, netlink.FAMILY_V6, dummyHostDeviceName, remoteNode1IPv6AllocCIDRsV1)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V6, remoteNode1IPv6AllocCIDRsV1)
	}

	// Add second remote node
	remoteNode2IPv4AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("12.12.12.0/24"),
		cidr.MustParseCIDR("13.13.13.0/24"),
		cidr.MustParseCIDR("14.14.14.0/24"),
	}
	remoteNode2IPv6AllocCIDRsV1 := []*cidr.CIDR{
		cidr.MustParseCIDR("2008:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2009:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2010:aaaa:bbbb::/96"),
	}
	remoteNode2V1 := nodeTypes.Node{
		Name: "remote_node_2",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("2.2.2.2"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: remoteNode2IPv4, Type: nodeaddressing.NodeInternalIP},
			{IP: net.ParseIP("face::4"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: remoteNode2IPv6, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           remoteNode2IPv4AllocCIDRsV1[0],
		IPv4SecondaryAllocCIDRs: remoteNode2IPv4AllocCIDRsV1[1:],
		IPv6AllocCIDR:           remoteNode2IPv6AllocCIDRsV1[0],
		IPv6SecondaryAllocCIDRs: remoteNode2IPv6AllocCIDRsV1[1:],
		BootID:                  "581ec425-11af-4a29-9a0f-5550218463a7",
	}
	err = linuxNodeHandler.NodeAdd(remoteNode2V1)
	require.NoError(t, err)
	if s.enableIPv4 {
		expectedCIDRs := slices.Concat(remoteNode1IPv4AllocCIDRsV1, remoteNode2IPv4AllocCIDRsV1)
		lookupIPSecOutRoutes(t, netlink.FAMILY_V4, dummyHostDeviceName, expectedCIDRs)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V4, expectedCIDRs)
	}
	if s.enableIPv6 {
		expectedCIDRs := slices.Concat(remoteNode1IPv6AllocCIDRsV1, remoteNode2IPv6AllocCIDRsV1)
		lookupIPSecOutRoutes(t, netlink.FAMILY_V6, dummyHostDeviceName, expectedCIDRs)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V6, expectedCIDRs)
	}

	// Update first remote node and change the podCIDRs
	remoteNode2IPv4AllocCIDRsV2 := []*cidr.CIDR{
		cidr.MustParseCIDR("13.13.13.0/24"),
		cidr.MustParseCIDR("14.14.14.0/24"),
		cidr.MustParseCIDR("15.15.15.0/24"),
	}
	remoteNode2IPv6AllocCIDRsV2 := []*cidr.CIDR{
		cidr.MustParseCIDR("2009:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2010:aaaa:bbbb::/96"),
		cidr.MustParseCIDR("2011:aaaa:bbbb::/96"),
	}
	remoteNode2V2 := remoteNode2V1
	remoteNode2V2.IPv4AllocCIDR = remoteNode2IPv4AllocCIDRsV2[0]
	remoteNode2V2.IPv4SecondaryAllocCIDRs = remoteNode2IPv4AllocCIDRsV2[1:]
	remoteNode2V2.IPv6AllocCIDR = remoteNode2IPv6AllocCIDRsV2[0]
	remoteNode2V2.IPv6SecondaryAllocCIDRs = remoteNode2IPv6AllocCIDRsV2[1:]
	err = linuxNodeHandler.NodeUpdate(remoteNode2V1, remoteNode2V2)
	require.NoError(t, err)
	if s.enableIPv4 {
		expectedCIDRs := slices.Concat(remoteNode1IPv4AllocCIDRsV1, remoteNode2IPv4AllocCIDRsV2)
		lookupIPSecOutRoutes(t, netlink.FAMILY_V4, dummyHostDeviceName, expectedCIDRs)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V4, expectedCIDRs)
	}
	if s.enableIPv6 {
		expectedCIDRs := slices.Concat(remoteNode1IPv6AllocCIDRsV1, remoteNode2IPv6AllocCIDRsV2)
		lookupIPSecOutRoutes(t, netlink.FAMILY_V6, dummyHostDeviceName, expectedCIDRs)
		lookupIPSecXFRMPoliciesOut(t, netlink.FAMILY_V6, expectedCIDRs)
	}
}

func BenchmarkPrivilegedAll(b *testing.B) {
	for _, tt := range []string{"IPv4", "IPv6", "dual"} {
		b.Run(tt, func(b *testing.B) {
			b.Run("BenchmarkNodeUpdate", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeUpdate(b)
			})
			b.Run("BenchmarkNodeUpdateEncap", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeUpdateEncap(b)
			})
			b.Run("BenchmarkNodeUpdateDirectRoute", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeUpdateDirectRoute(b)
			})
			b.Run("BenchmarkNoChangeNodeUpdate", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNoChangeNodeUpdate(b)
			})
			b.Run("BenchmarkNoChangeNodeUpdateEncapAll", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNoChangeNodeUpdateEncapAll(b)
			})
			b.Run("BenchmarkNoChangeNodeUpdateDirectRouteAll", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNoChangeNodeUpdateDirectRouteAll(b)
			})
			b.Run("BenchmarkNodeValidateImplementation", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeValidateImplementation(b)
			})
			b.Run("BenchmarkNodeValidateImplementationEncap", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeValidateImplementationEncap(b)
			})
			b.Run("BenchmarkNodeValidateImplementationDirectRoute", func(b *testing.B) {
				s := setup(b, tt)
				s.BenchmarkNodeValidateImplementationDirectRoute(b)
			})
		})
	}
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeUpdate(b *testing.B, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("6.6.6.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	ip6Alloc2 := cidr.MustParseCIDR("2001:bbbb::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(b)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(b), fakeTypes.IPsecConfig{}, lns)

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(b, err)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv4,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv6,
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
			IP:   config.NodeIPv4,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev2.IPv4AllocCIDR = ip4Alloc2
	}

	if s.enableIPv6 {
		nodev2.IPAddresses = append(nodev2.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv6,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev2.IPv6AllocCIDR = ip6Alloc2
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(b, err)

	oldNode := nodev1
	newNode := nodev2

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = linuxNodeHandler.NodeUpdate(oldNode, newNode)
		require.NoError(b, err)

		tmp := oldNode
		oldNode = newNode
		newNode = tmp
	}
	b.StopTimer()

	err = linuxNodeHandler.NodeDelete(oldNode)
	require.NoError(b, err)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdate(b *testing.B) {
	s.benchmarkNodeUpdate(b, datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdateEncap(b *testing.B) {
	s.benchmarkNodeUpdate(b, datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeUpdateDirectRoute(b *testing.B) {
	s.benchmarkNodeUpdate(b, datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeUpdateNOP(b *testing.B, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(b)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(b), fakeTypes.IPsecConfig{}, lns)

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(b, err)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv4,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv6,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = linuxNodeHandler.NodeUpdate(nodev1, nodev1)
		require.NoError(b, err)
	}
	b.StopTimer()

	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(b, err)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdate(b *testing.B) {
	s.benchmarkNodeUpdateNOP(b, datapath.LocalNodeConfiguration{
		EnableIPv4: s.enableIPv4,
		EnableIPv6: s.enableIPv6,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdateEncapAll(b *testing.B) {
	s.benchmarkNodeUpdateNOP(b, datapath.LocalNodeConfiguration{
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		EnableEncapsulation: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNoChangeNodeUpdateDirectRouteAll(b *testing.B) {
	s.benchmarkNodeUpdateNOP(b, datapath.LocalNodeConfiguration{
		EnableIPv4:              s.enableIPv4,
		EnableIPv6:              s.enableIPv6,
		EnableAutoDirectRouting: true,
	})
}

func (s *linuxPrivilegedBaseTestSuite) benchmarkNodeValidateImplementation(b *testing.B, config datapath.LocalNodeConfiguration) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(b)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsec.NewTestIPsecAgent(b), fakeTypes.IPsecConfig{}, lns)

	err := linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(b, err)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv4,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   config.NodeIPv6,
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = linuxNodeHandler.NodeValidateImplementation(nodev1)
		require.NoError(b, err)
	}
	b.StopTimer()

	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(b, err)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementation(b *testing.B) {
	s.benchmarkNodeValidateImplementation(b, s.nodeConfigTemplate)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementationEncap(b *testing.B) {
	config := s.nodeConfigTemplate
	config.EnableEncapsulation = true
	s.benchmarkNodeValidateImplementation(b, config)
}

func (s *linuxPrivilegedBaseTestSuite) BenchmarkNodeValidateImplementationDirectRoute(b *testing.B) {
	config := s.nodeConfigTemplate
	config.EnableAutoDirectRouting = true
	s.benchmarkNodeValidateImplementation(b, config)
}
