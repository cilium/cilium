// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

type linuxPrivilegedBaseTestSuite struct {
	sysctl     sysctl.Sysctl
	mtuConfig  mtu.Configuration
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

	baseIPv4Time = "net.ipv4.neigh.default.base_reachable_time_ms"
	baseIPv6Time = "net.ipv6.neigh.default.base_reachable_time_ms"
	baseTime     = 2500

	mcastNumIPv4 = "net.ipv4.neigh.default.mcast_solicit"
	mcastNumIPv6 = "net.ipv6.neigh.default.mcast_solicit"
	mcastNum     = 6
)

func setupLinuxPrivilegedBaseTestSuite(tb testing.TB, addressing datapath.NodeAddressing, enableIPv6, enableIPv4 bool) *linuxPrivilegedBaseTestSuite {
	testutils.PrivilegedTest(tb)
	s := &linuxPrivilegedBaseTestSuite{}

	s.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	rlimit.RemoveMemlock()
	s.mtuConfig = mtu.NewConfiguration(0, false, false, false, false, 1500, nil, false)
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
		NodeIPv4:            addressing.IPv4().PrimaryExternal(),
		NodeIPv6:            addressing.IPv6().PrimaryExternal(),
		CiliumInternalIPv4:  addressing.IPv4().Router(),
		CiliumInternalIPv6:  addressing.IPv6().Router(),
		AllocCIDRIPv4:       addressing.IPv4().AllocationCIDR(),
		AllocCIDRIPv6:       addressing.IPv6().AllocationCIDR(),
		EnableIPv4:          s.enableIPv4,
		EnableIPv6:          s.enableIPv6,
		DeviceMTU:           s.mtuConfig.GetDeviceMTU(),
		RouteMTU:            s.mtuConfig.GetRouteMTU(),
		RoutePostEncryptMTU: s.mtuConfig.GetRoutePostEncryptMTU(),
	}

	tunnel.SetTunnelMap(tunnel.NewTunnelMap("test_cilium_tunnel_map"))
	err = tunnel.TunnelMap().OpenOrCreate()
	require.NoError(tb, err)

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

func tearDownTest(tb testing.TB) {
	ipsec.DeleteXFRM(hivetest.Logger(tb), ipsec.AllReqID)
	node.UnsetTestLocalNodeStore()
	removeDevice(dummyHostDeviceName)
	removeDevice(dummyExternalDeviceName)
	err := tunnel.TunnelMap().Unpin()
	require.NoError(tb, err)
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

	link, err := netlink.LinkByName(name)
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
	l, err := netlink.LinkByName(name)
	if err == nil {
		netlink.LinkDel(l)
	}
}

func TestAll(t *testing.T) {

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
			t.Run("TestNodeUpdateDirectRouting", func(t *testing.T) {
				s := setup(t, tt)
				s.TestNodeUpdateDirectRouting(t)
			})
			t.Run("TestAgentRestartOptionChanges", func(t *testing.T) {
				s := setup(t, tt)
				s.TestAgentRestartOptionChanges(t)
			})
			t.Run("TestNodeValidationDirectRouting", func(t *testing.T) {
				s := setup(t, tt)
				s.TestAgentRestartOptionChanges(t)
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
	linuxNodeHandler = newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
	externalNodeIP2 := net.ParseIP("8.8.8.8")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// nodev2: ip4Alloc1, ip6alloc1 => externalNodeIP2
	nodev2 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
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
	require.NoError(t, err)

	// alloc range v1 should map to underlay2
	if s.enableIPv4 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP2))

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP2))

		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// nodev3: ip4Alloc2, ip6alloc2 => externalNodeIP1
	nodev3 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
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
	require.NoError(t, err)

	// alloc range v1 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	require.Error(t, err)

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	require.Error(t, err)

	if s.enableIPv4 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

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
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

		// node routes for alloc1 ranges should be gone
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc1, false)
		require.NoError(t, err)
		require.Nil(t, foundRoute)

		// node routes for alloc2 ranges should have been installed
		foundRoute, err = linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// nodev4: stop announcing CIDRs
	nodev4 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
		IPAddresses: []nodeTypes.Address{
			{IP: externalNodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(nodev3, nodev4)
	require.NoError(t, err)

	// alloc range v2 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
	require.Error(t, err)

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
	require.Error(t, err)

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

	// nodev5: re-announce CIDRs
	nodev5 := nodeTypes.Node{
		Name:      "node1",
		ClusterID: 11,
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
	require.NoError(t, err)

	if s.enableIPv4 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip4Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		// alloc range v2 should map to underlay1
		underlayIP, err := tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
		require.NoError(t, err)
		require.Equal(t, true, underlayIP.Equal(externalNodeIP1))

		// node routes for alloc2 ranges should have been installed
		foundRoute, err := linuxNodeHandler.lookupNodeRoute(ip6Alloc2, false)
		require.NoError(t, err)
		require.NotNil(t, foundRoute)
	}

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	require.NoError(t, err)

	// alloc range v1 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	require.Error(t, err)

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	require.Error(t, err)

	// alloc range v2 should fail
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc2.IP))
	require.Error(t, err)

	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc2.IP))
	require.Error(t, err)

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
	nodeIP1 := net.ParseIP("4.4.4.4")
	nodeIP2 := net.ParseIP("8.8.8.8")
	nodeIP3 := net.ParseIP("1.1.1.1")

	nodeMap := nodemapfake.NewFakeNodeMapV2()

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodeMap, new(mockEnqueuer))

	nodeConfig := s.nodeConfigTemplate
	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// New node receives a node ID.
	node1v1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node1v1)
	require.NoError(t, err)

	nodeID1, err := nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	require.NotEqual(t, 0, nodeID1)

	// When the node is updated, the new IPs are mapped to the existing node ID.
	node1v2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1, Type: nodeaddressing.NodeInternalIP},
			{IP: nodeIP2, Type: nodeaddressing.NodeExternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(node1v1, node1v2)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	nodeID2, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	require.Equal(t, *nodeID1, *nodeID2)

	// When the node is updated, the old IPs are unmapped from the node ID.
	node1v3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP2, Type: nodeaddressing.NodeExternalIP},
		},
	}
	err = linuxNodeHandler.NodeUpdate(node1v2, node1v3)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP1)
	require.ErrorContains(t, err, "IP not found in node ID map")
	nodeID3, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	require.Equal(t, *nodeID2, *nodeID3)

	// If a second node is created, it receives a different node ID.
	node2 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1, Type: nodeaddressing.NodeInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node2)
	require.NoError(t, err)

	nodeID4, err := nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	require.NotEqual(t, nodeID3, nodeID4)

	// When the node is deleted, all references to its ID are also removed.
	err = linuxNodeHandler.NodeDelete(node1v3)
	require.NoError(t, err)

	_, err = nodeMap.Lookup(nodeIP2)
	require.ErrorContains(t, err, "IP not found in node ID map")

	// When a node is created with multiple IP addresses, they all have the same ID.
	node3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP2, Type: nodeaddressing.NodeInternalIP},
			{IP: nodeIP3, Type: nodeaddressing.NodeCiliumInternalIP},
		},
	}
	err = linuxNodeHandler.NodeAdd(node3)
	require.NoError(t, err)

	nodeID5, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	nodeID6, err := nodeMap.Lookup(nodeIP3)
	require.NoError(t, err)
	require.Equal(t, *nodeID6, *nodeID5)
}

// Tests that we don't leak XFRM policies and states as nodes come and go.
func (s *linuxPrivilegedBaseTestSuite) TestNodeChurnXFRMLeaks(t *testing.T) {

	// Cover the XFRM configuration for IPAM modes cluster-pool, kubernetes, etc.
	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	s.testNodeChurnXFRMLeaksWithConfig(t, config)
}

// Tests the same as linuxPrivilegedBaseTestSuite.TestNodeChurnXFRMLeaks just
// for the subnet encryption. IPv4-only because of https://github.com/cilium/cilium/issues/27280.
func TestNodeChurnXFRMLeaks(t *testing.T) {
	s := setupLinuxPrivilegedIPv4OnlyTestSuite(t)

	externalNodeDevice := "ipsec_interface"

	// Cover the XFRM configuration for IPAM modes cluster-pool, kubernetes, etc.
	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	s.testNodeChurnXFRMLeaksWithConfig(t, config)

	// In the case of subnet encryption (tested below), the IPsec logic
	// retrieves the IP address of the encryption interface directly so we need
	// a dummy interface.
	removeDevice(externalNodeDevice)
	_, err := setupDummyDevice(externalNodeDevice, net.ParseIP("1.1.1.1"), net.ParseIP("face::1"))
	require.NoError(t, err)
	defer removeDevice(externalNodeDevice)
	option.Config.EncryptInterface = []string{externalNodeDevice}
	option.Config.RoutingMode = option.RoutingModeNative

	// Cover the XFRM configuration for subnet encryption: IPAM modes AKS and EKS.
	_, ipv4PodSubnets, err := net.ParseCIDR("4.4.0.0/16")
	require.NoError(t, err)
	require.NotNil(t, ipv4PodSubnets)
	config.IPv4PodSubnets = []*net.IPNet{ipv4PodSubnets}
	_, ipv6PodSubnets, err := net.ParseCIDR("2001:aaaa::/64")
	require.NoError(t, err)
	require.NotNil(t, ipv6PodSubnets)
	config.IPv6PodSubnets = []*net.IPNet{ipv6PodSubnets}
	s.testNodeChurnXFRMLeaksWithConfig(t, config)
}

func (s *linuxPrivilegedIPv4OnlyTestSuite) TestEncryptedOverlayXFRMLeaks(t *testing.T) {
	// Cover the XFRM configuration for IPAM modes cluster-pool, kubernetes, etc.
	config := datapath.LocalNodeConfiguration{
		EnableIPv4:  s.enableIPv4,
		EnableIPv6:  s.enableIPv6,
		EnableIPSec: true,
	}
	s.testEncryptedOverlayXFRMLeaks(t, config)
}

// TestEncryptedOverlayXFRMLeaks tests that the XFRM policies and states are accurate when the encrypted overlay
// feature is enabled and disabled.
func (s *linuxPrivilegedIPv4OnlyTestSuite) testEncryptedOverlayXFRMLeaks(t *testing.T, config datapath.LocalNodeConfiguration) {
	tlog := hivetest.Logger(t)
	keys := bytes.NewReader([]byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"))
	_, _, err := ipsec.LoadIPSecKeys(tlog, keys)
	require.NoError(t, err)

	var linuxNodeHandler *linuxNodeHandler
	h := hive.New(
		DevicesControllerCell,
		cell.Invoke(func(db *statedb.DB, devices statedb.Table[*tables.Device]) {
			dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
			linuxNodeHandler = newNodeHandler(tlog, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))
		}),
	)

	require.Nil(t, h.Start(tlog, context.TODO()))
	defer func() { require.Nil(t, h.Stop(tlog, context.TODO())) }()
	require.NotNil(t, linuxNodeHandler)

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(t, err)

	// Adding a node adds some XFRM states and policies.
	node := nodeTypes.Node{
		Name: "node",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("3.3.3.3"), Type: nodeaddressing.NodeInternalIP},
			{IP: net.ParseIP("4.4.4.4"), Type: nodeaddressing.NodeCiliumInternalIP},
		},
		IPv4AllocCIDR: cidr.MustParseCIDR("4.4.4.0/24"),
		BootID:        "test-boot-id",
	}
	err = linuxNodeHandler.NodeAdd(node)
	require.NoError(t, err)

	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 4, len(states))
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 2, countXFRMPolicies(policies))

	// disable encrypted overlay feature
	config.EnableIPSecEncryptedOverlay = false

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(t, err)

	states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 2, len(states))
	policies, err = netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 1, countXFRMPolicies(policies))
}

func (s *linuxPrivilegedBaseTestSuite) testNodeChurnXFRMLeaksWithConfig(t *testing.T, config datapath.LocalNodeConfiguration) {
	log := hivetest.Logger(t)
	keys := bytes.NewReader([]byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"))
	_, _, err := ipsec.LoadIPSecKeys(log, keys)
	require.NoError(t, err)

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

	err = linuxNodeHandler.NodeConfigurationChanged(config)
	require.NoError(t, err)

	// Adding a node adds some XFRM states and policies.
	node := nodeTypes.Node{
		Name: "node",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("4.4.4.4"), Type: nodeaddressing.NodeCiliumInternalIP},
			{IP: net.ParseIP("2001:aaaa::1"), Type: nodeaddressing.NodeCiliumInternalIP},
		},
		IPv4AllocCIDR: cidr.MustParseCIDR("4.4.4.0/24"),
		IPv6AllocCIDR: cidr.MustParseCIDR("2001:aaaa::/96"),
		BootID:        "test-boot-id",
	}
	err = linuxNodeHandler.NodeAdd(node)
	require.NoError(t, err)

	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(states))
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.NotEqual(t, 0, countXFRMPolicies(policies))

	// Removing the node removes those XFRM states and policies.
	err = linuxNodeHandler.NodeDelete(node)
	require.NoError(t, err)

	states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 0, len(states))
	policies, err = netlink.XfrmPolicyList(netlink.FAMILY_ALL)
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
	return netlink.RouteListFiltered(family, routeSpec, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF)
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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
	require.Equal(t, expectedIPv4Routes, len(foundRoutes))

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
	require.Equal(t, expectedIPv4Routes, len(foundRoutes))

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
	require.Equal(t, 0, len(foundRoutes)) // route should not exist regardless whether ipv4 is enabled or not

	// node routes for alloc2 ranges should have been installed
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Equal(t, expectedIPv4Routes, len(foundRoutes))

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
	require.Equal(t, 0, len(foundRoutes))

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
	require.Equal(t, expectedIPv4Routes, len(foundRoutes))

	// delete nodev5
	err = linuxNodeHandler.NodeDelete(nodev5)
	require.NoError(t, err)

	// node routes for alloc2 ranges should be gone
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Equal(t, 0, len(foundRoutes)) // route should not exist regardless whether ipv4 is enabled or not

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
		require.Equal(t, expectedIPv4Routes, len(foundRoutes))
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
		require.Equal(t, expectedIPv4Routes, len(foundRoutes))
	}
	// Checks route for removed CIDR has been deleted
	foundRoutes, err = lookupDirectRoute(log, ipv4SecondaryAlloc2, externalNode1IP4v1)
	require.NoError(t, err)
	require.Equal(t, 0, len(foundRoutes))

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
		require.Equal(t, expectedIPv4Routes, len(foundRoutes))
	}
	// Checks all routes with the old node IP have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v1)
		require.NoError(t, err)
		require.Equal(t, 0, len(foundRoutes))
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
	require.Equal(t, expectedIPv4Routes, len(foundRoutes))

	// Checks all old routes have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		foundRoutes, err = lookupDirectRoute(log, ip4Alloc, externalNode1IP4v2)
		require.NoError(t, err)
		require.Equal(t, 0, len(foundRoutes))
	}

	// delete nodev9
	err = linuxNodeHandler.NodeDelete(nodev9)
	require.NoError(t, err)

	// remaining primary node route must have been deleted
	foundRoutes, err = lookupDirectRoute(log, ip4Alloc2, externalNode1IP4v2)
	require.NoError(t, err)
	require.Equal(t, 0, len(foundRoutes))
}

func (s *linuxPrivilegedBaseTestSuite) TestAgentRestartOptionChanges(t *testing.T) {
	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	underlayIP := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: dummyHostDeviceName}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

	require.NotNil(t, linuxNodeHandler)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = true

	err := linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

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
	require.NoError(t, err)

	// tunnel map entries must exist
	if s.enableIPv4 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		require.NoError(t, err)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		require.NoError(t, err)
	}

	// Simulate agent restart with address families disables
	nodeConfig.EnableIPv4 = false
	nodeConfig.EnableIPv6 = false
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// Simulate initial node addition
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)

	// tunnel map entries should have been removed
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
	require.Error(t, err)
	_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
	require.Error(t, err)

	// Simulate agent restart with address families enabled again
	nodeConfig.EnableIPv4 = true
	nodeConfig.EnableIPv6 = true
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// Simulate initial node addition
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)

	// tunnel map entries must exist
	if s.enableIPv4 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip4Alloc1.IP))
		require.NoError(t, err)
	}
	if s.enableIPv6 {
		_, err = tunnel.TunnelMap().GetTunnelEndpoint(cmtypes.MustAddrClusterFromIP(ip6Alloc1.IP))
		require.NoError(t, err)
	}

	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
}

func insertFakeRoute(t *testing.T, n *linuxNodeHandler, prefix *cidr.CIDR) {
	nodeRoute, err := n.createNodeRouteSpec(prefix, false)
	require.NoError(t, err)

	nodeRoute.Device = dummyExternalDeviceName

	err = route.Upsert(nodeRoute)
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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

	if s.enableIPv4 {
		insertFakeRoute(t, linuxNodeHandler, ip4Alloc1)
	}

	if s.enableIPv6 {
		insertFakeRoute(t, linuxNodeHandler, ip6Alloc1)
	}

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
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
		require.Equal(t, true, lookupFakeRoute(t, linuxNodeHandler, ip4Alloc1))
	}

	if s.enableIPv6 {
		require.Equal(t, true, lookupFakeRoute(t, linuxNodeHandler, ip6Alloc1))
	}
}

func neighStateOk(n netlink.Neigh) bool {
	switch {
	case (n.State & netlink.NUD_REACHABLE) > 0:
		fallthrough
	case (n.State & netlink.NUD_STALE) > 0:
		// Current final state
		return true
	}
	return false
}

func TestArpPingHandlingIPv6(t *testing.T) {
	s := setupLinuxPrivilegedIPv6OnlyTestSuite(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := t.TempDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := s.sysctl.Read(baseIPv6Time)
	require.NoError(t, err)
	err = s.sysctl.Write(baseIPv6Time, fmt.Sprintf("%d", baseTime))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(baseIPv6Time, baseTimeOld) }()

	mcastNumOld, err := s.sysctl.Read(mcastNumIPv6)
	require.NoError(t, err)
	err = s.sysctl.Write(mcastNumIPv6, fmt.Sprintf("%d", mcastNum))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(mcastNumIPv6, mcastNumOld) }()

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
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(veth) })
	veth0, err := netlink.LinkByName("veth0")
	require.NoError(t, err)
	veth1, err := netlink.LinkByName("veth1")
	require.NoError(t, err)
	_, ipnet, _ := net.ParseCIDR("f00d::/96")
	ip0 := net.ParseIP("f00d::249")
	ip1 := net.ParseIP("f00d::250")
	ipG := net.ParseIP("f00d::251")
	ipnet.IP = ip0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth0)
	require.NoError(t, err)

	ns := netns.NewNetNS(t)

	err = netlink.LinkSetNsFd(veth1, int(ns.FD()))
	require.NoError(t, err)
	ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		ipnet.IP = ip1
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		ipnet.IP = ipG
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth1)
		require.NoError(t, err)
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
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = time.Duration(1 * time.Nanosecond)

	mq := new(mockEnqueuer)
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), mq)
	mq.nh = linuxNodeHandler

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		t.Helper()
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
		require.NoError(t, err)
	}

	assertNeigh := func(ip net.IP, checkNeigh func(neigh netlink.Neigh) bool) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
			require.NoError(t, err)
			for _, n := range neighs {
				if n.IP.Equal(ip) && checkNeigh(n) {
					return true
				}
			}
			return false
		}, 5*time.Second)
		require.Nil(t, err, fmt.Sprintf("expected neighbor %s", ip))
	}

	assertNoNeigh := func(msg string, ips ...net.IP) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
			require.NoError(t, err)
			for _, n := range neighs {
				for _, ip := range ips {
					if n.IP.Equal(ip) {
						return false
					}
				}
			}
			return true
		}, 5*time.Second)
		require.Nil(t, err, msg)
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
	require.NoError(t, err)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)

	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	assertNeigh(ip1, neighStateOk)

	// Swap MAC addresses of veth0 and veth1 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		require.NoError(t, err)
		return nil
	})

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	require.NoError(t, err)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1, true)
	wait(nodev1.Identity(), "veth0", &now, false)

	assertNeigh(ip1, func(neigh netlink.Neigh) bool {
		if neighStateOk(neigh) {
			updatedHwAddrFromArpEntry = neigh.HardwareAddr
			return true
		}
		return false
	})
	require.Equal(t, veth0HwAddr.String(), updatedHwAddrFromArpEntry.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)

	assertNoNeigh("expected removed neigh "+ip1.String(), ip1)

	// Create multiple goroutines which call insertNeighbor and check whether
	// MAC changes of veth1 are properly handled. This is a basic randomized
	// testing of insertNeighbor() fine-grained locking.
	now = time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	wait(nodev1.Identity(), "veth0", &now, false)

	rndHWAddr := func() net.HardwareAddr {
		mac := make([]byte, 6)
		_, err := rand.Read(mac)
		require.NoError(t, err)
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
	for i := 0; i < 3; i++ {
		mac := rndHWAddr()
		// Change MAC
		ns.Do(func() error {
			veth1, err := netlink.LinkByName("veth1")
			require.NoError(t, err)
			err = netlink.LinkSetHardwareAddr(veth1, mac)
			require.NoError(t, err)
			return nil
		})

		// Check that MAC has been changed in the neigh table
		var found bool
		err := testutils.WaitUntilWithSleep(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V6)
			require.NoError(t, err)
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
		}, 60*time.Second, 200*time.Millisecond)
		require.NoError(t, err)
		require.Equal(t, true, found)
	}

	// Cleanup
	close(done)
	wg.Wait()
	now = time.Now()
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
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
		ns2 := netns.NewNetNS(t)
		cleanup = func() {
			cleanup1()
			ns2.Close()
		}
		if errRet = netlink.LinkSetNsFd(veth2, int(ns.FD())); errRet != nil {
			return
		}
		if errRet = netlink.LinkSetNsFd(veth3, int(ns2.FD())); errRet != nil {
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

		if errRet = ns.Do(func() error {
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

		if errRet = ns2.Do(func() error {
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
	require.NoError(t, err)
	defer cleanup1()
	cleanup2, err := setupRemoteNode("veth4", "veth5", "test-arping-netns2",
		"f00b::/96", "f00b::249", "f00b::250")
	require.NoError(t, err)
	defer cleanup2()

	node2IP := net.ParseIP("f00a::250")
	nodev2 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node2IP}},
	}
	now = time.Now()
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev2))
	wait(nodev2.Identity(), "veth0", &now, false)

	node3IP := net.ParseIP("f00b::250")
	nodev3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node3IP,
		}},
	}
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop := net.ParseIP("f00d::250")
	// Check that both node{2,3} are via nextHop (gw)
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Check that removing node2 will not remove nextHop, as it is still used by node3
	require.Nil(t, linuxNodeHandler.NodeDelete(nodev2))
	wait(nodev2.Identity(), "veth0", nil, true)

	assertNeigh(nextHop, func(n netlink.Neigh) bool { return true })

	// However, removing node3 should remove the neigh entry for nextHop
	require.Nil(t, linuxNodeHandler.NodeDelete(nodev3))
	wait(nodev3.Identity(), "veth0", nil, true)

	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)

	now = time.Now()
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("f00d::250")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// We have stored the devices in NodeConfigurationChanged
	linuxNodeHandler.NodeCleanNeighbors(false)

	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

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
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev2))
	wait(nodev2.Identity(), "veth0", &now, false)

	now = time.Now()
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("f00d::250")

	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Switch to new nextHop address for node2
	err = setupNewGateway("f00a::/96", "f00d::251")
	require.NoError(t, err)

	// waitGw waits for the nextHop to appear in the agent's nextHop table
	waitGw := func(nextHopNew string, nodeID nodeTypes.Identity, link string, before *time.Time) {
		t.Helper()
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
		require.NoError(t, err)
	}

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2, true)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3, true)
	waitGw("f00d::251", nodev2.Identity(), "veth0", &now)
	waitGw("f00d::250", nodev3.Identity(), "veth0", &now)

	// Both nextHops now need to be present
	nextHop = net.ParseIP("f00d::250")
	assertNeigh(nextHop, neighStateOk)
	nextHop = net.ParseIP("f00d::251")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Now also switch over the other node.
	err = setupNewGateway("f00b::/96", "f00d::251")
	require.NoError(t, err)

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2, true)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3, true)
	waitGw("f00d::251", nodev2.Identity(), "veth0", &now)
	waitGw("f00d::251", nodev3.Identity(), "veth0", &now)

	nextHop = net.ParseIP("f00d::250")

	// Check that old nextHop address got removed
	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	nextHop = net.ParseIP("f00d::251")
	assertNeigh(nextHop, neighStateOk)

	require.Nil(t, linuxNodeHandler.NodeDelete(nodev3))
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
	require.NoError(t, err)

	// Check that new nextHop address got added, we don't care about its NUD_* state
	assertNeigh(nextHop, func(neigh netlink.Neigh) bool { return true })

	// Clean unrelated externally learned entries
	linuxNodeHandler.NodeCleanNeighborsLink(veth0, true)

	// Check that new nextHop address got removed
	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)

	// Check that node2 nextHop address is still there
	nextHop = net.ParseIP("f00d::251")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node2 should not be in the same L2", node2IP)

	require.Nil(t, linuxNodeHandler.NodeDelete(nodev2))
	wait(nodev2.Identity(), "veth0", nil, true)

	linuxNodeHandler.NodeCleanNeighborsLink(veth0, false)
}

func getDevice(tb testing.TB, name string) *tables.Device {
	link, err := netlink.LinkByName(name)
	require.NoError(tb, err, "LinkByName")
	return &tables.Device{Index: link.Attrs().Index, Name: name, Selected: true}
}

func TestArpPingHandlingForMultiDeviceIPv6(t *testing.T) {
	s := setupLinuxPrivilegedIPv6OnlyTestSuite(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := t.TempDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := s.sysctl.Read(baseIPv6Time)
	require.NoError(t, err)
	err = s.sysctl.Write(baseIPv6Time, fmt.Sprintf("%d", baseTime))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(baseIPv6Time, baseTimeOld) }()

	mcastNumOld, err := s.sysctl.Read(mcastNumIPv6)
	require.NoError(t, err)
	err = s.sysctl.Write(mcastNumIPv6, fmt.Sprintf("%d", mcastNum))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(mcastNumIPv6, mcastNumOld) }()

	// 1. Test whether another node with multiple paths can be arpinged.
	//    Each node has two devices and the other node in the different netns
	//    is reachable via either pair.
	//    Neighbor entries are not installed on devices where no route exists
	//
	//      +--------------+     +-------------------+
	//      |  host netns  |     |      netns1       |
	//      |              |     |      nodev1       |
	//      |              |     |  fc00:c111::1/128 |
	//      |         veth0+-----+veth1              |
	//      |          |   |     |   |               |
	//      | f00a::249/96 |     | f00a::250/96      |
	//      |              |     |                   |
	//      |         veth2+-----+veth3              |
	//      |          |   |     | |                 |
	//      | f00b::249/96 |     | f00b::250/96      |
	//      |              |     |                   |
	//      | f00c::249/96 |     |                   |
	//      |  |           |     |                   |
	//      | veth4        |     |                   |
	//      +-+------------+     +-------------------+
	//        |
	//      +-+--------------------------------------+
	//      | veth5        other netns               |
	//      |  |                                     |
	//      | f00c::250/96                           |
	//      +----------------------------------------+

	// Setup
	vethPair01 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(vethPair01)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair01) })
	veth0, err := netlink.LinkByName("veth0")
	require.NoError(t, err)
	veth1, err := netlink.LinkByName("veth1")
	require.NoError(t, err)
	_, ipnet, _ := net.ParseCIDR("f00a::/96")
	v1IP0 := net.ParseIP("f00a::249")
	v1IP1 := net.ParseIP("f00a::250")
	v1IPG := net.ParseIP("f00a::251")
	ipnet.IP = v1IP0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth0)
	require.NoError(t, err)

	ns := netns.NewNetNS(t)
	err = netlink.LinkSetNsFd(veth1, int(ns.FD()))
	require.NoError(t, err)
	node1Addr, err := netlink.ParseAddr("fc00:c111::1/128")
	require.NoError(t, err)
	ns.Do(func() error {
		lo, err := netlink.LinkByName("lo")
		require.NoError(t, err)
		err = netlink.LinkSetUp(lo)
		require.NoError(t, err)
		err = netlink.AddrAdd(lo, node1Addr)
		require.NoError(t, err)

		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		ipnet.IP = v1IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		ipnet.IP = v1IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth1)
		require.NoError(t, err)
		return nil
	})

	vethPair23 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth2"},
		PeerName:  "veth3",
	}
	err = netlink.LinkAdd(vethPair23)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair23) })
	veth2, err := netlink.LinkByName("veth2")
	require.NoError(t, err)
	veth3, err := netlink.LinkByName("veth3")
	require.NoError(t, err)
	_, ipnet, _ = net.ParseCIDR("f00b::/96")
	v2IP0 := net.ParseIP("f00b::249")
	v2IP1 := net.ParseIP("f00b::250")
	v2IPG := net.ParseIP("f00b::251")
	ipnet.IP = v2IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth2, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth2)
	require.NoError(t, err)

	err = netlink.LinkSetNsFd(veth3, int(ns.FD()))
	require.NoError(t, err)
	err = ns.Do(func() error {
		veth3, err := netlink.LinkByName("veth3")
		require.NoError(t, err)
		ipnet.IP = v2IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		require.NoError(t, err)
		ipnet.IP = v2IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth3)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	r := &netlink.Route{
		Dst: netlink.NewIPNet(node1Addr.IP),
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
	require.NoError(t, err)
	defer netlink.RouteDel(r)

	// Setup another veth pair that doesn't have a route to node
	vethPair45 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth4"},
		PeerName:  "veth5",
	}
	err = netlink.LinkAdd(vethPair45)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair45) })
	veth4, err := netlink.LinkByName("veth4")
	require.NoError(t, err)
	veth5, err := netlink.LinkByName("veth5")
	require.NoError(t, err)
	_, ipnet, _ = net.ParseCIDR("f00c::/96")
	v3IP0 := net.ParseIP("f00c::249")
	v3IP1 := net.ParseIP("f00c::250")
	ipnet.IP = v3IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth4, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth4)
	require.NoError(t, err)

	ns2 := netns.NewNetNS(t)

	err = netlink.LinkSetNsFd(veth5, int(ns2.FD()))
	require.NoError(t, err)
	err = ns2.Do(func() error {
		veth5, err := netlink.LinkByName("veth5")
		require.NoError(t, err)
		ipnet.IP = v3IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth5, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth5)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = 1 * time.Nanosecond

	mq := new(mockEnqueuer)
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), mq)
	mq.nh = linuxNodeHandler

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices),
		getDevice(t, "veth0"),
		getDevice(t, "veth2"),
		getDevice(t, "veth4"))

	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		t.Helper()
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
		require.NoError(t, err)
	}

	assertNeigh := func(ip net.IP, link netlink.Link, checkNeigh func(neigh netlink.Neigh) bool) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
			require.NoError(t, err)
			for _, n := range neighs {
				if n.IP.Equal(ip) && checkNeigh(n) {
					return true
				}
			}
			return false
		}, 5*time.Second)
		require.NoError(t, err, "expected neighbor %s", ip)
	}

	assertNoNeigh := func(link netlink.Link, ips ...net.IP) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
			require.NoError(t, err)
			for _, n := range neighs {
				for _, ip := range ips {
					if n.IP.Equal(ip) {
						return false
					}
				}
			}
			return true
		}, 5*time.Second)
		require.NoError(t, err, "expected no neighbors: %v", ips)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node1Addr.IP,
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)

	assertNeigh(v1IP1, veth0, neighStateOk)
	assertNeigh(v2IP1, veth2, neighStateOk)

	// Check whether we don't install the neighbor entries to nodes on the device where the actual route isn't.
	// "Consistently(<check>, 5sec, 1sec)"
	start := time.Now()
	for {
		if time.Since(start) > 5*time.Second {
			break
		}

		neighs, err := netlink.NeighList(veth4.Attrs().Index, netlink.FAMILY_V6)
		require.NoError(t, err)
		found := false
		for _, n := range neighs {
			if n.IP.Equal(v3IP1) || n.IP.Equal(node1Addr.IP) {
				found = true
			}
		}
		require.Equal(t, false, found)

		time.Sleep(1 * time.Second)
	}

	// Swap MAC addresses of veth0 and veth1, veth2 and veth3 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, veth2HwAddr, veth3HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	veth2HwAddr = veth2.Attrs().HardwareAddr
	err = ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		require.NoError(t, err)

		veth3, err := netlink.LinkByName("veth3")
		require.NoError(t, err)
		veth3HwAddr = veth3.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth3, veth2HwAddr)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	require.NoError(t, err)
	err = netlink.LinkSetHardwareAddr(veth2, veth3HwAddr)
	require.NoError(t, err)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1, true)
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)

	assertNeigh(v1IP1, veth0,
		func(neigh netlink.Neigh) bool {
			if neighStateOk(neigh) {
				updatedHwAddrFromArpEntry = neigh.HardwareAddr
				return true
			}
			return false
		})

	require.Equal(t, veth0HwAddr.String(), updatedHwAddrFromArpEntry.String())

	assertNeigh(v2IP1, veth2,
		func(neigh netlink.Neigh) bool {
			if neighStateOk(neigh) {
				updatedHwAddrFromArpEntry = neigh.HardwareAddr
				return true
			}
			return false
		})

	require.Equal(t, veth2HwAddr.String(), updatedHwAddrFromArpEntry.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)
	wait(nodev1.Identity(), "veth2", nil, true)

	assertNoNeigh(veth0, v1IP1)
	assertNoNeigh(veth2, v2IP1)
}

func TestArpPingHandlingIPv4(t *testing.T) {
	s := setupLinuxPrivilegedIPv4OnlyTestSuite(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := t.TempDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := s.sysctl.Read(baseIPv4Time)
	require.NoError(t, err)
	err = s.sysctl.Write(baseIPv4Time, fmt.Sprintf("%d", baseTime))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(baseIPv4Time, baseTimeOld) }()

	mcastNumOld, err := s.sysctl.Read(mcastNumIPv4)
	require.NoError(t, err)
	err = s.sysctl.Write(mcastNumIPv4, fmt.Sprintf("%d", mcastNum))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(mcastNumIPv4, mcastNumOld) }()

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
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(veth) })
	veth0, err := netlink.LinkByName("veth0")
	require.NoError(t, err)
	veth1, err := netlink.LinkByName("veth1")
	require.NoError(t, err)
	_, ipnet, _ := net.ParseCIDR("9.9.9.252/29")
	ip0 := net.ParseIP("9.9.9.249")
	ip1 := net.ParseIP("9.9.9.250")
	ipG := net.ParseIP("9.9.9.251")
	ipnet.IP = ip0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth0)
	require.NoError(t, err)

	ns := netns.NewNetNS(t)

	err = netlink.LinkSetNsFd(veth1, int(ns.FD()))
	require.NoError(t, err)
	ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		ipnet.IP = ip1
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		ipnet.IP = ipG
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth1)
		require.NoError(t, err)
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
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = time.Duration(1 * time.Nanosecond)

	mq := new(mockEnqueuer)
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), mq)
	mq.nh = linuxNodeHandler

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.Devices = []*tables.Device{
		{Index: veth0.Attrs().Index, Name: "veth0", Selected: true},
	}
	nodeConfig.EnableEncapsulation = false
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		t.Helper()
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
		require.NoError(t, err)
	}

	assertNeigh := func(ip net.IP, checkNeigh func(neigh netlink.Neigh) bool) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
			require.NoError(t, err)
			for _, n := range neighs {
				if n.IP.Equal(ip) && checkNeigh(n) {
					return true
				}
			}
			return false
		}, 5*time.Second)
		require.NoError(t, err, "expected neighbor %s", ip)
	}

	assertNoNeigh := func(msg string, ips ...net.IP) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
			require.NoError(t, err)
			for _, n := range neighs {
				for _, ip := range ips {
					if n.IP.Equal(ip) {
						return false
					}
				}
			}
			return true
		}, 5*time.Second)
		require.NoError(t, err, msg)
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
	require.NoError(t, err)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)

	assertNeigh(ip1, neighStateOk)

	// Swap MAC addresses of veth0 and veth1 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		require.NoError(t, err)
		return nil
	})

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	require.NoError(t, err)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1, true)
	wait(nodev1.Identity(), "veth0", &now, false)

	assertNeigh(ip1,
		func(neigh netlink.Neigh) bool {
			if neighStateOk(neigh) {
				updatedHwAddrFromArpEntry = neigh.HardwareAddr
				return true
			}
			return false
		})

	require.Equal(t, veth0HwAddr.String(), updatedHwAddrFromArpEntry.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)

	assertNoNeigh("expected removed neigh "+ip1.String(), ip1)

	// Create multiple goroutines which call insertNeighbor and check whether
	// MAC changes of veth1 are properly handled. This is a basic randomized
	// testing of insertNeighbor() fine-grained locking.
	now = time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	wait(nodev1.Identity(), "veth0", &now, false)

	rndHWAddr := func() net.HardwareAddr {
		mac := make([]byte, 6)
		_, err := rand.Read(mac)
		require.NoError(t, err)
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
	for i := 0; i < 3; i++ {
		mac := rndHWAddr()
		// Change MAC
		ns.Do(func() error {
			veth1, err := netlink.LinkByName("veth1")
			require.NoError(t, err)
			err = netlink.LinkSetHardwareAddr(veth1, mac)
			require.NoError(t, err)
			return nil
		})

		// Check that MAC has been changed in the neigh table
		var found bool
		err := testutils.WaitUntilWithSleep(func() bool {
			neighs, err := netlink.NeighList(veth0.Attrs().Index, netlink.FAMILY_V4)
			require.NoError(t, err)
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
		}, 60*time.Second, 200*time.Millisecond)
		require.NoError(t, err)
		require.Equal(t, true, found)
	}

	// Cleanup
	close(done)
	wg.Wait()
	now = time.Now()
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
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
		ns2 := netns.NewNetNS(t)
		cleanup = func() {
			cleanup1()
			ns2.Close()
		}
		if errRet = netlink.LinkSetNsFd(veth2, int(ns.FD())); errRet != nil {
			return
		}
		if errRet = netlink.LinkSetNsFd(veth3, int(ns2.FD())); errRet != nil {
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

		if errRet = ns.Do(func() error {
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

		if errRet = ns2.Do(func() error {
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
	require.NoError(t, err)
	defer cleanup1()
	cleanup2, err := setupRemoteNode("veth4", "veth5", "test-arping-netns2",
		"7.7.7.248/29", "7.7.7.249", "7.7.7.250")
	require.NoError(t, err)
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
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev2))
	wait(nodev2.Identity(), "veth0", &now, false)

	node3IP := net.ParseIP("7.7.7.250")
	nodev3 := nodeTypes.Node{
		Name: "node3",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node3IP,
		}},
	}
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop := net.ParseIP("9.9.9.250")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Check that removing node2 will not remove nextHop, as it is still used by node3
	require.Nil(t, linuxNodeHandler.NodeDelete(nodev2))
	wait(nodev2.Identity(), "veth0", nil, true)

	assertNeigh(nextHop, func(n netlink.Neigh) bool { return true })

	// However, removing node3 should remove the neigh entry for nextHop
	require.Nil(t, linuxNodeHandler.NodeDelete(nodev3))
	wait(nodev3.Identity(), "veth0", nil, true)

	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)

	now = time.Now()
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("9.9.9.250")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// We have stored the devices in NodeConfigurationChanged
	linuxNodeHandler.NodeCleanNeighbors(false)

	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

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
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev2))
	wait(nodev2.Identity(), "veth0", &now, false)

	now = time.Now()
	require.Nil(t, linuxNodeHandler.NodeAdd(nodev3))
	wait(nodev3.Identity(), "veth0", &now, false)

	nextHop = net.ParseIP("9.9.9.250")

	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Switch to new nextHop address for node2
	err = setupNewGateway("8.8.8.248/29", "9.9.9.251")
	require.NoError(t, err)

	// waitGw waits for the nextHop to appear in the agent's nextHop table
	waitGw := func(nextHopNew string, nodeID nodeTypes.Identity, link string, before *time.Time) {
		t.Helper()
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
		require.NoError(t, err)
	}

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2, true)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3, true)
	waitGw("9.9.9.251", nodev2.Identity(), "veth0", &now)
	waitGw("9.9.9.250", nodev3.Identity(), "veth0", &now)

	// Both nextHops now need to be present
	nextHop = net.ParseIP("9.9.9.250")
	assertNeigh(nextHop, neighStateOk)
	nextHop = net.ParseIP("9.9.9.251")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	// Now also switch over the other node.
	err = setupNewGateway("7.7.7.248/29", "9.9.9.251")
	require.NoError(t, err)

	// insertNeighbor is invoked async, so thus this wait based on last ping
	now = time.Now()
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev2, true)
	linuxNodeHandler.NodeNeighborRefresh(context.Background(), nodev3, true)
	waitGw("9.9.9.251", nodev2.Identity(), "veth0", &now)
	waitGw("9.9.9.251", nodev3.Identity(), "veth0", &now)

	nextHop = net.ParseIP("9.9.9.250")

	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)
	assertNoNeigh("node{2,3} should not be in the same L2", node2IP, node3IP)

	nextHop = net.ParseIP("9.9.9.251")
	assertNeigh(nextHop, neighStateOk)

	require.Nil(t, linuxNodeHandler.NodeDelete(nodev3))
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
	require.NoError(t, err)

	// Check that new nextHop address got added, we don't care about its NUD_* state
	assertNeigh(nextHop, func(n netlink.Neigh) bool { return true })

	// Clean unrelated externally learned entries
	linuxNodeHandler.NodeCleanNeighborsLink(veth0, true)

	// Check that new nextHop address got removed
	assertNoNeigh("expected removed neigh "+nextHop.String(), nextHop)

	// Check that node2 nextHop address is still there
	nextHop = net.ParseIP("9.9.9.251")
	assertNeigh(nextHop, neighStateOk)
	assertNoNeigh("node2 should not be in the same L2", node2IP)

	require.Nil(t, linuxNodeHandler.NodeDelete(nodev2))
	wait(nodev2.Identity(), "veth0", nil, true)

	linuxNodeHandler.NodeCleanNeighborsLink(veth0, false)
}

func TestArpPingHandlingForMultiDeviceIPv4(t *testing.T) {
	s := setupLinuxPrivilegedIPv4OnlyTestSuite(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevEnableL2NeighDiscovery := option.Config.EnableL2NeighDiscovery
	defer func() { option.Config.EnableL2NeighDiscovery = prevEnableL2NeighDiscovery }()

	option.Config.EnableL2NeighDiscovery = true

	prevStateDir := option.Config.StateDir
	defer func() { option.Config.StateDir = prevStateDir }()

	tmpDir := t.TempDir()
	option.Config.StateDir = tmpDir

	baseTimeOld, err := s.sysctl.Read(baseIPv4Time)
	require.NoError(t, err)
	err = s.sysctl.Write(baseIPv4Time, fmt.Sprintf("%d", baseTime))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(baseIPv4Time, baseTimeOld) }()

	mcastNumOld, err := s.sysctl.Read(mcastNumIPv4)
	require.NoError(t, err)
	err = s.sysctl.Write(mcastNumIPv4, fmt.Sprintf("%d", mcastNum))
	require.NoError(t, err)
	defer func() { s.sysctl.Write(mcastNumIPv4, mcastNumOld) }()

	// 1. Test whether another node with multiple paths can be arpinged.
	//    Each node has two devices and the other node in the different netns
	//    is reachable via either pair.
	//    Neighbor entries are not installed on devices where no route exists.
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
	//      |              |     |              |
	//      | 7.7.7.249/29 |     |              |
	//      |  |           |     |              |
	//      | veth4        |     |              |
	//      +-+------------+     +--------------+
	//        |
	//      +-+---------------------------------+
	//      | veth5      other netns            |
	//      |  |                                |
	//      | 7.7.7.250/29                      |
	//      +-----------------------------------+

	// Setup
	vethPair01 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(vethPair01)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair01) })
	veth0, err := netlink.LinkByName("veth0")
	require.NoError(t, err)
	veth1, err := netlink.LinkByName("veth1")
	require.NoError(t, err)
	_, ipnet, _ := net.ParseCIDR("9.9.9.252/29")
	v1IP0 := net.ParseIP("9.9.9.249")
	v1IP1 := net.ParseIP("9.9.9.250")
	v1IPG := net.ParseIP("9.9.9.251")
	ipnet.IP = v1IP0
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth0, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth0)
	require.NoError(t, err)

	ns := netns.NewNetNS(t)

	err = netlink.LinkSetNsFd(veth1, int(ns.FD()))
	require.NoError(t, err)
	node1Addr, err := netlink.ParseAddr("10.0.0.1/32")
	require.NoError(t, err)
	err = ns.Do(func() error {
		lo, err := netlink.LinkByName("lo")
		require.NoError(t, err)
		err = netlink.LinkSetUp(lo)
		require.NoError(t, err)
		err = netlink.AddrAdd(lo, node1Addr)
		require.NoError(t, err)

		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		ipnet.IP = v1IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		ipnet.IP = v1IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth1, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth1)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	vethPair23 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth2"},
		PeerName:  "veth3",
	}
	err = netlink.LinkAdd(vethPair23)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair23) })
	veth2, err := netlink.LinkByName("veth2")
	require.NoError(t, err)
	veth3, err := netlink.LinkByName("veth3")
	require.NoError(t, err)
	_, ipnet, _ = net.ParseCIDR("8.8.8.252/29")
	v2IP0 := net.ParseIP("8.8.8.249")
	v2IP1 := net.ParseIP("8.8.8.250")
	v2IPG := net.ParseIP("8.8.8.251")
	ipnet.IP = v2IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth2, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth2)
	require.NoError(t, err)

	err = netlink.LinkSetNsFd(veth3, int(ns.FD()))
	require.NoError(t, err)
	err = ns.Do(func() error {
		veth3, err := netlink.LinkByName("veth3")
		require.NoError(t, err)
		ipnet.IP = v2IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		require.NoError(t, err)
		ipnet.IP = v2IPG
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth3, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth3)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	r := &netlink.Route{
		Dst: netlink.NewIPNet(node1Addr.IP),
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
	require.NoError(t, err)
	defer netlink.RouteDel(r)

	// Setup another veth pair that doesn't have a route to node
	vethPair45 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth4"},
		PeerName:  "veth5",
	}
	err = netlink.LinkAdd(vethPair45)
	require.NoError(t, err)
	t.Cleanup(func() { netlink.LinkDel(vethPair45) })
	veth4, err := netlink.LinkByName("veth4")
	require.NoError(t, err)
	veth5, err := netlink.LinkByName("veth5")
	require.NoError(t, err)
	_, ipnet, _ = net.ParseCIDR("7.7.7.252/29")
	v3IP0 := net.ParseIP("7.7.7.249")
	v3IP1 := net.ParseIP("7.7.7.250")
	ipnet.IP = v3IP0
	addr = &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(veth4, addr)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth4)
	require.NoError(t, err)

	ns2 := netns.NewNetNS(t)

	err = netlink.LinkSetNsFd(veth5, int(ns2.FD()))
	require.NoError(t, err)
	err = ns2.Do(func() error {
		veth5, err := netlink.LinkByName("veth5")
		require.NoError(t, err)
		ipnet.IP = v3IP1
		addr = &netlink.Addr{IPNet: ipnet}
		err = netlink.AddrAdd(veth5, addr)
		require.NoError(t, err)
		err = netlink.LinkSetUp(veth5)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative
	prevDRDev := option.Config.DirectRoutingDevice
	defer func() { option.Config.DirectRoutingDevice = prevDRDev }()
	option.Config.DirectRoutingDevice = "veth0"
	prevNP := option.Config.EnableNodePort
	defer func() { option.Config.EnableNodePort = prevNP }()
	option.Config.EnableNodePort = true
	prevARPPeriod := option.Config.ARPPingRefreshPeriod
	defer func() { option.Config.ARPPingRefreshPeriod = prevARPPeriod }()
	option.Config.ARPPingRefreshPeriod = 1 * time.Nanosecond

	mq := new(mockEnqueuer)
	dpConfig := DatapathConfiguration{HostDevice: "veth0"}
	log := hivetest.Logger(t)
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), mq)
	mq.nh = linuxNodeHandler

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices),
		getDevice(t, "veth0"),
		getDevice(t, "veth2"),
		getDevice(t, "veth4"))
	err = linuxNodeHandler.NodeConfigurationChanged(nodeConfig)
	require.NoError(t, err)

	// wait waits for neigh entry update or waits for removal if waitForDelete=true
	wait := func(nodeID nodeTypes.Identity, link string, before *time.Time, waitForDelete bool) {
		t.Helper()
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
		require.NoError(t, err)
	}

	assertNeigh := func(ip net.IP, link netlink.Link, checkNeigh func(neigh netlink.Neigh) bool) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			require.NoError(t, err)
			for _, n := range neighs {
				if n.IP.Equal(ip) && checkNeigh(n) {
					return true
				}
			}
			return false
		}, 5*time.Second)
		require.NoError(t, err, "expected neighbor %s", ip)
	}

	assertNoNeigh := func(link netlink.Link, ips ...net.IP) {
		t.Helper()
		err := testutils.WaitUntil(func() bool {
			neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			require.NoError(t, err)
			for _, n := range neighs {
				for _, ip := range ips {
					if n.IP.Equal(ip) {
						return false
					}
				}
			}
			return true
		}, 5*time.Second)
		require.NoError(t, err, "expected no neighbors: %v", ips)
	}

	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: nodeaddressing.NodeInternalIP,
			IP:   node1Addr.IP,
		}},
	}
	now := time.Now()
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async
	// Insert the same node second time. This should not increment refcount for
	// the same nextHop. We test it by checking that NodeDelete has removed the
	// related neigh entry.
	err = linuxNodeHandler.NodeAdd(nodev1)
	require.NoError(t, err)
	// insertNeighbor is invoked async, so thus this wait based on last ping
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)

	// Check whether an arp entry for nodev1 IP addr (=veth1) was added
	assertNeigh(v1IP1, veth0, neighStateOk)

	// Check whether an arp entry for nodev2 IP addr (=veth3) was added
	assertNeigh(v2IP1, veth2, neighStateOk)

	// Check whether we don't install the neighbor entries to nodes on the device where the actual route isn't.
	// "Consistently(<check>, 5sec, 1sec)"
	start := time.Now()
	for {
		if time.Since(start) > 5*time.Second {
			break
		}

		neighs, err := netlink.NeighList(veth4.Attrs().Index, netlink.FAMILY_V4)
		require.NoError(t, err)
		found := false
		for _, n := range neighs {
			if n.IP.Equal(v3IP1) || n.IP.Equal(node1Addr.IP) {
				found = true
			}
		}
		require.Equal(t, false, found)

		time.Sleep(1 * time.Second)
	}

	// Swap MAC addresses of veth0 and veth1, veth2 and veth3 to ensure the MAC address of veth1 changed.
	// Trigger neighbor refresh on veth0 and check whether the arp entry was updated.
	var veth0HwAddr, veth1HwAddr, veth2HwAddr, veth3HwAddr, updatedHwAddrFromArpEntry net.HardwareAddr
	veth0HwAddr = veth0.Attrs().HardwareAddr
	veth2HwAddr = veth2.Attrs().HardwareAddr
	err = ns.Do(func() error {
		veth1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		veth1HwAddr = veth1.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth1, veth0HwAddr)
		require.NoError(t, err)

		veth3, err := netlink.LinkByName("veth3")
		require.NoError(t, err)
		veth3HwAddr = veth3.Attrs().HardwareAddr
		err = netlink.LinkSetHardwareAddr(veth3, veth2HwAddr)
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	now = time.Now()
	err = netlink.LinkSetHardwareAddr(veth0, veth1HwAddr)
	require.NoError(t, err)
	err = netlink.LinkSetHardwareAddr(veth2, veth3HwAddr)
	require.NoError(t, err)

	linuxNodeHandler.NodeNeighborRefresh(context.TODO(), nodev1, true)
	wait(nodev1.Identity(), "veth0", &now, false)
	wait(nodev1.Identity(), "veth2", &now, false)

	assertNeigh(v1IP1, veth0,
		func(neigh netlink.Neigh) bool {
			if neighStateOk(neigh) {
				updatedHwAddrFromArpEntry = neigh.HardwareAddr
				return true
			}
			return false
		})

	require.Equal(t, veth0HwAddr.String(), updatedHwAddrFromArpEntry.String())

	assertNeigh(v2IP1, veth2,
		func(neigh netlink.Neigh) bool {
			if neighStateOk(neigh) {
				updatedHwAddrFromArpEntry = neigh.HardwareAddr
				return true
			}
			return false
		})

	require.Equal(t, veth2HwAddr.String(), updatedHwAddrFromArpEntry.String())

	// Remove nodev1, and check whether the arp entry was removed
	err = linuxNodeHandler.NodeDelete(nodev1)
	require.NoError(t, err)
	// deleteNeighbor is invoked async too
	wait(nodev1.Identity(), "veth0", nil, true)
	wait(nodev1.Identity(), "veth2", nil, true)

	assertNoNeigh(veth0, v1IP1)
	assertNoNeigh(veth2, v2IP1)
}

func BenchmarkAll(b *testing.B) {
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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
	linuxNodeHandler := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), new(mockEnqueuer))

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
