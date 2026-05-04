// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"bytes"
	"fmt"
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
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/kpr"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeaddressing "github.com/cilium/cilium/pkg/node/addressing"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	tnl "github.com/cilium/cilium/pkg/testutils/netlink"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

type nodeSuite struct {
	ns         *netns.NetNS
	sysctl     sysctl.Sysctl
	mtuCalc    mtu.RouteMTU
	enableIPv4 bool
	enableIPv6 bool

	// nodeConfigTemplate is the partially filled template for local node configuration.
	// copy it, don't mutate it.
	nodeConfigTemplate config.Config
}

func setup(tb testing.TB, family string) *nodeSuite {
	switch family {
	case "IPv4":
		return setupNodeSuite(tb, fakenode.NewIPv4OnlyAddressing(), false, true)
	case "IPv6":
		return setupNodeSuite(tb, fakenode.NewIPv6OnlyAddressing(), true, false)
	case "dual":
		return setupNodeSuite(tb, fakenode.NewAddressing(), true, true)
	}

	tb.Fatalf("unknown family: %s", family)

	return nil
}

const (
	hostDevice     = "host"
	externalDevice = "external"
)

var families = []string{"IPv4", "IPv6", "dual"}

func setupNodeSuite(tb testing.TB, addressing node.Addressing, enableIPv6, enableIPv4 bool) *nodeSuite {
	testutils.PrivilegedTest(tb)

	rlimit.RemoveMemlock()

	mtuConfig := mtu.NewConfiguration(0, false, false, false, false)
	s := &nodeSuite{
		ns:         netns.NewNetNS(tb),
		sysctl:     sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		mtuCalc:    mtuConfig.Calculate(1500),
		enableIPv6: enableIPv6,
		enableIPv4: enableIPv4,
	}
	tb.Cleanup(func() { s.ns.Close() })

	ips := make([]net.IP, 0)
	if enableIPv6 {
		ips = append(ips, addressing.IPv6().PrimaryExternal())
	}
	if enableIPv4 {
		ips = append(ips, addressing.IPv4().PrimaryExternal())
	}
	devExt := mustSetupDevice(tb, s.ns, externalDevice, ips...)

	ips = []net.IP{}
	if enableIPv4 {
		ips = append(ips, addressing.IPv4().Router())
	}
	if enableIPv6 {
		ips = append(ips, addressing.IPv6().Router())
	}
	devHost := mustSetupDevice(tb, s.ns, hostDevice, ips...)

	s.nodeConfigTemplate = config.Config{
		Devices:             []*tables.Device{devExt, devHost},
		DirectRoutingDevice: devHost,
		NodeIPv4:            ip.AddrFromIP(addressing.IPv4().PrimaryExternal()),
		NodeIPv6:            ip.AddrFromIP(addressing.IPv6().PrimaryExternal()),
		CiliumInternalIPv4:  ip.AddrFromIP(addressing.IPv4().Router()),
		CiliumInternalIPv6:  ip.AddrFromIP(addressing.IPv6().Router()),
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

func mustSetupDevice(tb testing.TB, ns *netns.NetNS, name string, ips ...net.IP) *tables.Device {
	tb.Helper()

	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}

	tnl.MustLinkAdd(tb, ns, dummy)
	tnl.MustLinkSetUp(tb, ns, dummy)

	for _, ip := range ips {
		var ipnet *net.IPNet
		if ip.To4() != nil {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}

		tnl.MustAddrAdd(tb, ns, dummy, netlink.Addr{IPNet: ipnet})
	}

	link := tnl.MustLinkByName(tb, ns, name)
	return &tables.Device{
		Index:        link.Attrs().Index,
		MTU:          link.Attrs().MTU,
		Name:         name,
		HardwareAddr: tables.HardwareAddr(link.Attrs().HardwareAddr),
		Type:         "dummy",
		Selected:     true,
	}
}

func mustAddNode(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, node nodeTypes.Node) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.NodeAdd(node)
	}))
}

func mustUpdateNode(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, old, new nodeTypes.Node) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.NodeUpdate(old, new)
	}))
}

func mustDeleteNode(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, node nodeTypes.Node) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.NodeDelete(node)
	}))
}

func mustConfigureNode(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, nodeConfig config.Config) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.NodeConfigurationChanged(nodeConfig)
	}))
}

func mustValidateNodeImplementation(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, node nodeTypes.Node) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.NodeValidateImplementation(node)
	}))
}

func mustUpdateNodeRoute(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, cidr *cidr.CIDR) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.updateNodeRoute(cidr, true, false)
	}))
}

func mustDeleteNodeRoute(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, cidr *cidr.CIDR) {
	tb.Helper()
	require.NoError(tb, ns.Do(func() error {
		return lnh.deleteNodeRoute(cidr, false)
	}))
}

// mustGetNodeRoute looks up a node route for the given CIDR in the given namespace and returns it.
func mustGetNodeRoute(tb testing.TB, ns *netns.NetNS, lnh *linuxNodeHandler, cidr *cidr.CIDR) *route.Route {
	tb.Helper()

	var r *route.Route
	require.NoError(tb, ns.Do(func() error {
		var err error
		r, err = lnh.lookupNodeRoute(cidr, false)
		return err
	}))
	return r
}

func testWithFamilies(t *testing.T, f func(t *testing.T, family string)) {
	t.Helper()

	for _, family := range families {
		t.Run(family, func(t *testing.T) {
			f(t, family)
		})
	}
}

func TestPrivilegedUpdateNodeRoute(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpdateNodeRoute(t, family)
	})
}

func testUpdateNodeRoute(t *testing.T, family string) {
	s := setup(t, family)

	ip4CIDR := cidr.MustParseCIDR("254.254.254.0/24")
	require.NotNil(t, ip4CIDR)

	ip6CIDR := cidr.MustParseCIDR("cafe:cafe:cafe:cafe::/96")
	require.NotNil(t, ip6CIDR)

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})

	a, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)

	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, a, fakeipsec.Config{}, lns)
	mustConfigureNode(t, s.ns, lnh, s.nodeConfigTemplate)

	if s.enableIPv4 {
		// add & remove IPv4 node route
		mustUpdateNodeRoute(t, s.ns, lnh, ip4CIDR)
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4CIDR)
		require.NotNil(t, foundRoute)

		mustDeleteNodeRoute(t, s.ns, lnh, ip4CIDR)
		foundRoute = mustGetNodeRoute(t, s.ns, lnh, ip4CIDR)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// add & remove IPv6 node route
		mustUpdateNodeRoute(t, s.ns, lnh, ip6CIDR)
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6CIDR)
		require.NotNil(t, foundRoute)

		mustDeleteNodeRoute(t, s.ns, lnh, ip6CIDR)
		foundRoute = mustGetNodeRoute(t, s.ns, lnh, ip6CIDR)
		require.Nil(t, foundRoute)
	}
}

func TestPrivilegedAuxiliaryPrefixes(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testAuxiliaryPrefixes(t, family)
	})
}

func testAuxiliaryPrefixes(t *testing.T, family string) {
	s := setup(t, family)

	net1 := cidr.MustParseCIDR("30.30.0.0/24")
	net2 := cidr.MustParseCIDR("cafe:f00d::/112")

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	ipsecAgent, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)

	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsecAgent, fakeipsec.Config{}, lns)
	nodeConfig := s.nodeConfigTemplate
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net1, net2}
	mustConfigureNode(t, s.ns, lnh, nodeConfig)

	if s.enableIPv4 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net1)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net2)
		require.NotNil(t, foundRoute)
	}

	// remove aux prefix net2
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net1}
	mustConfigureNode(t, s.ns, lnh, nodeConfig)

	if s.enableIPv4 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net1)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net2)
		require.Nil(t, foundRoute)
	}

	// remove aux prefix net1, re-add net2
	nodeConfig.AuxiliaryPrefixes = []*cidr.CIDR{net2}
	mustConfigureNode(t, s.ns, lnh, nodeConfig)

	if s.enableIPv4 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net1)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, net2)
		require.NotNil(t, foundRoute)
	}
}

func TestPrivilegedNodeUpdateEncapsulation(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeUpdateEncapsulation(t, family)
	})
}

func testNodeUpdateEncapsulation(t *testing.T, family string) {
	commonNodeUpdateEncapsulation(t, family, true, nil)
}

func TestPrivilegedNodeUpdateEncapsulationWithOverride(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeUpdateEncapsulationWithOverride(t, family)
	})
}

func testNodeUpdateEncapsulationWithOverride(t *testing.T, family string) {
	commonNodeUpdateEncapsulation(t, family, false, func(*nodeTypes.Node) bool { return true })
}

func commonNodeUpdateEncapsulation(t *testing.T, family string, encap bool, override func(*nodeTypes.Node) bool) {
	s := setup(t, family)

	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("6.6.6.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")
	ip6Alloc2 := cidr.MustParseCIDR("2001:bbbb::/96")

	externalNodeIP1 := net.ParseIP("4.4.4.4")

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	ipsecAgent, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsecAgent, fakeipsec.Config{}, lns)

	lnh.OverrideEnableEncapsulation(override)

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = encap
	mustConfigureNode(t, s.ns, lnh, nodeConfig)

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

	mustAddNode(t, s.ns, lnh, nodev1)

	if s.enableIPv4 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4Alloc1)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6Alloc1)
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

	mustUpdateNode(t, s.ns, lnh, nodev1, nodev2)

	if s.enableIPv4 {
		// node routes for alloc1 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4Alloc1)
		require.Nil(t, foundRoute)

		// node routes for alloc2 ranges should have been installed
		foundRoute = mustGetNodeRoute(t, s.ns, lnh, ip4Alloc2)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc1 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6Alloc1)
		require.Nil(t, foundRoute)

		// node routes for alloc2 ranges should have been installed
		foundRoute = mustGetNodeRoute(t, s.ns, lnh, ip6Alloc2)
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
	mustUpdateNode(t, s.ns, lnh, nodev2, nodev3)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4Alloc2)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6Alloc2)
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

	mustUpdateNode(t, s.ns, lnh, nodev3, nodev4)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should have been installed
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4Alloc2)
		require.NotNil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should have been installed
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6Alloc2)
		require.NotNil(t, foundRoute)
	}

	// delete nodev4
	mustDeleteNode(t, s.ns, lnh, nodev4)

	if s.enableIPv4 {
		// node routes for alloc2 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip4Alloc2)
		require.Nil(t, foundRoute)
	}

	if s.enableIPv6 {
		// node routes for alloc2 ranges should be gone
		foundRoute := mustGetNodeRoute(t, s.ns, lnh, ip6Alloc2)
		require.Nil(t, foundRoute)
	}
}

func TestPrivilegedNodeUpdateIDs(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeUpdateIDs(t, family)
	})
}

// Tests that the node ID BPF map is correctly updated during the lifecycle of
// nodes and that the mapping nodeID:node remains 1:1.
func testNodeUpdateIDs(t *testing.T, family string) {
	s := setup(t, family)

	nodeIP1 := netip.MustParseAddr("4.4.4.4")
	nodeIP2 := netip.MustParseAddr("8.8.8.8")
	nodeIP3 := netip.MustParseAddr("1.1.1.1")

	nodeMap := nodemapfake.NewFakeNodeMapV2()

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	ipsecAgent, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)

	lnh := newNodeHandler(log, dpConfig, nodeMap, kpr.KPRConfig{}, ipsecAgent, fakeipsec.Config{}, lns)

	mustConfigureNode(t, s.ns, lnh, s.nodeConfigTemplate)

	// New node receives a node ID.
	node1v1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: nodeIP1.AsSlice(), Type: nodeaddressing.NodeInternalIP},
		},
	}
	mustAddNode(t, s.ns, lnh, node1v1)

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
	mustUpdateNode(t, s.ns, lnh, node1v1, node1v2)

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
	mustUpdateNode(t, s.ns, lnh, node1v2, node1v3)

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
	mustAddNode(t, s.ns, lnh, node2)

	nodeValue4, err := nodeMap.Lookup(nodeIP1)
	require.NoError(t, err)
	require.NotEqual(t, nodeValue3.NodeID, nodeValue4.NodeID)

	// When the node is deleted, all references to its ID are also removed.
	mustDeleteNode(t, s.ns, lnh, node1v3)

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
	mustAddNode(t, s.ns, lnh, node3)

	nodeValue5, err := nodeMap.Lookup(nodeIP2)
	require.NoError(t, err)
	nodeValue6, err := nodeMap.Lookup(nodeIP3)
	require.NoError(t, err)
	require.Equal(t, nodeValue6.NodeID, nodeValue5.NodeID)
}

func TestPrivilegedNodeChurnXFRMLeaks(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeChurnXFRMLeaks(t, family)
	})
}

// Tests that we don't leak XFRM policies and states as nodes come and go.
func testNodeChurnXFRMLeaks(t *testing.T, family string) {
	s := setup(t, family)

	// Cover the XFRM configuration for IPAM modes cluster-pool, kubernetes, etc.
	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"
	testNodeChurnXFRMLeaksWithConfig(t, s, config)
}

func TestPrivilegedNodeChurnXFRMLeaksEncryptedOverlay(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeChurnXFRMLeaksEncryptedOverlay(t, family)
	})
}

// Tests the same as TestNodeChurnXFRMLeaks, but in tunneling mode. As a
// consequence, encrypted overlay will kick in.
func testNodeChurnXFRMLeaksEncryptedOverlay(t *testing.T, family string) {
	s := setup(t, family)

	config := s.nodeConfigTemplate
	config.EnableIPSec = true
	config.EnableEncapsulation = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"
	testNodeChurnXFRMLeaksWithConfig(t, s, config)
}

func TestPrivilegedNodeChurnXFRMLeaksSubnetMode(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeChurnXFRMLeaksSubnetMode(t, family)
	})
}

// Tests the same as linuxPrivilegedBaseTestSuite.TestNodeChurnXFRMLeaks just
// for the subnet encryption.
func testNodeChurnXFRMLeaksSubnetMode(t *testing.T, family string) {
	s := setup(t, family)

	externalNodeDevice := "ipsec_interface"
	config := s.nodeConfigTemplate
	config.EnableIPSec = true

	// In the case of subnet encryption, the IPsec logic retrieves the IP
	// address of the encryption interface directly so we need a dummy
	// interface.
	mustSetupDevice(t, s.ns, externalNodeDevice, net.ParseIP("1.1.1.1"), net.ParseIP("face::1"))
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
	testNodeChurnXFRMLeaksWithConfig(t, s, config)
}

func testNodeChurnXFRMLeaksWithConfig(t *testing.T, s *nodeSuite, config config.Config) {
	log := hivetest.Logger(t)
	a, err := ipsec.NewTestIPsecAgent(t, bytes.NewReader([]byte("6+ rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")))
	require.NoError(t, err)

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, a, fakeipsec.Config{}, lns)

	mustConfigureNode(t, s.ns, lnh, config)

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
	mustAddNode(t, s.ns, lnh, node)

	require.NotEmpty(t, tnl.MustXfrmStateList(t, s.ns, netlink.FAMILY_ALL))
	require.NotEqual(t, 0, countXFRMPolicies(tnl.MustXfrmPolicyList(t, s.ns, netlink.FAMILY_ALL)))

	// Removing the node removes those XFRM states and policies.
	mustDeleteNode(t, s.ns, lnh, node)

	require.Empty(t, tnl.MustXfrmStateList(t, s.ns, netlink.FAMILY_ALL))
	require.Equal(t, 0, countXFRMPolicies(tnl.MustXfrmPolicyList(t, s.ns, netlink.FAMILY_ALL)))
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

func mustLookupDirectRoute(tb testing.TB, ns *netns.NetNS, log *slog.Logger, CIDR *cidr.CIDR, nodeIP net.IP) []netlink.Route {
	family := netlink.FAMILY_V4
	if nodeIP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	var err error
	var routeSpec *netlink.Route
	require.NoError(tb, ns.Do(func() error {
		routeSpec, _, err = createDirectRouteSpec(log, CIDR, nodeIP, false)
		if err != nil {
			return fmt.Errorf("creating direct route spec: %w", err)
		}
		return nil
	}))

	return tnl.MustRouteListFiltered(tb, ns, family, routeSpec, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF)
}

func TestPrivilegedNodeUpdateDirectRouting(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeUpdateDirectRouting(t, family)
	})
}

func testNodeUpdateDirectRouting(t *testing.T, family string) {
	s := setup(t, family)

	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip4Alloc2 := cidr.MustParseCIDR("5.5.5.0/26")

	ipv4SecondaryAlloc1 := cidr.MustParseCIDR("5.5.6.0/24")
	ipv4SecondaryAlloc2 := cidr.MustParseCIDR("5.5.7.0/24")
	ipv4SecondaryAlloc3 := cidr.MustParseCIDR("5.5.8.0/24")

	externalNode1IP4v1 := net.ParseIP("4.4.4.4")
	externalNode1IP4v2 := net.ParseIP("4.4.4.5")

	externalNode1Device := "dummy_node1"
	dev1 := mustSetupDevice(t, s.ns, externalNode1Device, externalNode1IP4v1, net.ParseIP("face::1"))

	externalNode2Device := "dummy_node2"
	dev2 := mustSetupDevice(t, s.ns, externalNode2Device, externalNode1IP4v2, net.ParseIP("face::2"))

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	ipsecAgent, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)

	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsecAgent, fakeipsec.Config{}, lns)

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices), dev1, dev2)
	nodeConfig.EnableAutoDirectRouting = true

	expectedIPv4Routes := 0
	if s.enableIPv4 {
		expectedIPv4Routes = 1
	}

	mustConfigureNode(t, s.ns, lnh, nodeConfig)

	// nodev1: ip4Alloc1 => externalNodeIP1
	nodev1 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}
	mustAddNode(t, s.ns, lnh, nodev1)

	foundRoutes := mustLookupDirectRoute(t, s.ns, log, ip4Alloc1, externalNode1IP4v1)
	require.Len(t, foundRoutes, expectedIPv4Routes)

	// nodev2: ip4Alloc1 => externalNodeIP2
	nodev2 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc1,
	}

	mustUpdateNode(t, s.ns, lnh, nodev1, nodev2)

	require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc1, externalNode1IP4v2), expectedIPv4Routes)

	// nodev3: ip4Alloc2 => externalNodeIP2
	nodev3 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	mustUpdateNode(t, s.ns, lnh, nodev2, nodev3)

	// node routes for alloc1 ranges should be gone
	require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc1, externalNode1IP4v2)) // route should not exist regardless whether ipv4 is enabled or not

	// node routes for alloc2 ranges should have been installed
	require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2), expectedIPv4Routes)

	// nodev4: no longer announce CIDR
	nodev4 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
	}
	mustUpdateNode(t, s.ns, lnh, nodev3, nodev4)

	// node routes for alloc2 ranges should have been removed
	require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2))

	// nodev5: Re-announce CIDR
	nodev5 := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR: ip4Alloc2,
	}
	mustUpdateNode(t, s.ns, lnh, nodev4, nodev5)

	// node routes for alloc2 ranges should have been removed
	require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2), expectedIPv4Routes)

	// delete nodev5
	mustDeleteNode(t, s.ns, lnh, nodev5)

	// node routes for alloc2 ranges should be gone
	require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2)) // route should not exist regardless whether ipv4 is enabled or not

	// nodev6: Re-introduce node with secondary CIDRs
	nodev6 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v1, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc2},
	}
	mustAddNode(t, s.ns, lnh, nodev6)

	// expecting both primary and secondary routes to exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v1), expectedIPv4Routes)
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
	mustUpdateNode(t, s.ns, lnh, nodev6, nodev7)

	// Checks all three required routes exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v1), expectedIPv4Routes)
	}
	// Checks route for removed CIDR has been deleted
	require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ipv4SecondaryAlloc2, externalNode1IP4v1))

	// nodev8: Change node IP to externalNode1IP4v2
	nodev8 := nodeTypes.Node{
		Name: "node2",
		IPAddresses: []nodeTypes.Address{
			{IP: externalNode1IP4v2, Type: nodeaddressing.NodeInternalIP},
		},
		IPv4AllocCIDR:           ip4Alloc1,
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{ipv4SecondaryAlloc1, ipv4SecondaryAlloc3},
	}
	mustUpdateNode(t, s.ns, lnh, nodev7, nodev8)

	// Checks all routes with the new node IP exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v2), expectedIPv4Routes)
	}
	// Checks all routes with the old node IP have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v1))
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
	mustUpdateNode(t, s.ns, lnh, nodev8, nodev9)

	// Checks primary route has been created
	require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2), expectedIPv4Routes)

	// Checks all old routes have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc3} {
		require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v2))
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
	mustUpdateNode(t, s.ns, lnh, nodev9, nodev10)

	// expecting both primary and secondary routes to exist
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		require.Len(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v1), expectedIPv4Routes)
	}

	// node routes for alloc2 ranges should have been removed
	require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc2, externalNode1IP4v2))

	// delete nodev10
	mustDeleteNode(t, s.ns, lnh, nodev10)

	// all node routes must have been deleted
	for _, ip4Alloc := range []*cidr.CIDR{ip4Alloc1, ipv4SecondaryAlloc1, ipv4SecondaryAlloc2} {
		require.Empty(t, mustLookupDirectRoute(t, s.ns, log, ip4Alloc, externalNode1IP4v1))
	}
}

func mustInsertRoute(tb testing.TB, ns *netns.NetNS, n *linuxNodeHandler, prefix *cidr.CIDR) {
	tb.Helper()

	nodeRoute, err := n.createNodeRouteSpec(prefix, false)
	require.NoError(tb, err)

	nodeRoute.Device = externalDevice

	require.NoError(tb, ns.Do(func() error {
		return route.Upsert(hivetest.Logger(tb), nodeRoute)
	}))
}

func mustLookupRoute(tb testing.TB, ns *netns.NetNS, n *linuxNodeHandler, prefix *cidr.CIDR) bool {
	tb.Helper()

	routeSpec, err := n.createNodeRouteSpec(prefix, false)
	require.NoError(tb, err)

	routeSpec.Device = externalDevice

	var rt *route.Route
	require.NoError(tb, ns.Do(func() error {
		var err error
		rt, err = route.Lookup(routeSpec)
		return err
	}))

	return rt != nil
}

func TestPrivilegedNodeValidationDirectRouting(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodeValidationDirectRouting(t, family)
	})
}

func testNodeValidationDirectRouting(t *testing.T, family string) {
	s := setup(t, family)

	ip4Alloc1 := cidr.MustParseCIDR("5.5.5.0/24")
	ip6Alloc1 := cidr.MustParseCIDR("2001:aaaa::/96")

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	ipsecAgent, err := ipsec.NewTestIPsecAgent(t, nil)
	require.NoError(t, err)

	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, ipsecAgent, fakeipsec.Config{}, lns)

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.EnableEncapsulation = false
	lnh.nodeConfig = nodeConfig

	if s.enableIPv4 {
		mustInsertRoute(t, s.ns, lnh, ip4Alloc1)
	}

	if s.enableIPv6 {
		mustInsertRoute(t, s.ns, lnh, ip6Alloc1)
	}

	mustConfigureNode(t, s.ns, lnh, nodeConfig)

	nodev1 := nodeTypes.Node{
		Name:        "node1",
		IPAddresses: []nodeTypes.Address{},
	}

	if s.enableIPv4 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   net.IP(nodeConfig.NodeIPv4.AsSlice()),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv4AllocCIDR = ip4Alloc1
	}

	if s.enableIPv6 {
		nodev1.IPAddresses = append(nodev1.IPAddresses, nodeTypes.Address{
			IP:   net.IP(nodeConfig.NodeIPv6.AsSlice()),
			Type: nodeaddressing.NodeInternalIP,
		})
		nodev1.IPv6AllocCIDR = ip6Alloc1
	}

	mustAddNode(t, s.ns, lnh, nodev1)
	mustValidateNodeImplementation(t, s.ns, lnh, nodev1)

	if s.enableIPv4 {
		require.True(t, mustLookupRoute(t, s.ns, lnh, ip4Alloc1))
	}

	if s.enableIPv6 {
		require.True(t, mustLookupRoute(t, s.ns, lnh, ip6Alloc1))
	}
}

func mustLookupIPSecInRoutes(tb testing.TB, ns *netns.NetNS, family int, extDev string, prefixes []*cidr.CIDR) {
	tb.Helper()

	link := tnl.MustLinkByName(tb, ns, extDev)
	routes := tnl.MustRouteListFiltered(tb, ns, family, &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     linux_defaults.RouteTableIPSec,
		Protocol:  linux_defaults.RTProto,
		Type:      route.RTN_LOCAL,
	}, netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TYPE)
	require.Len(tb, routes, len(prefixes))

	dests := make([]*cidr.CIDR, 0, len(routes))
	for _, route := range routes {
		dests = append(dests, &cidr.CIDR{IPNet: route.Dst})
	}
	require.ElementsMatch(tb, dests, prefixes)
}

func mustLookupIPSecXFRMPoliciesOut(tb testing.TB, ns *netns.NetNS, family int, prefixes []*cidr.CIDR) {
	tb.Helper()

	policies := tnl.MustXfrmPolicyList(tb, ns, family)

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
	require.ElementsMatch(tb, dests, prefixes)
}

func mustLookupIPSecOutRoutes(tb testing.TB, ns *netns.NetNS, family int, extDev string, prefixes []*cidr.CIDR) {
	tb.Helper()

	link := tnl.MustLinkByName(tb, ns, extDev)
	routes := tnl.MustRouteListFiltered(tb, ns, family,
		&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Table:     linux_defaults.RouteTableIPSec,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)

	require.Len(tb, routes, len(prefixes))
	dests := make([]*cidr.CIDR, 0, len(routes))
	for _, route := range routes {
		dests = append(dests, &cidr.CIDR{IPNet: route.Dst})
	}
	require.ElementsMatch(tb, dests, prefixes)
}

func TestPrivilegedNodePodCIDRsChurnIPSec(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testNodePodCIDRsChurnIPSec(t, family)
	})
}

func testNodePodCIDRsChurnIPSec(t *testing.T, family string) {
	s := setup(t, family)

	remoteNode1IPv4, remoteNode1IPv6 := net.ParseIP("4.4.4.4"), net.ParseIP("face::1")
	remoteNode1Device := "remote_node_1"
	dev1 := mustSetupDevice(t, s.ns, remoteNode1Device, remoteNode1IPv4, remoteNode1IPv6)

	remoteNode2IPv4, remoteNode2IPv6 := net.ParseIP("4.4.4.5"), net.ParseIP("face::2")
	remoteNode2Device := "remote_node_2"
	dev2 := mustSetupDevice(t, s.ns, remoteNode2Device, remoteNode2IPv4, remoteNode2IPv6)

	dpConfig := DatapathConfiguration{HostDevice: hostDevice}
	log := hivetest.Logger(t)
	a, err := ipsec.NewTestIPsecAgent(t, bytes.NewReader([]byte("6+ rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")))
	require.NoError(t, err)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	lnh := newNodeHandler(log, dpConfig, nodemapfake.NewFakeNodeMapV2(), kpr.KPRConfig{}, a, fakeipsec.Config{}, lns)

	nodeConfig := s.nodeConfigTemplate
	nodeConfig.Devices = append(slices.Clone(nodeConfig.Devices), dev1, dev2)

	option.Config.RoutingMode = option.RoutingModeNative
	nodeConfig.EnableIPSec = true
	option.Config.BootIDFile = "/proc/sys/kernel/random/boot_id"

	// set "local_node" as the local node name
	nodeTypes.SetName("local_node")

	mustConfigureNode(t, s.ns, lnh, nodeConfig)

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
	mustAddNode(t, s.ns, lnh, localNodeV1)
	if s.enableIPv4 {
		mustLookupIPSecInRoutes(t, s.ns, netlink.FAMILY_V4, externalDevice, localIPv4AllocCIDRsV1)
	}
	if s.enableIPv6 {
		mustLookupIPSecInRoutes(t, s.ns, netlink.FAMILY_V6, externalDevice, localIPv6AllocCIDRsV1)
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
	mustUpdateNode(t, s.ns, lnh, localNodeV1, localNodeV2)
	if s.enableIPv4 {
		mustLookupIPSecInRoutes(t, s.ns, netlink.FAMILY_V4, externalDevice, localIPv4AllocCIDRsV2)
	}
	if s.enableIPv6 {
		mustLookupIPSecInRoutes(t, s.ns, netlink.FAMILY_V6, externalDevice, localIPv6AllocCIDRsV2)
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
	mustAddNode(t, s.ns, lnh, remoteNode1V1)
	if s.enableIPv4 {
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V4, hostDevice, remoteNode1IPv4AllocCIDRsV1)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V4, remoteNode1IPv4AllocCIDRsV1)
	}
	if s.enableIPv6 {
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V6, hostDevice, remoteNode1IPv6AllocCIDRsV1)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V6, remoteNode1IPv6AllocCIDRsV1)
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
	mustAddNode(t, s.ns, lnh, remoteNode2V1)
	if s.enableIPv4 {
		expectedCIDRs := slices.Concat(remoteNode1IPv4AllocCIDRsV1, remoteNode2IPv4AllocCIDRsV1)
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V4, hostDevice, expectedCIDRs)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V4, expectedCIDRs)
	}
	if s.enableIPv6 {
		expectedCIDRs := slices.Concat(remoteNode1IPv6AllocCIDRsV1, remoteNode2IPv6AllocCIDRsV1)
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V6, hostDevice, expectedCIDRs)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V6, expectedCIDRs)
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
	mustUpdateNode(t, s.ns, lnh, remoteNode2V1, remoteNode2V2)
	if s.enableIPv4 {
		expectedCIDRs := slices.Concat(remoteNode1IPv4AllocCIDRsV1, remoteNode2IPv4AllocCIDRsV2)
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V4, hostDevice, expectedCIDRs)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V4, expectedCIDRs)
	}
	if s.enableIPv6 {
		expectedCIDRs := slices.Concat(remoteNode1IPv6AllocCIDRsV1, remoteNode2IPv6AllocCIDRsV2)
		mustLookupIPSecOutRoutes(t, s.ns, netlink.FAMILY_V6, hostDevice, expectedCIDRs)
		mustLookupIPSecXFRMPoliciesOut(t, s.ns, netlink.FAMILY_V6, expectedCIDRs)
	}
}
