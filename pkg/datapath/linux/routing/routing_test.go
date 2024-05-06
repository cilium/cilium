// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func setupLinuxRoutingSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)
}

func TestConfigure(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns1 := netns.NewNetNS(t)
	ns1.Do(func() error {
		ip, ri := getFakes(t, true, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})

	ns2 := netns.NewNetNS(t)
	ns2.Do(func() error {
		ip, ri := getFakes(t, false, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})

	ns3 := netns.NewNetNS(t)
	ns3.Do(func() error {
		ip, ri := getFakes(t, true, true)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()
		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})
}

func TestConfigureIPv6(t *testing.T) {
	// Create a new network namespace for the test to ensure isolation
	nsIPv6 := netns.NewNetNS(t)
	nsIPv6.Do(func() error {
		// Get fake IPv6 configuration and routing info
		ip, ri := getFakesIPv6()
		masterMAC := ri.MasterIfMAC

		// Create a dummy network device to simulate interface
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		// Run configuration and deletion tests
		runConfigureThenDeleteIPv6(t, ri, ip, 1500)
		return nil
	})
}

// getFakesIPv6 returns fake IPv6 addresses and routing information for testing
func getFakesIPv6() (net.IP, *RoutingInfo) {
	// Example IPv6 address and routing info
	ipv6Address := net.ParseIP("2001:db8::1")
	routingInfo := &RoutingInfo{
		IPv6Gateway:     net.ParseIP("2001:db8::fffe"),
		IPv6CIDRs:       []net.IPNet{{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}},
		MasterIfMAC:     mac.MAC{0x00, 0x15, 0x5d, 0x22, 0x54, 0x00},
		Masquerade:      true,
		InterfaceNumber: 2,
		IpamMode:        ipamOption.IPAMENI,
	}
	return ipv6Address, routingInfo
}

func TestDelete(t *testing.T) {
	setupLinuxRoutingSuite(t)

	fakeIP, fakeRoutingInfo := getFakes(t, true, false)
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() netip.Addr
		wantErr bool
	}{
		{
			name: "valid IP addr matching rules",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IP addr doesn't match rules",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return ip
			},
			wantErr: true,
		},
		{
			name: "IP addr matches more than number expected",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, ip, 1500)

				// Find interface ingress rules so that we can create a
				// near-duplicate.
				rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
					Priority: linux_defaults.RulePriorityIngress,
				})
				require.Nil(t, err)
				require.NotEqual(t, 0, len(rules))

				// Insert almost duplicate rule; the reason for this is to
				// trigger an error while trying to delete the ingress rule. We
				// are setting the Src because ingress rules don't have
				// one (only Dst), thus we set Src to create a near-duplicate.
				r := rules[0]
				r.Src = &net.IPNet{IP: fakeIP.AsSlice(), Mask: net.CIDRMask(32, 32)}
				require.Nil(t, netlink.RuleAdd(&r))

				return ip
			},
			wantErr: true,
		},
		{
			name: "fails to delete rules due to masquerade misconfiguration",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				// inconsistency with fakeRoutingInfo.Masquerade should lead to failure
				option.Config.EnableIPv4Masquerade = false
				return fakeIP
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Log("Test: " + tt.name)
		ns := netns.NewNetNS(t)
		ns.Do(func() error {
			ifaceCleanup := createDummyDevice(t, masterMAC)
			defer ifaceCleanup()

			ip := tt.preRun()
			err := Delete(ip, false)
			require.Equal(t, tt.wantErr, (err != nil))
			return nil
		})
	}
}

func TestDeleteIPv6(t *testing.T) {
	fakeIP, fakeRoutingInfo := getFakes(t, true, true)
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() netip.Addr
		wantErr bool
	}{
		{
			name: "valid IPv6 addr matching rules",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IPv6 addr doesn't match rules",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("2001:db8::321")

				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return ip
			},
			wantErr: true,
		},
		{
			name: "IPv6 addr matches more rules than number expected",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("2001:db8::321")

				runConfigure(t, fakeRoutingInfo, ip, 1500)

				// Find interface ingress rules so that we can create a
				// near-duplicate.
				rules, err := route.ListRules(netlink.FAMILY_V6, &route.Rule{
					Priority: linux_defaults.RulePriorityIngress,
				})
				require.Nil(t, err)
				require.NotEqual(t, len(rules), 0)

				// Insert almost duplicate rule; the reason for this is to
				// trigger an error while trying to delete the ingress rule. We
				// are setting the Src because ingress rules don't have
				// one (only Dst), thus we set Src to create a near-duplicate.
				r := rules[0]
				r.Src = &net.IPNet{IP: fakeIP.AsSlice(), Mask: net.CIDRMask(128, 128)}
				require.Nil(t, netlink.RuleAdd(&r))

				return ip
			},
			wantErr: true,
		},
		{
			name: "fails to delete rules due to IPv6 masquerade misconfiguration",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				// inconsistency with fakeRoutingInfo.Masquerade should lead to failure
				option.Config.EnableIPv6Masquerade = false
				return fakeIP
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Log("Test: " + tt.name)
		ns := netns.NewNetNS(t)
		ns.Do(func() error {
			ifaceCleanup := createDummyDevice(t, masterMAC)
			defer ifaceCleanup()

			ip := tt.preRun()
			err := Delete(ip, false)
			require.Equal(t, (err != nil), tt.wantErr)
			return nil
		})
	}
}

func runConfigureThenDelete(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	// Determine if the rule is for IPv4 or IPv6
	family := netlink.FAMILY_V4
	if ip.Is6() {
		family = netlink.FAMILY_V6
	}

	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(t, family)
	runConfigure(t, ri, ip, mtu)
	afterCreationRules, afterCreationRoutes := listRulesAndRoutes(t, family)

	require.NotEqual(t, 0, len(afterCreationRules))
	require.NotEqual(t, 0, len(afterCreationRoutes))
	require.NotEqual(t, len(afterCreationRules), len(beforeCreationRules))
	require.NotEqual(t, len(afterCreationRoutes), len(beforeCreationRoutes))

	// Delete rules and routes
	beforeDeletionRules, beforeDeletionRoutes := listRulesAndRoutes(t, family)
	runDelete(t, ip)
	afterDeletionRules, afterDeletionRoutes := listRulesAndRoutes(t, family)

	require.NotEqual(t, len(afterDeletionRules), len(beforeDeletionRules))
	require.NotEqual(t, len(afterDeletionRoutes), len(beforeDeletionRoutes))
	require.Equal(t, len(beforeCreationRules), len(afterDeletionRules))
	require.Equal(t, len(beforeCreationRoutes), len(afterDeletionRoutes))
}

func runConfigure(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	err := ri.Configure(ip.AsSlice(), mtu, false, false)
	require.Nil(t, err)
}

// runConfigureThenDeleteIPv6 configures and then deletes IPv6 routes and rules
func runConfigureThenDeleteIPv6(t *testing.T, ri *RoutingInfo, ip net.IP, mtu int) {
	err := ri.Configure(ip, mtu, false, false)
	require.Nilf(t, err, "Failed to configure IPv6 routing: %s", err)
}

func runDelete(t *testing.T, ip netip.Addr) {
	err := Delete(ip, false)
	require.Nil(t, err)
}

// listRulesAndRoutes returns all rules and routes configured on the machine
// this test is running on. Note that this function is intended to be used
// within a network namespace for isolation.
func listRulesAndRoutes(t *testing.T, family int) ([]netlink.Rule, []netlink.Route) {
	rules, err := route.ListRules(family, nil)
	require.Nil(t, err)

	// Rules are created under specific tables, so find the routes that are in
	// those tables.
	var routes []netlink.Route
	for _, r := range rules {
		rr, err := netlink.RouteListFiltered(family, &netlink.Route{
			Table: r.Table,
		}, netlink.RT_FILTER_TABLE)
		require.Nil(t, err)

		if family == netlink.FAMILY_V6 {
			// Filter out IPv6 link-local routes
			rr = filterLinkLocalAndMcastRoutes(rr)
		}

		routes = append(routes, rr...)
	}

	return rules, routes
}

// filterLinkLocalAndMcastRoutes excludes IPv6 link-local unicast and multicast
// routes from a slice of routes.
func filterLinkLocalAndMcastRoutes(routes []netlink.Route) []netlink.Route {
	var filteredRoutes []netlink.Route
	for _, r := range routes {
		if r.Dst != nil && !r.Dst.IP.IsLinkLocalUnicast() && !r.Dst.IP.IsMulticast() {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

// createDummyDevice creates a new dummy device with a MAC of `macAddr` to be
// used as a harness in this test. This function returns a function which can
// be used to remove the device for cleanup purposes.
func createDummyDevice(t *testing.T, macAddr mac.MAC) func() {
	if linkExistsWithMAC(t, macAddr) {
		t.FailNow()
	}

	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			// NOTE: This name must be less than 16 chars, source:
			// https://elixir.bootlin.com/linux/v5.6/source/include/uapi/linux/if.h#L33
			Name:         "linuxrout-test",
			HardwareAddr: net.HardwareAddr(macAddr),
		},
	}
	err := netlink.LinkAdd(dummy)
	require.Nil(t, err)

	found := linkExistsWithMAC(t, macAddr)
	require.Equal(t, true, found)

	return func() {
		require.Nil(t, netlink.LinkDel(dummy))
	}
}

// getFakes returns a fake IP simulating an Endpoint IP and RoutingInfo as test harnesses.
// To create routing info with a list of CIDRs which the interface has access to, set withCIDR parameter to true
func getFakes(t *testing.T, withCIDR, withV6 bool) (netip.Addr, RoutingInfo) {
	fakeGateway := netip.MustParseAddr("192.168.2.1")
	fakeSubnet1CIDR := netip.MustParsePrefix("192.168.0.0/16")
	fakeSubnet2CIDR := netip.MustParsePrefix("192.170.0.0/16")
	fakeMAC, err := mac.ParseMAC("00:11:22:33:44:55")
	require.Nil(t, err)
	require.NotNil(t, fakeMAC)

	if withV6 {
		fakeGateway = netip.MustParseAddr("2001:db8::1")
		fakeSubnet1CIDR = netip.MustParsePrefix("2001:db8::/80")
		fakeSubnet2CIDR = netip.MustParsePrefix("2001:db9::/80")
	}

	var fakeRoutingInfo *RoutingInfo
	if withCIDR {
		fakeRoutingInfo, err = parse(
			fakeGateway.String(),
			[]string{fakeSubnet1CIDR.String(), fakeSubnet2CIDR.String()},
			fakeMAC.String(),
			"1",
			ipamOption.IPAMENI,
			true,
		)
	} else {
		fakeRoutingInfo, err = parse(
			fakeGateway.String(),
			nil,
			fakeMAC.String(),
			"1",
			ipamOption.IPAMAzure,
			false,
		)
	}
	require.Nil(t, err)
	require.NotNil(t, fakeRoutingInfo)

	node.SetRouterInfo(fakeRoutingInfo)
	option.Config.IPAM = fakeRoutingInfo.IpamMode
	option.Config.EnableIPv4Masquerade = fakeRoutingInfo.Masquerade

	fakeIP := netip.MustParseAddr("192.168.2.123")
	if withV6 {
		fakeIP = netip.MustParseAddr("2001:db8::123")
		option.Config.EnableIPv4Masquerade = false
		option.Config.EnableIPv6Masquerade = fakeRoutingInfo.Masquerade
	}
	return fakeIP, *fakeRoutingInfo
}

func linkExistsWithMAC(t *testing.T, macAddr mac.MAC) bool {
	links, err := netlink.LinkList()
	require.Nil(t, err)

	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == macAddr.String() {
			return true
		}
	}

	return false
}
