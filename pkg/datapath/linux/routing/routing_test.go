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
		ip, ri := getFakes(t, true)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})

	ns2 := netns.NewNetNS(t)
	ns2.Do(func() error {
		ip, ri := getFakes(t, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})
}

func TestConfigureRouteWithIncompatibleIP(t *testing.T) {
	setupLinuxRoutingSuite(t)

	_, ri := getFakes(t, true)
	ipv6 := netip.MustParseAddr("fd00::2").AsSlice()
	err := ri.Configure(ipv6, 1500, false, false)
	require.Error(t, err)
	require.ErrorContains(t, err, "IP not compatible")
}

func TestDeleteRouteWithIncompatibleIP(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ipv6 := netip.MustParseAddr("fd00::2")
	err := Delete(ipv6, false)
	require.Error(t, err)
	require.ErrorContains(t, err, "IP not compatible")
}

func TestDelete(t *testing.T) {
	setupLinuxRoutingSuite(t)

	fakeIP, fakeRoutingInfo := getFakes(t, true)
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

func runConfigureThenDelete(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)
	runConfigure(t, ri, ip, mtu)
	afterCreationRules, afterCreationRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)

	require.NotEqual(t, 0, len(afterCreationRules))
	require.NotEqual(t, 0, len(afterCreationRoutes))
	require.NotEqual(t, len(afterCreationRules), len(beforeCreationRules))
	require.NotEqual(t, len(afterCreationRoutes), len(beforeCreationRoutes))

	// Delete rules and routes
	beforeDeletionRules, beforeDeletionRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)
	runDelete(t, ip)
	afterDeletionRules, afterDeletionRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)

	require.NotEqual(t, len(afterDeletionRules), len(beforeDeletionRules))
	require.NotEqual(t, len(afterDeletionRoutes), len(beforeDeletionRoutes))
	require.Equal(t, len(beforeCreationRules), len(afterDeletionRules))
	require.Equal(t, len(beforeCreationRoutes), len(afterDeletionRoutes))
}

func runConfigure(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	err := ri.Configure(ip.AsSlice(), mtu, false, false)
	require.Nil(t, err)
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

		routes = append(routes, rr...)
	}

	return rules, routes
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
func getFakes(t *testing.T, withCIDR bool) (netip.Addr, RoutingInfo) {
	fakeGateway := netip.MustParseAddr("192.168.2.1")
	fakeSubnet1CIDR := netip.MustParsePrefix("192.168.0.0/16")
	fakeSubnet2CIDR := netip.MustParsePrefix("192.170.0.0/16")
	fakeMAC, err := mac.ParseMAC("00:11:22:33:44:55")
	require.Nil(t, err)
	require.NotNil(t, fakeMAC)

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
