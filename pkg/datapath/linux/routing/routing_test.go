// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
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

func TestPrivilegedConfigure(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns1 := netns.NewNetNS(t)
	ns1.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMENI, true, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})

	ns2 := netns.NewNetNS(t)
	ns2.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMAzure, false, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})
}

func TestPrivilegedConfigureAzureMasquerade(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMAzure, true, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})
}

func TestPrivilegedConfigureZeros(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns1 := netns.NewNetNS(t)
	ns1.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMENI, true, true)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip, 1500)
		return nil
	})
}

func TestPrivilegedConfigureRouteWithIncompatibleIP(t *testing.T) {
	setupLinuxRoutingSuite(t)

	_, ri := getFakes(t, ipamOption.IPAMENI, true, false)
	err := ri.Configure(nil, 1500, false)
	require.Error(t, err)
	require.ErrorContains(t, err, "IP not compatible")
}

func TestPrivilegedDeleteRouteWithIncompatibleIP(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ip := netip.Addr{}
	err := Delete(hivetest.Logger(t), ip)
	require.Error(t, err)
	require.ErrorContains(t, err, "IP not compatible")
}

func TestPrivilegedDelete(t *testing.T) {
	setupLinuxRoutingSuite(t)

	fakeIP, fakeRoutingInfo := getFakes(t, ipamOption.IPAMENI, true, false)
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() netip.Addr
		wantErr bool
	}{
		{
			name: "valid IP addr matching a single rule",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IP addr doesn't match any rule",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				return ip
			},
			wantErr: true,
		},
		{
			name: "IP addr matches multiple rules",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, ip, 1500)

				// Find interface ingress rules so that we can create a
				// near-duplicate.
				rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
					Priority: linux_defaults.RulePriorityIngress,
				})
				require.NoError(t, err)
				require.NotEmpty(t, rules)

				// Insert almost duplicate rule; the reason for this is to
				// trigger the deletion of all the matching rules. We
				// are setting the Src because ingress rules don't have
				// one (only Dst), thus we set Src to create a near-duplicate.
				r := rules[0]
				r.Src = &net.IPNet{IP: fakeIP.AsSlice(), Mask: net.CIDRMask(32, 32)}
				require.NoError(t, netlink.RuleAdd(&r))

				return ip
			},
			wantErr: false,
		},
		{
			name: "delete rules with dest CIDR after masquerade is disabled",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP, 1500)
				option.Config.EnableIPv4Masquerade = false
				return fakeIP
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := netns.NewNetNS(t)
			ns.Do(func() error {
				ifaceCleanup := createDummyDevice(t, masterMAC)
				defer ifaceCleanup()

				ip := tt.preRun()
				err := Delete(hivetest.Logger(t), ip)
				require.Equalf(t, tt.wantErr, (err != nil), "got error: %v", err)

				return nil
			})
		})
	}
}

func runConfigureThenDelete(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)
	runConfigure(t, ri, ip, mtu)
	afterCreationRules, afterCreationRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)

	require.NotEmpty(t, afterCreationRules)
	require.NotEmpty(t, afterCreationRoutes)
	require.NotEqual(t, len(afterCreationRules), len(beforeCreationRules))
	require.NotEqual(t, len(afterCreationRoutes), len(beforeCreationRoutes))

	verifyMasqueradeRules(t, afterCreationRules, ri, ip)

	// Delete rules and routes
	beforeDeletionRules, beforeDeletionRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)
	runDelete(t, ip)
	afterDeletionRules, afterDeletionRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)

	require.NotEqual(t, len(afterDeletionRules), len(beforeDeletionRules))
	require.NotEqual(t, len(afterDeletionRoutes), len(beforeDeletionRoutes))
	require.Len(t, afterDeletionRules, len(beforeCreationRules))
	require.Len(t, afterDeletionRoutes, len(beforeCreationRoutes))
}

func runConfigure(t *testing.T, ri RoutingInfo, ip netip.Addr, mtu int) {
	err := ri.Configure(ip.AsSlice(), mtu, false)
	require.NoError(t, err)
}

// verifyMasqueradeRules checks that rules are consistent with the masquerading configuration:
// - If masquerading is enabled, rules need to have the 'to' field (example: 'from 10.194.0.56 to 10.0.0.0/8 lookup 3')
// - If masquerading is disabled or if ri.CIDRs has 0.0.0.0/0, the 'to' field should not be there
func verifyMasqueradeRules(t *testing.T, rules []netlink.Rule, ri RoutingInfo, ip netip.Addr) {
	t.Helper()

	hasZeroCidr := false
	for _, cidr := range ri.CIDRs {
		if cidr.IP.IsUnspecified() {
			hasZeroCidr = true
			break
		}
	}

	for _, rule := range rules {
		if rule.Src != nil && rule.Src.IP.Equal(ip.AsSlice()) {
			if ri.Masquerade && !hasZeroCidr && rule.Dst == nil {
				require.Fail(t, "rule is missing the 'to' field with masquerading enabled")
			} else if ri.Masquerade && hasZeroCidr && rule.Dst != nil {
				require.Fail(t, "rule has the 'to' field with a 0.0.0.0/0 CIDR")
			} else if !ri.Masquerade && rule.Dst != nil {
				require.Fail(t, "rule has the 'to' field despite masquerading being disabled")
			}
		}
	}
}

func runDelete(t *testing.T, ip netip.Addr) {
	err := Delete(hivetest.Logger(t), ip)
	require.NoError(t, err)
}

// listRulesAndRoutes returns all rules and routes configured on the machine
// this test is running on. Note that this function is intended to be used
// within a network namespace for isolation.
func listRulesAndRoutes(t *testing.T, family int) ([]netlink.Rule, []netlink.Route) {
	rules, err := route.ListRules(family, nil)
	require.NoError(t, err)

	// Rules are created under specific tables, so find the routes that are in
	// those tables.
	var routes []netlink.Route
	for _, r := range rules {
		rr, err := safenetlink.RouteListFiltered(family, &netlink.Route{
			Table: r.Table,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)

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
	require.NoError(t, err)

	found := linkExistsWithMAC(t, macAddr)
	require.True(t, found)

	return func() {
		require.NoError(t, netlink.LinkDel(dummy))
	}
}

// getFakes returns a fake IP simulating an Endpoint IP and RoutingInfo as test harnesses.
// To create routing info with a list of CIDRs which the interface has access to, set masquerade parameter to true
// If withZeroCIDR is also set to true, the function will use the "0.0.0.0/0" CIDR block instead of other CIDR blocks.
func getFakes(t *testing.T, ipamMode string, masquerade bool, withZeroCIDR bool) (netip.Addr, RoutingInfo) {
	t.Helper()

	logger := hivetest.Logger(t)

	fakeGateway := "192.168.2.1"
	fakeSubnet1CIDR := "192.168.0.0/16"
	fakeSubnet2CIDR := "192.170.0.0/16"
	fakeMAC := "00:11:22:33:44:55"

	var cidrs []string
	if masquerade {
		cidrs = []string{fakeSubnet1CIDR, fakeSubnet2CIDR}
		if withZeroCIDR {
			cidrs = []string{"0.0.0.0/0"}
		}
	}

	fakeRoutingInfo, err := NewRoutingInfo(
		logger,
		fakeGateway,
		cidrs,
		fakeMAC,
		"1",
		ipamMode,
		masquerade,
	)

	require.NoError(t, err)
	require.NotNil(t, fakeRoutingInfo)

	node.SetRouterInfo(fakeRoutingInfo)
	option.Config.IPAM = fakeRoutingInfo.IpamMode
	option.Config.EnableIPv4Masquerade = fakeRoutingInfo.Masquerade

	return netip.MustParseAddr("192.168.2.123"), *fakeRoutingInfo
}

func linkExistsWithMAC(t *testing.T, macAddr mac.MAC) bool {
	links, err := safenetlink.LinkList()
	require.NoError(t, err)

	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == macAddr.String() {
			return true
		}
	}

	return false
}
