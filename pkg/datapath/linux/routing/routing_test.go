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
	"go4.org/netipx"

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
		require.NoError(t, ri.WithOptions(WithMTU(1500), WithLinkState(true)))
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip)
		return nil
	})

	ns2 := netns.NewNetNS(t)
	ns2.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMAzure, false, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip)
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

		runConfigureThenDelete(t, ri, ip)
		return nil
	})
}

func TestPrivilegedConfigureZeros(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns1 := netns.NewNetNS(t)
	ns1.Do(func() error {
		ip, ri := getFakes(t, ipamOption.IPAMENI, true, true)
		require.NoError(t, ri.WithOptions(WithMTU(1500), WithLinkState(true)))
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(t, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(t, ri, ip)
		return nil
	})
}

func TestPrivilegedConfigureRouteWithIncompatibleIP(t *testing.T) {
	setupLinuxRoutingSuite(t)

	_, ri := getFakes(t, ipamOption.IPAMENI, true, false)
	err := ri.Configure(netip.Addr{}, false)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to install endpoint rules: invalid endpoint IP address")
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
	require.NoError(t, fakeRoutingInfo.WithOptions(WithMTU(1500), WithLinkState(true)))
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() netip.Addr
		wantErr bool
	}{
		{
			name: "valid IP addr matching a single rule",
			preRun: func() netip.Addr {
				runConfigure(t, fakeRoutingInfo, fakeIP)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IP addr doesn't match any rule",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, fakeIP)
				return ip
			},
			wantErr: false,
		},
		{
			name: "IP addr matches multiple rules",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(t, fakeRoutingInfo, ip)

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
				runConfigure(t, fakeRoutingInfo, fakeIP)
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

func TestPrivilegedDeleteRulesAllEgressSchemes(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		ip := netip.MustParseAddr("192.0.2.10")
		ipWithMask := netipx.AddrIPNet(ip)
		for _, rule := range []route.Rule{
			{
				Priority: linux_defaults.RulePriorityEgress,
				From:     ipWithMask,
				Table:    100,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     ipWithMask,
				Table:    linux_defaults.RouteTableInterfacesOffset + 1,
				Protocol: linux_defaults.RTProto,
			},
		} {
			require.NoError(t, route.ReplaceRule(rule))
		}

		// A rule outside the known endpoint-egress priorities must be preserved.
		require.NoError(t, route.ReplaceRule(route.Rule{
			Priority: linux_defaults.RulePriorityEgressv2 + 1,
			From:     ipWithMask,
			Table:    100,
			Protocol: linux_defaults.RTProto,
		}))

		require.NoError(t, DeleteRulesIfExists(hivetest.Logger(t), ip))
		// call DeleteRulesIfExists again to ensure that it is idempotent and
		// does not return an error if the rules have already been deleted
		require.NoError(t, DeleteRulesIfExists(hivetest.Logger(t), ip))

		rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{From: ipWithMask})
		require.NoError(t, err)
		require.Len(t, rules, 1)
		require.Equal(t, linux_defaults.RulePriorityEgressv2+1, rules[0].Priority)
		return nil
	})
}

func TestIsCiliumEndpointIngressRule(t *testing.T) {
	mask := uint32(0xffffffff)
	dst := netipx.AddrIPNet(netip.MustParseAddr("192.0.2.10"))

	tests := []struct {
		name string
		rule netlink.Rule
		want bool
	}{
		{
			"ingress-rule",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Dst:      dst,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto},
			true,
		},
		{
			"missing-destination",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"different-priority",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress + 1,
				Dst:      dst,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"different-table",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Dst:      dst,
				Table:    100,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"marked",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Dst:      dst,
				Table:    route.MainTable,
				Mark:     1,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"masked",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Dst:      dst,
				Table:    route.MainTable,
				Mask:     &mask,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"different-protocol",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				Dst:      dst,
				Table:    route.MainTable},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isCiliumEndpointIngressRule(tt.rule))
		})
	}
}

func TestIsCiliumEndpointEgressRule(t *testing.T) {
	ipWithMask := netipx.AddrIPNet(netip.MustParseAddr("192.0.2.10"))
	mask := uint32(0xffffffff)

	tests := []struct {
		name string
		rule netlink.Rule
		want bool
	}{
		{
			"legacy-priority",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Src:      ipWithMask,
				Table:    100,
				Protocol: linux_defaults.RTProto},
			true,
		},
		{
			"current-priority",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgressv2,
				Src:      ipWithMask,
				Table:    linux_defaults.RouteTableInterfacesOffset + 1,
				Protocol: linux_defaults.RTProto},
			true,
		},
		{
			"legacy-priority-reserved-table",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Src:      ipWithMask,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"current-priority-outside-interface-table-range",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgressv2,
				Src:      ipWithMask,
				Table:    linux_defaults.RouteTableInterfacesOffset - 1,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"marked",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Src:      ipWithMask,
				Table:    100,
				Mark:     1,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"masked",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Src:      ipWithMask,
				Table:    100,
				Mask:     &mask,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"different-protocol",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Src:      ipWithMask,
				Table:    100},
			false,
		},
		{
			"missing-source",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				Table:    100,
				Protocol: linux_defaults.RTProto},
			false,
		},
		{
			"different-priority",
			netlink.Rule{
				Priority: linux_defaults.RulePriorityEgressv2 + 1,
				Src:      ipWithMask,
				Table:    100,
				Protocol: linux_defaults.RTProto},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isCiliumEndpointEgressRule(tt.rule))
		})
	}
}

func TestPrivilegedDeleteRuleIfExists(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		ip := netip.MustParseAddr("192.0.2.10")
		spec := route.Rule{
			Priority: linux_defaults.RulePriorityEgressv2,
			From:     netipx.AddrIPNet(ip),
			Table:    linux_defaults.RouteTableInterfacesOffset + 1,
			Protocol: linux_defaults.RTProto,
		}
		require.NoError(t, route.ReplaceRule(spec))

		rules, err := route.ListRules(netlink.FAMILY_V4, &spec)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		deleted, err := deleteRuleIfExists(&rules[0])
		require.NoError(t, err)
		require.True(t, deleted)

		deleted, err = deleteRuleIfExists(&rules[0])
		require.NoError(t, err)
		require.False(t, deleted)
		return nil
	})
}

func TestPrivilegedGCOrphanRules(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		orphan := netip.MustParseAddr("192.0.2.10")
		inUse := netip.MustParseAddr("192.0.2.11")
		_, subnet, err := net.ParseCIDR("198.51.100.0/24")
		require.NoError(t, err)

		// rules that should be preserved after GCOrphanRules is called, even if they match the orphan IP
		preservedRules := []route.Rule{
			{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     subnet,
				Table:    linux_defaults.RouteTableInterfacesOffset + 2,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     netipx.AddrIPNet(netip.MustParseAddr("192.0.2.20")),
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     netipx.AddrIPNet(netip.MustParseAddr("192.0.2.21")),
				Table:    linux_defaults.RouteTableInterfacesOffset + 2,
				Mark:     1,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityIngress,
				To:       netipx.AddrIPNet(netip.MustParseAddr("192.0.2.22")),
				Table:    route.MainTable,
				Mask:     0xff,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     netipx.AddrIPNet(netip.MustParseAddr("192.0.2.23")),
				Table:    linux_defaults.RouteTableInterfacesOffset + 2,
				Mask:     0xff,
				Protocol: linux_defaults.RTProto,
			},
			{
				Priority: linux_defaults.RulePriorityEgress,
				From:     netipx.AddrIPNet(netip.MustParseAddr("192.0.2.24")),
				Table:    300,
				Mask:     0xff,
				Protocol: linux_defaults.RTProto,
			},
		}

		// create rules for both the orphan and in-use IPs
		for _, addr := range []netip.Addr{orphan, inUse} {
			require.NoError(t, route.ReplaceRule(route.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				To:       netipx.AddrIPNet(addr),
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto,
			}))
			require.NoError(t, route.ReplaceRule(route.Rule{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     netipx.AddrIPNet(addr),
				Table:    linux_defaults.RouteTableInterfacesOffset + 1,
				Protocol: linux_defaults.RTProto,
			}))
			require.NoError(t, route.ReplaceRule(route.Rule{
				Priority: linux_defaults.RulePriorityEgress,
				From:     netipx.AddrIPNet(addr),
				Table:    300,
				Protocol: linux_defaults.RTProto,
			}))
		}
		for _, rule := range preservedRules {
			require.NoError(t, route.ReplaceRule(rule))
		}

		err = GCOrphanRules(hivetest.Logger(t), func(addr netip.Addr) bool {
			return addr != inUse
		})
		require.NoError(t, err)

		// verify that the rules for the orphan IP have been deleted, and the rules for the in-use IP remain
		orphanIngressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       netipx.AddrIPNet(orphan),
			Table:    route.MainTable,
		})
		require.NoError(t, err)
		require.Empty(t, orphanIngressRules)

		orphanEgressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityEgressv2,
			From:     netipx.AddrIPNet(orphan),
		})
		require.NoError(t, err)
		require.Empty(t, orphanEgressRules)

		orphanLegacyEgressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityEgress,
			From:     netipx.AddrIPNet(orphan),
		})
		require.NoError(t, err)
		require.Empty(t, orphanLegacyEgressRules)

		inUseIngressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       netipx.AddrIPNet(inUse),
			Table:    route.MainTable,
		})
		require.NoError(t, err)
		require.Len(t, inUseIngressRules, 1)

		inUseEgressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityEgressv2,
			From:     netipx.AddrIPNet(inUse),
		})
		require.NoError(t, err)
		require.Len(t, inUseEgressRules, 1)

		inUseLegacyEgressRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Priority: linux_defaults.RulePriorityEgress,
			From:     netipx.AddrIPNet(inUse),
		})
		require.NoError(t, err)
		require.Len(t, inUseLegacyEgressRules, 1)

		// verify that the preserved rules are still present
		for _, rule := range preservedRules {
			rules, err := route.ListRules(netlink.FAMILY_V4, &rule)
			require.NoError(t, err)
			require.Len(t, rules, 1)
		}
		return nil
	})
}

func runConfigureThenDelete(t *testing.T, ri RoutingInfo, ip netip.Addr) {
	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(t, netlink.FAMILY_V4)
	runConfigure(t, ri, ip)
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

func runConfigure(t *testing.T, ri RoutingInfo, ip netip.Addr) {
	err := ri.Configure(ip, false)
	require.NoError(t, err)
}

// verifyMasqueradeRules checks that rules are consistent with the masquerading configuration:
//   - An unconditional rule (from <IP> lookup <table>) must always be present for correct ENI routing.
//   - No CIDR-specific rules (with 'to' field) should be present.
func verifyMasqueradeRules(t *testing.T, rules []netlink.Rule, ri RoutingInfo, ip netip.Addr) {
	t.Helper()

	var hasUnconditionalRule bool
	for _, rule := range rules {
		if rule.Src != nil && rule.Src.IP.Equal(ip.AsSlice()) {
			// Should not have CIDR-specific rules
			if rule.Dst != nil {
				require.Fail(t, "unexpected CIDR-specific rule found; only unconditional rule should be present")
			}
			if rule.Dst == nil {
				hasUnconditionalRule = true
			}
		}
	}

	// The unconditional rule must always be present for correct ENI routing.
	require.True(t, hasUnconditionalRule, "unconditional egress rule (from <IP> lookup <table>) must be present")
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
			HardwareAddr: macAddr.HardwareAddr(),
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

	fakeGateway := "192.168.2.1"
	fakeSubnet1CIDR := netip.MustParsePrefix("192.168.0.0/16")
	fakeSubnet2CIDR := netip.MustParsePrefix("192.170.0.0/16")
	fakeMAC := mac.MustParseMAC("00:11:22:33:44:55")

	var cidrs []netip.Prefix
	if masquerade {
		cidrs = []netip.Prefix{fakeSubnet1CIDR, fakeSubnet2CIDR}
		if withZeroCIDR {
			cidrs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}
	}

	options := []RoutingInfoOption{
		WithCIDRsAndMasquerade(cidrs, masquerade),
	}
	if ipamMode != ipamOption.IPAMENI {
		options = append(options, WithMTU(1500), WithLinkState(true))
	}
	if ipamMode == ipamOption.IPAMAzure {
		options = append(options, WithCompatEgressPriority())
	}

	fakeRoutingInfo, err := NewRoutingInfo(fakeGateway, fakeMAC, "1", options...)

	require.NoError(t, err)
	require.NotNil(t, fakeRoutingInfo)

	node.SetRouterInfo(fakeRoutingInfo)
	option.Config.IPAM = ipamMode
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
