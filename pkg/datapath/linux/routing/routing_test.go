// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"runtime"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test(t *testing.T) {
	TestingT(t)
}

type LinuxRoutingSuite struct{}

var _ = Suite(&LinuxRoutingSuite{})

func (s *LinuxRoutingSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (e *LinuxRoutingSuite) TestConfigure(c *C) {
	runFuncInNetNS(c, func() {
		ip, ri := getFakes(c, true)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(c, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(c, ri, ip, 1500)
	})
	runFuncInNetNS(c, func() {
		ip, ri := getFakes(c, false)
		masterMAC := ri.MasterIfMAC
		ifaceCleanup := createDummyDevice(c, masterMAC)
		defer ifaceCleanup()

		runConfigureThenDelete(c, ri, ip, 1500)
	})
}

func (e *LinuxRoutingSuite) TestConfigureRoutewithIncompatibleIP(c *C) {
	_, ri := getFakes(c, true)
	ipv6 := netip.MustParseAddr("fd00::2").AsSlice()
	err := ri.Configure(ipv6, 1500, false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "IP not compatible")
}

func (e *LinuxRoutingSuite) TestDeleteRoutewithIncompatibleIP(c *C) {
	ipv6 := netip.MustParseAddr("fd00::2")
	err := Delete(ipv6, false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "IP not compatible")
}

func (e *LinuxRoutingSuite) TestDelete(c *C) {
	fakeIP, fakeRoutingInfo := getFakes(c, true)
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() netip.Addr
		wantErr bool
	}{
		{
			name: "valid IP addr matching rules",
			preRun: func() netip.Addr {
				runConfigure(c, fakeRoutingInfo, fakeIP, 1500)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IP addr doesn't match rules",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(c, fakeRoutingInfo, fakeIP, 1500)
				return ip
			},
			wantErr: true,
		},
		{
			name: "IP addr matches more than number expected",
			preRun: func() netip.Addr {
				ip := netip.MustParseAddr("192.168.2.233")

				runConfigure(c, fakeRoutingInfo, ip, 1500)

				// Find interface ingress rules so that we can create a
				// near-duplicate.
				rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
					Priority: linux_defaults.RulePriorityIngress,
				})
				c.Assert(err, IsNil)
				c.Assert(len(rules), Not(Equals), 0)

				// Insert almost duplicate rule; the reason for this is to
				// trigger an error while trying to delete the ingress rule. We
				// are setting the Src because ingress rules don't have
				// one (only Dst), thus we set Src to create a near-duplicate.
				r := rules[0]
				r.Src = &net.IPNet{IP: fakeIP.AsSlice(), Mask: net.CIDRMask(32, 32)}
				c.Assert(netlink.RuleAdd(&r), IsNil)

				return ip
			},
			wantErr: true,
		},
		{
			name: "fails to delete rules due to masquerade misconfiguration",
			preRun: func() netip.Addr {
				runConfigure(c, fakeRoutingInfo, fakeIP, 1500)
				// inconsistency with fakeRoutingInfo.Masquerade should lead to failure
				option.Config.EnableIPv4Masquerade = false
				return fakeIP
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		c.Log("Test: " + tt.name)
		runFuncInNetNS(c, func() {
			ifaceCleanup := createDummyDevice(c, masterMAC)
			defer ifaceCleanup()

			ip := tt.preRun()
			err := Delete(ip, false)
			c.Assert((err != nil), Equals, tt.wantErr)
		})
	}
}

func runFuncInNetNS(c *C, run func()) {
	// Source:
	// https://github.com/vishvananda/netlink/blob/c79a4b7b40668c3f7867bf256b80b6b2dc65e58e/netns_test.go#L49
	runtime.LockOSThread() // We need a constant OS thread
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	c.Assert(err, IsNil)
	defer c.Assert(netns.Set(currentNS), IsNil)

	networkNS, err := netns.New()
	c.Assert(err, IsNil)
	defer c.Assert(networkNS.Close(), IsNil)

	run()
}

func runConfigureThenDelete(c *C, ri RoutingInfo, ip netip.Addr, mtu int) {
	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(c, netlink.FAMILY_V4)
	runConfigure(c, ri, ip, mtu)
	afterCreationRules, afterCreationRoutes := listRulesAndRoutes(c, netlink.FAMILY_V4)

	c.Assert(len(afterCreationRules), Not(Equals), 0)
	c.Assert(len(afterCreationRoutes), Not(Equals), 0)
	c.Assert(len(beforeCreationRules), Not(Equals), len(afterCreationRules))
	c.Assert(len(beforeCreationRoutes), Not(Equals), len(afterCreationRoutes))

	// Delete rules and routes
	beforeDeletionRules, beforeDeletionRoutes := listRulesAndRoutes(c, netlink.FAMILY_V4)
	runDelete(c, ip)
	afterDeletionRules, afterDeletionRoutes := listRulesAndRoutes(c, netlink.FAMILY_V4)

	c.Assert(len(beforeDeletionRules), Not(Equals), len(afterDeletionRules))
	c.Assert(len(beforeDeletionRoutes), Not(Equals), len(afterDeletionRoutes))
	c.Assert(len(afterDeletionRules), Equals, len(beforeCreationRules))
	c.Assert(len(afterDeletionRoutes), Equals, len(beforeCreationRoutes))
}

func runConfigure(c *C, ri RoutingInfo, ip netip.Addr, mtu int) {
	err := ri.Configure(ip.AsSlice(), mtu, false)
	c.Assert(err, IsNil)
}

func runDelete(c *C, ip netip.Addr) {
	err := Delete(ip, false)
	c.Assert(err, IsNil)
}

// listRulesAndRoutes returns all rules and routes configured on the machine
// this test is running on. Note that this function is intended to be used
// within a network namespace for isolation.
func listRulesAndRoutes(c *C, family int) ([]netlink.Rule, []netlink.Route) {
	rules, err := route.ListRules(family, nil)
	c.Assert(err, IsNil)

	// Rules are created under specific tables, so find the routes that are in
	// those tables.
	var routes []netlink.Route
	for _, r := range rules {
		rr, err := netlink.RouteListFiltered(family, &netlink.Route{
			Table: r.Table,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)

		routes = append(routes, rr...)
	}

	return rules, routes
}

// createDummyDevice creates a new dummy device with a MAC of `macAddr` to be
// used as a harness in this test. This function returns a function which can
// be used to remove the device for cleanup purposes.
func createDummyDevice(c *C, macAddr mac.MAC) func() {
	if linkExistsWithMAC(c, macAddr) {
		c.FailNow()
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
	c.Assert(err, IsNil)

	found := linkExistsWithMAC(c, macAddr)
	c.Assert(found, Equals, true)

	return func() {
		c.Assert(netlink.LinkDel(dummy), IsNil)
	}
}

// getFakes returns a fake IP simulating an Endpoint IP and RoutingInfo as test harnesses.
// To create routing info with a list of CIDRs which the interface has access to, set withCIDR parameter to true
func getFakes(c *C, withCIDR bool) (netip.Addr, RoutingInfo) {
	fakeGateway := netip.MustParseAddr("192.168.2.1")
	fakeSubnet1CIDR := netip.MustParsePrefix("192.168.0.0/16")
	fakeSubnet2CIDR := netip.MustParsePrefix("192.170.0.0/16")
	fakeMAC, err := mac.ParseMAC("00:11:22:33:44:55")
	c.Assert(err, IsNil)
	c.Assert(fakeMAC, NotNil)

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
	c.Assert(err, IsNil)
	c.Assert(fakeRoutingInfo, NotNil)

	node.SetRouterInfo(fakeRoutingInfo)
	option.Config.IPAM = fakeRoutingInfo.IpamMode
	option.Config.EnableIPv4Masquerade = fakeRoutingInfo.Masquerade

	fakeIP := netip.MustParseAddr("192.168.2.123")
	return fakeIP, *fakeRoutingInfo
}

func linkExistsWithMAC(c *C, macAddr mac.MAC) bool {
	links, err := netlink.LinkList()
	c.Assert(err, IsNil)

	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == macAddr.String() {
			return true
		}
	}

	return false
}
