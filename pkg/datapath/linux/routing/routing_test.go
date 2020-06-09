// Copyright 2020 Authors of Cilium
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

package linuxrouting

import (
	"net"
	"runtime"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type LinuxRoutingSuite struct{}

var _ = Suite(&LinuxRoutingSuite{})

func (e *LinuxRoutingSuite) TestConfigure(c *C) {
	ip, ri := getFakes(c)
	masterMAC := ri.MasterIfMAC
	runFuncInNetNS(c, func() { runConfigureThenDelete(c, ri, ip, 1500, false) }, masterMAC)
	runFuncInNetNS(c, func() { runConfigureThenDelete(c, ri, ip, 1500, true) }, masterMAC)
}

func (e *LinuxRoutingSuite) TestConfigureRoutewithIncompatibleIP(c *C) {
	_, ri := getFakes(c)
	ipv6 := net.ParseIP("fd00::2").To16()
	c.Assert(ipv6, NotNil)
	err := ri.Configure(ipv6, 1500, true)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "IP not compatible")
}

func (e *LinuxRoutingSuite) TestDeleteRoutewithIncompatibleIP(c *C) {
	ipv6 := net.ParseIP("fd00::2").To16()
	c.Assert(ipv6, NotNil)
	err := Delete(ipv6)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "IP not compatible")
}

func (e *LinuxRoutingSuite) TestDelete(c *C) {
	fakeIP, fakeRoutingInfo := getFakes(c)
	masterMAC := fakeRoutingInfo.MasterIfMAC

	tests := []struct {
		name    string
		preRun  func() net.IP
		wantErr bool
	}{
		{
			name: "valid IP addr matching rules",
			preRun: func() net.IP {
				runConfigure(c, fakeRoutingInfo, fakeIP, 1500, false)
				return fakeIP
			},
			wantErr: false,
		},
		{
			name: "IP addr doesn't match rules",
			preRun: func() net.IP {
				ip := net.ParseIP("192.168.2.233")
				c.Assert(ip, NotNil)

				runConfigure(c, fakeRoutingInfo, fakeIP, 1500, false)
				return ip
			},
			wantErr: true,
		},
		{
			name: "IP addr matches more than number expected",
			preRun: func() net.IP {
				ip := net.ParseIP("192.168.2.233")
				c.Assert(ip, NotNil)

				runConfigure(c, fakeRoutingInfo, ip, 1500, false)

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
				r.Src = &net.IPNet{IP: fakeIP, Mask: net.CIDRMask(32, 32)}
				c.Assert(netlink.RuleAdd(&r), IsNil)

				return ip
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		c.Log("Test: " + tt.name)
		runFuncInNetNS(c, func() {
			ip := tt.preRun()
			err := Delete(ip)
			c.Assert((err != nil), Equals, tt.wantErr)
		}, masterMAC)
	}
}

func runFuncInNetNS(c *C, run func(), macAddr mac.MAC) {
	// Source:
	// https://github.com/vishvananda/netlink/blob/c79a4b7b40668c3f7867bf256b80b6b2dc65e58e/netns_test.go#L49
	runtime.LockOSThread() // We need a constant OS thread
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	c.Assert(err, IsNil)
	c.Logf("[DEBUG] Root network ns %v", currentNS.UniqueId())
	defer func() {
		c.Assert(netns.Set(currentNS), IsNil)
		c.Logf("[DEBUG] Set back to previous network ns %v", currentNS.UniqueId())
	}()

	networkNS, err := netns.New()
	c.Assert(err, IsNil)
	c.Logf("[DEBUG] Inside new network ns %v", networkNS.UniqueId())
	defer func() {
		uid := networkNS.UniqueId()
		c.Assert(networkNS.Close(), IsNil)
		c.Logf("[DEBUG] Closed new network ns %v", uid)
	}()

	ifaceCleanup := createDummyDevice(c, macAddr)
	defer ifaceCleanup()

	run()
}

func runConfigureThenDelete(c *C, ri RoutingInfo, ip net.IP, mtu int, masq bool) {
	// Create rules and routes
	beforeCreationRules, beforeCreationRoutes := listRulesAndRoutes(c, netlink.FAMILY_V4)
	runConfigure(c, ri, ip, mtu, masq)
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

func runConfigure(c *C, ri RoutingInfo, ip net.IP, mtu int, masq bool) {
	err := ri.Configure(ip, mtu, masq)
	c.Assert(err, IsNil)
}

func runDelete(c *C, ip net.IP) {
	err := Delete(ip)
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
		c.Logf("[DEBUG] Found device with identical mac addr: %s", macAddr.String())
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

	c.Log("[DEBUG] Added dummy device")

	found := linkExistsWithMAC(c, macAddr)
	if !found {
		c.Log("[DEBUG] Couldn't find device even after creation")
	}
	c.Assert(found, Equals, true)

	return func() {
		c.Assert(netlink.LinkDel(dummy), IsNil)
		c.Log("[DEBUG] Cleaned up dummy device")
	}
}

// getFakes returns a fake IP simulating an Endpoint IP and RoutingInfo as test
// harnesses.
func getFakes(c *C) (net.IP, RoutingInfo) {
	fakeGateway := net.ParseIP("192.168.2.1")
	c.Assert(fakeGateway, NotNil)

	_, fakeCIDR, err := net.ParseCIDR("192.168.0.0/16")
	c.Assert(err, IsNil)
	c.Assert(fakeCIDR, NotNil)

	fakeMAC, err := mac.ParseMAC("00:11:22:33:44:55")
	c.Assert(err, IsNil)
	c.Assert(fakeMAC, NotNil)

	fakeRoutingInfo, err := parse(fakeGateway.String(),
		[]string{fakeCIDR.String()},
		fakeMAC.String(),
		true)
	c.Assert(err, IsNil)
	c.Assert(fakeRoutingInfo, NotNil)

	fakeIP := net.ParseIP("192.168.2.123")
	c.Assert(fakeIP, NotNil)

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
