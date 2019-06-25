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

package route

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type RouteSuitePrivileged struct{}

var _ = Suite(&RouteSuitePrivileged{})

func parseIP(ip string) *net.IP {
	result := net.ParseIP(ip)
	return &result
}

func testReplaceNexthopRoute(c *C, link netlink.Link, routerNet *net.IPNet) {
	route := Route{
		Table: 10,
	}
	// delete route in case it exists from a previous failed run
	deleteNexthopRoute(route, link, routerNet)

	// defer cleanup in case of failure
	defer deleteNexthopRoute(route, link, routerNet)

	replaced, err := replaceNexthopRoute(route, link, routerNet)
	c.Assert(err, IsNil)
	c.Assert(replaced, Equals, true)

	// We expect routes to always be replaced
	replaced, err = replaceNexthopRoute(route, link, routerNet)
	c.Assert(err, IsNil)
	c.Assert(replaced, Equals, true)

	err = deleteNexthopRoute(route, link, routerNet)
	c.Assert(err, IsNil)
}

func (p *RouteSuitePrivileged) TestReplaceNexthopRoute(c *C) {
	link, err := netlink.LinkByName("lo")
	c.Assert(err, IsNil)

	_, routerNet, err := net.ParseCIDR("1.2.3.4/32")
	c.Assert(err, IsNil)
	testReplaceNexthopRoute(c, link, routerNet)

	_, routerNet, err = net.ParseCIDR("f00d::a02:100:0:815b/128")
	c.Assert(err, IsNil)
	testReplaceNexthopRoute(c, link, routerNet)
}

func testReplaceRoute(c *C, prefixStr, nexthopStr string, lookupTest bool) {
	_, prefix, err := net.ParseCIDR(prefixStr)
	c.Assert(err, IsNil)
	c.Assert(prefix, Not(IsNil))

	nexthop := net.ParseIP(nexthopStr)
	c.Assert(nexthop, Not(IsNil))

	rt := Route{
		Device:  "lo",
		Prefix:  *prefix,
		Nexthop: &nexthop,
	}

	// delete route in case it exists from a previous failed run
	Delete(rt)

	// Defer deletion of route and nexthop route to cleanup in case of failure
	defer Delete(rt)
	defer Delete(Route{
		Device: "lo",
		Prefix: *rt.getNexthopAsIPNet(),
		Scope:  netlink.SCOPE_LINK,
	})

	mtuConf := mtu.NewConfiguration(0, false, false, 0)
	_, err = Upsert(rt, &mtuConf)
	c.Assert(err, IsNil)

	if lookupTest {
		// Account for minimal kernel race condition where route is not
		// yet available
		c.Assert(testutils.WaitUntil(func() bool {
			installedRoute, err := Lookup(rt)
			c.Assert(err, IsNil)
			return installedRoute != nil
		}, 5*time.Second), IsNil)
	}

	err = Delete(rt)
	c.Assert(err, IsNil)
}

func (p *RouteSuitePrivileged) TestReplaceRoute(c *C) {
	testReplaceRoute(c, "2.2.0.0/16", "1.2.3.4", true)
	// lookup test broken for IPv6 as long as use lo as device
	testReplaceRoute(c, "f00d::a02:200:0:0/96", "f00d::a02:100:0:815b", false)
}

func testReplaceRule(c *C, mark int, from, to *net.IPNet, table int) {
	rule := Rule{Mark: mark, From: from, To: to, Table: table}

	// delete rule in case it exists from a previous failed run
	DeleteRule(rule)

	rule.Priority = 1
	err := ReplaceRule(rule)
	c.Assert(err, IsNil)

	exists, err := lookupRule(rule, netlink.FAMILY_V4)
	c.Assert(err, IsNil)
	c.Assert(exists, Equals, true)

	err = DeleteRule(rule)
	c.Assert(err, IsNil)

	exists, err = lookupRule(rule, netlink.FAMILY_V4)
	c.Assert(err, IsNil)
	c.Assert(exists, Equals, false)
}

func testReplaceRuleIPv6(c *C, mark int, from, to *net.IPNet, table int) {
	rule := Rule{Mark: mark, From: from, To: to, Table: table}

	// delete rule in case it exists from a previous failed run
	DeleteRuleIPv6(rule)

	rule.Priority = 1
	err := ReplaceRuleIPv6(rule)
	c.Assert(err, IsNil)

	exists, err := lookupRule(rule, netlink.FAMILY_V6)
	c.Assert(err, IsNil)
	c.Assert(exists, Equals, true)

	err = DeleteRuleIPv6(rule)
	c.Assert(err, IsNil)

	exists, err = lookupRule(rule, netlink.FAMILY_V6)
	c.Assert(err, IsNil)
	c.Assert(exists, Equals, false)
}

func (p *RouteSuitePrivileged) TestReplaceRule(c *C) {
	_, cidr1, err := net.ParseCIDR("10.10.0.0/16")
	c.Assert(err, IsNil)
	testReplaceRule(c, 0xf00, nil, nil, 123)
	testReplaceRule(c, 0xf00, cidr1, nil, 124)
	testReplaceRule(c, 0, nil, cidr1, 125)
	testReplaceRule(c, 0, cidr1, cidr1, 126)
}

func (p *RouteSuitePrivileged) TestReplaceRule6(c *C) {
	_, cidr1, err := net.ParseCIDR("beef::/48")
	c.Assert(err, IsNil)
	testReplaceRuleIPv6(c, 0xf00, nil, nil, 123)
	testReplaceRuleIPv6(c, 0xf00, cidr1, nil, 124)
	testReplaceRuleIPv6(c, 0, nil, cidr1, 125)
	testReplaceRuleIPv6(c, 0, cidr1, cidr1, 126)
}
