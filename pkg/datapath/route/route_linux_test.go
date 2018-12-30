// Copyright 2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/mtu"

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
	// delete route in case it exists from a previous failed run
	deleteNexthopRoute(link, routerNet)

	// defer cleanup in case of failure
	defer deleteNexthopRoute(link, routerNet)

	replaced, err := replaceNexthopRoute(link, routerNet)
	c.Assert(err, IsNil)
	c.Assert(replaced, Equals, true)

	replaced, err = replaceNexthopRoute(link, routerNet)
	c.Assert(err, IsNil)
	c.Assert(replaced, Equals, false)

	err = deleteNexthopRoute(link, routerNet)
	c.Assert(err, IsNil)
}

func (p *RouteSuitePrivileged) TestReplaceNexthopRoute(c *C) {
	link, err := netlink.LinkByName("lo")
	c.Assert(err, IsNil)

	ip := net.ParseIP("1.2.3.4")
	c.Assert(ip, Not(IsNil))
	routerNet := &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	testReplaceNexthopRoute(c, link, routerNet)

	ip = net.ParseIP("f00d::a02:100:0:815b")
	c.Assert(ip, Not(IsNil))
	routerNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	testReplaceNexthopRoute(c, link, routerNet)
}

func testReplaceRoute(c *C, prefixStr, nexthopStr string) {
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
	DeleteRoute(rt)

	// Defer deletion of route and nexthop route to cleanup in case of failure
	defer DeleteRoute(rt)
	defer DeleteRoute(Route{
		Device: "lo",
		Prefix: *rt.getNexthopAsIPNet(),
		Scope:  netlink.SCOPE_LINK,
	})

	err = ReplaceRoute(rt, mtu.NewConfiguration(false, 0))
	c.Assert(err, IsNil)

	err = DeleteRoute(rt)
	c.Assert(err, IsNil)
}

func (p *RouteSuitePrivileged) TestReplaceRoute(c *C) {
	testReplaceRoute(c, "2.2.0.0/16", "1.2.3.4")
	testReplaceRoute(c, "f00d::a02:200:0:0/96", "f00d::a02:100:0:815b")
}
