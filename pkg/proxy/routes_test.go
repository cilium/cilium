// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	t.Run("IPv4", func(t *testing.T) {
		t.Run("toProxy", func(t *testing.T) {
			nn := "to-proxy-routing-ipv4"
			tns, err := netns.ReplaceNetNSWithName(nn)
			assert.NoError(t, err)
			t.Cleanup(func() {
				tns.Close()
				netns.RemoveNetNSWithName(nn)
			})

			tns.Do(func(_ ns.NetNS) error {
				// Install routes and rules the first time.
				assert.NoError(t, installToProxyRoutesIPv4())

				rules, err := route.ListRules(netlink.FAMILY_V4, &toProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 1)

				// Ensure idempotence.
				assert.NoError(t, installToProxyRoutesIPv4())

				// Remove routes installed before.
				assert.NoError(t, removeToProxyRoutesIPv4())

				rules, err = route.ListRules(netlink.FAMILY_V4, &toProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 0)

				return nil
			})
		})

		t.Run("fromProxy", func(t *testing.T) {
			nn := "from-proxy-routing-ipv4"
			testIPv4 := net.ParseIP("1.2.3.4")
			tns, err := netns.ReplaceNetNSWithName(nn)
			assert.NoError(t, err)
			t.Cleanup(func() {
				tns.Close()
				netns.RemoveNetNSWithName(nn)
			})

			tns.Do(func(_ ns.NetNS) error {
				// create test device
				ifName := "dummy"
				dummy := &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: ifName,
					},
				}
				err := netlink.LinkAdd(dummy)
				assert.NoError(t, err)

				// Install routes and rules the first time.
				assert.NoError(t, installFromProxyRoutesIPv4(testIPv4, ifName))

				rules, err := route.ListRules(netlink.FAMILY_V4, &fromProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the from proxy (2005) routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv4(testIPv4, ifName))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRoutesIPv4())

				rules, err = route.ListRules(netlink.FAMILY_V4, &fromProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 0)

				return nil
			})
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Run("toProxy", func(t *testing.T) {
			nn := "to-proxy-routing-ipv6"
			tns, err := netns.ReplaceNetNSWithName(nn)
			assert.NoError(t, err)
			t.Cleanup(func() {
				tns.Close()
				netns.RemoveNetNSWithName(nn)
			})

			tns.Do(func(_ ns.NetNS) error {
				// Install routes and rules the first time.
				assert.NoError(t, installToProxyRoutesIPv6())

				rules, err := route.ListRules(netlink.FAMILY_V6, &toProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 1)

				// Ensure idempotence.
				assert.NoError(t, installToProxyRoutesIPv6())

				// Remove routes installed before.
				assert.NoError(t, removeToProxyRoutesIPv6())

				rules, err = route.ListRules(netlink.FAMILY_V6, &toProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = netlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 0)

				return nil
			})
		})

		t.Run("fromProxy", func(t *testing.T) {
			nn := "from-proxy-routing-ipv6"
			testIPv6 := net.ParseIP("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
			tns, err := netns.ReplaceNetNSWithName(nn)
			assert.NoError(t, err)
			t.Cleanup(func() {
				tns.Close()
				netns.RemoveNetNSWithName(nn)
			})

			tns.Do(func(_ ns.NetNS) error {
				// create test device
				ifName := "dummy"
				dummy := &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: ifName,
					},
				}
				err := netlink.LinkAdd(dummy)
				assert.NoError(t, err)

				// Install routes and rules the first time.
				assert.NoError(t, installFromProxyRoutesIPv6(testIPv6, ifName))

				rules, err := route.ListRules(netlink.FAMILY_V6, &fromProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv6(testIPv6, ifName))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRoutesIPv6())

				rules, err = route.ListRules(netlink.FAMILY_V6, &fromProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = netlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 0)

				return nil
			})
		})
	})

}
