// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	t.Run("IPv4", func(t *testing.T) {
		nn := "proxy-routing-ipv4"
		tns, err := netns.ReplaceNetNSWithName(nn)
		assert.NoError(t, err)
		t.Cleanup(func() {
			tns.Close()
			netns.RemoveNetNSWithName(nn)
		})

		tns.Do(func(_ ns.NetNS) error {
			// Install routes and rules the first time.
			assert.NoError(t, installRoutesIPv4())

			rules, err := route.ListRules(netlink.FAMILY_V4, &tproxyRule)
			assert.NoError(t, err)
			assert.NotEmpty(t, rules)

			// List the proxy routing table, expect a single entry.
			rt, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
				&netlink.Route{Table: proxyRoutingTable}, netlink.RT_FILTER_TABLE)
			assert.NoError(t, err)
			assert.Len(t, rt, 1)

			// Ensure idempotence.
			assert.NoError(t, installRoutesIPv4())

			// Remove routes installed before.
			assert.NoError(t, removeRoutesIPv4())

			rules, err = route.ListRules(netlink.FAMILY_V4, &tproxyRule)
			assert.NoError(t, err)
			assert.Empty(t, rules)

			// List the proxy routing table, expect it to be empty.
			rt, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
				&netlink.Route{Table: proxyRoutingTable}, netlink.RT_FILTER_TABLE)
			assert.NoError(t, err)
			assert.Len(t, rt, 0)

			return nil
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		nn := "proxy-routing-ipv6"
		tns, err := netns.ReplaceNetNSWithName(nn)
		assert.NoError(t, err)
		t.Cleanup(func() {
			tns.Close()
			netns.RemoveNetNSWithName(nn)
		})

		tns.Do(func(_ ns.NetNS) error {
			// Install routes and rules the first time.
			assert.NoError(t, installRoutesIPv6())

			rules, err := route.ListRules(netlink.FAMILY_V6, &tproxyRule)
			assert.NoError(t, err)
			assert.NotEmpty(t, rules)

			// List the proxy routing table, expect a single entry.
			rt, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
				&netlink.Route{Table: proxyRoutingTable}, netlink.RT_FILTER_TABLE)
			assert.NoError(t, err)
			assert.Len(t, rt, 1)

			// Ensure idempotence.
			assert.NoError(t, installRoutesIPv6())

			// Remove routes installed before.
			assert.NoError(t, removeRoutesIPv6())

			rules, err = route.ListRules(netlink.FAMILY_V6, &tproxyRule)
			assert.NoError(t, err)
			assert.Empty(t, rules)

			// List the proxy routing table, expect it to be empty.
			rt, err = netlink.RouteListFiltered(netlink.FAMILY_V6,
				&netlink.Route{Table: proxyRoutingTable}, netlink.RT_FILTER_TABLE)
			assert.NoError(t, err)
			assert.Len(t, rt, 0)

			return nil
		})
	})
}
