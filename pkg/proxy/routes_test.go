// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	t.Run("IPv4", func(t *testing.T) {
		t.Run("toProxy", func(t *testing.T) {
			ns := netns.NewNetNS(t)

			ns.Do(func() error {
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
			testIPv4 := net.ParseIP("1.2.3.4")
			ns := netns.NewNetNS(t)
			ns.Do(func() error {
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
				assert.NoError(t, installFromProxyRoutesIPv4(testIPv4, ifName, true, true))

				rules, err := route.ListRules(netlink.FAMILY_V4, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the from proxy (2005) routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv4(testIPv4, ifName, true, true))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRoutesIPv4())

				rules, err = route.ListRules(netlink.FAMILY_V4, &fromIngressProxyRule)
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
			ns := netns.NewNetNS(t)

			ns.Do(func() error {
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
			testIPv6 := net.ParseIP("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
			ns := netns.NewNetNS(t)

			ns.Do(func() error {
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
				assert.NoError(t, installFromProxyRoutesIPv6(testIPv6, ifName, true, true))

				rules, err := route.ListRules(netlink.FAMILY_V6, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv6(testIPv6, ifName, true, true))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRoutesIPv6())

				rules, err = route.ListRules(netlink.FAMILY_V6, &fromIngressProxyRule)
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
