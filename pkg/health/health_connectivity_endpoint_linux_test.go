// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedConfigureHealthRouting(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		dev      = "test-health0"
		routeMTU = 1400
		routerV4 = "10.0.0.1"
		routerV6 = "f00d::a00:0:0:1"
	)

	addressing := &models.NodeAddressing{
		IPv4: &models.NodeAddressingElement{Enabled: true, IP: iputil.AddrFrom(netip.MustParseAddr(routerV4))},
		IPv6: &models.NodeAddressingElement{Enabled: true, IP: iputil.AddrFrom(netip.MustParseAddr(routerV6))},
	}
	v4Routes, err := connector.IPv4Routes(addressing, routeMTU)
	require.NoError(t, err)
	v6Routes, err := connector.IPv6Routes(addressing, routeMTU)
	require.NoError(t, err)
	routes := append(v4Routes, v6Routes...)

	h := &ciliumHealthManager{logger: hivetest.Logger(t)}

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		// The interface is left down on purpose: route installation has to
		// bring it up, like it does for a freshly created endpoint interface.
		require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dev}}))

		// Installing the routes more than once must succeed.
		for range 2 {
			require.NoError(t, h.configureHealthRouting(routes, dev))
		}

		link, err := safenetlink.LinkByName(dev)
		require.NoError(t, err)
		require.NotZero(t, link.Attrs().Flags&net.FlagUp, "interface not up")

		installed, err := safenetlink.RouteList(link, netlink.FAMILY_ALL)
		require.NoError(t, err)

		for _, tc := range []struct {
			name   string
			router string
			host   string
			def    string
			family int
			scope  netlink.Scope
		}{
			{name: "IPv4", router: routerV4, host: routerV4 + "/32", def: "0.0.0.0/0", family: netlink.FAMILY_V4, scope: netlink.SCOPE_LINK},
			{name: "IPv6", router: routerV6, host: routerV6 + "/128", def: "::/0", family: netlink.FAMILY_V6, scope: netlink.SCOPE_UNIVERSE},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// Route to the router, without a gateway. IPv6 has no route
				// scope, the kernel always reports it as universe.
				hostRoute := findRoute(installed, tc.family, tc.host)
				require.NotNil(t, hostRoute, "missing route to router %s", tc.host)
				require.Empty(t, hostRoute.Gw)
				require.Equal(t, tc.scope, hostRoute.Scope)

				// Default route via the router, with the route MTU.
				defRoute := findRoute(installed, tc.family, tc.def)
				require.NotNil(t, defRoute, "missing default route")
				require.True(t, net.ParseIP(tc.router).Equal(defRoute.Gw), "unexpected gateway %s", defRoute.Gw)
				require.Equal(t, routeMTU, defRoute.MTU)
			})
		}
		return nil
	}))
}

// findRoute returns the route to the given prefix in the given address family.
func findRoute(routes []netlink.Route, family int, prefix string) *netlink.Route {
	for _, r := range routes {
		if r.Family != family {
			continue
		}
		dst := "0.0.0.0/0"
		if family == netlink.FAMILY_V6 {
			dst = "::/0"
		}
		if r.Dst != nil {
			dst = r.Dst.String()
		}
		if dst == prefix {
			return &r
		}
	}
	return nil
}
