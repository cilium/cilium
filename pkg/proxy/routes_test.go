// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"expvar"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

const (
	defaultMTU      = 0
	withOverheadMTU = mtu.EthernetMTU - mtu.EncryptionIPsecOverhead
)

func filterDefaultRouteIPv4(t *testing.T, rt []netlink.Route) netlink.Route {
	_, defaultDst4, _ := net.ParseCIDR("0.0.0.0/0")
	i := slices.IndexFunc(rt, func(r netlink.Route) bool { return r.Dst.String() == defaultDst4.String() })
	require.Greater(t, i, -1, "unable to retrieve default IPv4 route")
	return rt[i]
}

func filterDefaultRouteIPv6(t *testing.T, rt []netlink.Route) netlink.Route {
	_, defaultDst6, _ := net.ParseCIDR("::/0")
	i := slices.IndexFunc(rt, func(r netlink.Route) bool { return r.Dst.String() == defaultDst6.String() })
	require.Greater(t, i, -1, "unable to retrieve default IPv6 route")
	return rt[i]
}

func TestRequireFromProxyRoutes(t *testing.T) {
	saved := option.Config
	t.Cleanup(func() { option.Config = saved })

	tests := []struct {
		name                 string
		routingMode          string
		enableEnvoyConfig    bool
		enableEndpointRoutes bool
		ipsecEnabled         bool
		wireguardEnabled     bool
		wantIngress          bool
		wantEgress           bool
		wantEPID             bool
	}{
		{
			name:                 "tunneling mode: all false regardless of features",
			routingMode:          option.RoutingModeTunnel,
			enableEnvoyConfig:    true,
			enableEndpointRoutes: true,
		},
		{
			name:        "native, no features",
			routingMode: option.RoutingModeNative,
		},
		{
			name:                 "native, envoy without per-ep routes",
			routingMode:          option.RoutingModeNative,
			enableEnvoyConfig:    true,
			enableEndpointRoutes: false,
			wantIngress:          true,
		},
		{
			name:                 "native, envoy with per-ep routes",
			routingMode:          option.RoutingModeNative,
			enableEnvoyConfig:    true,
			enableEndpointRoutes: true,
			wantIngress:          true,
			wantEPID:             true,
		},
		{
			name:         "native, ipsec",
			routingMode:  option.RoutingModeNative,
			ipsecEnabled: true,
			wantIngress:  true,
			wantEgress:   true,
		},
		{
			name:             "native, wireguard",
			routingMode:      option.RoutingModeNative,
			wireguardEnabled: true,
			wantIngress:      true,
		},
		{
			name:                 "native, envoy + per-ep routes + ipsec",
			routingMode:          option.RoutingModeNative,
			enableEnvoyConfig:    true,
			enableEndpointRoutes: true,
			ipsecEnabled:         true,
			wantIngress:          true,
			wantEgress:           true,
			wantEPID:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config = &option.DaemonConfig{
				RoutingMode:          tt.routingMode,
				EnableEnvoyConfig:    tt.enableEnvoyConfig,
				EnableEndpointRoutes: tt.enableEndpointRoutes,
			}

			gotIngress, gotEgress, gotEPID, _ := requireFromProxyRoutes(tt.ipsecEnabled, tt.wireguardEnabled, 0)
			assert.Equal(t, tt.wantIngress, gotIngress, "fromIngressProxy")
			assert.Equal(t, tt.wantEgress, gotEgress, "fromEgressProxy")
			assert.Equal(t, tt.wantEPID, gotEPID, "fromProxyEgressEPID")
		})
	}
}

func TestPrivilegedRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	newHive := func(t *testing.T, routeManager **reconciler.DesiredRouteManager, reconcilerMetrics *reconciler.RouteReconcilerMetrics) *hive.Hive {
		t.Helper()
		return hive.New(
			linux.DevicesControllerCell,
			reconciler.Cell,
			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{
					StateDir: t.TempDir(),
				}
			}),
			cell.Invoke(func(routeManagerp *reconciler.DesiredRouteManager, metrics reconciler.RouteReconcilerMetrics) {
				*routeManager = routeManagerp
				*reconcilerMetrics = metrics
			}),
		)
	}

	loDevice := &tables.Device{
		Name:  "lo",
		Index: 1,
	}

	t.Run("IPv4", func(t *testing.T) {
		t.Run("toProxy", func(t *testing.T) {
			ns := netns.NewNetNS(t)
			logger := hivetest.Logger(t)

			ns.Do(func() error {
				var (
					routeManager      *reconciler.DesiredRouteManager
					reconcilerMetrics reconciler.RouteReconcilerMetrics
				)
				h := newHive(t, &routeManager, &reconcilerMetrics)
				err := h.Start(logger, t.Context())
				require.NoError(t, err, "start hive")

				defer func() {
					err := h.Stop(logger, t.Context())
					require.NoError(t, err, "stop hive")
				}()

				loLink, err := safenetlink.LinkByName(loDevice.Name)
				require.NoError(t, err, "get loopback link")
				netlink.LinkSetUp(loLink)

				owner, err := routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Install routes and rules the first time.
				assert.NoError(t, installToProxyRoutesIPv4(loDevice, routeManager, owner))

				rules, err := route.ListRules(netlink.FAMILY_V4, &toProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 1)

				// Ensure idempotence.
				assert.NoError(t, installToProxyRoutesIPv4(loDevice, routeManager, owner))

				recCount := reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value()

				// Remove routes installed before.
				assert.NoError(t, removeToProxyRulesIPv4())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				// Wait for the reconciler to process the deletions.
				tick := time.NewTicker(100 * time.Millisecond)
			loop:
				for {
					select {
					case <-t.Context().Done():
						t.Fatal("timeout waiting for toProxy routes and rules to be removed")
					case <-tick.C:
						if reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value() > recCount {
							tick.Stop()
							break loop
						}
					}
				}

				rules, err = route.ListRules(netlink.FAMILY_V4, &toProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Empty(t, rt)

				return nil
			})
		})

		t.Run("fromProxy", func(t *testing.T) {
			testIPv4 := netip.MustParseAddr("1.2.3.4")
			ns := netns.NewNetNS(t)
			logger := hivetest.Logger(t)
			ns.Do(func() error {
				var (
					routeManager      *reconciler.DesiredRouteManager
					reconcilerMetrics reconciler.RouteReconcilerMetrics
				)
				h := newHive(t, &routeManager, &reconcilerMetrics)
				err := h.Start(logger, t.Context())
				require.NoError(t, err, "start hive")

				defer func() {
					err := h.Stop(logger, t.Context())
					require.NoError(t, err, "stop hive")
				}()

				owner, err := routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// create test device
				ifName := "dummy"
				dummy := &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: ifName,
					},
				}
				err = netlink.LinkAdd(dummy)
				assert.NoError(t, err)

				assert.NoError(t, netlink.LinkSetUp(dummy))

				dummyLink, err := safenetlink.LinkByName(ifName)
				assert.NoError(t, err)
				dummyDevice := &tables.Device{
					Name:  dummyLink.Attrs().Name,
					Index: dummyLink.Attrs().Index,
				}

				// Install routes and rules the first time.
				assert.NoError(t, installFromProxyRoutesIPv4(routeManager, owner, testIPv4, dummyDevice, true, true, false, defaultMTU))

				rules, err := route.ListRules(netlink.FAMILY_V4, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the from proxy (2005) routing table, expect a single entry.
				rt, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Expect default route MTU set.
				defaultRoute := filterDefaultRouteIPv4(t, rt)
				assert.Equal(t, defaultMTU, defaultRoute.MTU)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv4(routeManager, owner, testIPv4, dummyDevice, true, true, false, defaultMTU))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRulesIPv4())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				owner, err = routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Verify the EPID rule is installed and removed when fromProxyEgressEPID is true.
				assert.NoError(t, installFromProxyRoutesIPv4(routeManager, owner, testIPv4, dummyDevice, false, false, true, defaultMTU))

				epIDRules, err := route.ListRules(netlink.FAMILY_V4, &fromProxyEgressEPIDRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, epIDRules, "EPID rule should be present")

				// Neither ingress nor egress proxy rule should be installed.
				ingressRules, err := route.ListRules(netlink.FAMILY_V4, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, ingressRules, "ingress proxy rule should not be present")

				assert.NoError(t, removeFromProxyRulesIPv4())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				epIDRules, err = route.ListRules(netlink.FAMILY_V4, &fromProxyEgressEPIDRule)
				assert.NoError(t, err)
				assert.Empty(t, epIDRules, "EPID rule should be removed")

				owner, err = routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Install routes and rules with non-default MTU -- this would happen with
				// IPSec enabled and both ingress and egress policies in-place.
				assert.NoError(t, installFromProxyRoutesIPv4(routeManager, owner, testIPv4, dummyDevice, true, true, false, withOverheadMTU))

				// Re-list the from proxy (2005) routing table, expect a single entry.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Expect default route to use the lower MTU.
				defaultRoute = filterDefaultRouteIPv4(t, rt)
				assert.Equal(t, withOverheadMTU, defaultRoute.MTU)

				recCount := reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value()

				// Remove installed routes.
				assert.NoError(t, removeFromProxyRulesIPv4())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				// Wait for the reconciler to process the deletions.
				tick := time.NewTicker(100 * time.Millisecond)
			loop:
				for {
					select {
					case <-t.Context().Done():
						t.Fatal("timeout waiting for toProxy routes and rules to be removed")
					case <-tick.C:
						if reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value() > recCount {
							tick.Stop()
							break loop
						}
					}
				}

				rules, err = route.ListRules(netlink.FAMILY_V4, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V4,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Empty(t, rt)

				return nil
			})
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Run("toProxy", func(t *testing.T) {
			ns := netns.NewNetNS(t)
			logger := hivetest.Logger(t)

			ns.Do(func() error {
				var routeManager *reconciler.DesiredRouteManager
				var reconcilerMetrics reconciler.RouteReconcilerMetrics
				h := newHive(t, &routeManager, &reconcilerMetrics)
				err := h.Start(logger, t.Context())
				require.NoError(t, err, "start hive")

				defer func() {
					err := h.Stop(logger, t.Context())
					require.NoError(t, err, "stop hive")
				}()

				loLink, err := safenetlink.LinkByName(loDevice.Name)
				require.NoError(t, err, "get loopback link")
				netlink.LinkSetUp(loLink)

				owner, err := routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Install routes and rules the first time.
				assert.NoError(t, installToProxyRulesIPv6(loDevice, routeManager, owner))

				rules, err := route.ListRules(netlink.FAMILY_V6, &toProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 1)

				// Ensure idempotence.
				assert.NoError(t, installToProxyRulesIPv6(loDevice, routeManager, owner))

				recCount := reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value()

				// Remove routes installed before.
				assert.NoError(t, removeToProxyRulesIPv6())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				// Wait for the reconciler to process the deletions.
				tick := time.NewTicker(100 * time.Millisecond)
			loop:
				for {
					select {
					case <-t.Context().Done():
						t.Fatal("timeout waiting for toProxy routes and rules to be removed")
					case <-tick.C:
						if reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value() > recCount {
							tick.Stop()
							break loop
						}
					}
				}

				rules, err = route.ListRules(netlink.FAMILY_V6, &toProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableToProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Empty(t, rt)

				return nil
			})
		})

		t.Run("fromProxy", func(t *testing.T) {
			testIPv6 := netip.MustParseAddr("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
			ns := netns.NewNetNS(t)
			logger := hivetest.Logger(t)

			ns.Do(func() error {
				var (
					routeManager      *reconciler.DesiredRouteManager
					reconcilerMetrics reconciler.RouteReconcilerMetrics
				)
				h := newHive(t, &routeManager, &reconcilerMetrics)
				err := h.Start(logger, t.Context())
				require.NoError(t, err, "start hive")

				defer func() {
					err := h.Stop(logger, t.Context())
					require.NoError(t, err, "stop hive")
				}()

				owner, err := routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// create test device
				ifName := "dummy"
				dummy := &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: ifName,
					},
				}
				err = netlink.LinkAdd(dummy)
				assert.NoError(t, err)
				assert.NoError(t, netlink.LinkSetUp(dummy))

				dummyLink, err := safenetlink.LinkByName(ifName)
				assert.NoError(t, err)
				dummyDevice := &tables.Device{
					Name:  dummyLink.Attrs().Name,
					Index: dummyLink.Attrs().Index,
				}

				// Install routes and rules the first time.
				assert.NoError(t, installFromProxyRoutesIPv6(owner, routeManager, testIPv6, dummyDevice, true, true, false, defaultMTU))

				rules, err := route.ListRules(netlink.FAMILY_V6, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)

				// List the proxy routing table, expect a single entry.
				rt, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Expect default route MTU set.
				defaultRoute := filterDefaultRouteIPv6(t, rt)
				assert.Equal(t, defaultMTU, defaultRoute.MTU)

				// Ensure idempotence.
				assert.NoError(t, installFromProxyRoutesIPv6(owner, routeManager, testIPv6, dummyDevice, true, true, false, defaultMTU))

				// Remove routes installed before.
				assert.NoError(t, removeFromProxyRulesIPv6())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				owner, err = routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Verify the EPID rule is installed and removed when fromProxyEgressEPID is true.
				assert.NoError(t, installFromProxyRoutesIPv6(owner, routeManager, testIPv6, dummyDevice, false, false, true, defaultMTU))

				epIDRules, err := route.ListRules(netlink.FAMILY_V6, &fromProxyEgressEPIDRule)
				assert.NoError(t, err)
				assert.NotEmpty(t, epIDRules, "EPID rule should be present")

				// Neither ingress nor egress proxy rule should be installed.
				ingressRules, err := route.ListRules(netlink.FAMILY_V6, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, ingressRules, "ingress proxy rule should not be present")

				assert.NoError(t, removeFromProxyRulesIPv6())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				epIDRules, err = route.ListRules(netlink.FAMILY_V6, &fromProxyEgressEPIDRule)
				assert.NoError(t, err)
				assert.Empty(t, epIDRules, "EPID rule should be removed")

				owner, err = routeManager.RegisterOwner("test-proxy")
				require.NoError(t, err, "register route owner")

				// Install routes and rules with non-default MTU -- this would happen with
				// IPSec enabled and both ingress and egress policies in-place.
				assert.NoError(t, installFromProxyRoutesIPv6(owner, routeManager, testIPv6, dummyDevice, true, true, false, withOverheadMTU))

				// Re-list the from proxy (2005) routing table, expect a single entry.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Len(t, rt, 2)

				// Expect default route to use the lower MTU.
				defaultRoute = filterDefaultRouteIPv6(t, rt)
				assert.Equal(t, withOverheadMTU, defaultRoute.MTU)

				recCount := reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value()

				// Remove installed routes.
				assert.NoError(t, removeFromProxyRulesIPv6())
				assert.NoError(t, routeManager.RemoveOwner(owner))

				// Wait for the reconciler to process the deletions.
				tick := time.NewTicker(100 * time.Millisecond)
			loop:
				for {
					select {
					case <-t.Context().Done():
						t.Fatal("timeout waiting for toProxy routes and rules to be removed")
					case <-tick.C:
						if reconcilerMetrics.ReconciliationCountVar.Get("route-reconciler").(*expvar.Int).Value() > recCount {
							tick.Stop()
							break loop
						}
					}
				}

				rules, err = route.ListRules(netlink.FAMILY_V6, &fromIngressProxyRule)
				assert.NoError(t, err)
				assert.Empty(t, rules)

				// List the proxy routing table, expect it to be empty.
				rt, err = safenetlink.RouteListFiltered(netlink.FAMILY_V6,
					&netlink.Route{Table: linux_defaults.RouteTableFromProxy}, netlink.RT_FILTER_TABLE)
				assert.NoError(t, err)
				assert.Empty(t, rt)

				return nil
			})
		})
	})

}
