// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
)

func insertTestRoute(t testing.TB, db *statedb.DB, routes statedb.RWTable[*tables.Route], r *tables.Route) {
	t.Helper()
	txn := db.WriteTxn(routes)
	_, _, err := routes.Insert(txn, r)
	require.NoError(t, err)
	txn.Commit()
}

func assertRoute(t testing.TB,
	route *routeReconciler.DesiredRoute,
	expectedPrefix string,
	expectedOwner *routeReconciler.RouteOwner,
	expectedNexthop string,
) {
	t.Helper()
	require.Equal(t, expectedOwner, route.Owner)
	require.Equal(t, netip.MustParsePrefix(expectedPrefix), route.Prefix)
	require.Equal(t, netip.MustParseAddr(expectedNexthop), route.Nexthop)

	require.Equal(t, routeReconciler.TableMain, route.Table)
	require.Equal(t, routeReconciler.AdminDistanceDefault, route.AdminDistance)
}

func newTestDesiredRouteManagerSetup(t testing.TB) (
	*statedb.DB,
	statedb.Table[*routeReconciler.DesiredRoute],
	*routeReconciler.DesiredRouteManager,
) {
	t.Helper()
	var (
		routeManager  *routeReconciler.DesiredRouteManager
		desiredRoutes statedb.Table[*routeReconciler.DesiredRoute]
		db            *statedb.DB
	)
	hive.New(
		routeReconciler.TableCell,
		cell.Provide(func() reconciler.Reconciler[*routeReconciler.DesiredRoute] {
			return nil
		}),
		cell.Invoke(func(
			db_ *statedb.DB,
			routes statedb.Table[*routeReconciler.DesiredRoute],
			manager *routeReconciler.DesiredRouteManager,
		) {
			db = db_
			desiredRoutes = routes
			routeManager = manager
		}),
	).Populate(hivetest.Logger(t))
	return db, desiredRoutes, routeManager
}

func TestIsDirectRoute(t *testing.T) {
	tests := []struct {
		name    string
		route   *tables.Route
		ip      netip.Addr
		matches bool
	}{
		{
			name: "match",
			route: &tables.Route{
				Dst: netip.MustParsePrefix("192.168.1.0/24"),
			},
			ip:      netip.MustParseAddr("192.168.1.1"),
			matches: true,
		},
		{
			name: "no_match_due_to_gateway",
			route: &tables.Route{
				Dst: netip.MustParsePrefix("192.168.1.0/16"),
				Gw:  netip.MustParseAddr("192.168.1.254"),
			},
			ip:      netip.MustParseAddr("192.168.1.1"),
			matches: false,
		},
		{
			name: "match_node_is_gateway",
			route: &tables.Route{
				Dst: netip.MustParsePrefix("192.168.1.0/16"),
				Gw:  netip.MustParseAddr("192.168.1.254"),
			},
			ip:      netip.MustParseAddr("192.168.1.254"),
			matches: true,
		},
		{
			name: "no_match_different_subnet",
			route: &tables.Route{
				Dst: netip.MustParsePrefix("192.168.2.0/24"),
			},
			ip:      netip.MustParseAddr("192.168.1.1"),
			matches: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.matches, isDirectRoute(tt.route, tt.ip))
		})
	}
}

func TestIsNodeOnSameL2(t *testing.T) {
	db := statedb.New()
	routeTable, err := tables.NewRouteTable(db)
	require.NoError(t, err)

	for _, r := range []tables.Route{
		{
			Table: tables.RT_TABLE_MAIN,
			Dst:   netip.MustParsePrefix("0.0.0.0/0"),
			Gw:    netip.MustParseAddr("192.168.1.1"),
		},
		{
			Table: tables.RT_TABLE_MAIN,
			Dst:   netip.MustParsePrefix("10.0.0.0/8"),
			Gw:    netip.MustParseAddr("10.255.0.1"),
		},
		{
			Table: tables.RT_TABLE_MAIN,
			Dst:   netip.MustParsePrefix("10.1.2.0/24"),
		},
	} {
		insertTestRoute(t, db, routeTable, &r)
	}

	tests := []struct {
		name    string
		ip      net.IP
		matches bool
	}{
		{
			name:    "no_match",
			ip:      net.ParseIP("10.5.5.1"),
			matches: false,
		},
		{
			name:    "match",
			ip:      net.ParseIP("10.1.2.1"),
			matches: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.matches, isNodeOnSameL2(tt.ip, routeTable.ToTable(), db))
		})
	}
}

func TestDeleteNodeRoutes(t *testing.T) {
	db, desiredRoutes, rm := newTestDesiredRouteManagerSetup(t)

	// Create a route for the node
	nodeName := "node1"
	owner, err := rm.GetOrRegisterOwner(getOwnerName(nodeName))
	require.NoError(t, err)
	rm.UpsertRoute(routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        netip.MustParsePrefix("192.168.1.0/24"),
		AdminDistance: routeReconciler.AdminDistanceDefault,
	})
	routes := slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
	require.Len(t, routes, 1)

	// No error on deletion
	require.NoError(t, deleteNodeRoutes(rm, nodeName))
	// We should not find entries after the deletion
	routes = slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
	require.Empty(t, routes)

	// remove a non-existent owner should return nil
	require.NoError(t, deleteNodeRoutes(rm, "not-exist"))
}

func TestReplaceOwnerRoutes(t *testing.T) {
	baseIPv4 := netip.MustParseAddr("192.0.1.2")
	baseIPv6 := netip.MustParseAddr("fd00::2")
	baseIPv4Prefix := netip.MustParsePrefix("10.10.2.0/24")
	baseIPv6Prefix := netip.MustParsePrefix("fd00:10:10:2::/64")

	newIPv4 := netip.MustParseAddr("192.0.1.3")
	newIPv6 := netip.MustParseAddr("fd00::3")
	newIPv4Prefix := netip.MustParsePrefix("10.10.3.0/24")
	newIPv6Prefix := netip.MustParsePrefix("fd00:10:10:3::/64")

	newRoute := func(prefix netip.Prefix, nexthop netip.Addr) routeReconciler.DesiredRoute {
		return routeReconciler.DesiredRoute{
			Table:         routeReconciler.TableMain,
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       nexthop,
		}
	}

	baseRoutes := []routeReconciler.DesiredRoute{
		newRoute(baseIPv4Prefix, baseIPv4),
		newRoute(baseIPv6Prefix, baseIPv6),
	}
	tests := []struct {
		name     string
		initial  []routeReconciler.DesiredRoute
		replaced []routeReconciler.DesiredRoute
	}{
		{
			name:     "adds_routes",
			initial:  nil,
			replaced: baseRoutes,
		},
		{
			name:     "removes_routes",
			initial:  baseRoutes,
			replaced: nil,
		},
		{
			name:    "changes_prefix",
			initial: baseRoutes,
			replaced: []routeReconciler.DesiredRoute{
				newRoute(newIPv4Prefix, newIPv4),
				newRoute(newIPv6Prefix, newIPv6),
			},
		},
		{
			name:    "changes_nexthop_and_device",
			initial: baseRoutes,
			replaced: []routeReconciler.DesiredRoute{
				newRoute(baseIPv4Prefix, newIPv4),
				newRoute(baseIPv6Prefix, newIPv6),
			},
		},
		{
			name:    "add_new_route",
			initial: baseRoutes,
			replaced: append([]routeReconciler.DesiredRoute{
				newRoute(newIPv4Prefix, newIPv4),
			}, baseRoutes...),
		},
		{
			name:    "remove_stale_route",
			initial: baseRoutes,
			replaced: []routeReconciler.DesiredRoute{
				newRoute(baseIPv4Prefix, baseIPv4),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, desiredRoutes, rm := newTestDesiredRouteManagerSetup(t)
			owner, err := rm.RegisterOwner(getOwnerName("node1"))
			require.NoError(t, err)
			handler := &Handler{db: db, desiredRoutes: desiredRoutes, routeManager: rm}

			for i := range tt.initial {
				tt.initial[i].Owner = owner
			}
			for i := range tt.replaced {
				tt.replaced[i].Owner = owner
			}

			require.NoError(t, handler.replaceOwnerRoutes(owner, tt.initial))
			require.Len(t, slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn()))), len(tt.initial))
			require.NoError(t, handler.replaceOwnerRoutes(owner, tt.replaced))

			routes := slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
			require.Len(t, routes, len(tt.replaced))
			for _, expected := range tt.replaced {
				actual, _, found := desiredRoutes.Get(db.ReadTxn(), routeReconciler.DesiredRouteIndex.Query(expected.GetFullKey()))
				require.True(t, found)
				assertRoute(t, actual, expected.Prefix.String(), owner, expected.Nexthop.String())
			}
		})
	}
}

func TestReplaceOwnerRoutesDoesNotInsertUnchangedRoute(t *testing.T) {
	db, desiredRoutes, rm := newTestDesiredRouteManagerSetup(t)
	owner, err := rm.RegisterOwner(getOwnerName("node1"))
	require.NoError(t, err)
	handler := &Handler{db: db, desiredRoutes: desiredRoutes, routeManager: rm}
	route := routeReconciler.DesiredRoute{
		Owner:         owner,
		Table:         routeReconciler.TableMain,
		Prefix:        netip.MustParsePrefix("10.10.2.0/24"),
		AdminDistance: routeReconciler.AdminDistanceDefault,
		Nexthop:       netip.MustParseAddr("192.0.1.2"),
	}

	// We first insert the route
	require.NoError(t, handler.replaceOwnerRoutes(owner, []routeReconciler.DesiredRoute{route}))
	before, beforeRevision, found := desiredRoutes.Get(
		db.ReadTxn(), routeReconciler.DesiredRouteIndex.Query(route.GetFullKey()),
	)
	require.True(t, found)

	// we now try to replace a new identical route and expect no changes
	require.NoError(t, handler.replaceOwnerRoutes(owner, []routeReconciler.DesiredRoute{route}))
	after, afterRevision, found := desiredRoutes.Get(
		db.ReadTxn(), routeReconciler.DesiredRouteIndex.Query(route.GetFullKey()),
	)
	// Same object, same revision, same status.
	require.True(t, found)
	require.Same(t, before, after)
	require.Equal(t, beforeRevision, afterRevision)
	require.Equal(t, before.GetStatus(), after.GetStatus())
}
