// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
)

func TestUpsertRoute(t *testing.T) {
	db := statedb.New()
	tbl, err := newDesiredRouteTable(db)
	require.NoError(t, err)
	manager := newDesiredRouteManager(db, tbl, nil)

	defaultPriority := uint32(1)
	defaultPrefix := netip.MustParsePrefix("10.0.0.1/32")
	newDesiredRouteWithOwner := func(owner *RouteOwner) DesiredRoute {
		return DesiredRoute{
			Owner:         owner,
			Prefix:        defaultPrefix,
			AdminDistance: AdminDistanceDefault,
			Table:         TableMain,
			Priority:      defaultPriority,
		}
	}

	assertRoute := func(key DesiredRouteKey, selected bool, statusKind reconciler.StatusKind) {
		t.Helper()
		stored, _, found := tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(key))
		require.True(t, found)
		require.Equal(t, selected, stored.selected)
		require.Equal(t, statusKind, stored.GetStatus().Kind)
		require.Equal(t, AdminDistanceDefault, stored.AdminDistance)
		require.Equal(t, TableMain, stored.Table)
		require.Equal(t, defaultPriority, stored.Priority)
		require.Equal(t, defaultPrefix, stored.Prefix)
	}

	// We create 3 owners, and they will all try to insert the same route.
	// We want to test the selection logic and the status updates of the routes.
	owner1, err := manager.RegisterOwner("owner1")
	require.NoError(t, err)
	owner2, err := manager.RegisterOwner("owner2")
	require.NoError(t, err)
	owner3, err := manager.RegisterOwner("owner3")
	require.NoError(t, err)

	// Insert a route with owner2 first.
	owner2Route := newDesiredRouteWithOwner(owner2)
	require.NoError(t, manager.UpsertRoute(owner2Route))
	// After the upsert the route should be selected and be in pending state waiting for reconciliation.
	assertRoute(owner2Route.GetFullKey(), true, reconciler.StatusKindPending)

	// Now we insert a route with owner1.
	owner1Route := newDesiredRouteWithOwner(owner1)
	require.NoError(t, manager.UpsertRoute(owner1Route))
	// After the upsert the route with owner1 should be selected because owner1 comes first in lexicographical order.
	assertRoute(owner1Route.GetFullKey(), true, reconciler.StatusKindPending)
	assertRoute(owner2Route.GetFullKey(), false, reconciler.StatusKindPending)

	// Now we insert a route with owner3.
	owner3Route := newDesiredRouteWithOwner(owner3)
	require.NoError(t, manager.UpsertRoute(owner3Route))

	// The other 2 routes should remain untouched
	assertRoute(owner1Route.GetFullKey(), true, reconciler.StatusKindPending)
	assertRoute(owner2Route.GetFullKey(), false, reconciler.StatusKindPending)
	// After the upsert the route with owner3 should not be selected because owner1 comes first in lexicographical order.
	// And the status should be Done since its not selected.
	assertRoute(owner3Route.GetFullKey(), false, reconciler.StatusKindDone)
}

func TestSameSpec(t *testing.T) {
	base := DesiredRoute{
		Owner:         &RouteOwner{name: "owner"},
		Table:         TableMain,
		Priority:      uint32(1),
		Prefix:        netip.MustParsePrefix("10.0.0.1/32"),
		AdminDistance: AdminDistanceDefault,
		Nexthop:       netip.MustParseAddr("192.0.2.1"),
		selected:      true,
		status: reconciler.Status{
			UpdatedAt: time.Now(),
			Kind:      reconciler.StatusKindPending,
		},
	}

	tests := []struct {
		name      string
		mutate    func(r *DesiredRoute)
		wantEqual bool
	}{
		{
			name:      "same",
			mutate:    func(r *DesiredRoute) {},
			wantEqual: true,
		},
		{
			name: "status",
			mutate: func(r *DesiredRoute) {
				r.selected = false
				r.status = reconciler.Status{
					Kind: reconciler.StatusKindDone,
				}
			},
			wantEqual: true,
		},
		{
			name: "owner",
			mutate: func(r *DesiredRoute) {
				r.Owner = &RouteOwner{name: "owner"}
			},
			wantEqual: false,
		},
		{
			name: "table",
			mutate: func(r *DesiredRoute) {
				r.Table = TableLocal
			},
			wantEqual: false,
		},
		{
			name: "prefix",
			mutate: func(r *DesiredRoute) {
				r.Prefix = netip.MustParsePrefix("10.0.0.0/24")
			},
			wantEqual: false,
		},
		{
			name: "nexthop",
			mutate: func(r *DesiredRoute) {
				r.Nexthop = netip.MustParseAddr("192.0.2.2")
			},
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			tt.mutate(&other)
			require.Equal(t, tt.wantEqual, base.SameSpec(&other))
		})
	}
}
