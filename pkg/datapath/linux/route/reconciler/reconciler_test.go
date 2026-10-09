// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"maps"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
)

func newTestOps(t *testing.T,
	fakeRouteHandle *fakeRouteHandle,
	desiredRoutes map[DesiredRouteKey]struct{},
	pruneExclusions map[DesiredRouteKey]struct{},
	persisted map[DesiredRouteKey]struct{},
) *ops {
	t.Helper()

	db := statedb.New()
	tbl, err := newDesiredRouteTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(tbl)
	for key := range desiredRoutes {
		_, _, err := tbl.Insert(wtxn, &DesiredRoute{
			Table:    key.Table,
			Prefix:   key.Prefix,
			Priority: key.Priority,
		})
		require.NoError(t, err)
	}
	wtxn.Commit()

	ex := NewPruneExclusion()
	ex.keys = pruneExclusions

	return &ops{
		db:              db,
		tbl:             tbl,
		log:             hivetest.Logger(t),
		handle:          fakeRouteHandle,
		persistedKeys:   persisted,
		pruneExclusions: ex,
	}
}

type fakeRouteHandle struct {
	routes map[DesiredRouteKey]struct{}
}

func (h *fakeRouteHandle) Close() error { return nil }

func (h *fakeRouteHandle) RouteReplace(*netlink.Route) error {
	return nil
}

func fromRouteToKey(r *netlink.Route) (DesiredRouteKey, error) {
	prefix, ok := netipx.FromStdIPNet(r.Dst)
	if !ok {
		return DesiredRouteKey{}, fmt.Errorf("failed to parse prefix from route destination: %v", r.Dst)
	}
	return DesiredRouteKey{
		Table:    TableID(r.Table),
		Prefix:   prefix,
		Priority: uint32(r.Priority),
	}, nil
}

func (h *fakeRouteHandle) RouteDel(r *netlink.Route) error {
	key, err := fromRouteToKey(r)
	if err != nil {
		return err
	}
	delete(h.routes, key)
	return nil
}

func (h *fakeRouteHandle) RouteListFiltered(_ int, r *netlink.Route, _ uint64) ([]netlink.Route, error) {
	key, err := fromRouteToKey(r)
	if err != nil {
		return nil, err
	}
	if _, found := h.routes[key]; !found {
		return nil, nil
	}
	return []netlink.Route{*r}, nil
}

func TestRemoveStaleEntries(t *testing.T) {
	routeKey := func(prefix string) DesiredRouteKey {
		return DesiredRouteKey{
			Table:    TableMain,
			Prefix:   netip.MustParsePrefix(prefix),
			Priority: 0,
		}
	}
	keySet := func(keys ...DesiredRouteKey) map[DesiredRouteKey]struct{} {
		set := make(map[DesiredRouteKey]struct{}, len(keys))
		for _, key := range keys {
			set[key] = struct{}{}
		}
		return set
	}

	route1 := routeKey("10.0.0.0/24")
	route2 := routeKey("10.0.1.0/24")
	route3 := routeKey("10.0.2.0/24")

	tests := []struct {
		name                 string
		initialNetlinkRoutes map[DesiredRouteKey]struct{}
		desiredRoutes        map[DesiredRouteKey]struct{}
		pruneExclusions      map[DesiredRouteKey]struct{}
		persisted            map[DesiredRouteKey]struct{}
		expecteNetlinkRoutes map[DesiredRouteKey]struct{}
	}{
		{
			name:                 "remove no more desired entries",
			initialNetlinkRoutes: keySet(route1),
			desiredRoutes:        keySet(),
			pruneExclusions:      keySet(),
			persisted:            keySet(route1),
			expecteNetlinkRoutes: keySet(),
		},
		{
			name:                 "keep desired entries",
			initialNetlinkRoutes: keySet(route1),
			desiredRoutes:        keySet(route1),
			pruneExclusions:      keySet(),
			persisted:            keySet(route1),
			expecteNetlinkRoutes: keySet(route1),
		},
		{
			name:                 "keep excluded entries",
			initialNetlinkRoutes: keySet(route1),
			desiredRoutes:        keySet(),
			pruneExclusions:      keySet(route1),
			persisted:            keySet(route1),
			expecteNetlinkRoutes: keySet(route1),
		},
		{
			name:                 "ignore entries not persisted in WAL",
			initialNetlinkRoutes: keySet(route1),
			desiredRoutes:        keySet(),
			pruneExclusions:      keySet(),
			persisted:            keySet(),
			expecteNetlinkRoutes: keySet(route1),
		},
		{
			name:                 "ignore entries already absent from netlink",
			initialNetlinkRoutes: keySet(),
			desiredRoutes:        keySet(),
			pruneExclusions:      keySet(),
			persisted:            keySet(route1),
			expecteNetlinkRoutes: keySet(),
		},
		{
			name:                 "remove only no more desired entries",
			initialNetlinkRoutes: keySet(route1, route2, route3),
			desiredRoutes:        keySet(route2),
			pruneExclusions:      keySet(route3),
			persisted:            keySet(route1, route2, route3),
			expecteNetlinkRoutes: keySet(route2, route3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := &fakeRouteHandle{
				routes: maps.Clone(tt.initialNetlinkRoutes),
			}
			ops := newTestOps(t, handle, tt.desiredRoutes, tt.pruneExclusions, tt.persisted)
			ops.removeStaleEntries(ops.db.ReadTxn())
			require.Equal(t, tt.expecteNetlinkRoutes, handle.routes)
			require.Nil(t, ops.persistedKeys)
		})
	}
}
