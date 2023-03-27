// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2responder

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type fixture struct {
	reconciler         *l2ResponderReconciler
	proxyNeighborTable statedb.Table[*tables.L2AnnounceEntry]
	stateDB            statedb.DB
	mockNetlink        *mockNeighborNetlink
}

func newFixture() *fixture {
	var (
		tbl statedb.Table[*tables.L2AnnounceEntry]
		db  statedb.DB
	)

	hive.New(
		statedb.Cell,
		tables.Cell,
		cell.Invoke(func(d statedb.DB, t statedb.Table[*tables.L2AnnounceEntry]) {
			db = d
			tbl = t
		}),
	).Populate()

	nl := &mockNeighborNetlink{}

	return &fixture{
		reconciler: NewL2ResponderReconciler(params{
			Lifecycle:           &hive.DefaultLifecycle{},
			Logger:              logrus.New(),
			L2AnnouncementTable: tbl,
			StateDB:             db,
			L2ResponderMap:      l2respondermap.NewFakeMap(),
			NetLink:             nl,
		}),
		proxyNeighborTable: tbl,
		stateDB:            db,
		mockNetlink:        nl,
	}
}

// empty map, add entry, partial
// empty map, add + del entry, partial
// empty map, add entry, full
// empty map, add + del entry, full

// 1 rouge, add entry, partial
// 1 rouge, add entry, full
// 1 rouge, del entry, partial
// 1 rouge, del entry, full

// 1 normal, add entry, partial
// 1 normal, add entry, full
// 1 normal, del entry, partial
// 1 normal, del entry, full

type mockNeighborNetlink struct {
	LinkByNameFn func(name string) (netlink.Link, error)
}

func (m *mockNeighborNetlink) LinkByName(name string) (netlink.Link, error) {
	if m.LinkByNameFn == nil {
		return nil, fmt.Errorf("Not implemented")
	}

	return m.LinkByNameFn(name)
}
