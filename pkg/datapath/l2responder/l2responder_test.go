// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2responder

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

type fixture struct {
	reconciler         *l2ResponderReconciler
	proxyNeighborTable statedb.RWTable[*tables.L2AnnounceEntry]
	stateDB            *statedb.DB
	mockNetlink        *mockNeighborNetlink
	respondermap       l2respondermap.Map
}

func newFixture() *fixture {
	var (
		tbl statedb.RWTable[*tables.L2AnnounceEntry]
		db  *statedb.DB
		jr  job.Registry
	)

	hive.New(
		statedb.Cell,
		job.Cell,
		cell.Provide(
			tables.NewL2AnnounceTable,
			statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
		),
		cell.Invoke(
			statedb.RegisterTable[*tables.L2AnnounceEntry],
			func(d *statedb.DB, t statedb.RWTable[*tables.L2AnnounceEntry], j job.Registry) {

				db = d
				tbl = t
				jr = j
			}),
	).Populate()

	nl := &mockNeighborNetlink{}
	m := l2respondermap.NewFakeMap()

	return &fixture{
		reconciler: NewL2ResponderReconciler(params{
			Lifecycle:           &hive.DefaultLifecycle{},
			Logger:              logrus.New(),
			L2AnnouncementTable: tbl,
			StateDB:             db,
			L2ResponderMap:      m,
			NetLink:             nl,
			JobRegistry:         jr,
		}),
		proxyNeighborTable: tbl,
		stateDB:            db,
		mockNetlink:        nl,
		respondermap:       m,
	}
}

var (
	ip1     = netip.MustParseAddr("1.2.3.4")
	ip2     = netip.MustParseAddr("2.3.4.5")
	ip3     = netip.MustParseAddr("3.4.5.6")
	origin1 = resource.Key{Name: "abc"}
)

const (
	if1    = "eno01"
	ifidx1 = 123
)

// Start with an empty map, add a new entry to the table, trigger a partial reconciliation.
// We expect to see the new entry being added.
func TestEmptyMapAddPartialSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	rev := fix.proxyNeighborTable.Revision(txn)
	tracker, err := fix.proxyNeighborTable.DeleteTracker(txn, "l2-responder-reconciler")
	assert.NoError(t, err)
	txn.Commit()

	defer tracker.Close()

	txn = fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err = fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	txn.Commit()

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	// Pre canceled context so `cycle` exits after partial reconciliation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fix.reconciler.cycle(ctx, tracker, rev, nil)

	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
}

// Start with an empty map, add a new entry to the table and do a soft deleted of a non-existing entry,
// trigger a partial reconciliation. We expect to see the new entry being added and the deleted entry
// to not be added.
func TestEmptyMapAddDelPartialSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	rev := fix.proxyNeighborTable.Revision(txn)
	tracker, err := fix.proxyNeighborTable.DeleteTracker(txn, "l2-responder-reconciler")
	assert.NoError(t, err)
	txn.Commit()

	defer tracker.Close()

	txn = fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err = fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	_, _, err = fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip2,
			NetworkInterface: if1,
		},
	})
	assert.NoError(t, err)
	txn.Commit()

	txn = fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err = fix.proxyNeighborTable.Delete(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip2,
			NetworkInterface: if1,
		},
	})
	assert.NoError(t, err)
	txn.Commit()

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	// Pre canceled context so `cycle` exits after partial reconciliation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fix.reconciler.cycle(ctx, tracker, rev, nil)

	// Added entry should be present
	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Deleted entry should not be present
	stats, err = fix.respondermap.Lookup(ip2, ifidx1)
	assert.NoError(t, err)
	assert.Nil(t, stats)
}

// Start with an empty map, add a new entry to the table, trigger a full reconciliation.
// We expect to see the new entry being added.
func TestEmptyMapAddFullSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err := fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	txn.Commit()

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	_, err = fix.reconciler.fullReconciliation()
	assert.NoError(t, err)

	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
}

// Start with an empty map, add a new entry to the table and do a soft deleted of a non-existing entry,
// trigger a full reconciliation. We expect to see the new entry being added and the deleted entry
// to not be added.
func TestEmptyMapAddDelFullSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err := fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	_, _, err = fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip2,
			NetworkInterface: if1,
		},
	})
	assert.NoError(t, err)
	txn.Commit()

	txn = fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err = fix.proxyNeighborTable.Delete(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip2,
			NetworkInterface: if1,
		},
	})
	assert.NoError(t, err)
	txn.Commit()

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	_, err = fix.reconciler.fullReconciliation()
	assert.NoError(t, err)

	// Added entry should be present
	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Deleted entry should not be present
	stats, err = fix.respondermap.Lookup(ip2, ifidx1)
	assert.NoError(t, err)
	assert.Nil(t, stats)
}

// Add a rouge entry to the map, add a new entry, trigger partial reconciliation.
// We expect both entry to be present, since partial reconciliation does not purge rouge entries.
func Test1RougeAddPartialSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	rev := fix.proxyNeighborTable.Revision(txn)
	tracker, err := fix.proxyNeighborTable.DeleteTracker(txn, "l2-responder-reconciler")
	assert.NoError(t, err)
	txn.Commit()

	defer tracker.Close()

	txn = fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err = fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	txn.Commit()

	err = fix.respondermap.Create(ip3, ifidx1)
	assert.NoError(t, err)

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	// Pre canceled context so `cycle` exits after partial reconciliation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fix.reconciler.cycle(ctx, tracker, rev, nil)

	// Added entry should be present
	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Rouge entry will not be deleted
	stats, err = fix.respondermap.Lookup(ip3, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
}

// Add a rouge entry to the map, add a new entry, trigger full reconciliation.
// We expect only our new entry to be present, no rouge entry anymore.
func Test1RougeAddFullSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err := fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	txn.Commit()

	err = fix.respondermap.Create(ip3, ifidx1)
	assert.NoError(t, err)

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	_, err = fix.reconciler.fullReconciliation()
	assert.NoError(t, err)

	// Added entry should be present
	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Rouge entry will be deleted
	stats, err = fix.respondermap.Lookup(ip3, ifidx1)
	assert.NoError(t, err)
	assert.Nil(t, stats)
}

// Add a entry to the map, add the same entry, trigger full reconciliation.
// We expect nothing to happen since the same entry already exists.
func Test1ExistingAddFullSync(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.proxyNeighborTable)
	_, _, err := fix.proxyNeighborTable.Insert(txn, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               ip1,
			NetworkInterface: if1,
		},
		Origins: []resource.Key{origin1},
	})
	assert.NoError(t, err)
	txn.Commit()

	err = fix.respondermap.Create(ip1, ifidx1)
	assert.NoError(t, err)

	fix.mockNetlink.LinkByNameFn = func(name string) (netlink.Link, error) {
		return &mockLink{
			attr: netlink.LinkAttrs{Index: ifidx1},
		}, nil
	}

	_, err = fix.reconciler.fullReconciliation()
	assert.NoError(t, err)

	// Added entry should be present
	stats, err := fix.respondermap.Lookup(ip1, ifidx1)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
}

type mockNeighborNetlink struct {
	LinkByNameFn func(name string) (netlink.Link, error)
}

func (m *mockNeighborNetlink) LinkByName(name string) (netlink.Link, error) {
	if m.LinkByNameFn == nil {
		return nil, fmt.Errorf("Not implemented")
	}

	return m.LinkByNameFn(name)
}

type mockLink struct {
	attr netlink.LinkAttrs
}

func (ml *mockLink) Attrs() *netlink.LinkAttrs {
	return &ml.attr
}

func (ml *mockLink) Type() string {
	return "mock"
}
