// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_test

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestBackendNeighborSync(t *testing.T) {
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions.
	goleakOpt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, goleakOpt) })

	var (
		db       *statedb.DB
		backends statedb.RWTable[*loadbalancer.Backend]
	)
	mock := &mockNodeNeighbors{
		updates: make(chan *nodeTypes.Node),
		deletes: make(chan *nodeTypes.Node),
	}

	h := hive.New(
		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
			func() types.NodeNeighbors { return mock },
		),
		linux.BackendNeighborSyncCell,
		cell.Invoke(func(db_ *statedb.DB, backends_ statedb.RWTable[*loadbalancer.Backend]) {
			db = db_
			backends = backends_
		}),
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
	})

	var addr1, addr2 loadbalancer.L3n4Addr
	addr1.ParseFromString("1.0.0.1:80/TCP")
	addr2.ParseFromString("2.0.0.2:80/TCP")

	wtxn := db.WriteTxn(backends)
	backends.Insert(wtxn, &loadbalancer.Backend{Address: addr1})
	backends.Insert(wtxn, &loadbalancer.Backend{Address: addr2})
	wtxn.Commit()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)

	requireHasAddress := func(ch chan *nodeTypes.Node, addr loadbalancer.L3n4Addr) {
		select {
		case n := <-ch:
			require.True(t, nodeHasAddress(n, addr))
		case <-ctx.Done():
			t.Fatalf("timeout waiting for address")
		}
	}

	requireHasAddress(mock.updates, addr1)
	requireHasAddress(mock.updates, addr2)

	wtxn = db.WriteTxn(backends)
	backends.DeleteAll(wtxn)
	wtxn.Commit()

	requireHasAddress(mock.deletes, addr1)
	requireHasAddress(mock.deletes, addr2)
}

type mockNodeNeighbors struct {
	updates chan *nodeTypes.Node
	deletes chan *nodeTypes.Node
}

func nodeHasAddress(n *nodeTypes.Node, addr loadbalancer.L3n4Addr) bool {
	return len(n.IPAddresses) > 0 && n.IPAddresses[0].IP.Equal(addr.AddrCluster.AsNetIP())
}

// DeleteMiscNeighbor implements types.NodeNeighbors.
func (m *mockNodeNeighbors) DeleteMiscNeighbor(oldNode *nodeTypes.Node) {
	m.deletes <- oldNode
}

// InsertMiscNeighbor implements types.NodeNeighbors.
func (m *mockNodeNeighbors) InsertMiscNeighbor(newNode *nodeTypes.Node) {
	m.updates <- newNode
}

func (m *mockNodeNeighbors) NodeCleanNeighbors(migrateOnly bool) { panic("unimplemented") }
func (m *mockNodeNeighbors) NodeNeighDiscoveryEnabled() bool     { panic("unimplemented") }
func (m *mockNodeNeighbors) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node) error {
	panic("unimplemented")
}

var _ types.NodeNeighbors = &mockNodeNeighbors{}
