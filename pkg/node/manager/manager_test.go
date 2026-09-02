// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func testClusterSizeDependantInterval(interval time.Duration) time.Duration {
	return interval
}

func TestNodeTableMirroring(t *testing.T) {
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	require.NoError(t, err)
	writer := node.NewWriter(logger, db, nodeTable)

	h, _ := cell.NewSimpleHealth()
	mngr, err := New(
		logger,
		NewNodeMetrics(),
		h,
		nil,
		db,
		nil,
		writer,
		testClusterSizeDependantInterval,
	)
	require.NoError(t, err)

	initialized, initWatch := nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)
	require.ElementsMatch(t, []string{
		ClusterNodeTableInitializerName,
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
		Source: source.KVStore,
	}
	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		}},
		Source: source.KVStore,
	}

	requireNode := func(t *testing.T, n nodeTypes.Node) {
		stored, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.True(t, found)
		require.Equal(t, n, stored.Node)
		require.Nil(t, stored.Local)
	}
	requireNoNode := func(t *testing.T, n nodeTypes.Node) {
		_, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.False(t, found)
	}

	mngr.NodeUpdated(n1)
	requireNode(t, n1)

	txn := db.WriteTxn(nodeTable)
	stored, _, found := nodeTable.Get(txn, node.NodeByName(n1.Fullname()))
	require.True(t, found)
	stored = stored.DeepCopy()
	stored.Statuses = stored.Statuses.Set("test", reconciler.StatusDone())
	_, _, err = nodeTable.Insert(txn, stored)
	require.NoError(t, err)
	txn.Commit()

	n1.EncryptionKey = 42
	mngr.NodeUpdated(n1)
	requireNode(t, n1)
	stored, _, found = nodeTable.Get(db.ReadTxn(), node.NodeByName(n1.Fullname()))
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindPending, stored.Statuses.Get("test").Kind)

	mngr.NodeUpdated(n2)
	requireNode(t, n1)
	requireNode(t, n2)

	// NodeManager delegates table conflict resolution to node.Writer. For
	// equal-priority address owners the latest update wins.
	n3 := n2.DeepCopy()
	n3.Name = "node3"
	mngr.NodeUpdated(*n3)
	requireNode(t, n1)
	requireNoNode(t, n2)
	requireNode(t, *n3)

	// Deleting the displaced node must not delete the current address owner.
	mngr.NodeDeleted(n2)
	requireNoNode(t, n2)
	requireNode(t, *n3)

	mngr.NodeUpdated(n2)
	requireNode(t, n1)
	requireNode(t, n2)
	requireNoNode(t, *n3)

	select {
	case <-initWatch:
		t.Fatal("node table initialized before NodeSync")
	default:
	}

	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)

	mngr.NodeSync()
	require.Equal(t, []string{
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	select {
	case <-initWatch:
		t.Fatal("node table initialized before MeshNodeSync")
	default:
	}

	mngr.MeshNodeSync()

	select {
	case <-initWatch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for node table initializer")
	}
	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.True(t, initialized)

	mngr.NodeDeleted(n1)
	requireNoNode(t, n1)
	requireNode(t, n2)
}

func TestPrefixClusterMutatorPropagatesToWriter(t *testing.T) {
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	require.NoError(t, err)
	writer := node.NewWriter(logger, db, nodeTable)

	health, _ := cell.NewSimpleHealth()
	mngr, err := New(
		logger,
		NewNodeMetrics(),
		health,
		nil,
		db,
		nil,
		writer,
		testClusterSizeDependantInterval,
	)
	require.NoError(t, err)

	mngr.SetPrefixClusterMutatorFn(func(n *nodeTypes.Node) []cmtypes.PrefixClusterOpts {
		clusterIDs := map[string]uint32{"cluster-1": 1, "cluster-2": 2}
		return []cmtypes.PrefixClusterOpts{cmtypes.WithClusterID(clusterIDs[n.Cluster])}
	})

	for _, cluster := range []string{"cluster-1", "cluster-2"} {
		mngr.NodeUpdated(nodeTypes.Node{
			Name:    "node-1",
			Cluster: cluster,
			Source:  source.Kubernetes,
			IPAddresses: []nodeTypes.Address{{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			}},
		})
	}

	for _, cluster := range []string{"cluster-1", "cluster-2"} {
		_, _, found := nodeTable.Get(
			db.ReadTxn(),
			node.NodeByName(nodeTypes.Identity{Name: "node-1", Cluster: cluster}.String()),
		)
		require.True(t, found, cluster)
	}
}

func TestNodeTableInitializersCompleteInEitherOrder(t *testing.T) {
	for _, meshFirst := range []bool{false, true} {
		name := "cluster-first"
		if meshFirst {
			name = "mesh-first"
		}
		t.Run(name, func(t *testing.T) {
			db := statedb.New()
			nodeTable, err := node.NewNodeTable(db)
			require.NoError(t, err)
			writer := node.NewWriter(hivetest.Logger(t), db, nodeTable)

			health, _ := cell.NewSimpleHealth()
			mngr, err := New(
				hivetest.Logger(t),
				NewNodeMetrics(),
				health,
				nil,
				db,
				nil,
				writer,
				testClusterSizeDependantInterval,
			)
			require.NoError(t, err)

			if meshFirst {
				mngr.MeshNodeSync()
				require.Equal(t, []string{
					ClusterNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.NodeSync()
			} else {
				mngr.NodeSync()
				require.Equal(t, []string{
					MeshNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.MeshNodeSync()
			}

			initialized, _ := nodeTable.Initialized(db.ReadTxn())
			require.True(t, initialized)
		})
	}
}
