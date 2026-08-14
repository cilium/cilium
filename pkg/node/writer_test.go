// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestSourceWriter(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewNodeWriter(hivetest.Logger(t), db, nodes)
	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Abort()
		changed := w.Upsert(txn, n)
		txn.Commit()
		return changed
	}
	deleteNode := func(src source.Source, identity types.Identity) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Abort()
		changed := w.Delete(txn, src, identity)
		txn.Commit()
		return changed
	}

	n := &types.Node{Name: "node-1", Source: source.Kubernetes}
	require.True(t, upsert(n))

	txn := db.ReadTxn()
	got, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	require.Equal(t, source.Kubernetes, got.Source)

	got = got.DeepCopy()
	got.Statuses = got.Statuses.Set("test", reconciler.StatusDone())
	wtxn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(wtxn, got)
	require.NoError(t, err)
	wtxn.Commit()

	// An identical update preserves the completed status and table revision.
	revision := nodes.Revision(db.ReadTxn())
	require.False(t, upsert(n))
	require.Equal(t, revision, nodes.Revision(db.ReadTxn()))

	// A weaker source cannot replace or delete the object.
	weakNode := n.DeepCopy()
	weakNode.Source = source.ClusterMesh
	weakNode.Labels = map[string]string{"source": "mesh"}
	require.False(t, upsert(weakNode))
	require.False(t, deleteNode(weakNode.Source, weakNode.Identity()))

	// A stronger source takes ownership and resets reconciliation statuses.
	strongNode := n.DeepCopy()
	strongNode.Source = source.KVStore
	strongNode.Labels = map[string]string{"source": "kvstore"}
	require.True(t, upsert(strongNode))
	got, _, found = nodes.Get(db.ReadTxn(), NodeByName("node-1"))
	require.True(t, found)
	require.Equal(t, source.KVStore, got.Source)
	require.Equal(t, reconciler.StatusKindPending, got.Statuses.Get("test").Kind)

	require.False(t, deleteNode(n.Source, n.Identity()))
	require.True(t, deleteNode(strongNode.Source, strongNode.Identity()))
	_, _, found = nodes.Get(db.ReadTxn(), NodeByName("node-1"))
	require.False(t, found)
}

func TestSourceWriterDoesNotOverwriteLocalNode(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewNodeWriter(hivetest.Logger(t), db, nodes)

	local := &Node{
		Node:  types.Node{Name: "local", Source: source.Local},
		Local: &LocalNodeInfo{},
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()

	remote := &types.Node{Name: "local", Source: source.KVStore}
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, remote))
	require.False(t, w.Delete(txn, remote.Source, remote.Identity()))
	txn.Commit()
	got, _, found := nodes.Get(db.ReadTxn(), NodeByName("local"))
	require.True(t, found)
	require.NotNil(t, got.Local)
}

func TestNodeWriterRefresh(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewNodeWriter(hivetest.Logger(t), db, nodes)

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background()) }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found && n.Statuses.Get("test").Kind == reconciler.StatusKindPending
	}, time.Second, 10*time.Millisecond)

	txn = db.WriteTxn(nodes)
	n, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	n = n.DeepCopy()
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
	require.NoError(t, <-done)
}
