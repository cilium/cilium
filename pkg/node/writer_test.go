// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestWriterReconcilerRegistration(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	get := func(name string) *Node {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found)
		return n
	}

	// Registration also adds a pending status to nodes that already exist.
	require.True(t, upsert(&types.Node{
		Name:   "existing",
		Source: source.Kubernetes,
	}))
	require.Empty(t, maps.Collect(get("existing").Statuses.All()))
	existing := get("existing").DeepCopy()
	existing.Statuses = existing.Statuses.Set("already-done", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, existing)
	require.NoError(t, err)
	txn.Commit()

	w.RegisterReconciler("wireguard")
	existing = get("existing")
	require.Equal(t,
		reconciler.StatusKindPending,
		existing.Statuses.Get("wireguard").Kind,
	)
	require.Contains(t, maps.Collect(existing.Statuses.All()), "wireguard")
	require.Equal(t,
		reconciler.StatusKindDone,
		existing.Statuses.Get("already-done").Kind,
	)
	require.Equal(t, []NodeReconciler{"wireguard"}, requiredReconcilers(db, nodes, w))

	// Required reconcilers are materialized on newly inserted nodes. Seeing one
	// completed status therefore cannot hide another required pending status.
	w.RegisterReconciler("ipset")
	require.Equal(t,
		[]NodeReconciler{"ipset", "wireguard"},
		requiredReconcilers(db, nodes, w),
	)
	require.True(t, upsert(&types.Node{
		Name:   "new",
		Source: source.Kubernetes,
	}))

	// Duplicate registration panics
	require.Panics(t,
		func() {
			w.RegisterReconciler("ipset")
		})

	newNode := get("new").DeepCopy()
	require.Len(t, maps.Collect(newNode.Statuses.All()), 2)
	newNode.Statuses = newNode.Statuses.Set("ipset", reconciler.StatusDone())
	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, newNode)
	require.NoError(t, err)
	txn.Commit()

	newNode = get("new")
	require.Equal(t,
		reconciler.StatusKindDone,
		newNode.Statuses.Get("ipset").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindPending,
		newNode.Statuses.Get("wireguard").Kind,
	)

	w.UnregisterReconciler("wireguard")
	require.Equal(t, []NodeReconciler{"ipset"}, requiredReconcilers(db, nodes, w))
	existing = get("existing")
	newNode = get("new")
	require.NotContains(t, maps.Collect(existing.Statuses.All()), "wireguard")
	require.NotContains(t, maps.Collect(newNode.Statuses.All()), "wireguard")
	require.Equal(t,
		reconciler.StatusKindDone,
		existing.Statuses.Get("already-done").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindDone,
		newNode.Statuses.Get("ipset").Kind,
	)

	// Duplicate unregistration does not rewrite the nodes.
	revision := nodes.Revision(db.ReadTxn())
	w.UnregisterReconciler("wireguard")
	require.Equal(t, revision, nodes.Revision(db.ReadTxn()))

	// Re-registering materializes a fresh pending status on all nodes.
	w.RegisterReconciler("wireguard")
	require.Contains(t, maps.Collect(get("existing").Statuses.All()), "wireguard")
	require.Contains(t, maps.Collect(get("new").Statuses.All()), "wireguard")
	require.Equal(t,
		reconciler.StatusKindPending,
		get("existing").Statuses.Get("wireguard").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindPending,
		get("new").Statuses.Get("wireguard").Kind,
	)
}

func requiredReconcilers(
	db *statedb.DB,
	nodes statedb.RWTable[*Node],
	w *Writer,
) []NodeReconciler {
	txn := db.WriteTxn(nodes)
	defer txn.Abort()
	return w.getRequiredReconcilers(txn)
}

func TestWriterWaitUntilReconciled(t *testing.T) {
	newWriter := func(t *testing.T) (*statedb.DB, statedb.RWTable[*Node], *Writer) {
		t.Helper()
		db := statedb.New()
		nodes, err := NewNodeTable(db)
		require.NoError(t, err)
		return db, nodes, NewWriter(hivetest.Logger(t), db, nodes)
	}
	upsert := func(
		t *testing.T,
		db *statedb.DB,
		nodes statedb.RWTable[*Node],
		w *Writer,
		name string,
	) {
		t.Helper()
		txn := db.WriteTxn(nodes)
		require.True(t, w.Upsert(txn, &types.Node{
			Name:   name,
			Source: source.Kubernetes,
		}))
		txn.Commit()
	}
	setStatus := func(
		t *testing.T,
		db *statedb.DB,
		nodes statedb.RWTable[*Node],
		nodeName, reconcilerName string,
		status reconciler.Status,
	) {
		t.Helper()
		txn := db.WriteTxn(nodes)
		n, _, found := nodes.Get(txn, NodeByName(nodeName))
		require.True(t, found)
		updated := *n
		updated.Statuses = updated.Statuses.Set(reconcilerName, status)
		_, _, err := nodes.Insert(txn, &updated)
		require.NoError(t, err)
		txn.Commit()
	}
	waitUntilReconciled := func(
		t *testing.T,
		w *Writer,
		txn statedb.ReadTxn,
		requireDone bool,
	) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		require.NoError(t, w.WaitUntilReconciled(ctx, txn, requireDone))
	}

	t.Run("all statuses must finish", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("ipset")
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "node-1")
		setStatus(t, db, nodes, "node-1", "ipset", reconciler.StatusDone())

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err := w.WaitUntilReconciled(ctx, db.ReadTxn(), false)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		setStatus(t, db, nodes, "node-1", "wireguard", reconciler.StatusError(errors.New("failed")))
		waitUntilReconciled(t, w, db.ReadTxn(), false)

		ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err = w.WaitUntilReconciled(ctx, db.ReadTxn(), true)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		setStatus(t, db, nodes, "node-1", "wireguard", reconciler.StatusDone())
		waitUntilReconciled(t, w, db.ReadTxn(), true)
	})

	t.Run("deleted target is finished", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "node-1")
		txn := db.ReadTxn()

		wtxn := db.WriteTxn(nodes)
		n, _, found := nodes.Get(wtxn, NodeByName("node-1"))
		require.True(t, found)
		_, _, err := nodes.Delete(wtxn, n)
		require.NoError(t, err)
		wtxn.Commit()

		waitUntilReconciled(t, w, txn, false)
	})

	t.Run("new nodes are not included", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "initial")
		setStatus(t, db, nodes, "initial", "wireguard", reconciler.StatusDone())
		txn := db.ReadTxn()

		upsert(t, db, nodes, w, "later")
		waitUntilReconciled(t, w, txn, true)
	})
}

func TestWriterRefresh(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	w.RegisterReconciler("other")
	w.RegisterReconciler("test")

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("other", reconciler.StatusPending())
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background(), "test") }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found &&
			n.Statuses.Get("test").Kind == reconciler.StatusKindPending &&
			n.Statuses.Get("other").Kind == reconciler.StatusKindPending
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

	require.ErrorContains(
		t,
		w.Refresh(context.Background(), "not-registered"),
		`node reconciler "not-registered" is not registered`,
	)
}

func TestWriterRefreshAll(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	w.RegisterReconciler("first")
	w.RegisterReconciler("second")

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("first", reconciler.StatusDone())
	n.Statuses = n.Statuses.Set("second", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background()) }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found &&
			n.Statuses.Get("first").Kind == reconciler.StatusKindPending &&
			n.Statuses.Get("second").Kind == reconciler.StatusKindPending
	}, time.Second, 10*time.Millisecond)

	txn = db.WriteTxn(nodes)
	n, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	n = n.DeepCopy()
	n.Statuses = n.Statuses.Set("first", reconciler.StatusDone())
	n.Statuses = n.Statuses.Set("second", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
	require.NoError(t, <-done)
}
