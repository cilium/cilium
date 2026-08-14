// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestNodeWriterSingleBackgroundLoop(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	metrics := NewNodeMetrics()
	writer := NewNodeWriter(hivetest.Logger(t), db, nodes, metrics)

	done := &Node{Node: types.Node{Name: "done"}}
	done.Statuses = done.Statuses.Set("linux", reconciler.StatusDone())
	done.Statuses = done.Statuses.Set("wireguard", reconciler.StatusDone())
	done.Statuses = done.Statuses.Set(
		"retrying",
		reconciler.StatusError(errors.New("retrying")),
	)
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, done)
	require.NoError(t, err)
	txn.Commit()

	loopDone := make(chan struct{})
	go func() {
		writer.singleBackgroundLoop(t.Context(), time.Millisecond)
		close(loopDone)
	}()

	require.Eventually(t, func() bool {
		done, _, found := nodes.Get(db.ReadTxn(), NodeByName("done"))
		return found &&
			done.Statuses.Get("linux").Kind == reconciler.StatusKindRefreshing &&
			done.Statuses.Get("wireguard").Kind == reconciler.StatusKindRefreshing
	}, time.Second, time.Millisecond)
	select {
	case <-loopDone:
		t.Fatal("background loop did not wait for reconciliation")
	default:
	}

	txn = db.WriteTxn(nodes)
	done, _, found := nodes.Get(txn, NodeByName("done"))
	require.True(t, found)
	done = done.DeepCopy()
	done.Statuses = done.Statuses.Set("linux", reconciler.StatusDone())
	done.Statuses = done.Statuses.Set("wireguard", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, done)
	require.NoError(t, err)
	txn.Commit()

	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("background loop did not observe completed reconciliation")
	}
	done, _, found = nodes.Get(db.ReadTxn(), NodeByName("done"))
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindError,
		done.Statuses.Get("retrying").Kind)
	require.Equal(t, float64(1),
		prometheustestutil.ToFloat64(metrics.DatapathValidations))
}

func TestNodeWriterRefreshNodeLeavesPendingStatus(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	writer := NewNodeWriter(hivetest.Logger(t), db, nodes, NewNodeMetrics())

	pending := &Node{Node: types.Node{Name: "pending"}}
	pending.Statuses = pending.Statuses.Set("linux", reconciler.StatusPending())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, pending)
	require.NoError(t, err)
	txn.Commit()

	writer.refreshNode("pending")
	pending, _, found := nodes.Get(db.ReadTxn(), NodeByName("pending"))
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindPending,
		pending.Statuses.Get("linux").Kind)
}
