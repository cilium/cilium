// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/statedb"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/types"
)

func TestNodeCountMetric(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	metrics := NewNodeMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- trackNodeCount(ctx, db, nodes, metrics)
	}()

	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, &Node{Node: types.Node{Name: "node-1"}})
	require.NoError(t, err)
	txn.Commit()
	require.Eventually(t, func() bool {
		return prometheustestutil.ToFloat64(metrics.NumNodes) == 1
	}, time.Second, 10*time.Millisecond)

	txn = db.WriteTxn(nodes)
	n, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	_, _, err = nodes.Delete(txn, n)
	require.NoError(t, err)
	txn.Commit()
	require.Eventually(t, func() bool {
		return prometheustestutil.ToFloat64(metrics.NumNodes) == 0
	}, time.Second, 10*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
}
