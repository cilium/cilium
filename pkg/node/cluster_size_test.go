// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/backoff"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestClusterSizeDependantInterval(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	interval := NewClusterSizeDependantInterval(db, nodes)
	base := time.Minute

	require.Equal(t, base, interval(base))

	txn := db.WriteTxn(nodes)
	for _, name := range []string{"node-1", "node-2", "node-3"} {
		_, _, err := nodes.Insert(txn, &Node{Node: nodeTypes.Node{Name: name}})
		require.NoError(t, err)
	}
	txn.Commit()

	require.Equal(
		t,
		backoff.ClusterSizeDependantInterval(base, 3),
		interval(base),
	)
}
