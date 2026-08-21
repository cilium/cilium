// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestLinuxNodeCheckpointPruning(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	live := nodeTypes.Node{Name: "live", Cluster: "cluster"}
	stale := nodeTypes.Node{Name: "stale", Cluster: "cluster"}
	stateDir := t.TempDir()
	file, err := os.Create(filepath.Join(stateDir, nodesFilename))
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(file).Encode([]nodeTypes.Node{live, stale}))
	require.NoError(t, file.Close())

	txn := db.WriteTxn(nodes)
	nodes.Insert(txn, &node.Node{Node: live})
	txn.Commit()

	cleaned := []nodeTypes.Identity{}
	health, _ := cell.NewSimpleHealth()
	checkpoint := newLinuxNodeCheckpoint(
		hivetest.Logger(t),
		health,
		db,
		nodes,
		func(_ context.Context, n nodeTypes.Node) error {
			cleaned = append(cleaned, n.Identity())
			return nil
		},
		stateDir,
	)
	checkpoint.restore()

	require.NoError(t, checkpoint.prune(t.Context(), health))
	require.Equal(t, []nodeTypes.Identity{stale.Identity()}, cleaned)
	require.Empty(t, checkpoint.restoredNodes)
}

func TestLinuxNodeCheckpointRetainsCleanupFailures(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	stale := nodeTypes.Node{Name: "stale", Cluster: "cluster"}
	stale.Source = source.Restored
	health, _ := cell.NewSimpleHealth()
	checkpoint := newLinuxNodeCheckpoint(
		hivetest.Logger(t),
		health,
		db,
		nodes,
		func(context.Context, nodeTypes.Node) error {
			return fmt.Errorf("cleanup failed")
		},
		t.TempDir(),
	)
	checkpoint.restoredNodes[stale.Identity()] = &stale

	require.Error(t, checkpoint.prune(t.Context(), health))
	require.Contains(t, checkpoint.restoredNodes, stale.Identity())
	require.NoError(t, checkpoint.checkpoint())

	contents, err := os.ReadFile(filepath.Join(checkpoint.stateDir, nodesFilename))
	require.NoError(t, err)
	var stored []nodeTypes.Node
	require.NoError(t, json.Unmarshal(contents, &stored))
	require.Equal(t, []nodeTypes.Node{stale}, stored)
}
