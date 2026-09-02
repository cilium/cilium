// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

func TestStore(t *testing.T) {
	db := statedb.New()
	table, err := node.NewNodeTable(db)
	require.NoError(t, err)
	store := NewStore(db, table)

	txn := db.WriteTxn(table)
	_, _, err = table.Insert(txn, &node.Node{Node: types.Node{Name: "node-1"}})
	require.NoError(t, err)
	txn.Commit()

	require.Equal(t, map[string]types.Node{
		"node-1": {Name: "node-1"},
	}, store.Nodes())
}
