// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb/index"
)

func Test_runQuery(t *testing.T) {
	db, table, _ := newTestDB(t, tagsIndex)

	wtxn := db.WriteTxn(table)
	table.Insert(wtxn, testObject{1, []string{"foo"}})
	table.Insert(wtxn, testObject{2, []string{"foo"}})
	table.Insert(wtxn, testObject{3, []string{"foobar"}})
	table.Insert(wtxn, testObject{4, []string{"baz"}})
	wtxn.Commit()

	txn := db.ReadTxn()

	// idIndex, unique
	indexTxn, err := txn.getTxn().indexReadTxn(table.Name(), idIndex.Name)
	require.NoError(t, err)
	items := []object{}
	onObject := func(obj object) error {
		items = append(items, obj)
		return nil
	}
	runQuery(indexTxn, false, index.Uint64(1), onObject)
	if assert.Len(t, items, 1) {
		assert.EqualValues(t, items[0].data.(testObject).ID, 1)
	}

	// tagsIndex, non-unique
	indexTxn, err = txn.getTxn().indexReadTxn(table.Name(), tagsIndex.Name)
	require.NoError(t, err)
	items = nil
	runQuery(indexTxn, false, index.String("foo"), onObject)

	if assert.Len(t, items, 2) {
		assert.EqualValues(t, items[0].data.(testObject).ID, 1)
		assert.EqualValues(t, items[1].data.(testObject).ID, 2)
	}

	// lower-bound on revision index
	indexTxn, err = txn.getTxn().indexReadTxn(table.Name(), RevisionIndex)
	require.NoError(t, err)
	items = nil
	runQuery(indexTxn, true, index.Uint64(0), onObject)
	if assert.Len(t, items, 4) {
		// Items are in revision (creation) order
		assert.EqualValues(t, items[0].data.(testObject).ID, 1)
		assert.EqualValues(t, items[1].data.(testObject).ID, 2)
		assert.EqualValues(t, items[2].data.(testObject).ID, 3)
		assert.EqualValues(t, items[3].data.(testObject).ID, 4)
	}
}
