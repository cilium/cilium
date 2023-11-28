// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb/index"
)

// Test_Regression_29324 tests that Get() on a index.String-based
// unique index only returns exact matches.
// https://github.com/cilium/cilium/issues/29324
func Test_Regression_29324(t *testing.T) {
	type object struct {
		ID  string
		Tag string
	}
	idIndex := Index[object, string]{
		Name: "id",
		FromObject: func(t object) index.KeySet {
			return index.NewKeySet(index.String(t.ID))
		},
		FromKey: index.String,
		Unique:  true,
	}
	tagIndex := Index[object, string]{
		Name: "tag",
		FromObject: func(t object) index.KeySet {
			return index.NewKeySet(index.String(t.Tag))
		},
		FromKey: index.String,
		Unique:  false,
	}

	db, _, _ := newTestDB(t)
	table, err := NewTable[object]("objects", idIndex, tagIndex)
	require.NoError(t, err)
	require.NoError(t, db.RegisterTable(table))

	wtxn := db.WriteTxn(table)
	table.Insert(wtxn, object{"foo", "aa"})
	table.Insert(wtxn, object{"foobar", "aaa"})
	table.Insert(wtxn, object{"baz", "aaaa"})
	wtxn.Commit()

	// Exact match should only return "foo"
	txn := db.ReadTxn()
	iter, _ := table.Get(txn, idIndex.Query("foo"))
	items := Collect(iter)
	if assert.Len(t, items, 1, "Get(\"foo\") should return one match") {
		assert.EqualValues(t, "foo", items[0].ID)
	}

	// Partial match on prefix should not return anything
	iter, _ = table.Get(txn, idIndex.Query("foob"))
	items = Collect(iter)
	assert.Len(t, items, 0, "Get(\"foob\") should return nothing")

	// Query on non-unique index should only return exact match
	iter, _ = table.Get(txn, tagIndex.Query("aa"))
	items = Collect(iter)
	if assert.Len(t, items, 1, "Get(\"aa\") on tags should return one match") {
		assert.EqualValues(t, "foo", items[0].ID)
	}

	// Partial match on prefix should not return anything on non-unique index
	iter, _ = table.Get(txn, idIndex.Query("a"))
	items = Collect(iter)
	assert.Len(t, items, 0, "Get(\"a\") should return nothing")

}
