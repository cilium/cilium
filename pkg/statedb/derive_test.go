// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type derived struct {
	ID      uint64
	Deleted bool
}

var derivedIdIndex = Index[derived, uint64]{
	Name: "id",
	FromObject: func(t derived) index.KeySet {
		return index.NewKeySet(index.Uint64(t.ID))
	},
	FromKey: index.Uint64,
	Unique:  true,
}

func TestDerive(t *testing.T) {
	var db *DB
	inTable, err := NewTable[testObject]("test", idIndex)
	require.NoError(t, err)
	outTable, err := NewTable[derived]("derived", derivedIdIndex)
	require.NoError(t, err)

	transform := func(obj testObject, deleted bool) (derived, DeriveResult) {
		t.Logf("transform(%v, %v)", obj, deleted)

		if len(obj.Tags) > 0 && obj.Tags[0] == "skip" {
			return derived{}, DeriveSkip
		}
		if deleted {
			if len(obj.Tags) > 0 && obj.Tags[0] == "delete" {
				return derived{ID: obj.ID}, DeriveDelete
			}
			return derived{ID: obj.ID, Deleted: true}, DeriveUpdate
		}
		return derived{ID: obj.ID, Deleted: false}, DeriveInsert
	}

	h := hive.New(
		Cell, // DB
		job.Cell,

		cell.Module(
			"test", "Test",

			cell.Provide(func(db_ *DB) (Table[testObject], RWTable[derived], error) {
				db = db_
				if err := db.RegisterTable(inTable); err != nil {
					return nil, nil, err
				}
				if err := db.RegisterTable(outTable); err != nil {
					return nil, nil, err
				}
				return inTable, outTable, nil
			}),

			cell.Invoke(Derive[testObject, derived]("testObject-to-derived", transform)),
		),
	)
	require.NoError(t, h.Start(context.TODO()), "Start")

	getDerived := func() []derived {
		txn := db.ReadTxn()
		iter, _ := outTable.All(txn)
		objs := Collect(iter)
		// Log so we can trace the failed eventually calls
		t.Logf("derived: %+v", objs)
		return objs
	}

	// Insert 1, 2 and 3 (skipped) and validate.
	wtxn := db.WriteTxn(inTable)
	inTable.Insert(wtxn, testObject{ID: 1})
	inTable.Insert(wtxn, testObject{ID: 2})
	inTable.Insert(wtxn, testObject{ID: 3, Tags: []string{"skip"}})
	wtxn.Commit()

	require.Eventually(t,
		func() bool {
			objs := getDerived()
			return len(objs) == 2 && // 3 is skipped
				objs[0].ID == 1 && objs[1].ID == 2
		},
		time.Second,
		10*time.Millisecond,
		"expected 1 & 2 to be derived",
	)

	// Delete 2 (testing DeriveUpdate)
	wtxn = db.WriteTxn(inTable)
	inTable.Delete(wtxn, testObject{ID: 2})
	wtxn.Commit()

	require.Eventually(t,
		func() bool {
			objs := getDerived()
			return len(objs) == 2 && // 3 is skipped
				objs[0].ID == 1 && !objs[0].Deleted &&
				objs[1].ID == 2 && objs[1].Deleted
		},
		time.Second,
		10*time.Millisecond,
		"expected 1 & 2, with 2 marked deleted",
	)

	// Delete 1 (testing DeriveDelete)
	wtxn = db.WriteTxn(inTable)
	inTable.Insert(wtxn, testObject{ID: 1, Tags: []string{"delete"}})
	wtxn.Commit()
	wtxn = db.WriteTxn(inTable)
	inTable.Delete(wtxn, testObject{ID: 1})
	wtxn.Commit()

	require.Eventually(t,
		func() bool {
			objs := getDerived()
			return len(objs) == 1 &&
				objs[0].ID == 2 && objs[0].Deleted
		},
		time.Second,
		10*time.Millisecond,
		"expected 1 to be gone, and 2 mark deleted",
	)

	require.NoError(t, h.Stop(context.TODO()), "Stop")
}
