// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"math/rand"
	"testing"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb/index"
)

func BenchmarkDB_WriteTxn_1(b *testing.B) {
	db, table, _ := newTestDB(b)
	for i := 0; i < b.N; i++ {
		txn := db.WriteTxn(table)
		_, _, err := table.Insert(txn, testObject{ID: 123, Tags: nil})
		require.NoError(b, err)
		txn.Commit()
	}
}

func BenchmarkDB_WriteTxn_10(b *testing.B) {
	db, table, _ := newTestDB(b)
	n := b.N
	for n > 0 {
		txn := db.WriteTxn(table)
		for j := 0; j < 10; j++ {
			_, _, err := table.Insert(txn, testObject{ID: uint64(j), Tags: nil})
			require.NoError(b, err)
		}
		txn.Commit()
		n -= 10
	}
	txn := db.WriteTxn(table)
	for j := 0; j < n; j++ {
		_, _, err := table.Insert(txn, testObject{ID: uint64(j), Tags: nil})
		require.NoError(b, err)
	}
	txn.Commit()
}

func BenchmarkDB_RandomInsert(b *testing.B) {
	db, table, _ := newTestDB(b)

	ids := []uint64{}
	for i := 0; i < b.N; i++ {
		ids = append(ids, uint64(i))
	}
	rand.Shuffle(b.N, func(i, j int) {
		ids[i], ids[j] = ids[j], ids[i]
	})
	b.ResetTimer()
	txn := db.WriteTxn(table)
	for _, id := range ids {
		_, _, err := table.Insert(txn, testObject{ID: id, Tags: nil})
		require.NoError(b, err)
	}
	txn.Commit()
	b.StopTimer()

	iter, _ := table.All(db.ReadTxn())
	require.Len(b, Collect(iter), b.N)
}

func BenchmarkDB_SequentialInsert(b *testing.B) {
	db, table, _ := newTestDB(b)

	b.ResetTimer()
	txn := db.WriteTxn(table)
	for id := uint64(0); id < uint64(b.N); id++ {
		_, _, err := table.Insert(txn, testObject{ID: id, Tags: nil})
		require.NoError(b, err)
	}
	txn.Commit()
	b.StopTimer()

	iter, _ := table.All(db.ReadTxn())
	require.Len(b, Collect(iter), b.N)
}

func BenchmarkDB_Baseline_SingleRadix_Insert(b *testing.B) {
	tree := iradix.New[uint64]()
	txn := tree.Txn()
	for i := uint64(0); i < uint64(b.N); i++ {
		txn.Insert(index.Uint64(i), i)
	}
	txn.Commit()
}

func BenchmarkDB_Baseline_Hashmap_Insert(b *testing.B) {
	m := map[uint64]uint64{}
	for i := uint64(0); i < uint64(b.N); i++ {
		m[i] = i
	}
}

func BenchmarkDB_Baseline_Hashmap_Lookup(b *testing.B) {
	m := map[uint64]uint64{}
	for i := uint64(0); i < uint64(b.N); i++ {
		m[i] = i
	}
	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); i++ {
		require.Equal(b, m[i], i)
	}
}

func BenchmarkDB_DeleteTracker_Baseline(b *testing.B) {
	db, table, _ := newTestDB(b)

	// Create b.N objects
	txn := db.WriteTxn(table)
	for i := 0; i < b.N; i++ {
		_, _, err := table.Insert(txn, testObject{ID: uint64(i), Tags: nil})
		require.NoError(b, err)
	}
	txn.Commit()
	b.ResetTimer()

	// Start the timer and delete all objects to time
	// the baseline without deletion tracking.
	txn = db.WriteTxn(table)
	table.DeleteAll(txn)
	txn.Commit()
}

func BenchmarkDB_DeleteTracker(b *testing.B) {
	db, table, _ := newTestDB(b)

	// Start tracking deletions from the start

	// Create b.N objects
	txn := db.WriteTxn(table)
	dt, err := table.DeleteTracker(txn, "test")
	require.NoError(b, err)
	defer dt.Close()
	for i := 0; i < b.N; i++ {
		_, _, err := table.Insert(txn, testObject{ID: uint64(i), Tags: nil})
		require.NoError(b, err)
	}
	txn.Commit()
	b.ResetTimer()

	// Start the timer and delete all objects to time the cost for
	// deletion tracking.
	txn = db.WriteTxn(table)
	table.DeleteAll(txn)
	txn.Commit()

	nDeleted := 0
	dt.Process(
		db.ReadTxn(),
		0,
		func(obj testObject, deleted bool, _ Revision) error {
			nDeleted++
			return nil
		})
	require.EqualValues(b, nDeleted, b.N)
	b.StopTimer()

	eventuallyGraveyardIsEmpty(b, db)
}

func BenchmarkDB_RandomLookup(b *testing.B) {
	db, table, _ := newTestDB(b)

	wtxn := db.WriteTxn(table)
	ids := []uint64{}
	for i := 0; i < b.N; i++ {
		ids = append(ids, uint64(i))
		_, _, err := table.Insert(wtxn, testObject{ID: uint64(i), Tags: nil})
		require.NoError(b, err)
	}
	wtxn.Commit()
	rand.Shuffle(b.N, func(i, j int) {
		ids[i], ids[j] = ids[j], ids[i]
	})
	b.ResetTimer()

	txn := db.ReadTxn()
	for _, id := range ids {
		_, _, ok := table.First(txn, idIndex.Query(id))
		require.True(b, ok)
	}
}

func BenchmarkDB_SequentialLookup(b *testing.B) {
	db, table, _ := newTestDB(b)
	wtxn := db.WriteTxn(table)
	ids := []uint64{}
	for i := 0; i < b.N; i++ {
		ids = append(ids, uint64(i))
		_, _, err := table.Insert(wtxn, testObject{ID: uint64(i), Tags: nil})
		require.NoError(b, err)
	}
	wtxn.Commit()
	b.ResetTimer()

	txn := db.ReadTxn()
	for _, id := range ids {
		obj, _, ok := table.First(txn, idIndex.Query(id))
		require.True(b, ok)
		require.Equal(b, obj.ID, id)
	}
}

func BenchmarkDB_FullIteration(b *testing.B) {
	db, table, _ := newTestDB(b)
	wtxn := db.WriteTxn(table)
	for i := 0; i < b.N; i++ {
		_, _, err := table.Insert(wtxn, testObject{ID: uint64(i), Tags: nil})
		require.NoError(b, err)
	}
	wtxn.Commit()
	b.ResetTimer()

	txn := db.ReadTxn()
	iter, _ := table.All(txn)
	i := uint64(0)
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		require.Equal(b, obj.ID, i)
		i++
	}
}
