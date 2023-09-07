// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb/index"
)

func TestMain(m *testing.M) {
	// Catch any leaks of goroutines from these tests.
	goleak.VerifyTestMain(m)
}

type testObject struct {
	ID   uint64
	Tags []string
}

var (
	idIndex = Index[testObject, uint64]{
		Name: "id",
		FromObject: func(t testObject) index.KeySet {
			return index.NewKeySet(index.Uint64(t.ID))
		},
		FromKey: func(n uint64) []byte {
			return index.Uint64(n)
		},
		Unique: true,
	}

	tagsIndex = Index[testObject, string]{
		Name: "tags",
		FromObject: func(t testObject) index.KeySet {
			return index.StringSlice(t.Tags)
		},
		FromKey: func(tag string) []byte {
			return index.String(tag)
		},
		Unique: false,
	}
)

func testWithDB(t testing.TB, withTags bool, test func(db *DB, table Table[testObject])) {
	var (
		db    *DB
		table Table[testObject]
	)

	logging.SetLogLevel(logrus.ErrorLevel)
	defer logging.SetLogLevel(logrus.InfoLevel)

	secondaryIndexers := []Indexer[testObject]{}
	if withTags {
		secondaryIndexers = append(secondaryIndexers, tagsIndex)
	}

	h := hive.New(
		Cell, // DB
		NewTableCell[testObject](
			"test",
			idIndex,
			secondaryIndexers...,
		),

		cell.Invoke(func(db_ *DB, table_ Table[testObject]) {
			// Use a short GC interval.
			db_.setGCRateLimitInterval(50 * time.Millisecond)

			db = db_
			table = table_
		}),
	)

	require.NoError(t, h.Start(context.TODO()))
	t.Cleanup(func() {
		assert.NoError(t, h.Stop(context.TODO()))
	})
	test(db, table)
}

func TestDB_LowerBound_ByRevision(t *testing.T) {
	testWithDB(t, true, func(db *DB, table Table[testObject]) {
		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 42, Tags: []string{"hello", "world"}})
			txn.Commit()

			txn = db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 71, Tags: []string{"foo"}})
			txn.Commit()
		}

		txn := db.ReadTxn()

		iter, watch := table.LowerBound(txn, ByRevision[testObject](0))
		obj, rev, ok := iter.Next()
		require.True(t, ok, "expected ByRevision(rev1) to return results")
		require.EqualValues(t, 42, obj.ID)
		prevRev := rev
		obj, rev, ok = iter.Next()
		require.True(t, ok)
		require.EqualValues(t, 71, obj.ID)
		require.Greater(t, rev, prevRev)
		_, _, ok = iter.Next()
		require.False(t, ok)

		iter, _ = table.LowerBound(txn, ByRevision[testObject](prevRev+1))
		obj, _, ok = iter.Next()
		require.True(t, ok, "expected ByRevision(rev2) to return results")
		require.EqualValues(t, 71, obj.ID)
		_, _, ok = iter.Next()
		require.False(t, ok)

		select {
		case <-watch:
			t.Fatalf("expected LowerBound watch to not be closed before changes")
		default:
		}

		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 71, Tags: []string{"foo", "modified"}})
			txn.Commit()
		}

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatalf("expected LowerBound watch to close after changes")
		}

		txn = db.ReadTxn()
		iter, _ = table.LowerBound(txn, ByRevision[testObject](rev+1))
		obj, _, ok = iter.Next()
		require.True(t, ok, "expected ByRevision(rev2+1) to return results")
		require.EqualValues(t, 71, obj.ID)
		_, _, ok = iter.Next()
		require.False(t, ok)

	})
}

func TestDB_DeleteTracker(t *testing.T) {
	testWithDB(t, true, func(db *DB, table Table[testObject]) {
		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 42, Tags: []string{"hello", "world"}})
			table.Insert(txn, testObject{ID: 71, Tags: []string{"foo"}})
			table.Insert(txn, testObject{ID: 83, Tags: []string{"bar"}})
			txn.Commit()
		}

		// Create two delete trackers
		wtxn := db.WriteTxn(table)
		deleteTracker, err := table.DeleteTracker(wtxn, "test")
		require.NoError(t, err, "failed to create DeleteTracker")
		wtxn.Commit()

		wtxn = db.WriteTxn(table)
		deleteTracker2, err := table.DeleteTracker(wtxn, "test2")
		require.NoError(t, err, "failed to create DeleteTracker")
		wtxn.Commit()

		// Delete 2/3 objects
		{
			txn := db.WriteTxn(table)
			old, deleted, err := table.Delete(txn, testObject{ID: 42})
			require.True(t, deleted)
			require.EqualValues(t, 42, old.ID)
			require.NoError(t, err)
			old, deleted, err = table.Delete(txn, testObject{ID: 71})
			require.True(t, deleted)
			require.EqualValues(t, 71, old.ID)
			require.NoError(t, err)
			txn.Commit()

			// Reinsert and redelete to test updating graveyard with existing object.
			txn = db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 71, Tags: []string{"foo"}})
			txn.Commit()

			txn = db.WriteTxn(table)
			_, deleted, err = table.Delete(txn, testObject{ID: 71})
			require.True(t, deleted)
			require.NoError(t, err)
			txn.Commit()
		}

		// 1 object should exist.
		txn := db.ReadTxn()
		iter, _ := table.All(txn)
		objs := Collect(iter)
		require.Len(t, objs, 1)

		// Consume the deletions using the first delete tracker.
		nExist := 0
		nDeleted := 0
		rev, _, err := deleteTracker.Process(
			txn,
			0,
			func(obj testObject, deleted bool, _ Revision) error {
				if deleted {
					nDeleted++
				} else {
					nExist++
				}
				return nil
			})
		require.NoError(t, err)
		require.Equal(t, nDeleted, 2)
		require.Equal(t, nExist, 1)
		require.Equal(t, table.Revision(txn), rev-1)

		// Since the second delete tracker has not processed the deletions,
		// the graveyard index should still hold them.
		require.False(t, db.graveyardIsEmpty())

		// Consume the deletions using the second delete tracker, but
		// with a failure first.
		nExist = 0
		nDeleted = 0
		failErr := errors.New("fail")
		rev, _, err = deleteTracker2.Process(
			txn,
			0,
			func(obj testObject, deleted bool, _ Revision) error {
				if deleted {
					nDeleted++
					return failErr
				}
				nExist++
				return nil
			})
		require.ErrorIs(t, err, failErr)
		require.Equal(t, nExist, 1) // Existing objects are iterated first.
		require.Equal(t, nDeleted, 1)
		nExist = 0
		nDeleted = 0

		// Process again from the failed revision.
		rev, _, err = deleteTracker2.Process(
			txn,
			rev,
			func(obj testObject, deleted bool, _ Revision) error {
				if deleted {
					nDeleted++
				} else {
					nExist++
				}
				return nil
			})
		require.NoError(t, err)
		require.Equal(t, nDeleted, 2)
		require.Equal(t, nExist, 0) // This was already processed.
		require.Equal(t, table.Revision(txn), rev-1)

		// Graveyard will now be GCd.
		require.Eventually(t,
			db.graveyardIsEmpty,
			5*time.Second,
			100*time.Millisecond,
			"graveyard not garbage collected")

		// After closing the first delete tracker, deletes are still for second one.
		deleteTracker.Close()
		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 77, Tags: []string{"hello"}})
			txn.Commit()
			txn = db.WriteTxn(table)
			table.DeleteAll(txn)
			txn.Commit()
		}
		require.False(t, db.graveyardIsEmpty())

		// And finally after closing the second tracker deletions are no longer tracked.
		deleteTracker2.Mark(table.Revision(db.ReadTxn()))
		require.Eventually(t,
			db.graveyardIsEmpty,
			5*time.Second,
			100*time.Millisecond,
			"graveyard not garbage collected")

		deleteTracker2.Close()
		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: 78, Tags: []string{"world"}})
			txn.Commit()
			txn = db.WriteTxn(table)
			table.DeleteAll(txn)
			txn.Commit()
		}
		require.True(t, db.graveyardIsEmpty())

	})
}

func TestDB_All(t *testing.T) {
	testWithDB(t, true, func(db *DB, table Table[testObject]) {
		{
			txn := db.WriteTxn(table)
			table.Insert(txn, testObject{ID: uint64(1)})
			table.Insert(txn, testObject{ID: uint64(2)})
			table.Insert(txn, testObject{ID: uint64(3)})
			iter, _ := table.All(txn)
			objs := Collect(iter)
			require.Len(t, objs, 3)
			require.EqualValues(t, 1, objs[0].ID)
			require.EqualValues(t, 2, objs[1].ID)
			require.EqualValues(t, 3, objs[2].ID)
			txn.Commit()
		}

		txn := db.ReadTxn()
		iter, watch := table.All(txn)
		objs := Collect(iter)
		require.Len(t, objs, 3)
		require.EqualValues(t, 1, objs[0].ID)
		require.EqualValues(t, 2, objs[1].ID)
		require.EqualValues(t, 3, objs[2].ID)

		select {
		case <-watch:
			t.Fatalf("expected All() watch channel to not close before changes")
		default:
		}

		{
			txn := db.WriteTxn(table)
			table.Delete(txn, testObject{ID: uint64(1)})
			txn.Commit()
		}

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatalf("expceted All() watch channel to close after changes")
		}
	})
}

func TestDB_Revision(t *testing.T) {
	testWithDB(t, false, func(db *DB, table Table[testObject]) {
		startRevision := table.Revision(db.ReadTxn())

		// On aborted write transactions the revision remains unchanged.
		txn := db.WriteTxn(table)
		_, _, err := table.Insert(txn, testObject{ID: 1})
		require.NoError(t, err)
		writeRevision := table.Revision(txn) // Returns new, but uncommitted revision
		txn.Abort()
		require.Equal(t, writeRevision, startRevision+1, "revision incremented on Insert")
		readRevision := table.Revision(db.ReadTxn())
		require.Equal(t, startRevision, readRevision, "aborted transaction does not change revision")

		// Committed write transactions increment the revision
		txn = db.WriteTxn(table)
		_, _, err = table.Insert(txn, testObject{ID: 1})
		require.NoError(t, err)
		writeRevision = table.Revision(txn)
		txn.Commit()
		require.Equal(t, writeRevision, startRevision+1, "revision incremented on Insert")
		readRevision = table.Revision(db.ReadTxn())
		require.Equal(t, writeRevision, readRevision, "committed transaction changed revision")
	})
}

func TestDB_FirstLast(t *testing.T) {
	testWithDB(t, true, func(db *DB, table Table[testObject]) {
		// Write test objects 1..10 to table with odd/even/odd/... tags.
		{
			txn := db.WriteTxn(table)
			for i := 1; i <= 10; i++ {
				tag := "odd"
				if i%2 == 0 {
					tag = "even"
				}
				_, _, err := table.Insert(txn, testObject{ID: uint64(i), Tags: []string{tag}})
				require.NoError(t, err)
			}
			// Check that we can query the not-yet-committed write transaction.
			obj, rev, ok := table.First(txn, idIndex.Query(1))
			require.True(t, ok, "expected First(1) to return result")
			require.NotZero(t, rev, "expected non-zero revision")
			require.EqualValues(t, obj.ID, 1, "expected first obj.ID to equal 1")
			obj, rev, ok = table.Last(txn, idIndex.Query(1))
			require.True(t, ok, "expected Last(1) to return result")
			require.NotZero(t, rev, "expected non-zero revision")
			require.EqualValues(t, obj.ID, 1, "expected last obj.ID to equal 1")
			txn.Commit()
		}

		txn := db.ReadTxn()

		// Test First/FirstWatch and Last/LastWatch against the ID index.

		_, _, ok := table.First(txn, idIndex.Query(0))
		require.False(t, ok, "expected First(0) to not return result")

		_, _, ok = table.Last(txn, idIndex.Query(0))
		require.False(t, ok, "expected Last(0) to not return result")

		obj, rev, ok := table.First(txn, idIndex.Query(1))
		require.True(t, ok, "expected First(1) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.EqualValues(t, obj.ID, 1, "expected first obj.ID to equal 1")

		obj, rev, ok = table.Last(txn, idIndex.Query(1))
		require.True(t, ok, "expected Last(1) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.EqualValues(t, obj.ID, 1, "expected last obj.ID to equal 1")

		obj, rev, firstWatch, ok := table.FirstWatch(txn, idIndex.Query(2))
		require.True(t, ok, "expected FirstWatch(2) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.EqualValues(t, obj.ID, 2, "expected obj.ID to equal 2")

		obj, rev, lastWatch, ok := table.LastWatch(txn, idIndex.Query(2))
		require.True(t, ok, "expected LastWatch(2) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.EqualValues(t, obj.ID, 2, "expected obj.ID to equal 2")

		select {
		case <-firstWatch:
			t.Fatalf("FirstWatch channel closed before changes")
		case <-lastWatch:
			t.Fatalf("LastWatch channel closed before changes")
		default:
		}

		// Modify the testObject(2) to trigger closing of the watch channels.
		wtxn := db.WriteTxn(table)
		_, hadOld, err := table.Insert(wtxn, testObject{ID: uint64(2), Tags: []string{"even", "modified"}})
		require.True(t, hadOld)
		require.NoError(t, err)
		wtxn.Commit()

		select {
		case <-firstWatch:
		case <-time.After(time.Second):
			t.Fatalf("FirstWatch channel not closed after change")
		}
		select {
		case <-lastWatch:
		case <-time.After(time.Second):
			t.Fatalf("LastWatch channel not closed after change")
		}

		// Since we modified the database, grab a fresh read transaction.
		txn = db.ReadTxn()

		// Test First and Last against the tags multi-index which will
		// return multiple results.

		obj, rev, _, ok = table.FirstWatch(txn, tagsIndex.Query("even"))
		require.True(t, ok, "expected First(even) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.ElementsMatch(t, obj.Tags, []string{"even", "modified"})
		require.EqualValues(t, 2, obj.ID)

		obj, rev, _, ok = table.LastWatch(txn, tagsIndex.Query("odd"))
		require.True(t, ok, "expected First(even) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.ElementsMatch(t, obj.Tags, []string{"odd"})
		require.EqualValues(t, 9, obj.ID)
	})
}

func TestDB_CommitAbort(t *testing.T) {
	testWithDB(t, false, func(db *DB, table Table[testObject]) {
		txn := db.WriteTxn(table)
		_, _, err := table.Insert(txn, testObject{ID: 123, Tags: nil})
		require.NoError(t, err)
		txn.Commit()

		obj, rev, ok := table.First(db.ReadTxn(), idIndex.Query(123))
		require.True(t, ok, "expected First(1) to return result")
		require.NotZero(t, rev, "expected non-zero revision")
		require.EqualValues(t, obj.ID, 123, "expected obj.ID to equal 123")
		require.Nil(t, obj.Tags, "expected no tags")

		_, _, err = table.Insert(txn, testObject{ID: 123, Tags: []string{"insert-after-commit"}})
		require.ErrorIs(t, err, ErrTransactionClosed)
		txn.Commit() // should be no-op

		txn = db.WriteTxn(table)
		txn.Abort()
		_, _, err = table.Insert(txn, testObject{ID: 123, Tags: []string{"insert-after-abort"}})
		require.ErrorIs(t, err, ErrTransactionClosed)
		txn.Commit() // should be no-op

		// Check that insert after commit and insert after abort do not change the
		// table.
		obj, newRev, ok := table.First(db.ReadTxn(), idIndex.Query(123))
		require.True(t, ok, "expected object to exist")
		require.Equal(t, rev, newRev, "expected unchanged revision")
		require.EqualValues(t, obj.ID, 123, "expected obj.ID to equal 123")
		require.Nil(t, obj.Tags, "expected no tags")

	})
}

func TestWriteJSON(t *testing.T) {
	testWithDB(t, true, func(db *DB, table Table[testObject]) {
		buf := new(bytes.Buffer)
		err := db.ReadTxn().WriteJSON(buf)
		require.NoError(t, err)

		txn := db.WriteTxn(table)
		for i := 1; i <= 10; i++ {
			_, _, err := table.Insert(txn, testObject{ID: uint64(i)})
			require.NoError(t, err)
		}
		txn.Commit()

	})
}

func BenchmarkDB_WriteTxn_1(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
		for i := 0; i < b.N; i++ {
			txn := db.WriteTxn(table)
			_, _, err := table.Insert(txn, testObject{ID: 123, Tags: nil})
			require.NoError(b, err)
			txn.Commit()
		}
	})
}

func BenchmarkDB_WriteTxn_10(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func BenchmarkDB_RandomInsert(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func BenchmarkDB_SequentialInsert(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
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
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func BenchmarkDB_DeleteTracker(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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

		require.Eventually(b,
			db.graveyardIsEmpty,
			10*time.Millisecond,
			100*time.Millisecond,
			"graveyard not garbage collected")
	})
}

func BenchmarkDB_RandomLookup(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func BenchmarkDB_SequentialLookup(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func BenchmarkDB_FullIteration(b *testing.B) {
	testWithDB(b, false, func(db *DB, table Table[testObject]) {
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
	})
}

func Test_callerPackage(t *testing.T) {
	pkg := func() string {
		return callerPackage()
	}()
	require.Equal(t, "pkg/statedb", pkg)
}
