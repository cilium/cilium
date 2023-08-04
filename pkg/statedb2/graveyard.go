// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"context"
	"time"

	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/rate"
)

const (
	// gcRateLimitInterval is the minium interval between garbage collections
	gcRateLimitInterval = time.Second
)

func graveyardWorker(db *DB) {
	limiter := rate.NewLimiter(gcRateLimitInterval, 1)
	defer limiter.Stop()
	defer close(db.gcExited)

	for {
		// Wait for delete trackers.
		if _, ok := <-db.gcTrigger; !ok {
			// Trigger closed, we're stopping.
			return
		}

		// Throttle garbage collection.
		limiter.Wait(context.Background())

		type deadObjectRevisionKey = []byte
		toBeDeleted := map[TableMeta][]deadObjectRevisionKey{}

		// Do a lockless read transaction to find potential dead objects.
		txn := db.ReadTxn().getTxn()
		tableIter := txn.rootReadTxn.Root().Iterator()
		for name, table, ok := tableIter.Next(); ok; name, table, ok = tableIter.Next() {
			// Find the low watermark
			lowWatermark := table.revision
			dtIter := table.deleteTrackers.Root().Iterator()
			for _, dt, ok := dtIter.Next(); ok; _, dt, ok = dtIter.Next() {
				rev := dt.getRevision()
				if rev < lowWatermark {
					lowWatermark = rev
				}
			}
			// Find objects to be deleted by iterating over the graveyard revision index up
			// to the low watermark.
			indexTree, ok := txn.getTable(string(name)).indexes.Get([]byte(GraveyardRevisionIndex))
			if !ok {
				panic("BUG: Index " + GraveyardRevisionIndex + " not found")
			}
			objIter := indexTree.Root().Iterator()
			for key, obj, ok := objIter.Next(); ok; key, obj, ok = objIter.Next() {
				if obj.revision > lowWatermark {
					break
				}
				toBeDeleted[table.meta] = append(toBeDeleted[table.meta], key)
			}
		}

		if len(toBeDeleted) == 0 {
			continue
		}

		// Dead objects found, do a write transaction against all tables with dead objects in them.
		tablesToModify := maps.Keys(toBeDeleted)
		txn = db.WriteTxn(tablesToModify[0], tablesToModify[1:]...).getTxn()
		for meta, deadObjs := range toBeDeleted {
			numCollected := 0
			tableName := meta.Name()
			for _, key := range deadObjs {
				_, existed := txn.indexWriteTxn(tableName, GraveyardRevisionIndex).Delete(key)
				if existed {
					// The dead object still existed (and wasn't replaced by a create->delete),
					// delete it from the primary index.
					txn.indexWriteTxn(tableName, GraveyardIndex).Delete(key[8:])
					numCollected++
				}
			}
		}
		txn.Commit()

	}
}

// graveyardIsEmpty returns true if no objects exist in the graveyard of any table.
// Used in tests.
func (db *DB) graveyardIsEmpty() bool {
	txn := db.ReadTxn().getTxn()
	tableIter := txn.rootReadTxn.Root().Iterator()
	for name, _, ok := tableIter.Next(); ok; name, _, ok = tableIter.Next() {
		indexTree, ok := txn.getTable(string(name)).indexes.Get([]byte(GraveyardIndex))
		if !ok {
			panic("BUG: Index " + GraveyardIndex + " not found")
		}
		if indexTree.Len() != 0 {
			return false
		}
	}
	return true
}
