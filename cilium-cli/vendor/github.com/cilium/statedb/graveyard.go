// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/time/rate"
)

const (
	// defaultGCRateLimitInterval is the default minimum interval between garbage collections.
	defaultGCRateLimitInterval = time.Second
)

func graveyardWorker(db *DB, ctx context.Context, gcRateLimitInterval time.Duration) {
	limiter := rate.NewLimiter(rate.Every(gcRateLimitInterval), 1)
	defer close(db.gcExited)

	for {
		select {
		case <-ctx.Done():
			return
		case <-db.gcTrigger:
		}

		// Throttle garbage collection.
		if err := limiter.Wait(ctx); err != nil {
			return
		}

		cleaningTimes := make(map[string]time.Duration)

		type deadObjectRevisionKey = []byte
		toBeDeleted := map[TableMeta][]deadObjectRevisionKey{}

		// Do a lockless read transaction to find potential dead objects.
		txn := db.ReadTxn().getTxn()
		for _, table := range txn.root {
			tableName := table.meta.Name()
			start := time.Now()

			// Find the low watermark
			lowWatermark := table.revision
			dtIter := table.deleteTrackers.Iterator()
			for _, dt, ok := dtIter.Next(); ok; _, dt, ok = dtIter.Next() {
				rev := dt.getRevision()
				if rev < lowWatermark {
					lowWatermark = rev
				}
			}

			db.metrics.GraveyardLowWatermark(
				tableName,
				lowWatermark,
			)

			// Find objects to be deleted by iterating over the graveyard revision index up
			// to the low watermark.
			indexTree := txn.mustIndexReadTxn(table.meta, GraveyardRevisionIndexPos)

			objIter := indexTree.Iterator()
			for key, obj, ok := objIter.Next(); ok; key, obj, ok = objIter.Next() {
				if obj.revision > lowWatermark {
					break
				}
				toBeDeleted[table.meta] = append(toBeDeleted[table.meta], key)
			}
			cleaningTimes[tableName] = time.Since(start)
		}

		if len(toBeDeleted) == 0 {
			for tableName, stat := range cleaningTimes {
				db.metrics.GraveyardCleaningDuration(
					tableName,
					stat,
				)
			}
			continue
		}

		// Dead objects found, do a write transaction against all tables with dead objects in them.
		tablesToModify := maps.Keys(toBeDeleted)
		txn = db.WriteTxn(tablesToModify[0], tablesToModify[1:]...).getTxn()
		for meta, deadObjs := range toBeDeleted {
			tableName := meta.Name()
			start := time.Now()
			for _, key := range deadObjs {
				oldObj, existed := txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).Delete(key)
				if existed {
					// The dead object still existed (and wasn't replaced by a create->delete),
					// delete it from the primary index.
					key = meta.primary().fromObject(oldObj).First()
					txn.mustIndexWriteTxn(meta, GraveyardIndexPos).Delete(key)
				}
			}
			cleaningTimes[tableName] = time.Since(start)
		}
		txn.Commit()

		for tableName, stat := range cleaningTimes {
			db.metrics.GraveyardCleaningDuration(
				tableName,
				stat,
			)
		}

		// Update object count metrics.
		txn = db.ReadTxn().getTxn()
		for _, table := range txn.root {
			name := table.meta.Name()
			db.metrics.GraveyardObjectCount(string(name), table.numDeletedObjects())
			db.metrics.ObjectCount(string(name), table.numObjects())
		}
	}
}

// graveyardIsEmpty returns true if no objects exist in the graveyard of any table.
// Used in tests.
func (db *DB) graveyardIsEmpty() bool {
	txn := db.ReadTxn().getTxn()
	for _, table := range txn.root {
		indexEntry := table.indexes[table.meta.indexPos(GraveyardIndex)]
		if indexEntry.tree.Len() != 0 {
			return false
		}
	}
	return true
}
