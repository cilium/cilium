// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/cilium/statedb/index"
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

		toBeDeleted := map[TableMeta][]index.Key{}

		// Do a lockless read transaction to find potential dead objects.
		rtxn := db.ReadTxn()
		for _, table := range rtxn.root() {
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
			indexTree := rtxn.mustIndexReadTxn(table.meta, GraveyardRevisionIndexPos)

			iter, _ := indexTree.all()
			for key, obj := range iter.All {
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
		tablesToModify := slices.Collect(maps.Keys(toBeDeleted))
		wtxn := db.WriteTxn(tablesToModify...)
		txn := wtxn.unwrap()
		for meta, deadObjs := range toBeDeleted {
			tableName := meta.Name()
			start := time.Now()
			for _, key := range deadObjs {
				oldObj, existed := txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).delete(key)
				if existed {
					// The dead object still existed (and wasn't replaced by a create->delete),
					// delete it from the primary index.
					graveyard := txn.mustIndexWriteTxn(meta, GraveyardIndexPos)
					graveyard.delete(graveyard.objectToKey(oldObj))
				}
			}
			cleaningTimes[tableName] = time.Since(start)
		}
		wtxn.Commit()

		for tableName, stat := range cleaningTimes {
			db.metrics.GraveyardCleaningDuration(
				tableName,
				stat,
			)
		}

		// Update object count metrics.
		rtxn = db.ReadTxn()
		for _, table := range rtxn.root() {
			name := table.meta.Name()
			db.metrics.GraveyardObjectCount(string(name), table.numDeletedObjects())
			db.metrics.ObjectCount(string(name), table.numObjects())
		}
	}
}

// graveyardIsEmpty returns true if no objects exist in the graveyard of any table.
// Used in tests.
func (db *DB) graveyardIsEmpty() bool {
	txn := db.ReadTxn()
	for _, table := range txn.root() {
		indexEntry := table.indexes[table.meta.indexPos(GraveyardIndex)]
		if indexEntry.len() != 0 {
			return false
		}
	}
	return true
}
