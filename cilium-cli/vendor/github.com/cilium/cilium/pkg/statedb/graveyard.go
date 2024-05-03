// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// defaultGCRateLimitInterval is the default minimum interval between garbage collections.
	defaultGCRateLimitInterval = time.Second
)

func graveyardWorker(db *DB, ctx context.Context, gcRateLimitInterval time.Duration) {
	limiter := rate.NewLimiter(gcRateLimitInterval, 1)
	defer limiter.Stop()
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

		cleaningTimes := make(map[string]*spanstat.SpanStat)

		type deadObjectRevisionKey = []byte
		toBeDeleted := map[TableMeta][]deadObjectRevisionKey{}

		// Do a lockless read transaction to find potential dead objects.
		txn := db.ReadTxn().getTxn()
		tableIter := txn.rootReadTxn.Root().Iterator()
		for nameKey, table, ok := tableIter.Next(); ok; nameKey, table, ok = tableIter.Next() {
			tableName := string(nameKey)
			cleaningTimes[tableName] = spanstat.Start()

			// Find the low watermark
			lowWatermark := table.revision
			dtIter := table.deleteTrackers.Root().Iterator()
			for _, dt, ok := dtIter.Next(); ok; _, dt, ok = dtIter.Next() {
				rev := dt.getRevision()
				// If the revision is higher than zero than the tracker has been observed
				// at least once. If it is zero, then no objects have been seen and thus
				// we don't need to hold onto deleted objects for it.
				if rev > 0 && rev < lowWatermark {
					lowWatermark = rev
				}
			}

			db.metrics.TableGraveyardLowWatermark.With(prometheus.Labels{
				"table": tableName,
			}).Set(float64(lowWatermark))

			// Find objects to be deleted by iterating over the graveyard revision index up
			// to the low watermark.
			indexTree := txn.mustIndexReadTxn(tableName, GraveyardRevisionIndex)

			objIter := indexTree.Root().Iterator()
			for key, obj, ok := objIter.Next(); ok; key, obj, ok = objIter.Next() {
				if obj.revision > lowWatermark {
					break
				}
				toBeDeleted[table.meta] = append(toBeDeleted[table.meta], key)
			}
			cleaningTimes[tableName].End(true)
		}

		if len(toBeDeleted) == 0 {
			for tableName, stat := range cleaningTimes {
				db.metrics.TableGraveyardCleaningDuration.With(prometheus.Labels{
					"table": tableName,
				}).Observe(stat.Total().Seconds())
			}
			continue
		}

		// Dead objects found, do a write transaction against all tables with dead objects in them.
		tablesToModify := maps.Keys(toBeDeleted)
		txn = db.WriteTxn(tablesToModify[0], tablesToModify[1:]...).getTxn()
		for meta, deadObjs := range toBeDeleted {
			tableName := meta.Name()
			cleaningTimes[tableName].Start()
			for _, key := range deadObjs {
				oldObj, existed := txn.mustIndexWriteTxn(tableName, GraveyardRevisionIndex).Delete(key)
				if existed {
					// The dead object still existed (and wasn't replaced by a create->delete),
					// delete it from the primary index.
					key = meta.primary().fromObject(oldObj).First()
					txn.mustIndexWriteTxn(tableName, GraveyardIndex).Delete(key)
				}
			}
			cleaningTimes[tableName].End(true)
		}
		txn.Commit()

		for tableName, stat := range cleaningTimes {
			db.metrics.TableGraveyardCleaningDuration.With(prometheus.Labels{
				"table": tableName,
			}).Observe(stat.Total().Seconds())
		}

		// Update object count metrics.
		txn = db.ReadTxn().getTxn()
		tableIter = txn.rootReadTxn.Root().Iterator()
		for name, table, ok := tableIter.Next(); ok; name, table, ok = tableIter.Next() {
			db.metrics.TableGraveyardObjectCount.With(
				prometheus.Labels{"table": string(name)},
			).Set(float64(table.numDeletedObjects()))
			db.metrics.TableObjectCount.With(
				prometheus.Labels{"table": string(name)},
			).Set(float64(table.numObjects()))
		}
	}
}

// graveyardIsEmpty returns true if no objects exist in the graveyard of any table.
// Used in tests.
func (db *DB) graveyardIsEmpty() bool {
	txn := db.ReadTxn().getTxn()
	tableIter := txn.rootReadTxn.Root().Iterator()
	for _, table, ok := tableIter.Next(); ok; _, table, ok = tableIter.Next() {
		indexEntry, ok := table.indexes.Get([]byte(GraveyardIndex))
		if !ok {
			panic("BUG: GraveyardIndex not found from table")
		}
		if indexEntry.tree.Len() != 0 {
			return false
		}
	}
	return true
}
