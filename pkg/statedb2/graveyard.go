// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/spanstat"
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

		cleaningTimes := make(map[string]*spanstat.SpanStat)

		type deadObjectRevisionKey = []byte
		toBeDeleted := map[TableMeta][]deadObjectRevisionKey{}

		// Do a lockless read transaction to find potential dead objects.
		txn := db.ReadTxn().getTxn()
		tableIter := txn.rootReadTxn.Root().Iterator()
		for name, table, ok := tableIter.Next(); ok; name, table, ok = tableIter.Next() {
			cleaningTimes[string(name)] = spanstat.Start()

			// Find the low watermark
			lowWatermark := table.revision
			dtIter := table.deleteTrackers.Root().Iterator()
			for _, dt, ok := dtIter.Next(); ok; _, dt, ok = dtIter.Next() {
				rev := dt.getRevision()
				if rev < lowWatermark {
					lowWatermark = rev
				}
			}

			db.metrics.TableGraveyardLowWatermark.With(prometheus.Labels{
				"table": string(name),
			}).Set(float64(lowWatermark))

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

			cleaningTimes[string(name)].End(true)
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
				_, existed := txn.indexWriteTxn(tableName, GraveyardRevisionIndex).Delete(key)
				if existed {
					// The dead object still existed (and wasn't replaced by a create->delete),
					// delete it from the primary index.
					txn.indexWriteTxn(tableName, GraveyardIndex).Delete(key[8:])
					txn.pendingGraveyardDeltas[tableName]--
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
